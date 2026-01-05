package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// VPNConfig VPN配置结构
type VPNConfig struct {
	ServerAddress    string
	ServerPort       int
	ClientAddress    string
	Network          string
	MTU              int
	KeepAliveTimeout time.Duration
	ReconnectDelay   time.Duration
	MaxConnections   int
	SessionTimeout   time.Duration
}

// 默认配置
var DefaultConfig = VPNConfig{
	ServerAddress:    "localhost",
	ServerPort:       8080,
	ClientAddress:    "10.8.0.2/24",
	Network:          "10.8.0.0/24",
	MTU:              1500,
	KeepAliveTimeout: 60 * time.Second,
	ReconnectDelay:   5 * time.Second,
	MaxConnections:   100,
	SessionTimeout:   5 * time.Minute,
}

// MessageType 消息类型枚举
type MessageType uint8

const (
	MessageTypeData MessageType = iota
	MessageTypeHeartbeat
	MessageTypeIPAssignment
	MessageTypeAuth
	MessageTypeControl
)

// Message VPN消息结构
type Message struct {
	Type    MessageType
	Length  uint32
	Payload []byte
}

// Serialize 序列化消息
func (m *Message) Serialize() ([]byte, error) {
	header := make([]byte, 5) // Type(1) + Length(4)
	header[0] = byte(m.Type)
	binary.BigEndian.PutUint32(header[1:], m.Length)

	return append(header, m.Payload...), nil
}

// Deserialize 反序列化消息
func Deserialize(data []byte) (*Message, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("消息长度不足")
	}

	msgType := MessageType(data[0])
	length := binary.BigEndian.Uint32(data[1:5])

	if uint32(len(data)) < 5+length {
		return nil, fmt.Errorf("消息长度不匹配")
	}

	payload := data[5 : 5+length]
	return &Message{
		Type:    msgType,
		Length:  length,
		Payload: payload,
	}, nil
}

// CertificatePair 证书对
type CertificatePair struct {
	Certificate tls.Certificate
	CAPool      *x509.CertPool
}

// CertificateManager 证书管理器
type CertificateManager struct {
	ServerCert CertificatePair
	ClientCert CertificatePair
	caCert     *x509.Certificate
}

// generateCertificatePair 生成证书对
func generateCertificatePair(isServer bool, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("生成序列号失败: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"SecureVPN Organization"},
			Country:       []string{"CN"},
			Province:      []string{"Beijing"},
			Locality:      []string{"Beijing"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	if isServer {
		template.Subject.CommonName = "vpn-server"
		template.DNSNames = []string{"localhost", "vpn-server"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.Subject.CommonName = "vpn-client"
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	var parentCert *x509.Certificate
	var signingKey interface{}
	if caCert == nil {
		// 生成自签名CA
		caTemplate := template
		caTemplate.IsCA = true
		caTemplate.KeyUsage |= x509.KeyUsageCertSign
		caTemplate.Subject.CommonName = "VPN-CA"
		caCertBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &privateKey.PublicKey, privateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("生成CA证书失败: %v", err)
		}
		caCert, err = x509.ParseCertificate(caCertBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("解析CA证书失败: %v", err)
		}
		signingKey = privateKey
		parentCert = caCert
	} else {
		// 使用现有CA签名
		signingKey = caKey
		parentCert = caCert
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &privateKey.PublicKey, signingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书失败: %v", err)
	}

	certPEM := pemEncode("CERTIFICATE", certDER)
	privateKeyPEM := pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey))

	return certPEM, privateKeyPEM, nil
}

// pemEncode 将数据编码为PEM格式
func pemEncode(blockType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: data,
	})
}

// NewCertificateManager 创建证书管理器
func NewCertificateManager() (*CertificateManager, error) {
	// 首先生成CA证书
	caCertPEM, caKeyPEM, err := generateCertificatePair(true, nil, nil)
	if err != nil {
		return nil, err
	}

	// 修复CA证书解析问题 - 使用pem.Decode
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("无法解码CA证书PEM块")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析CA证书失败: %v", err)
	}

	// 修复CA私钥解析问题 - 使用pem.Decode
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("无法解码CA私钥PEM块")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析CA私钥失败: %v", err)
	}

	// 生成服务器证书
	serverCertPEM, serverKeyPEM, err := generateCertificatePair(true, caCert, caKey)
	if err != nil {
		return nil, err
	}

	// 生成客户端证书
	clientCertPEM, clientKeyPEM, err := generateCertificatePair(false, caCert, caKey)
	if err != nil {
		return nil, err
	}

	// 创建服务器证书对
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("加载服务器证书失败: %v", err)
	}

	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(caCertPEM)

	// 创建客户端证书对
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("加载客户端证书失败: %v", err)
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(caCertPEM)

	return &CertificateManager{
		ServerCert: CertificatePair{
			Certificate: serverCert,
			CAPool:      serverCAPool,
		},
		ClientCert: CertificatePair{
			Certificate: clientCert,
			CAPool:      clientCAPool,
		},
		caCert: caCert,
	}, nil
}

// ServerTLSConfig 服务器TLS配置
func (cm *CertificateManager) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cm.ServerCert.Certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cm.ServerCert.CAPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfig 客户端TLS配置
func (cm *CertificateManager) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cm.ClientCert.Certificate},
		RootCAs:      cm.ClientCert.CAPool,
		ServerName:   "vpn-server",
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}

// VPNSession VPN会话结构
type VPNSession struct {
	ID           string
	RemoteAddr   net.Addr
	TLSConn      *tls.Conn
	LastActivity time.Time
	IP           net.IP
	CertSubject  string // 证书主题，用于绑定IP
	mutex        sync.RWMutex
}

// UpdateActivity 更新活动时间
func (s *VPNSession) UpdateActivity() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.LastActivity = time.Now()
}

// GetActivity 获取活动时间
func (s *VPNSession) GetActivity() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.LastActivity
}

// VPNServer VPN服务器结构
type VPNServer struct {
	listener       net.Listener
	config         *tls.Config
	sessions       map[string]*VPNSession
	sessionMutex   sync.RWMutex
	running        bool
	shutdownChan   chan struct{}
	vpnNetwork     *net.IPNet
	clientIPPool   *IPPool
	packetHandler  func([]byte) error
	sessionCount   int64
	config         VPNConfig
}

// NewVPNServer 创建新的VPN服务器
func NewVPNServer(address string, certManager *CertificateManager, config VPNConfig) (*VPNServer, error) {
	serverConfig := certManager.ServerTLSConfig()
	listener, err := tls.Listen("tcp", address, serverConfig)
	if err != nil {
		return nil, fmt.Errorf("监听失败: %v", err)
	}

	_, vpnNetwork, err := net.ParseCIDR(config.Network)
	if err != nil {
		return nil, fmt.Errorf("解析VPN网络失败: %v", err)
	}

	return &VPNServer{
		listener:     listener,
		config:       serverConfig,
		sessions:     make(map[string]*VPNSession),
		running:      true,
		shutdownChan: make(chan struct{}),
		vpnNetwork:   vpnNetwork,
		clientIPPool: NewIPPool(vpnNetwork),
		config:       config,
	}, nil
}

// Start 启动VPN服务器
func (s *VPNServer) Start() {
	log.Printf("VPN服务器启动，监听地址: %s", s.listener.Addr())
	defer s.listener.Close()

	// 启动会话清理协程
	go s.cleanupSessions()

	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if !s.running {
				break
			}
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}

	log.Println("VPN服务器已停止")
}

// handleConnection 处理连接
func (s *VPNServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("非TLS连接被拒绝: %s", conn.RemoteAddr())
		return
	}

	err := tlsConn.Handshake()
	if err != nil {
		log.Printf("TLS握手失败: %v", err)
		return
	}

	// 验证客户端证书
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("客户端未提供证书: %s", conn.RemoteAddr())
		return
	}

	// 检查连接数限制
	s.sessionMutex.RLock()
	count := s.sessionCount
	s.sessionMutex.RUnlock()
	if count >= int64(s.config.MaxConnections) {
		log.Printf("连接数已达到上限: %d", s.config.MaxConnections)
		return
	}

	// 获取证书主题
	clientCert := state.PeerCertificates[0]
	certSubject := clientCert.Subject.CommonName

	// 分配IP地址
	clientIP := s.clientIPPool.AllocateIP()
	if clientIP == nil {
		log.Printf("IP地址池已满: %s", conn.RemoteAddr())
		return
	}

	sessionID := fmt.Sprintf("%s_%d", conn.RemoteAddr(), time.Now().UnixNano())
	session := &VPNSession{
		ID:           sessionID,
		RemoteAddr:   conn.RemoteAddr(),
		TLSConn:      tlsConn,
		LastActivity: time.Now(),
		IP:           clientIP,
		CertSubject:  certSubject,
	}

	s.addSession(sessionID, session)
	log.Printf("客户端连接建立: %s (IP: %s, Cert: %s, ID: %s)", 
		conn.RemoteAddr(), clientIP, certSubject, sessionID)

	// 发送IP分配信息
	ipMsg := &Message{
		Type:    MessageTypeIPAssignment,
		Length:  uint32(len(clientIP)),
		Payload: clientIP,
	}
	ipData, err := ipMsg.Serialize()
	if err != nil {
		log.Printf("序列化IP分配消息失败: %v", err)
		s.removeSession(sessionID)
		return
	}

	_, err = tlsConn.Write(ipData)
	if err != nil {
		log.Printf("发送IP分配信息失败: %v", err)
		s.removeSession(sessionID)
		return
	}

	// 启动数据处理协程
	go s.handleSessionData(session)
}

// handleSessionData 处理会话数据
func (s *VPNServer) handleSessionData(session *VPNSession) {
	defer func() {
		s.removeSession(session.ID)
	}()

	for s.running {
		session.TLSConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// 读取消息头（5字节：类型+长度）
		header := make([]byte, 5)
		_, err := io.ReadFull(session.TLSConn, header)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 检查是否超时
				if time.Since(session.GetActivity()) > 60*time.Second {
					log.Printf("会话超时: %s", session.ID)
					break
				}
				continue // 继续等待数据
			}
			if err != io.EOF {
				log.Printf("读取消息头失败: %v", err)
			}
			break
		}

		// 解析消息头
		msgType := MessageType(header[0])
		length := binary.BigEndian.Uint32(header[1:])

		// 读取消息体
		payload := make([]byte, length)
		_, err = io.ReadFull(session.TLSConn, payload)
		if err != nil {
			log.Printf("读取消息体失败: %v", err)
			break
		}

		session.UpdateActivity()

		// 处理不同类型的消息
		switch msgType {
		case MessageTypeHeartbeat:
			// 响应心跳
			response := &Message{
				Type:    MessageTypeHeartbeat,
				Length:  0,
				Payload: []byte{},
			}
			responseData, err := response.Serialize()
			if err != nil {
				log.Printf("序列化心跳响应失败: %v", err)
				continue
			}
			_, err = session.TLSConn.Write(responseData)
			if err != nil {
				log.Printf("发送心跳响应失败: %v", err)
				break
			}
		case MessageTypeData:
			// 处理数据包
			log.Printf("从会话 %s 接收到数据包，长度: %d", session.ID, len(payload))
			// 这里可以实现IP包转发逻辑
			// 回显数据包（实际应用中应转发到目标地址）
			response := &Message{
				Type:    MessageTypeData,
				Length:  uint32(len(payload)),
				Payload: payload,
			}
			responseData, err := response.Serialize()
			if err != nil {
				log.Printf("序列化数据响应失败: %v", err)
				continue
			}
			_, err = session.TLSConn.Write(responseData)
			if err != nil {
				log.Printf("发送数据响应失败: %v", err)
				break
			}
		default:
			log.Printf("收到未知消息类型: %d", msgType)
		}
	}

	log.Printf("会话断开: %s", session.ID)
}

// addSession 添加会话
func (s *VPNServer) addSession(id string, session *VPNSession) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	s.sessions[id] = session
	s.sessionCount++
}

// removeSession 移除会话
func (s *VPNServer) removeSession(id string) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	if session, exists := s.sessions[id]; exists {
		s.clientIPPool.ReleaseIP(session.IP)
		delete(s.sessions, id)
		session.TLSConn.Close()
		s.sessionCount--
	}
}

// cleanupSessions 清理会话
func (s *VPNServer) cleanupSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.sessionMutex.Lock()
		for id, session := range s.sessions {
			if time.Since(session.GetActivity()) > s.config.SessionTimeout {
				log.Printf("清理超时会话: %s", id)
				s.clientIPPool.ReleaseIP(session.IP)
				delete(s.sessions, id)
				session.TLSConn.Close()
				s.sessionCount--
			}
		}
		s.sessionMutex.Unlock()
	}
}

// Stop 停止服务器
func (s *VPNServer) Stop() {
	s.running = false
	close(s.shutdownChan)
	s.listener.Close()

	s.sessionMutex.Lock()
	for id, session := range s.sessions {
		session.TLSConn.Close()
		delete(s.sessions, id)
	}
	s.sessionCount = 0
	s.sessionMutex.Unlock()
}

// IPPool IP地址池
type IPPool struct {
	network    *net.IPNet
	allocated  map[string]bool
	mutex      sync.RWMutex
}

// NewIPPool 创建IP地址池
func NewIPPool(network *net.IPNet) *IPPool {
	return &IPPool{
		network:   network,
		allocated: make(map[string]bool),
	}
}

// AllocateIP 分配IP地址
func (p *IPPool) AllocateIP() net.IP {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// 从网络中分配IP（跳过网络地址和广播地址）
	ip := p.network.IP.To4()
	if ip == nil {
		return nil
	}

	// 从10.8.0.2开始分配
	for i := 2; i < 254; i++ {
		testIP := net.IPv4(ip[0], ip[1], ip[2], byte(i))
		ipStr := testIP.String()
		if !p.allocated[ipStr] {
			p.allocated[ipStr] = true
			return testIP
		}
	}

	return nil
}

// ReleaseIP 释放IP地址
func (p *IPPool) ReleaseIP(ip net.IP) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.allocated[ip.String()] = false
}

// VPNClient VPN客户端结构
type VPNClient struct {
	tlsConfig    *tls.Config
	conn         *tls.Conn
	assignedIP   net.IP
	running      bool
	reconnect    bool
	config       VPNConfig
	packetHandler func([]byte) error
}

// NewVPNClient 创建新的VPN客户端
func NewVPNClient(certManager *CertificateManager, config VPNConfig) *VPNClient {
	return &VPNClient{
		tlsConfig:     certManager.ClientTLSConfig(),
		running:       true,
		reconnect:     true,
		config:        config,
		packetHandler: nil, // 现在使用这个字段
	}
}

// Connect 连接到VPN服务器
func (c *VPNClient) Connect() error {
	address := fmt.Sprintf("%s:%d", c.config.ServerAddress, c.config.ServerPort)
	
	conn, err := tls.Dial("tcp", address, c.tlsConfig)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	err = conn.Handshake()
	if err != nil {
		conn.Close()
		return fmt.Errorf("TLS握手失败: %v", err)
	}

	// 验证TLS版本
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		conn.Close()
		return fmt.Errorf("未使用TLS 1.3协议")
	}

	c.conn = conn
	log.Println("成功连接到VPN服务器，使用TLS 1.3协议")

	// 读取分配的IP
	header := make([]byte, 5)
	_, err = io.ReadFull(c.conn, header)
	if err != nil {
		return fmt.Errorf("读取消息头失败: %v", err)
	}

	msg, err := Deserialize(header)
	if err != nil {
		return fmt.Errorf("解析消息头失败: %v", err)
	}

	// 读取消息体
	payload := make([]byte, msg.Length)
	_, err = io.ReadFull(c.conn, payload)
	if err != nil {
		return fmt.Errorf("读取消息体失败: %v", err)
	}

	if msg.Type == MessageTypeIPAssignment && len(payload) >= 4 {
		c.assignedIP = net.IP(payload)
		log.Printf("分配的VPN IP: %s", c.assignedIP)
	} else {
		return fmt.Errorf("未收到有效的IP分配信息: type=%d, length=%d", msg.Type, msg.Length)
	}

	return nil
}

// SendData 发送数据
func (c *VPNClient) SendData(data []byte) error {
	if c.conn == nil {
		return fmt.Errorf("连接未建立")
	}

	msg := &Message{
		Type:    MessageTypeData,
		Length:  uint32(len(data)),
		Payload: data,
	}
	
	serialized, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}

	_, err = c.conn.Write(serialized)
	return err
}

// SendHeartbeat 发送心跳
func (c *VPNClient) SendHeartbeat() error {
	if c.conn == nil {
		return fmt.Errorf("连接未建立")
	}

	msg := &Message{
		Type:    MessageTypeHeartbeat,
		Length:  0,
		Payload: []byte{},
	}
	
	serialized, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("序列化心跳消息失败: %v", err)
	}

	_, err = c.conn.Write(serialized)
	return err
}

// ReceiveData 接收数据
func (c *VPNClient) ReceiveData() ([]byte, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("连接未建立")
	}

	// 读取消息头
	header := make([]byte, 5)
	_, err := io.ReadFull(c.conn, header)
	if err != nil {
		return nil, err
	}

	msg, err := Deserialize(header)
	if err != nil {
		return nil, err
	}

	// 读取消息体
	payload := make([]byte, msg.Length)
	_, err = io.ReadFull(c.conn, payload)
	if err != nil {
		return nil, err
	}

	// 处理心跳响应
	if msg.Type == MessageTypeHeartbeat {
		return nil, nil // 心跳不返回数据
	}

	return payload, nil
}

// Run 运行客户端
func (c *VPNClient) Run() {
	for c.running && c.reconnect {
		err := c.Connect()
		if err != nil {
			log.Printf("连接失败: %v，%v秒后重试", err, c.config.ReconnectDelay/time.Second)
			time.Sleep(c.config.ReconnectDelay)
			continue
		}

		log.Println("VPN客户端已连接，开始数据传输...")

		// 启动心跳协程
		go c.startHeartbeat()

		// 数据传输循环
		c.dataLoop()

		if c.reconnect {
			log.Println("连接断开，尝试重连...")
			time.Sleep(c.config.ReconnectDelay)
		}
	}

	log.Println("VPN客户端已退出")
}

// startHeartbeat 开始心跳
func (c *VPNClient) startHeartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if c.conn == nil {
			break
		}
		
		// 发送心跳包
		err := c.SendHeartbeat()
		if err != nil {
			log.Printf("发送心跳失败: %v", err)
			break
		}
	}
}

// dataLoop 数据传输循环
func (c *VPNClient) dataLoop() {
	for c.running {
		c.conn.SetReadDeadline(time.Now().Add(c.config.KeepAliveTimeout))

		data, err := c.ReceiveData()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("连接超时")
				break
			}
			log.Printf("读取数据失败: %v", err)
			break
		}

		// 如果有数据且有处理器，调用处理器
		if data != nil && c.packetHandler != nil {
			err := c.packetHandler(data)
			if err != nil {
				log.Printf("处理数据包失败: %v", err)
			}
		} else if data != nil {
			// 默认处理：打印数据包信息
			log.Printf("接收到数据包，长度: %d, 内容: %s", len(data), hex.EncodeToString(data[:min(len(data), 16)]))
		}
	}
}

// Close 关闭客户端
func (c *VPNClient) Close() {
	c.running = false
	c.reconnect = false
	if c.conn != nil {
		c.conn.Close()
	}
}

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	// 生成证书管理器
	log.Println("初始化证书管理器...")
	certManager, err := NewCertificateManager()
	if err != nil {
		log.Fatalf("初始化证书管理器失败: %v", err)
	}

	// 检查命令行参数
	if len(os.Args) < 2 {
		log.Println("用法: go run main.go [server|client]")
		log.Println("  server - 启动VPN服务器")
		log.Println("  client - 启动VPN客户端")
		return
	}

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	switch os.Args[1] {
	case "server":
		// 启动VPN服务器
		server, err := NewVPNServer(":8080", certManager, DefaultConfig)
		if err != nil {
			log.Fatalf("创建VPN服务器失败: %v", err)
		}

		// 在协程中启动服务器
		go server.Start()

		// 等待信号
		sig := <-sigChan
		log.Printf("收到信号: %v，正在关闭服务器...", sig)
		server.Stop()

	case "client":
		// 启动VPN客户端
		client := NewVPNClient(certManager, DefaultConfig)

		// 设置数据包处理器（可选）
		client.packetHandler = func(data []byte) error {
			log.Printf("客户端处理数据包: %s", hex.EncodeToString(data[:min(len(data), 16)]))
			return nil
		}

		// 运行客户端
		go client.Run()

		// 等待信号
		sig := <-sigChan
		log.Printf("收到信号: %v，正在关闭客户端...", sig)
		client.Close()

	default:
		log.Println("未知参数，使用 'server' 或 'client'")
	}
}



