package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
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
	// 证书相关配置
	CertDir        string // 证书目录，默认为 ./certs/
	CACertPath     string // CA证书路径
	CAKeyPath      string // CA私钥路径
	ServerCertPath string // 服务器证书路径
	ServerKeyPath  string // 服务器私钥路径
	ClientCertPath string // 客户端证书路径
	ClientKeyPath  string // 客户端私钥路径
	// 认证相关配置
	AuthKey string // 预共享密钥
}

// ValidateConfig 验证配置
func (c *VPNConfig) ValidateConfig() error {
	if c.ServerAddress == "" {
		return fmt.Errorf("服务器地址不能为空")
	}
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return fmt.Errorf("服务器端口必须在1-65535之间")
	}
	if c.Network == "" {
		return fmt.Errorf("VPN网络不能为空")
	}
	if _, _, err := net.ParseCIDR(c.Network); err != nil {
		return fmt.Errorf("VPN网络格式无效: %v", err)
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("MTU必须在576-9000之间")
	}
	if c.KeepAliveTimeout < 10*time.Second {
		return fmt.Errorf("保活超时不能小于10秒")
	}
	if c.ReconnectDelay < 1*time.Second {
		return fmt.Errorf("重连延迟不能小于1秒")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 10000 {
		return fmt.Errorf("最大连接数必须在1-10000之间")
	}
	if c.SessionTimeout < 30*time.Second {
		return fmt.Errorf("会话超时不能小于30秒")
	}
	return nil
}

// 默认配置
var DefaultConfig = VPNConfig{
	ServerAddress:    "localhost",
	ServerPort:       8080,
	ClientAddress:    "10.8.0.2/24",
	Network:          "10.8.0.0/24",
	MTU:              1500,
	KeepAliveTimeout: 90 * time.Second,
	ReconnectDelay:   5 * time.Second,
	MaxConnections:   100,
	SessionTimeout:   5 * time.Minute,
	CertDir:          "./certs/",
	CACertPath:       "./certs/ca.crt",
	CAKeyPath:        "./certs/ca.key",
	ServerCertPath:   "./certs/server.crt",
	ServerKeyPath:    "./certs/server.key",
	ClientCertPath:   "./certs/client.crt",
	ClientKeyPath:    "./certs/client.key",
	AuthKey:          "", // 默认不需要认证，可从环境变量VPN_AUTH_KEY读取
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

// generateCACertificate 生成CA证书
func generateCACertificate() ([]byte, []byte, *x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成CA私钥失败: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成CA序列号失败: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SecureVPN Organization"},
			Country:      []string{"CN"},
			Province:     []string{"Beijing"},
			Locality:     []string{"Beijing"},
			CommonName:   "VPN-CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years for CA
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成CA证书失败: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("解析CA证书失败: %v", err)
	}

	caCertPEM := pemEncode("CERTIFICATE", caCertBytes)
	caKeyPEM := pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey))

	return caCertPEM, caKeyPEM, caCert, privateKey, nil
}

// generateCertificatePair 生成由CA签名的证书对
func generateCertificatePair(isServer bool, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte, error) {
	if caCert == nil || caKey == nil {
		return nil, nil, fmt.Errorf("CA证书和私钥不能为空")
	}

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
			Organization: []string{"SecureVPN Organization"},
			Country:      []string{"CN"},
			Province:     []string{"Beijing"},
			Locality:     []string{"Beijing"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	if isServer {
		template.Subject.CommonName = "vpn-server"
		template.DNSNames = []string{"localhost", "vpn-server"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		template.Subject.CommonName = "vpn-client"
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
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

// ensureCertDir 确保证书目录存在
func ensureCertDir(certDir string) error {
	info, err := os.Stat(certDir)
	if os.IsNotExist(err) {
		// 创建目录
		if err := os.MkdirAll(certDir, 0700); err != nil {
			return fmt.Errorf("创建证书目录失败: %v", err)
		}
		log.Printf("证书目录已创建: %s", certDir)
		return nil
	}
	if err != nil {
		return fmt.Errorf("检查证书目录失败: %v", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("证书路径存在但不是目录: %s", certDir)
	}
	// 检查目录权限
	if info.Mode().Perm()&0077 != 0 {
		log.Printf("警告: 证书目录权限过于开放: %s (建议使用 chmod 700)", certDir)
	}
	return nil
}

// saveCertificateToFile 保存证书到文件
func saveCertificateToFile(certPath string, certPEM []byte) error {
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("保存证书失败: %v", err)
	}
	log.Printf("证书已保存: %s", certPath)
	return nil
}

// loadCertificateFromFile 从文件加载证书
func loadCertificateFromFile(certPath, keyPath string) ([]byte, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取证书文件失败 %s: %v", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取私钥文件失败 %s: %v", keyPath, err)
	}
	return certPEM, keyPEM, nil
}

// validateCertificate 验证证书有效性和有效期
func validateCertificate(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("无效的PEM格式")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析证书失败: %v", err)
	}
	
	// 检查证书是否已过期
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("证书尚未生效 (NotBefore: %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("证书已过期 (NotAfter: %v)", cert.NotAfter)
	}
	
	// 检查即将过期的证书 (30天内)
	if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		log.Printf("警告: 证书将在 %v 过期", cert.NotAfter)
	}
	
	return nil
}

// NewCertificateManager 创建证书管理器
func NewCertificateManager(config VPNConfig) (*CertificateManager, error) {
	var caCertPEM, caKeyPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM []byte
	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey
	var err error
	
	// 确保证书目录存在
	if err := ensureCertDir(config.CertDir); err != nil {
		return nil, err
	}
	
	// 尝试从文件加载CA证书
	if _, err := os.Stat(config.CACertPath); err == nil {
		log.Printf("从文件加载CA证书: %s", config.CACertPath)
		caCertPEM, caKeyPEM, err = loadCertificateFromFile(config.CACertPath, config.CAKeyPath)
		if err != nil {
			return nil, fmt.Errorf("加载CA证书失败: %v", err)
		}
		
		// 验证CA证书
		if err := validateCertificate(caCertPEM); err != nil {
			return nil, fmt.Errorf("CA证书验证失败: %v", err)
		}
		
		// 解析CA证书和私钥
		block, _ := pem.Decode(caCertPEM)
		if block == nil {
			return nil, fmt.Errorf("解码CA证书失败")
		}
		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析CA证书失败: %v", err)
		}
		
		keyBlock, _ := pem.Decode(caKeyPEM)
		if keyBlock == nil {
			return nil, fmt.Errorf("解码CA私钥失败")
		}
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析CA私钥失败: %v", err)
		}
	} else {
		// 生成新的CA证书
		log.Println("生成新的CA证书...")
		caCertPEM, caKeyPEM, caCert, caKey, err = generateCACertificate()
		if err != nil {
			return nil, fmt.Errorf("生成CA证书失败: %v", err)
		}
		
		// 保存CA证书
		if err := saveCertificateToFile(config.CACertPath, caCertPEM); err != nil {
			return nil, err
		}
		if err := saveCertificateToFile(config.CAKeyPath, caKeyPEM); err != nil {
			return nil, err
		}
	}
	
	// 尝试从文件加载服务器证书
	if _, err := os.Stat(config.ServerCertPath); err == nil {
		log.Printf("从文件加载服务器证书: %s", config.ServerCertPath)
		serverCertPEM, serverKeyPEM, err = loadCertificateFromFile(config.ServerCertPath, config.ServerKeyPath)
		if err != nil {
			return nil, fmt.Errorf("加载服务器证书失败: %v", err)
		}
		
		// 验证服务器证书
		if err := validateCertificate(serverCertPEM); err != nil {
			log.Printf("服务器证书验证失败: %v，将重新生成", err)
			serverCertPEM, serverKeyPEM = nil, nil
		}
	}
	
	// 如果服务器证书不存在或验证失败，生成新的
	if serverCertPEM == nil {
		log.Println("生成新的服务器证书...")
		serverCertPEM, serverKeyPEM, err = generateCertificatePair(true, caCert, caKey)
		if err != nil {
			return nil, fmt.Errorf("生成服务器证书失败: %v", err)
		}
		
		// 保存服务器证书
		if err := saveCertificateToFile(config.ServerCertPath, serverCertPEM); err != nil {
			return nil, err
		}
		if err := saveCertificateToFile(config.ServerKeyPath, serverKeyPEM); err != nil {
			return nil, err
		}
	}
	
	// 尝试从文件加载客户端证书
	if _, err := os.Stat(config.ClientCertPath); err == nil {
		log.Printf("从文件加载客户端证书: %s", config.ClientCertPath)
		clientCertPEM, clientKeyPEM, err = loadCertificateFromFile(config.ClientCertPath, config.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("加载客户端证书失败: %v", err)
		}
		
		// 验证客户端证书
		if err := validateCertificate(clientCertPEM); err != nil {
			log.Printf("客户端证书验证失败: %v，将重新生成", err)
			clientCertPEM, clientKeyPEM = nil, nil
		}
	}
	
	// 如果客户端证书不存在或验证失败，生成新的
	if clientCertPEM == nil {
		log.Println("生成新的客户端证书...")
		clientCertPEM, clientKeyPEM, err = generateCertificatePair(false, caCert, caKey)
		if err != nil {
			return nil, fmt.Errorf("生成客户端证书失败: %v", err)
		}
		
		// 保存客户端证书
		if err := saveCertificateToFile(config.ClientCertPath, clientCertPEM); err != nil {
			return nil, err
		}
		if err := saveCertificateToFile(config.ClientKeyPath, clientKeyPEM); err != nil {
			return nil, err
		}
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
	closed       bool   // 标记会话是否已关闭
	mutex        sync.RWMutex
	connMutex    sync.Mutex // 保护TLSConn操作
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

// IsClosed 检查会话是否已关闭
func (s *VPNSession) IsClosed() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.closed
}

// Close 关闭会话连接
func (s *VPNSession) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil // 已经关闭
	}
	s.closed = true
	if s.TLSConn != nil {
		return s.TLSConn.Close()
	}
	return nil
}

// VPNServer VPN服务器结构
type VPNServer struct {
	listener          net.Listener
	tlsConfig         *tls.Config
	sessions          map[string]*VPNSession
	ipMap             map[string]*VPNSession // IP到Session的映射，加速查找
	sessionMutex      sync.RWMutex
	running           bool
	shutdownChan      chan struct{}
	vpnNetwork        *net.IPNet
	clientIPPool      *IPPool
	packetHandler     func([]byte) error
	sessionCount      int64
	config            VPNConfig
	tunDevice         *water.Interface
	serverIP          net.IP
	originalIPForward string       // 保存原始IP转发设置
	wg                sync.WaitGroup // 跟踪所有goroutine
	ctx               context.Context
	cancel            context.CancelFunc
}

// NewVPNServer 创建新的VPN服务器
func NewVPNServer(address string, certManager *CertificateManager, config VPNConfig) (*VPNServer, error) {
	// 验证配置
	if err := config.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	serverConfig := certManager.ServerTLSConfig()
	listener, err := tls.Listen("tcp", address, serverConfig)
	if err != nil {
		return nil, fmt.Errorf("监听失败: %v", err)
	}

	_, vpnNetwork, err := net.ParseCIDR(config.Network)
	if err != nil {
		return nil, fmt.Errorf("解析VPN网络失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	return &VPNServer{
		listener:     listener,
		tlsConfig:    serverConfig,
		sessions:     make(map[string]*VPNSession),
		ipMap:        make(map[string]*VPNSession),
		running:      true,
		shutdownChan: make(chan struct{}),
		vpnNetwork:   vpnNetwork,
		clientIPPool: NewIPPool(vpnNetwork),
		config:       config,
		serverIP:     vpnNetwork.IP.To4(),
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// InitializeTUN 初始化TUN设备
func (s *VPNServer) InitializeTUN() error {
	// 检查root权限
	if err := checkRootPrivileges(); err != nil {
		return err
	}

	// 创建TUN设备
	tun, err := createTUNDevice("tun0")
	if err != nil {
		return err
	}
	s.tunDevice = tun

	// 配置TUN设备 - 服务器使用10.8.0.1/24
	serverIP := net.IPv4(s.serverIP[0], s.serverIP[1], s.serverIP[2], 1)
	s.serverIP = serverIP
	ipAddr := fmt.Sprintf("%s/24", serverIP.String())
	
	if err := configureTUNDevice(tun.Name(), ipAddr, s.config.MTU); err != nil {
		tun.Close()
		return err
	}

	// 启用IP转发并保存原始值
	originalIPForward, err := enableIPForwarding()
	if err != nil {
		tun.Close()
		return err
	}
	s.originalIPForward = originalIPForward

	log.Printf("服务器TUN设备已初始化: %s", serverIP.String())
	return nil
}

// Start 启动VPN服务器
func (s *VPNServer) Start() {
	log.Printf("VPN服务器启动，监听地址: %s", s.listener.Addr())
	defer s.listener.Close()
	
	// 如果有TUN设备，启动TUN数据转发
	if s.tunDevice != nil {
		s.wg.Add(1)
		go s.handleTUNRead()
	}

	// 启动会话清理协程
	s.wg.Add(1)
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

		s.wg.Add(1)
		go s.handleConnection(conn)
	}

	log.Println("VPN服务器已停止")
}

// handleConnection 处理连接
func (s *VPNServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
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

	// 如果配置了认证密钥，进行认证
	if s.config.AuthKey != "" {
		// 等待客户端发送认证消息
		tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		header := make([]byte, 5)
		_, err := io.ReadFull(tlsConn, header)
		if err != nil {
			log.Printf("读取认证消息头失败: %s - %v", conn.RemoteAddr(), err)
			return
		}
		
		msgType := MessageType(header[0])
		length := binary.BigEndian.Uint32(header[1:])
		
		if msgType != MessageTypeAuth {
			log.Printf("期望认证消息，但收到类型 %d: %s", msgType, conn.RemoteAddr())
			return
		}
		
		if length > 1024 {
			log.Printf("认证消息过大: %d 字节", length)
			return
		}
		
		payload := make([]byte, length)
		_, err = io.ReadFull(tlsConn, payload)
		if err != nil {
			log.Printf("读取认证消息体失败: %s - %v", conn.RemoteAddr(), err)
			return
		}
		
		// 验证认证密钥
		if string(payload) != s.config.AuthKey {
			log.Printf("认证失败: 无效的密钥 - %s", conn.RemoteAddr())
			return
		}
		
		log.Printf("客户端认证成功: %s", conn.RemoteAddr())
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
	s.wg.Add(1)
	go s.handleSessionData(session)
}

// handleSessionData 处理会话数据
func (s *VPNServer) handleSessionData(session *VPNSession) {
	defer func() {
		s.wg.Done()
		if r := recover(); r != nil {
			log.Printf("会话 %s 处理发生panic: %v", session.ID, r)
		}
		s.removeSession(session.ID)
	}()

	for s.running && !session.IsClosed() {
		// 使用connMutex保护SetReadDeadline
		session.connMutex.Lock()
		if session.TLSConn != nil {
			session.TLSConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
		conn := session.TLSConn
		session.connMutex.Unlock()
		
		if conn == nil {
			break
		}

		// 读取消息头（5字节：类型+长度）
		header := make([]byte, 5)
		_, err := io.ReadFull(conn, header)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 检查是否超时
				if time.Since(session.GetActivity()) > 90*time.Second {
					log.Printf("会话超时: %s", session.ID)
					break
				}
				continue // 继续等待数据
			}
			if err != io.EOF {
				log.Printf("会话 %s 读取消息头失败: %v", session.ID, err)
			}
			break
		}

		// 解析消息头
		msgType := MessageType(header[0])
		length := binary.BigEndian.Uint32(header[1:])

		// 防止过大的消息
		if length > 65535 {
			log.Printf("会话 %s 消息过大: %d 字节", session.ID, length)
			break
		}

		// 读取消息体
		payload := make([]byte, length)
		if length > 0 {
			_, err = io.ReadFull(session.TLSConn, payload)
			if err != nil {
				log.Printf("会话 %s 读取消息体失败: %v", session.ID, err)
				break
			}
		}

		session.UpdateActivity()

		// 处理不同类型的消息
		switch msgType {
		case MessageTypeHeartbeat:
			// 响应心跳
			if err := s.sendHeartbeatResponse(session); err != nil {
				log.Printf("会话 %s 发送心跳响应失败: %v", session.ID, err)
				break
			}
		case MessageTypeData:
			// 处理数据包 - 写入TUN设备
			if s.tunDevice != nil && len(payload) > 0 {
				_, err := s.tunDevice.Write(payload)
				if err != nil {
					log.Printf("会话 %s 写入TUN设备失败: %v", session.ID, err)
				}
			} else {
				log.Printf("从会话 %s 接收到数据包，长度: %d", session.ID, len(payload))
			}
		default:
			log.Printf("会话 %s 收到未知消息类型: %d", session.ID, msgType)
		}
	}

	log.Printf("会话断开: %s", session.ID)
}

// sendHeartbeatResponse 发送心跳响应
func (s *VPNServer) sendHeartbeatResponse(session *VPNSession) error {
	response := &Message{
		Type:    MessageTypeHeartbeat,
		Length:  0,
		Payload: []byte{},
	}
	responseData, err := response.Serialize()
	if err != nil {
		return fmt.Errorf("序列化心跳响应失败: %v", err)
	}
	_, err = session.TLSConn.Write(responseData)
	return err
}

// sendDataResponse 发送数据响应
func (s *VPNServer) sendDataResponse(session *VPNSession, payload []byte) error {
	response := &Message{
		Type:    MessageTypeData,
		Length:  uint32(len(payload)),
		Payload: payload,
	}
	responseData, err := response.Serialize()
	if err != nil {
		return fmt.Errorf("序列化数据响应失败: %v", err)
	}
	_, err = session.TLSConn.Write(responseData)
	return err
}

// handleTUNRead 处理从TUN设备读取的数据
func (s *VPNServer) handleTUNRead() {
	defer s.wg.Done()
	
	packet := make([]byte, s.config.MTU)
	
	for s.running {
		n, err := s.tunDevice.Read(packet)
		if err != nil {
			if s.running {
				log.Printf("从TUN设备读取失败: %v", err)
			}
			break
		}

		if n < 20 { // IP header minimum size
			continue
		}

		// 提取目标IP地址 (IP header offset 16-19)
		destIP := net.IP(packet[16:20])
		destIPStr := destIP.String()
		
		// 使用IP映射快速查找会话
		s.sessionMutex.RLock()
		targetSession := s.ipMap[destIPStr]
		// 检查会话是否有效
		if targetSession != nil && targetSession.IsClosed() {
			targetSession = nil
		}
		s.sessionMutex.RUnlock()

		if targetSession != nil {
			// 发送到目标客户端
			err := s.sendDataResponse(targetSession, packet[:n])
			if err != nil {
				log.Printf("转发数据包到客户端 %s 失败: %v", destIP, err)
			}
		}
	}
}

// addSession 添加会话
func (s *VPNServer) addSession(id string, session *VPNSession) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	s.sessions[id] = session
	// 维护IP映射
	if session.IP != nil {
		s.ipMap[session.IP.String()] = session
	}
	s.sessionCount++
}

// removeSession 移除会话
func (s *VPNServer) removeSession(id string) {
	s.sessionMutex.Lock()
	session, exists := s.sessions[id]
	if exists {
		s.clientIPPool.ReleaseIP(session.IP)
		delete(s.sessions, id)
		// 移除IP映射
		if session.IP != nil {
			delete(s.ipMap, session.IP.String())
		}
		s.sessionCount--
	}
	s.sessionMutex.Unlock()
	
	// 在锁外部关闭连接，避免死锁
	if exists && session != nil {
		session.Close()
	}
}

// cleanupSessions 清理会话
func (s *VPNServer) cleanupSessions() {
	defer s.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !s.running {
			return
		}
		
		// 收集需要清理的会话ID
		var toCleanup []string
		s.sessionMutex.RLock()
		for id, session := range s.sessions {
			if time.Since(session.GetActivity()) > s.config.SessionTimeout {
				toCleanup = append(toCleanup, id)
			}
		}
		s.sessionMutex.RUnlock()

		// 释放锁后再清理会话
		for _, id := range toCleanup {
			log.Printf("清理超时会话: %s", id)
			s.removeSession(id)
		}
	}
}

// Stop 停止服务器
func (s *VPNServer) Stop() {
	log.Println("正在停止VPN服务器...")
	
	// 标记停止并取消context
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	close(s.shutdownChan)
	
	// 关闭监听器，停止接受新连接
	if s.listener != nil {
		s.listener.Close()
	}

	// 收集所有会话ID
	s.sessionMutex.Lock()
	sessionIDs := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		sessionIDs = append(sessionIDs, id)
	}
	s.sessionMutex.Unlock()

	// 在锁外部关闭所有会话
	for _, id := range sessionIDs {
		s.removeSession(id)
	}
	
	// 等待所有goroutine退出
	log.Println("等待所有协程退出...")
	s.wg.Wait()
	
	// 清理TUN设备
	if s.tunDevice != nil {
		s.tunDevice.Close()
		if err := cleanupTUNDevice("tun0"); err != nil {
			log.Printf("清理TUN设备失败: %v", err)
		}
	}
	
	// 恢复IP转发设置
	if s.originalIPForward != "" {
		log.Printf("恢复IP转发设置: %s", s.originalIPForward)
		if err := setIPForwarding(s.originalIPForward); err != nil {
			log.Printf("恢复IP转发失败: %v", err)
		} else {
			log.Printf("已恢复IP转发设置为: %s", s.originalIPForward)
		}
	}
	
	log.Println("VPN服务器已完全停止")
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
	if ip == nil {
		return
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	delete(p.allocated, ip.String())
}

// VPNClient VPN客户端结构
type VPNClient struct {
	tlsConfig      *tls.Config
	conn           *tls.Conn
	connMutex      sync.Mutex
	assignedIP     net.IP
	running        bool
	reconnect      bool
	config         VPNConfig
	packetHandler  func([]byte) error
	heartbeatStop  chan struct{}
	heartbeatMutex sync.Mutex
	tunDevice      *water.Interface
	wg             sync.WaitGroup
}

// NewVPNClient 创建新的VPN客户端
func NewVPNClient(certManager *CertificateManager, config VPNConfig) *VPNClient {
	return &VPNClient{
		tlsConfig:     certManager.ClientTLSConfig(),
		running:       true,
		reconnect:     true,
		config:        config,
		packetHandler: nil,
	}
}

// InitializeTUN 初始化TUN设备
func (c *VPNClient) InitializeTUN() error {
	// 检查root权限
	if err := checkRootPrivileges(); err != nil {
		return err
	}

	// 创建TUN设备
	tun, err := createTUNDevice("tun0")
	if err != nil {
		return err
	}
	c.tunDevice = tun
	
	log.Println("客户端TUN设备已创建，等待IP分配...")
	return nil
}

// ConfigureTUN 配置TUN设备（在获得IP后调用）
func (c *VPNClient) ConfigureTUN() error {
	if c.tunDevice == nil {
		return fmt.Errorf("TUN设备未创建")
	}
	if c.assignedIP == nil {
		return fmt.Errorf("未分配IP地址")
	}

	// 配置TUN设备IP地址
	ipAddr := fmt.Sprintf("%s/24", c.assignedIP.String())
	if err := configureTUNDevice(c.tunDevice.Name(), ipAddr, c.config.MTU); err != nil {
		return err
	}

	log.Printf("客户端TUN设备已配置: %s", ipAddr)
	return nil
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

	c.connMutex.Lock()
	c.conn = conn
	c.connMutex.Unlock()
	log.Println("成功连接到VPN服务器，使用TLS 1.3协议")

	// 如果配置了认证密钥，发送认证消息
	if c.config.AuthKey != "" {
		authMsg := &Message{
			Type:    MessageTypeAuth,
			Length:  uint32(len(c.config.AuthKey)),
			Payload: []byte(c.config.AuthKey),
		}
		authData, err := authMsg.Serialize()
		if err != nil {
			conn.Close()
			return fmt.Errorf("序列化认证消息失败: %v", err)
		}
		
		_, err = conn.Write(authData)
		if err != nil {
			conn.Close()
			return fmt.Errorf("发送认证消息失败: %v", err)
		}
		log.Println("已发送认证消息")
	}

	// 读取分配的IP - 先读取消息头，手动解析
	header := make([]byte, 5)
	_, err = io.ReadFull(c.conn, header)
	if err != nil {
		return fmt.Errorf("读取消息头失败: %v", err)
	}

	// 手动解析消息头
	msgType := MessageType(header[0])
	length := binary.BigEndian.Uint32(header[1:5])

	// 读取消息体
	payload := make([]byte, length)
	_, err = io.ReadFull(c.conn, payload)
	if err != nil {
		return fmt.Errorf("读取消息体失败: %v", err)
	}

	if msgType == MessageTypeIPAssignment && len(payload) >= 4 {
		c.assignedIP = net.IP(payload)
		log.Printf("分配的VPN IP: %s", c.assignedIP)
	} else {
		return fmt.Errorf("未收到有效的IP分配信息: type=%d, length=%d", msgType, length)
	}

	return nil
}

// SendData 发送数据
func (c *VPNClient) SendData(data []byte) error {
	c.connMutex.Lock()
	conn := c.conn
	c.connMutex.Unlock()
	
	if conn == nil {
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

	_, err = conn.Write(serialized)
	return err
}

// SendHeartbeat 发送心跳
func (c *VPNClient) SendHeartbeat() error {
	c.connMutex.Lock()
	conn := c.conn
	c.connMutex.Unlock()
	
	if conn == nil {
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

	_, err = conn.Write(serialized)
	return err
}

// ReceiveData 接收数据，返回消息类型和数据
func (c *VPNClient) ReceiveData() (MessageType, []byte, error) {
	c.connMutex.Lock()
	conn := c.conn
	c.connMutex.Unlock()
	
	if conn == nil {
		return 0, nil, fmt.Errorf("连接未建立")
	}

	// 读取消息头
	header := make([]byte, 5)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return 0, nil, err
	}

	// 手动解析消息头
	msgType := MessageType(header[0])
	length := binary.BigEndian.Uint32(header[1:5])

	// 读取消息体
	payload := make([]byte, length)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		return 0, nil, err
	}

	return msgType, payload, nil
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
		
		// 如果有TUN设备，配置它
		if c.tunDevice != nil && c.assignedIP != nil {
			if err := c.ConfigureTUN(); err != nil {
				log.Printf("配置TUN设备失败: %v", err)
				c.Close()
				continue
			}
		}

		// 初始化心跳停止通道
		c.heartbeatMutex.Lock()
		c.heartbeatStop = make(chan struct{})
		c.heartbeatMutex.Unlock()

		// 启动心跳协程
		c.wg.Add(1)
		go c.startHeartbeat()
		
		// 如果有TUN设备，启动TUN读取协程
		if c.tunDevice != nil {
			c.wg.Add(1)
			go c.handleTUNRead()
		}

		// 数据传输循环
		c.dataLoop()

		// 停止心跳协程
		c.stopHeartbeat()

		if c.reconnect {
			log.Println("连接断开，尝试重连...")
			time.Sleep(c.config.ReconnectDelay)
		}
	}

	log.Println("VPN客户端已退出")
}

// startHeartbeat 开始心跳
func (c *VPNClient) startHeartbeat() {
	defer c.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	c.heartbeatMutex.Lock()
	stopChan := c.heartbeatStop
	c.heartbeatMutex.Unlock()

	for {
		select {
		case <-ticker.C:
			c.connMutex.Lock()
			conn := c.conn
			c.connMutex.Unlock()
			
			if conn == nil {
				return
			}
			
			// 发送心跳包
			err := c.SendHeartbeat()
			if err != nil {
				log.Printf("发送心跳失败: %v", err)
				return
			}
		case <-stopChan:
			return
		}
	}
}

// stopHeartbeat 停止心跳协程
func (c *VPNClient) stopHeartbeat() {
	c.heartbeatMutex.Lock()
	defer c.heartbeatMutex.Unlock()
	if c.heartbeatStop != nil {
		close(c.heartbeatStop)
		c.heartbeatStop = nil
	}
}

// handleTUNRead 处理从TUN设备读取的数据
func (c *VPNClient) handleTUNRead() {
	defer c.wg.Done()
	
	packet := make([]byte, c.config.MTU)
	
	for c.running {
		n, err := c.tunDevice.Read(packet)
		if err != nil {
			if c.running {
				log.Printf("从TUN设备读取失败: %v", err)
			}
			break
		}

		if n < 20 { // IP header minimum size
			continue
		}

		// 发送数据包到服务器
		err = c.SendData(packet[:n])
		if err != nil {
			log.Printf("发送数据包失败: %v", err)
			break
		}
	}
}

// dataLoop 数据传输循环
func (c *VPNClient) dataLoop() {
	for c.running {
		c.connMutex.Lock()
		conn := c.conn
		c.connMutex.Unlock()
		
		if conn == nil {
			break
		}
		
		conn.SetReadDeadline(time.Now().Add(c.config.KeepAliveTimeout))

		msgType, data, err := c.ReceiveData()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("连接超时")
				break
			}
			log.Printf("读取数据失败: %v", err)
			break
		}

		// 处理心跳响应 - 不打印日志
		if msgType == MessageTypeHeartbeat {
			continue
		}

		// 处理数据包
		if data != nil && len(data) > 0 {
			if c.tunDevice != nil {
				// 写入TUN设备
				_, err := c.tunDevice.Write(data)
				if err != nil {
					log.Printf("写入TUN设备失败: %v", err)
				}
			} else if c.packetHandler != nil {
				// 使用自定义处理器
				err := c.packetHandler(data)
				if err != nil {
					log.Printf("处理数据包失败: %v", err)
				}
			} else {
				// 默认处理：打印数据包信息
				log.Printf("接收到数据包，长度: %d, 内容: %s", len(data), hex.EncodeToString(data[:min(len(data), 16)]))
			}
		}
	}
}

// Close 关闭客户端
func (c *VPNClient) Close() {
	log.Println("正在关闭VPN客户端...")
	
	c.running = false
	c.reconnect = false
	
	// 停止心跳协程
	c.stopHeartbeat()
	
	c.connMutex.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMutex.Unlock()
	
	// 等待所有goroutine退出
	log.Println("等待所有协程退出...")
	c.wg.Wait()
	
	// 清理TUN设备
	if c.tunDevice != nil {
		c.tunDevice.Close()
		if err := cleanupTUNDevice("tun0"); err != nil {
			log.Printf("清理TUN设备失败: %v", err)
		}
	}
	
	log.Println("VPN客户端已完全关闭")
}

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TUN设备相关函数

// checkRootPrivileges 检查是否具有root权限
func checkRootPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("需要root权限运行，请使用sudo")
	}
	return nil
}

// createTUNDevice 创建TUN设备
func createTUNDevice(name string) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("创建TUN设备失败: %v", err)
	}

	log.Printf("创建TUN设备: %s", iface.Name())
	return iface, nil
}

// configureTUNDevice 配置TUN设备IP地址
func configureTUNDevice(ifaceName string, ipAddr string, mtu int) error {
	// 设置IP地址
	cmd := exec.Command("ip", "addr", "add", ipAddr, "dev", ifaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置IP地址失败: %v, 输出: %s", err, string(output))
	}

	// 启动接口
	cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "up")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("启动接口失败: %v, 输出: %s", err, string(output))
	}

	// 设置MTU
	cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "mtu", fmt.Sprintf("%d", mtu))
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置MTU失败: %v, 输出: %s", err, string(output))
	}

	log.Printf("配置TUN设备 %s: IP=%s, MTU=%d", ifaceName, ipAddr, mtu)
	return nil
}

// getIPForwarding 获取当前IP转发设置
func getIPForwarding() (string, error) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "", fmt.Errorf("读取IP转发设置失败: %v", err)
	}
	// 移除末尾的换行符
	value := string(data)
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
	}
	return value, nil
}

// setIPForwarding 设置IP转发
func setIPForwarding(value string) error {
	cmd := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", value))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置IP转发失败: %v, 输出: %s", err, string(output))
	}
	return nil
}

// enableIPForwarding 启用IP转发并返回原始值
func enableIPForwarding() (string, error) {
	// 保存原始值
	original, err := getIPForwarding()
	if err != nil {
		return "", err
	}
	
	// 如果已经启用，直接返回
	if original == "1" {
		log.Println("IP转发已启用")
		return original, nil
	}
	
	// 启用IP转发
	if err := setIPForwarding("1"); err != nil {
		return original, err
	}
	
	log.Printf("已启用IP转发 (原始值: %s)", original)
	return original, nil
}

// setupNAT 配置NAT（可选）
func setupNAT(vpnNetwork string, outInterface string) error {
	// 检查iptables规则是否已存在
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", vpnNetwork, "-o", outInterface, "-j", "MASQUERADE")
	err := checkCmd.Run()
	if err == nil {
		log.Println("NAT规则已存在")
		return nil
	}

	// 添加NAT规则
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpnNetwork, "-o", outInterface, "-j", "MASQUERADE")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("配置NAT失败: %v, 输出: %s", err, string(output))
	}
	log.Printf("已配置NAT: %s -> %s", vpnNetwork, outInterface)
	return nil
}

// cleanupTUNDevice 清理TUN设备
// cleanupTUNDevice 清理TUN设备
func cleanupTUNDevice(ifaceName string) error {
	// 检查设备是否存在
	checkCmd := exec.Command("ip", "link", "show", ifaceName)
	if err := checkCmd.Run(); err != nil {
		// 设备不存在，无需清理
		log.Printf("TUN设备 %s 不存在，无需清理", ifaceName)
		return nil
	}
	
	// 关闭设备
	downCmd := exec.Command("ip", "link", "set", "dev", ifaceName, "down")
	if output, err := downCmd.CombinedOutput(); err != nil {
		log.Printf("警告: 关闭TUN设备失败: %v, 输出: %s", err, string(output))
		// 继续尝试删除
	}
	
	// 删除设备
	deleteCmd := exec.Command("ip", "link", "delete", ifaceName)
	if output, err := deleteCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("删除TUN设备失败: %v, 输出: %s", err, string(output))
	}
	
	log.Printf("已成功清理TUN设备: %s", ifaceName)
	return nil
}

func main() {
	// 从环境变量读取认证密钥
	config := DefaultConfig
	if authKey := os.Getenv("VPN_AUTH_KEY"); authKey != "" {
		config.AuthKey = authKey
		log.Println("已从环境变量VPN_AUTH_KEY读取认证密钥")
	}
	
	// 生成证书管理器
	log.Println("初始化证书管理器...")
	certManager, err := NewCertificateManager(config)
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
		server, err := NewVPNServer(":8080", certManager, config)
		if err != nil {
			log.Fatalf("创建VPN服务器失败: %v", err)
		}
		
		// 初始化TUN设备
		if err := server.InitializeTUN(); err != nil {
			log.Fatalf("初始化TUN设备失败: %v", err)
		}

		// 在协程中启动服务器
		go server.Start()

		// 等待信号
		sig := <-sigChan
		log.Printf("收到信号: %v，正在关闭服务器...", sig)
		server.Stop()

	case "client":
		// 启动VPN客户端
		client := NewVPNClient(certManager, config)
		
		// 初始化TUN设备
		if err := client.InitializeTUN(); err != nil {
			log.Fatalf("初始化TUN设备失败: %v", err)
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
