package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
)

// DefaultCertDir 默认证书目录
const DefaultCertDir = "./certs"

// DefaultConfigFile 默认配置文件路径
const DefaultConfigFile = "./config.json"

// ConfigFile JSON配置文件结构（用于序列化和反序列化）
type ConfigFile struct {
	ServerAddress          string   `json:"server_address"`
	ServerPort             int      `json:"server_port"`
	ClientAddress          string   `json:"client_address"`
	Network                string   `json:"network"`
	MTU                    int      `json:"mtu"`
	KeepAliveTimeoutSec    int      `json:"keep_alive_timeout_sec"`
	ReconnectDelaySec      int      `json:"reconnect_delay_sec"`
	MaxConnections         int      `json:"max_connections"`
	SessionTimeoutSec      int      `json:"session_timeout_sec"`
	SessionCleanupIntervalSec int   `json:"session_cleanup_interval_sec"`
	ServerIP               string   `json:"server_ip"`
	ClientIPStart          int      `json:"client_ip_start"`
	ClientIPEnd            int      `json:"client_ip_end"`
	DNSServers             []string `json:"dns_servers"`
	PushRoutes             []string `json:"push_routes"`
}

// ToVPNConfig 将ConfigFile转换为VPNConfig
func (cf *ConfigFile) ToVPNConfig() VPNConfig {
	return VPNConfig{
		ServerAddress:          cf.ServerAddress,
		ServerPort:             cf.ServerPort,
		ClientAddress:          cf.ClientAddress,
		Network:                cf.Network,
		MTU:                    cf.MTU,
		KeepAliveTimeout:       time.Duration(cf.KeepAliveTimeoutSec) * time.Second,
		ReconnectDelay:         time.Duration(cf.ReconnectDelaySec) * time.Second,
		MaxConnections:         cf.MaxConnections,
		SessionTimeout:         time.Duration(cf.SessionTimeoutSec) * time.Second,
		SessionCleanupInterval: time.Duration(cf.SessionCleanupIntervalSec) * time.Second,
		ServerIP:               cf.ServerIP,
		ClientIPStart:          cf.ClientIPStart,
		ClientIPEnd:            cf.ClientIPEnd,
		DNSServers:             cf.DNSServers,
		PushRoutes:             cf.PushRoutes,
	}
}

// VPNConfig VPN配置结构
type VPNConfig struct {
	ServerAddress          string
	ServerPort             int
	ClientAddress          string
	Network                string
	MTU                    int
	KeepAliveTimeout       time.Duration
	ReconnectDelay         time.Duration
	MaxConnections         int
	SessionTimeout         time.Duration
	SessionCleanupInterval time.Duration // 新增：会话清理间隔
	ServerIP               string        // 新增：服务器VPN IP (例如 "10.8.0.1/24")
	ClientIPStart          int           // 新增：客户端IP起始 (默认 2)
	ClientIPEnd            int           // 新增：客户端IP结束 (默认 254)
	DNSServers             []string      // 新增：推送给客户端的DNS
	PushRoutes             []string      // 新增：推送给客户端的路由 (CIDR格式)
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
	if c.SessionCleanupInterval < 10*time.Second {
		return fmt.Errorf("会话清理间隔不能小于10秒")
	}
	if c.ClientIPStart < 2 || c.ClientIPStart > 253 {
		return fmt.Errorf("客户端IP起始必须在2-253之间")
	}
	if c.ClientIPEnd < c.ClientIPStart || c.ClientIPEnd > 254 {
		return fmt.Errorf("客户端IP结束必须在起始之后且不超过254")
	}
	// 验证ServerIP（如果提供）
	if c.ServerIP != "" {
		if _, _, err := net.ParseCIDR(c.ServerIP); err != nil {
			return fmt.Errorf("服务器IP格式无效: %v", err)
		}
	}
	return nil
}

// ParseServerIP 解析服务器IP配置
func (c *VPNConfig) ParseServerIP() (net.IP, *net.IPNet, error) {
	if c.ServerIP == "" {
		// 如果未指定，使用Network的第一个IP
		_, network, err := net.ParseCIDR(c.Network)
		if err != nil {
			return nil, nil, fmt.Errorf("无效的网络配置: %v", err)
		}
		ip := network.IP.To4()
		if ip == nil {
			return nil, nil, fmt.Errorf("仅支持IPv4")
		}
		serverIP := net.IPv4(ip[0], ip[1], ip[2], 1)
		return serverIP, network, nil
	}
	ip, ipNet, err := net.ParseCIDR(c.ServerIP)
	if err != nil {
		return nil, nil, fmt.Errorf("无效的服务器IP: %v", err)
	}
	return ip, ipNet, nil
}

// LoadConfigFromFile 从文件加载配置
func LoadConfigFromFile(filename string) (VPNConfig, error) {
	// 检查文件是否存在
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return VPNConfig{}, fmt.Errorf("配置文件不存在: %s", filename)
	}
	
	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return VPNConfig{}, fmt.Errorf("读取配置文件失败: %v", err)
	}
	
	// 解析JSON
	var configFile ConfigFile
	if err := json.Unmarshal(data, &configFile); err != nil {
		return VPNConfig{}, fmt.Errorf("解析配置文件失败: %v", err)
	}
	
	return configFile.ToVPNConfig(), nil
}

// SaveConfigToFile 保存配置到文件（创建示例配置）
func SaveConfigToFile(filename string, config VPNConfig) error {
	configFile := ConfigFile{
		ServerAddress:             config.ServerAddress,
		ServerPort:                config.ServerPort,
		ClientAddress:             config.ClientAddress,
		Network:                   config.Network,
		MTU:                       config.MTU,
		KeepAliveTimeoutSec:       int(config.KeepAliveTimeout / time.Second),
		ReconnectDelaySec:         int(config.ReconnectDelay / time.Second),
		MaxConnections:            config.MaxConnections,
		SessionTimeoutSec:         int(config.SessionTimeout / time.Second),
		SessionCleanupIntervalSec: int(config.SessionCleanupInterval / time.Second),
		ServerIP:                  config.ServerIP,
		ClientIPStart:             config.ClientIPStart,
		ClientIPEnd:               config.ClientIPEnd,
		DNSServers:                config.DNSServers,
		PushRoutes:                config.PushRoutes,
	}
	
	data, err := json.MarshalIndent(configFile, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}
	
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("保存配置文件失败: %v", err)
	}
	
	return nil
}

// 默认配置
var DefaultConfig = VPNConfig{
	ServerAddress:          "localhost",
	ServerPort:             8080,
	ClientAddress:          "10.8.0.2/24",
	Network:                "10.8.0.0/24",
	MTU:                    1500,
	KeepAliveTimeout:       90 * time.Second,
	ReconnectDelay:         5 * time.Second,
	MaxConnections:         100,
	SessionTimeout:         5 * time.Minute,
	SessionCleanupInterval: 30 * time.Second,
	ServerIP:               "10.8.0.1/24",
	ClientIPStart:          2,
	ClientIPEnd:            254,
	DNSServers:             []string{"8.8.8.8", "8.8.4.4"},
	PushRoutes:             []string{},
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
	Type     MessageType
	Length   uint32
	Sequence uint32 // 新增：消息序列号
	Checksum uint32 // 新增：CRC32校验和（可选，0表示不校验）
	Payload  []byte
}

// Serialize 序列化消息
func (m *Message) Serialize() ([]byte, error) {
	// 新格式: Type(1) + Length(4) + Sequence(4) + Checksum(4) + Payload
	header := make([]byte, 13)
	header[0] = byte(m.Type)
	binary.BigEndian.PutUint32(header[1:5], m.Length)
	binary.BigEndian.PutUint32(header[5:9], m.Sequence)
	binary.BigEndian.PutUint32(header[9:13], m.Checksum)

	return append(header, m.Payload...), nil
}

// Deserialize 反序列化消息
func Deserialize(data []byte) (*Message, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("消息长度不足")
	}

	msgType := MessageType(data[0])
	length := binary.BigEndian.Uint32(data[1:5])
	sequence := binary.BigEndian.Uint32(data[5:9])
	checksum := binary.BigEndian.Uint32(data[9:13])

	if uint32(len(data)) < 13+length {
		return nil, fmt.Errorf("消息长度不匹配")
	}

	payload := data[13 : 13+length]
	return &Message{
		Type:     msgType,
		Length:   length,
		Sequence: sequence,
		Checksum: checksum,
		Payload:  payload,
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

// CertificatesExist 检查证书文件是否存在
func CertificatesExist(certDir string) bool {
	files := []string{
		certDir + "/ca.pem",
		certDir + "/server.pem",
		certDir + "/server-key.pem",
		certDir + "/client.pem",
		certDir + "/client-key.pem",
	}
	
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// SaveCertificates 保存证书到文件
func SaveCertificates(certDir string, caCertPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM []byte) error {
	// 创建证书目录
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %v", err)
	}
	
	// 保存CA证书 (0644)
	if err := os.WriteFile(certDir+"/ca.pem", caCertPEM, 0644); err != nil {
		return fmt.Errorf("保存CA证书失败: %v", err)
	}
	
	// 保存服务器证书 (0644)
	if err := os.WriteFile(certDir+"/server.pem", serverCertPEM, 0644); err != nil {
		return fmt.Errorf("保存服务器证书失败: %v", err)
	}
	
	// 保存服务器私钥 (0600)
	if err := os.WriteFile(certDir+"/server-key.pem", serverKeyPEM, 0600); err != nil {
		return fmt.Errorf("保存服务器私钥失败: %v", err)
	}
	
	// 保存客户端证书 (0644)
	if err := os.WriteFile(certDir+"/client.pem", clientCertPEM, 0644); err != nil {
		return fmt.Errorf("保存客户端证书失败: %v", err)
	}
	
	// 保存客户端私钥 (0600)
	if err := os.WriteFile(certDir+"/client-key.pem", clientKeyPEM, 0600); err != nil {
		return fmt.Errorf("保存客户端私钥失败: %v", err)
	}
	
	return nil
}

// LoadCertificateManagerFromFiles 从文件加载证书
func LoadCertificateManagerFromFiles(certDir string) (*CertificateManager, error) {
	// 读取CA证书
	caCertPEM, err := os.ReadFile(certDir + "/ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取CA证书失败: %v", err)
	}
	
	// 解析CA证书
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("解码CA证书失败")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析CA证书失败: %v", err)
	}
	
	// 读取服务器证书和私钥
	serverCertPEM, err := os.ReadFile(certDir + "/server.pem")
	if err != nil {
		return nil, fmt.Errorf("读取服务器证书失败: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(certDir + "/server-key.pem")
	if err != nil {
		return nil, fmt.Errorf("读取服务器私钥失败: %v", err)
	}
	
	// 读取客户端证书和私钥
	clientCertPEM, err := os.ReadFile(certDir + "/client.pem")
	if err != nil {
		return nil, fmt.Errorf("读取客户端证书失败: %v", err)
	}
	clientKeyPEM, err := os.ReadFile(certDir + "/client-key.pem")
	if err != nil {
		return nil, fmt.Errorf("读取客户端私钥失败: %v", err)
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

// NewCertificateManager 创建证书管理器
func NewCertificateManager() (*CertificateManager, error) {
	// 检查证书文件是否存在
	if CertificatesExist(DefaultCertDir) {
		log.Printf("从 %s 目录加载已有证书", DefaultCertDir)
		return LoadCertificateManagerFromFiles(DefaultCertDir)
	}
	
	// 证书不存在，生成新证书
	log.Println("证书文件不存在，生成新证书...")
	
	// 首先生成CA证书
	caCertPEM, _, caCert, caKey, err := generateCACertificate()
	if err != nil {
		return nil, fmt.Errorf("生成CA证书失败: %v", err)
	}

	// 生成服务器证书
	serverCertPEM, serverKeyPEM, err := generateCertificatePair(true, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("生成服务器证书失败: %v", err)
	}

	// 生成客户端证书
	clientCertPEM, clientKeyPEM, err := generateCertificatePair(false, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("生成客户端证书失败: %v", err)
	}
	
	// 保存证书到文件
	if err := SaveCertificates(DefaultCertDir, caCertPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM); err != nil {
		return nil, fmt.Errorf("保存证书失败: %v", err)
	}
	log.Printf("证书已生成并保存到 %s 目录", DefaultCertDir)

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

// ClientConfig 客户端配置（用于推送给客户端）
type ClientConfig struct {
	AssignedIP string   `json:"assigned_ip"` // 分配的IP地址（例如 "10.8.0.2/24"）
	ServerIP   string   `json:"server_ip"`   // 服务器IP地址
	DNS        []string `json:"dns"`         // DNS服务器列表
	Routes     []string `json:"routes"`      // 路由列表（CIDR格式）
	MTU        int      `json:"mtu"`         // MTU大小
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
	sendSeq      uint32      // 新增：发送序列号
	recvSeq      uint32      // 新增：接收序列号
	seqMutex     sync.Mutex  // 新增：序列号锁
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

// NATRule NAT规则记录
type NATRule struct {
	Table string   // "nat"
	Chain string   // "POSTROUTING"
	Args  []string // 规则参数
}

// VPNServer VPN服务器结构
type VPNServer struct {
	listener       net.Listener
	tlsConfig      *tls.Config
	sessions       map[string]*VPNSession
	ipToSession    map[string]*VPNSession // 新增：IP到会话的快速映射
	sessionMutex   sync.RWMutex
	running        bool
	shutdownChan   chan struct{}
	vpnNetwork     *net.IPNet
	clientIPPool   *IPPool
	packetHandler  func([]byte) error
	sessionCount   int64
	config         VPNConfig
	tunDevice      *water.Interface
	serverIP       net.IP
	natRules       []NATRule // 新增：NAT规则跟踪
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

	return &VPNServer{
		listener:     listener,
		tlsConfig:    serverConfig,
		sessions:     make(map[string]*VPNSession),
		ipToSession:  make(map[string]*VPNSession), // 初始化IP映射
		running:      true,
		shutdownChan: make(chan struct{}),
		vpnNetwork:   vpnNetwork,
		clientIPPool: NewIPPool(vpnNetwork, &config),
		config:       config,
		serverIP:     vpnNetwork.IP.To4(),
		natRules:     make([]NATRule, 0), // 初始化NAT规则列表
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

	// 启用IP转发
	if err := enableIPForwarding(); err != nil {
		tun.Close()
		return err
	}

	log.Printf("服务器TUN设备已初始化: %s", serverIP.String())
	return nil
}

// Start 启动VPN服务器
func (s *VPNServer) Start() {
	log.Printf("VPN服务器启动，监听地址: %s", s.listener.Addr())
	defer s.listener.Close()
	
	// 如果有TUN设备，启动TUN数据转发
	if s.tunDevice != nil {
		go s.handleTUNRead()
	}

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
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("非TLS连接被拒绝: %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	err := tlsConn.Handshake()
	if err != nil {
		log.Printf("TLS握手失败: %v", err)
		conn.Close()
		return
	}

	// 验证客户端证书
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("客户端未提供证书: %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	// 检查连接数限制
	s.sessionMutex.RLock()
	count := s.sessionCount
	s.sessionMutex.RUnlock()
	if count >= int64(s.config.MaxConnections) {
		log.Printf("连接数已达到上限: %d", s.config.MaxConnections)
		conn.Close()
		return
	}

	// 获取证书主题
	clientCert := state.PeerCertificates[0]
	certSubject := clientCert.Subject.CommonName

	// 分配IP地址
	clientIP := s.clientIPPool.AllocateIP()
	if clientIP == nil {
		log.Printf("IP地址池已满: %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	// 生成唯一的SessionID (使用纳秒时间戳 + 随机数)
	sessionID := fmt.Sprintf("%s-%d-%d", 
		conn.RemoteAddr().String(), 
		time.Now().UnixNano(), 
		mathrand.Int31())
	session := &VPNSession{
		ID:           sessionID,
		RemoteAddr:   conn.RemoteAddr(),
		TLSConn:      tlsConn,
		LastActivity: time.Now(),
		IP:           clientIP,
		CertSubject:  certSubject,
		sendSeq:      0, // 初始化序列号
		recvSeq:      0,
	}

	s.addSession(sessionID, session)
	log.Printf("客户端连接建立: %s (IP: %s, Cert: %s, ID: %s)", 
		conn.RemoteAddr(), clientIP, certSubject, sessionID)

	// 发送IP分配信息
	ipMsg := &Message{
		Type:     MessageTypeIPAssignment,
		Length:   uint32(len(clientIP)),
		Sequence: 0, // IP分配消息不使用序列号
		Checksum: 0,
		Payload:  clientIP,
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
		if r := recover(); r != nil {
			log.Printf("会话 %s 处理发生panic: %v", session.ID, r)
		}
		s.removeSession(session.ID)
		log.Printf("会话 %s 已清理，IP %s 已回收", session.ID, session.IP)
	}()

	for s.running && !session.IsClosed() {
		session.TLSConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// 读取消息头（13字节：类型+长度+序列号+校验和）
		header := make([]byte, 13)
		_, err := io.ReadFull(session.TLSConn, header)
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
		length := binary.BigEndian.Uint32(header[1:5])
		sequence := binary.BigEndian.Uint32(header[5:9])
		checksum := binary.BigEndian.Uint32(header[9:13])

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

		// 验证序列号（心跳消息除外）
		if msgType != MessageTypeHeartbeat && msgType != MessageTypeIPAssignment {
			session.seqMutex.Lock()
			// 检测重放攻击（序列号回退）
			if sequence < session.recvSeq {
				session.seqMutex.Unlock()
				log.Printf("会话 %s 检测到重放攻击：期望序列号 >= %d，收到 %d", 
					session.ID, session.recvSeq, sequence)
				break
			}
			// 检测消息丢失（序列号跳跃）
			if sequence > session.recvSeq+1 && session.recvSeq > 0 {
				log.Printf("警告：会话 %s 检测到消息丢失，期望序列号 %d，收到 %d", 
					session.ID, session.recvSeq+1, sequence)
			}
			session.recvSeq = sequence
			session.seqMutex.Unlock()
		}

		// 验证校验和（如果提供）
		if checksum != 0 && len(payload) > 0 {
			actualChecksum := crc32.ChecksumIEEE(payload)
			if actualChecksum != checksum {
				log.Printf("会话 %s 消息校验和不匹配: 期望 %d, 收到 %d", 
					session.ID, actualChecksum, checksum)
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
		Type:     MessageTypeHeartbeat,
		Length:   0,
		Sequence: 0, // 心跳不使用序列号
		Checksum: 0,
		Payload:  []byte{},
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
	// 获取并递增发送序列号
	session.seqMutex.Lock()
	seq := session.sendSeq
	session.sendSeq++
	session.seqMutex.Unlock()
	
	// 计算校验和（可选）
	checksum := uint32(0)
	if len(payload) > 0 {
		checksum = crc32.ChecksumIEEE(payload)
	}
	
	response := &Message{
		Type:     MessageTypeData,
		Length:   uint32(len(payload)),
		Sequence: seq,
		Checksum: checksum,
		Payload:  payload,
	}
	responseData, err := response.Serialize()
	if err != nil {
		return fmt.Errorf("序列化数据响应失败: %v", err)
	}
	_, err = session.TLSConn.Write(responseData)
	return err
}

// pushConfigToClient 推送配置给客户端
func (s *VPNServer) pushConfigToClient(session *VPNSession) error {
	// 准备客户端配置
	config := ClientConfig{
		AssignedIP: session.IP.String() + "/24",
		ServerIP:   s.config.ServerIP,
		DNS:        s.config.DNSServers,
		Routes:     s.config.PushRoutes,
		MTU:        s.config.MTU,
	}
	
	// 序列化为JSON
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("序列化客户端配置失败: %v", err)
	}
	
	// 获取并递增发送序列号
	session.seqMutex.Lock()
	seq := session.sendSeq
	session.sendSeq++
	session.seqMutex.Unlock()
	
	// 发送控制消息
	msg := &Message{
		Type:     MessageTypeControl,
		Length:   uint32(len(data)),
		Sequence: seq,
		Checksum: crc32.ChecksumIEEE(data),
		Payload:  data,
	}
	
	msgData, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("序列化控制消息失败: %v", err)
	}
	
	_, err = session.TLSConn.Write(msgData)
	if err != nil {
		return fmt.Errorf("发送配置失败: %v", err)
	}
	
	log.Printf("已推送配置给客户端 %s: DNS=%v, Routes=%v, MTU=%d", 
		session.IP, config.DNS, config.Routes, config.MTU)
	return nil
}

// handleTUNRead 处理从TUN设备读取的数据
func (s *VPNServer) handleTUNRead() {
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
		
		// 使用IP到会话的映射进行O(1)查找
		s.sessionMutex.RLock()
		targetSession := s.ipToSession[destIP.String()]
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
	s.ipToSession[session.IP.String()] = session // 维护IP到会话的映射
	s.sessionCount++
}

// removeSession 移除会话
func (s *VPNServer) removeSession(id string) {
	s.sessionMutex.Lock()
	session, exists := s.sessions[id]
	if exists {
		s.clientIPPool.ReleaseIP(session.IP)
		delete(s.sessions, id)
		delete(s.ipToSession, session.IP.String()) // 删除IP映射
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
	ticker := time.NewTicker(s.config.SessionCleanupInterval)
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

// cleanupNATRules 清理NAT规则
func (s *VPNServer) cleanupNATRules() {
	for _, rule := range s.natRules {
		// 将 -A 改为 -D 来删除规则
		args := []string{"-t", rule.Table, "-D", rule.Chain}
		args = append(args, rule.Args...)
		
		cmd := exec.Command("iptables", args...)
		if err := cmd.Run(); err != nil {
			log.Printf("警告：删除NAT规则失败: %v (参数: %v)", err, args)
		} else {
			log.Printf("已删除NAT规则: %v", args)
		}
	}
	s.natRules = nil
}

// Stop 停止服务器
func (s *VPNServer) Stop() {
	s.running = false
	close(s.shutdownChan)
	s.listener.Close()

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
	
	// 清理NAT规则
	s.cleanupNATRules()
	
	// 清理TUN设备
	if s.tunDevice != nil {
		s.tunDevice.Close()
		cleanupTUNDevice("tun0")
	}
}

// IPPool IP地址池
type IPPool struct {
	network    *net.IPNet
	allocated  map[string]bool
	freeList   []int          // 新增：空闲IP索引队列
	ipToIndex  map[string]int // 新增：IP到索引的映射
	mutex      sync.RWMutex
	startIndex int            // IP范围起始索引
	endIndex   int            // IP范围结束索引
}

// NewIPPool 创建IP地址池
func NewIPPool(network *net.IPNet, config *VPNConfig) *IPPool {
	startIndex := config.ClientIPStart
	endIndex := config.ClientIPEnd
	
	// 初始化空闲列表
	freeList := make([]int, 0, endIndex-startIndex+1)
	for i := startIndex; i <= endIndex; i++ {
		freeList = append(freeList, i)
	}
	
	return &IPPool{
		network:    network,
		allocated:  make(map[string]bool),
		freeList:   freeList,
		ipToIndex:  make(map[string]int),
		startIndex: startIndex,
		endIndex:   endIndex,
	}
}

// AllocateIP 分配IP地址 - O(1)操作
func (p *IPPool) AllocateIP() net.IP {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(p.freeList) == 0 {
		return nil
	}

	// 从队列头取出空闲IP索引
	index := p.freeList[0]
	p.freeList = p.freeList[1:]

	ip := p.network.IP.To4()
	if ip == nil {
		return nil
	}

	allocatedIP := net.IPv4(ip[0], ip[1], ip[2], byte(index))
	ipStr := allocatedIP.String()
	p.allocated[ipStr] = true
	p.ipToIndex[ipStr] = index
	
	return allocatedIP
}

// ReleaseIP 释放IP地址 - O(1)操作
func (p *IPPool) ReleaseIP(ip net.IP) {
	if ip == nil {
		return
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	ipStr := ip.String()
	if p.allocated[ipStr] {
		delete(p.allocated, ipStr)
		if index, ok := p.ipToIndex[ipStr]; ok {
			delete(p.ipToIndex, ipStr)
			// 回收到队列尾部
			p.freeList = append(p.freeList, index)
		}
	}
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
	sendSeq        uint32      // 新增：发送序列号
	recvSeq        uint32      // 新增：接收序列号
	seqMutex       sync.Mutex  // 新增：序列号锁
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

	// 读取分配的IP - 读取新的消息头格式（13字节）
	header := make([]byte, 13)
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

	// 获取并递增发送序列号
	c.seqMutex.Lock()
	seq := c.sendSeq
	c.sendSeq++
	c.seqMutex.Unlock()

	// 计算校验和（可选）
	checksum := uint32(0)
	if len(data) > 0 {
		checksum = crc32.ChecksumIEEE(data)
	}

	msg := &Message{
		Type:     MessageTypeData,
		Length:   uint32(len(data)),
		Sequence: seq,
		Checksum: checksum,
		Payload:  data,
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
		Type:     MessageTypeHeartbeat,
		Length:   0,
		Sequence: 0, // 心跳不使用序列号
		Checksum: 0,
		Payload:  []byte{},
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

	// 读取消息头（13字节）
	header := make([]byte, 13)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return 0, nil, err
	}

	// 手动解析消息头
	msgType := MessageType(header[0])
	length := binary.BigEndian.Uint32(header[1:5])
	sequence := binary.BigEndian.Uint32(header[5:9])
	checksum := binary.BigEndian.Uint32(header[9:13])

	// 读取消息体
	payload := make([]byte, length)
	if length > 0 {
		_, err = io.ReadFull(conn, payload)
		if err != nil {
			return 0, nil, err
		}
	}

	// 验证序列号（心跳和IP分配消息除外）
	if msgType != MessageTypeHeartbeat && msgType != MessageTypeIPAssignment {
		c.seqMutex.Lock()
		// 检测重放攻击（序列号回退）
		if sequence < c.recvSeq {
			c.seqMutex.Unlock()
			return 0, nil, fmt.Errorf("检测到重放攻击：期望序列号 >= %d，收到 %d", c.recvSeq, sequence)
		}
		// 检测消息丢失（序列号跳跃）
		if sequence > c.recvSeq+1 && c.recvSeq > 0 {
			log.Printf("警告：检测到消息丢失，期望序列号 %d，收到 %d", c.recvSeq+1, sequence)
		}
		c.recvSeq = sequence
		c.seqMutex.Unlock()
	}

	// 验证校验和（如果提供）
	if checksum != 0 && len(payload) > 0 {
		actualChecksum := crc32.ChecksumIEEE(payload)
		if actualChecksum != checksum {
			return 0, nil, fmt.Errorf("消息校验和不匹配: 期望 %d, 收到 %d", actualChecksum, checksum)
		}
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
		go c.startHeartbeat()
		
		// 如果有TUN设备，启动TUN读取协程
		if c.tunDevice != nil {
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

		// 处理控制消息
		if msgType == MessageTypeControl {
			if len(data) > 0 {
				var config ClientConfig
				if err := json.Unmarshal(data, &config); err != nil {
					log.Printf("解析服务器配置失败: %v", err)
				} else {
					if err := c.applyServerConfig(&config); err != nil {
						log.Printf("应用服务器配置失败: %v", err)
					}
				}
			}
			continue
		}

		// 处理数据包
		if msgType == MessageTypeData && data != nil && len(data) > 0 {
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
	
	// 清理TUN设备
	if c.tunDevice != nil {
		c.tunDevice.Close()
		cleanupTUNDevice("tun0")
	}
}

// applyServerConfig 应用服务器推送的配置
func (c *VPNClient) applyServerConfig(config *ClientConfig) error {
	log.Printf("收到服务器配置: DNS=%v, Routes=%v, MTU=%d", config.DNS, config.Routes, config.MTU)
	
	// 记录DNS服务器（可以修改/etc/resolv.conf，但需谨慎）
	for _, dns := range config.DNS {
		log.Printf("推荐DNS: %s", dns)
	}
	
	// 添加路由
	for _, route := range config.Routes {
		// 解析服务器IP以获取网关（去掉CIDR后缀）
		serverIPStr := config.ServerIP
		for i := 0; i < len(serverIPStr); i++ {
			if serverIPStr[i] == '/' {
				serverIPStr = serverIPStr[:i]
				break
			}
		}
		
		cmd := exec.Command("ip", "route", "add", route, "via", serverIPStr, "dev", "tun0")
		if err := cmd.Run(); err != nil {
			log.Printf("警告：添加路由 %s 失败: %v", route, err)
		} else {
			log.Printf("已添加路由: %s via %s", route, serverIPStr)
		}
	}
	
	return nil
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

// enableIPForwarding 启用IP转发
func enableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("启用IP转发失败: %v, 输出: %s", err, string(output))
	}
	log.Println("已启用IP转发")
	return nil
}

// setupNAT 配置NAT（可选）- 已废弃，请使用 VPNServer.SetupNAT
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

// SetupNAT 配置NAT并跟踪规则
func (s *VPNServer) SetupNAT(vpnNetwork string, outInterface string) error {
	args := []string{"-s", vpnNetwork, "-o", outInterface, "-j", "MASQUERADE"}
	
	// 检查规则是否已存在
	checkArgs := append([]string{"-t", "nat", "-C", "POSTROUTING"}, args...)
	checkCmd := exec.Command("iptables", checkArgs...)
	if checkCmd.Run() == nil {
		log.Println("NAT规则已存在，跳过添加")
		return nil
	}
	
	// 添加规则
	addArgs := append([]string{"-t", "nat", "-A", "POSTROUTING"}, args...)
	cmd := exec.Command("iptables", addArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("添加NAT规则失败: %v, 输出: %s", err, string(output))
	}
	
	// 记录规则以便后续清理
	s.natRules = append(s.natRules, NATRule{
		Table: "nat",
		Chain: "POSTROUTING",
		Args:  args,
	})
	
	log.Printf("已配置NAT: %s -> %s", vpnNetwork, outInterface)
	return nil
}

// cleanupTUNDevice 清理TUN设备
func cleanupTUNDevice(ifaceName string) {
	cmd := exec.Command("ip", "link", "set", "dev", ifaceName, "down")
	cmd.Run()
	cmd = exec.Command("ip", "link", "delete", ifaceName)
	cmd.Run()
	log.Printf("已清理TUN设备: %s", ifaceName)
}

func main() {
	// 加载配置
	config := DefaultConfig
	if _, err := os.Stat(DefaultConfigFile); err == nil {
		log.Printf("从配置文件加载配置: %s", DefaultConfigFile)
		loadedConfig, err := LoadConfigFromFile(DefaultConfigFile)
		if err != nil {
			log.Printf("警告: 加载配置文件失败，使用默认配置: %v", err)
		} else {
			config = loadedConfig
			log.Println("配置文件加载成功")
		}
	} else {
		log.Printf("配置文件不存在，使用默认配置")
		log.Printf("提示: 可以创建 %s 文件来自定义配置", DefaultConfigFile)
	}
	
	// 生成证书管理器
	log.Println("初始化证书管理器...")
	certManager, err := NewCertificateManager()
	if err != nil {
		log.Fatalf("初始化证书管理器失败: %v", err)
	}

	// 检查命令行参数
	if len(os.Args) < 2 {
		log.Println("用法: ./vpn [server|client|generate-config]")
		log.Println("  server          - 启动VPN服务器")
		log.Println("  client          - 启动VPN客户端")
		log.Println("  generate-config - 生成示例配置文件")
		return
	}

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	switch os.Args[1] {
	case "generate-config":
		// 生成示例配置文件
		if err := SaveConfigToFile(DefaultConfigFile, DefaultConfig); err != nil {
			log.Fatalf("生成配置文件失败: %v", err)
		}
		log.Printf("示例配置文件已生成: %s", DefaultConfigFile)
		log.Println("请根据需要修改配置文件后重新运行程序")
		return
		
	case "server":
		// 启动VPN服务器
		serverAddr := fmt.Sprintf(":%d", config.ServerPort)
		server, err := NewVPNServer(serverAddr, certManager, config)
		if err != nil {
			log.Fatalf("创建VPN服务器失败: %v", err)
		}
		
		// 初始化TUN设备
		if err := server.InitializeTUN(); err != nil {
			log.Fatalf("初始化TUN设备失败: %v", err)
		}
		
		// 显示证书复制提示
		log.Println("")
		log.Println("========================================")
		log.Println("请将以下文件复制到客户端的 ./certs 目录：")
		log.Println("  - ca.pem")
		log.Println("  - client.pem")
		log.Println("  - client-key.pem")
		log.Println("========================================")
		log.Println("")

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
		log.Println("未知参数，使用 'server'、'client' 或 'generate-config'")
	}
}
