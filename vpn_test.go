package main

import (
	"fmt"
	mathrand "math/rand"
	"net"
	"testing"
	"time"
)

// BenchmarkIPAllocation 测试IP分配性能
func BenchmarkIPAllocation(b *testing.B) {
	config := DefaultConfig
	_, network, _ := net.ParseCIDR(config.Network)
	pool := NewIPPool(network, &config)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := pool.AllocateIP()
		if ip != nil {
			pool.ReleaseIP(ip)
		}
	}
}

// BenchmarkIPAllocation100 测试100个IP分配和释放
func BenchmarkIPAllocation100(b *testing.B) {
	config := DefaultConfig
	_, network, _ := net.ParseCIDR(config.Network)
	pool := NewIPPool(network, &config)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ips := make([]net.IP, 100)
		for j := 0; j < 100; j++ {
			ips[j] = pool.AllocateIP()
		}
		for j := 0; j < 100; j++ {
			pool.ReleaseIP(ips[j])
		}
	}
}

// TestIPPoolBasic 测试IP池基本功能
func TestIPPoolBasic(t *testing.T) {
	config := DefaultConfig
	_, network, _ := net.ParseCIDR(config.Network)
	pool := NewIPPool(network, &config)
	
	// 分配一个IP
	ip1 := pool.AllocateIP()
	if ip1 == nil {
		t.Fatal("分配IP失败")
	}
	
	// 分配第二个IP
	ip2 := pool.AllocateIP()
	if ip2 == nil {
		t.Fatal("分配第二个IP失败")
	}
	
	// 确保两个IP不同
	if ip1.Equal(ip2) {
		t.Fatal("分配了相同的IP")
	}
	
	// 释放第一个IP
	pool.ReleaseIP(ip1)
	
	// 再次分配，应该得到刚释放的IP
	ip3 := pool.AllocateIP()
	if ip3 == nil {
		t.Fatal("释放后分配IP失败")
	}
	
	t.Logf("分配的IP: %s, %s, %s", ip1, ip2, ip3)
}

// TestSessionIDUniqueness 测试SessionID唯一性
func TestSessionIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)
	count := 1000
	
	// 在短时间内生成1000个SessionID
	for i := 0; i < count; i++ {
		id := generateSessionID("192.168.1.1:12345")
		if ids[id] {
			t.Fatalf("检测到重复的SessionID: %s", id)
		}
		ids[id] = true
	}
	
	t.Logf("成功生成%d个唯一的SessionID", count)
}

// generateSessionID 生成SessionID（模拟handleConnection中的逻辑）
func generateSessionID(remoteAddr string) string {
	return fmt.Sprintf("%s-%d-%d", 
		remoteAddr, 
		time.Now().UnixNano(), 
		mathrand.Int31())
}

// TestMessageSerializeDeserialize 测试消息序列化和反序列化
func TestMessageSerializeDeserialize(t *testing.T) {
	// 创建测试消息
	original := &Message{
		Type:     MessageTypeData,
		Length:   10,
		Sequence: 42,
		Checksum: 12345,
		Payload:  []byte("test data!"),
	}
	
	// 序列化
	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	
	// 反序列化
	decoded, err := Deserialize(data)
	if err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	
	// 验证
	if decoded.Type != original.Type {
		t.Errorf("Type不匹配: 期望 %d, 得到 %d", original.Type, decoded.Type)
	}
	if decoded.Length != original.Length {
		t.Errorf("Length不匹配: 期望 %d, 得到 %d", original.Length, decoded.Length)
	}
	if decoded.Sequence != original.Sequence {
		t.Errorf("Sequence不匹配: 期望 %d, 得到 %d", original.Sequence, decoded.Sequence)
	}
	if decoded.Checksum != original.Checksum {
		t.Errorf("Checksum不匹配: 期望 %d, 得到 %d", original.Checksum, decoded.Checksum)
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Payload不匹配: 期望 %s, 得到 %s", original.Payload, decoded.Payload)
	}
}

// TestConfigValidation 测试配置验证
func TestConfigValidation(t *testing.T) {
	// 测试有效配置
	validConfig := DefaultConfig
	if err := validConfig.ValidateConfig(); err != nil {
		t.Errorf("有效配置验证失败: %v", err)
	}
	
	// 测试无效的SessionCleanupInterval
	invalidConfig := DefaultConfig
	invalidConfig.SessionCleanupInterval = 5 * time.Second
	if err := invalidConfig.ValidateConfig(); err == nil {
		t.Error("应该检测到无效的SessionCleanupInterval")
	}
	
	// 测试无效的ClientIPStart
	invalidConfig2 := DefaultConfig
	invalidConfig2.ClientIPStart = 1
	if err := invalidConfig2.ValidateConfig(); err == nil {
		t.Error("应该检测到无效的ClientIPStart")
	}
	
	// 测试无效的ClientIPEnd
	invalidConfig3 := DefaultConfig
	invalidConfig3.ClientIPEnd = 255
	if err := invalidConfig3.ValidateConfig(); err == nil {
		t.Error("应该检测到无效的ClientIPEnd")
	}
}

// TestParseServerIP 测试服务器IP解析
func TestParseServerIP(t *testing.T) {
	config := DefaultConfig
	
	ip, network, err := config.ParseServerIP()
	if err != nil {
		t.Fatalf("解析服务器IP失败: %v", err)
	}
	
	if ip == nil {
		t.Fatal("解析的IP为nil")
	}
	
	if network == nil {
		t.Fatal("解析的网络为nil")
	}
	
	t.Logf("服务器IP: %s, 网络: %s", ip, network)
}

// TestRoutingConfiguration 测试路由配置
func TestRoutingConfiguration(t *testing.T) {
	// 测试默认配置
	config := DefaultConfig
	
	if config.RouteMode != "split" {
		t.Errorf("默认路由模式应该是 'split'，实际是: %s", config.RouteMode)
	}
	
	if config.RedirectGateway != false {
		t.Error("默认不应该重定向网关")
	}
	
	if config.RedirectDNS != false {
		t.Error("默认不应该劫持DNS")
	}
	
	if config.EnableNAT != true {
		t.Error("默认应该启用NAT")
	}
	
	if len(config.ExcludeRoutes) != 0 {
		t.Error("默认排除路由列表应该为空")
	}
	
	// 测试配置序列化和反序列化
	configFile := ConfigFile{
		ServerAddress:   "test.example.com",
		ServerPort:      8080,
		Network:         "10.8.0.0/24",
		MTU:             1500,
		RouteMode:       "full",
		ExcludeRoutes:   []string{"192.168.1.0/24"},
		RedirectGateway: true,
		RedirectDNS:     true,
		EnableNAT:       false,
		NATInterface:    "eth0",
	}
	
	vpnConfig := configFile.ToVPNConfig()
	
	if vpnConfig.RouteMode != "full" {
		t.Errorf("路由模式转换错误，期望 'full'，得到: %s", vpnConfig.RouteMode)
	}
	
	if !vpnConfig.RedirectGateway {
		t.Error("RedirectGateway 转换错误")
	}
	
	if !vpnConfig.RedirectDNS {
		t.Error("RedirectDNS 转换错误")
	}
	
	if vpnConfig.EnableNAT {
		t.Error("EnableNAT 转换错误")
	}
	
	if vpnConfig.NATInterface != "eth0" {
		t.Errorf("NATInterface 转换错误，期望 'eth0'，得到: %s", vpnConfig.NATInterface)
	}
	
	if len(vpnConfig.ExcludeRoutes) != 1 || vpnConfig.ExcludeRoutes[0] != "192.168.1.0/24" {
		t.Errorf("ExcludeRoutes 转换错误: %v", vpnConfig.ExcludeRoutes)
	}
}

// TestRouteEntryStructure 测试路由条目结构
func TestRouteEntryStructure(t *testing.T) {
	entry := RouteEntry{
		Destination: "192.168.1.0/24",
		Gateway:     "10.8.0.1",
		Interface:   "tun0",
		Metric:      100,
	}
	
	if entry.Destination != "192.168.1.0/24" {
		t.Error("路由条目Destination字段错误")
	}
	
	if entry.Gateway != "10.8.0.1" {
		t.Error("路由条目Gateway字段错误")
	}
	
	if entry.Interface != "tun0" {
		t.Error("路由条目Interface字段错误")
	}
	
	if entry.Metric != 100 {
		t.Error("路由条目Metric字段错误")
	}
}
