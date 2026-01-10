# TLS VPN 修复文档

## 已修复的问题

### 1. 系统配置回滚 (严重安全问题)

**修复内容**:
- 在 `VPNServer` 结构体中添加 `originalIPForward` 字段存储原始IP转发状态
- 在启用IP转发前保存原始值
- 在 `Stop()` 函数中恢复原始IP转发设置
- 添加 `getIPForwarding()` 和 `setIPForwarding()` 辅助函数

**使用示例**:
```bash
# 查看当前IP转发设置
cat /proc/sys/net/ipv4/ip_forward

# 启动服务器
sudo ./vpn server

# 停止服务器 (Ctrl+C)
# IP转发会自动恢复到原始值
```

**代码变更**:
```go
// 保存原始IP转发值
originalIPForward, err := enableIPForwarding()
s.originalIPForward = originalIPForward

// Stop() 中恢复
if s.originalIPForward != "" {
    setIPForwarding(s.originalIPForward)
}
```

---

### 2. TUN设备清理健壮性

**修复内容**:
- `cleanupTUNDevice()` 现在返回错误而不是静默失败
- 在删除前检查设备是否存在
- 为每个命令添加错误检查和详细日志
- 日志准确反映清理状态

**代码变更**:
```go
func cleanupTUNDevice(ifaceName string) error {
    // 检查设备是否存在
    checkCmd := exec.Command("ip", "link", "show", ifaceName)
    if err := checkCmd.Run(); err != nil {
        log.Printf("TUN设备 %s 不存在，无需清理", ifaceName)
        return nil
    }
    
    // 关闭和删除设备，带错误处理
    // ...
}
```

---

### 3. 证书持久化和加载机制

**修复内容**:
- 支持从文件加载已有证书
- 自动生成并保存证书到 `./certs/` 目录
- 证书验证（有效期检查）
- 添加证书路径配置选项到 `VPNConfig`

**配置字段**:
```go
type VPNConfig struct {
    // ...
    CertDir        string // 证书目录，默认为 ./certs/
    CACertPath     string // CA证书路径
    CAKeyPath      string // CA私钥路径
    ServerCertPath string // 服务器证书路径
    ServerKeyPath  string // 服务器私钥路径
    ClientCertPath string // 客户端证书路径
    ClientKeyPath  string // 客户端私钥路径
}
```

**使用示例**:
```bash
# 首次运行 - 生成证书
sudo ./vpn server
# 输出: 生成新的CA证书...
#      证书已保存: ./certs/ca.crt

# 再次运行 - 加载证书
sudo ./vpn server
# 输出: 从文件加载CA证书: ./certs/ca.crt
```

**证书文件结构**:
```
./certs/
├── ca.crt         # CA证书
├── ca.key         # CA私钥 (权限 600)
├── server.crt     # 服务器证书
├── server.key     # 服务器私钥 (权限 600)
├── client.crt     # 客户端证书
└── client.key     # 客户端私钥 (权限 600)
```

---

### 4. 并发安全

**修复内容**:
- 在 `VPNSession` 中添加 `connMutex` 保护 `TLSConn` 操作
- 在 `VPNServer` 中添加 `ipMap` (IP到Session的映射) 加速查找
- 使用锁保护 `SetReadDeadline` 调用
- 修复会话遍历时的竞态条件

**代码变更**:
```go
// VPNSession 添加连接互斥锁
type VPNSession struct {
    // ...
    connMutex sync.Mutex // 保护TLSConn操作
}

// VPNServer 添加IP映射
type VPNServer struct {
    // ...
    ipMap map[string]*VPNSession // IP到Session的映射
}

// 保护TLS操作
session.connMutex.Lock()
session.TLSConn.SetReadDeadline(time.Now().Add(30 * time.Second))
session.connMutex.Unlock()

// 使用IP映射快速查找
s.sessionMutex.RLock()
targetSession := s.ipMap[destIPStr]
s.sessionMutex.RUnlock()
```

---

### 5. 资源泄漏防护

**修复内容**:
- 使用 `sync.WaitGroup` 跟踪所有goroutine
- 添加 `context.Context` 控制goroutine生命周期
- 在 `Stop()/Close()` 中等待所有goroutine退出
- panic恢复后正确清理资源

**代码变更**:
```go
// 启动goroutine时
s.wg.Add(1)
go s.handleTUNRead()

// 在goroutine中
defer s.wg.Done()

// Stop() 中等待
s.wg.Wait()
```

---

### 6. 用户认证机制

**修复内容**:
- 添加预共享密钥 (PSK) 认证
- 客户端连接后发送 `MessageTypeAuth` 消息
- 服务器验证密钥，失败则断开连接
- 支持从环境变量 `VPN_AUTH_KEY` 读取密钥

**配置**:
```go
type VPNConfig struct {
    // ...
    AuthKey string // 预共享密钥
}
```

**使用示例**:

1. **不使用认证** (默认):
```bash
sudo ./vpn server
sudo ./vpn client
```

2. **使用认证**:
```bash
# 服务器端
VPN_AUTH_KEY=secret123 sudo -E ./vpn server

# 客户端
VPN_AUTH_KEY=secret123 sudo -E ./vpn client

# 错误的密钥会被拒绝
VPN_AUTH_KEY=wrong sudo -E ./vpn client
# 输出: 认证失败: 无效的密钥
```

**流程**:
```
客户端                          服务器
  |                               |
  |--------- TLS握手 ------------->|
  |                               |
  |---- MessageTypeAuth --------->| 
  |    (包含AuthKey)              | 验证密钥
  |                               |
  |<--- MessageTypeIPAssignment --| (验证成功)
  |                               |
  或                              |
  |<-------- 连接断开 ----------| (验证失败)
```

---

## 测试指南

### 1. 系统配置回滚测试

```bash
# 记录初始状态
cat /proc/sys/net/ipv4/ip_forward
# 输出: 0

# 启动服务器
sudo ./vpn server &
SERVER_PID=$!

# 验证IP转发已启用
cat /proc/sys/net/ipv4/ip_forward
# 输出: 1

# 停止服务器
kill -SIGTERM $SERVER_PID
wait $SERVER_PID

# 验证IP转发已恢复
cat /proc/sys/net/ipv4/ip_forward
# 输出: 0
```

### 2. TUN清理测试

```bash
# 正常启动和停止
sudo ./vpn server &
SERVER_PID=$!
sleep 5
kill -SIGTERM $SERVER_PID
wait $SERVER_PID

# 验证设备已清理
ip link show tun0
# 输出: Device "tun0" does not exist.

# 异常场景: 手动删除设备
sudo ./vpn server &
SERVER_PID=$!
sleep 5
sudo ip link delete tun0
kill -SIGTERM $SERVER_PID
# 应该不报错，日志显示 "TUN设备 tun0 不存在，无需清理"
```

### 3. 证书持久化测试

```bash
# 删除旧证书
rm -rf certs/

# 首次运行
sudo ./vpn server &
SERVER_PID=$!
sleep 2
kill -SIGTERM $SERVER_PID

# 检查证书文件
ls -lah certs/
# 应该看到所有证书文件，权限为 600

# 再次运行
sudo ./vpn server &
SERVER_PID=$!
# 日志应显示 "从文件加载CA证书"
```

### 4. 并发安全测试

```bash
# 使用race detector
go test -race ./...

# 或在构建时启用
go build -race -o vpn "TLS VPN 系统.go"
sudo ./vpn server
# 在另一个终端启动多个客户端
```

### 5. 认证测试

```bash
# 启动带认证的服务器
VPN_AUTH_KEY=secret123 sudo -E ./vpn server &
SERVER_PID=$!

# 正确密钥 - 应该成功
VPN_AUTH_KEY=secret123 sudo -E ./vpn client &
CLIENT_PID=$!
sleep 5
kill $CLIENT_PID

# 错误密钥 - 应该失败
VPN_AUTH_KEY=wrong sudo -E ./vpn client
# 输出: 认证失败

# 清理
kill $SERVER_PID
```

---

## 配置示例

### 默认配置

```go
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
    AuthKey:          "", // 默认不需要认证
}
```

---

## 向后兼容性

所有修复保持向后兼容性：

1. **证书**: 如果不存在则自动生成，就像以前一样
2. **认证**: 默认不启用，保持原有行为
3. **IP转发**: 自动保存和恢复，对用户透明
4. **TUN清理**: 更健壮但行为相同

---

## 安全注意事项

1. **证书安全**: 
   - 私钥文件权限为 600
   - 证书目录权限为 700
   - 不要将 `certs/` 目录提交到版本控制

2. **认证密钥**:
   - 使用强密钥 (建议至少32字符)
   - 不要在命令行中直接输入密钥
   - 使用环境变量或配置文件

3. **生产环境**:
   - 使用受信任CA签发的证书
   - 定期轮换证书和密钥
   - 监控证书过期时间

---

## 故障排除

### 问题: 证书验证失败

**症状**: `证书验证失败: 证书已过期`

**解决**:
```bash
# 删除旧证书并重新生成
rm -rf certs/
./vpn server
```

### 问题: 认证总是失败

**症状**: `认证失败: 无效的密钥`

**检查**:
1. 确保服务器和客户端使用相同的 `VPN_AUTH_KEY`
2. 使用 `sudo -E` 保留环境变量
3. 检查环境变量: `echo $VPN_AUTH_KEY`

### 问题: IP转发未恢复

**症状**: 停止后 `/proc/sys/net/ipv4/ip_forward` 仍为 1

**可能原因**:
1. 程序被强制终止 (kill -9)
2. 崩溃未正常退出

**解决**:
```bash
# 手动恢复
sudo sysctl -w net.ipv4.ip_forward=0
```

---

## 性能改进

1. **IP映射**: 从 O(n) 查找改进为 O(1)
2. **并发安全**: 减少锁竞争
3. **证书缓存**: 避免重复生成证书

---

## 未来增强

计划中的改进：

1. NAT规则清理
2. 多种认证方式 (证书 + PSK, LDAP等)
3. 证书自动续期
4. 更细粒度的访问控制
