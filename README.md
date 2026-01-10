# TLS VPN 系统

基于 TLS 1.3 的安全 VPN 系统，支持 Linux 平台的实际网络流量转发。

## 特性

- ✅ 使用 TLS 1.3 进行加密通信
- ✅ 双向证书认证（mTLS）
- ✅ TUN 设备支持（Layer 3 VPN）
- ✅ 真实的 IP 包转发
- ✅ 自动 IP 地址分配
- ✅ 支持多客户端同时连接
- ✅ 自动重连机制
- ✅ 心跳保活
- ✅ 会话管理
- ✅ **证书持久化** - 自动生成并保存证书，支持从文件加载
- ✅ **系统配置自动恢复** - 退出时自动恢复 IP 转发等系统设置
- ✅ **预共享密钥认证** - 可选的额外认证层
- ✅ **并发安全** - 完善的锁机制和资源管理
- ✅ **健壮的资源清理** - WaitGroup 跟踪所有 goroutine

## 系统要求

- **操作系统**: Linux（内核支持 TUN 设备）
- **权限**: root/sudo 权限（创建和配置 TUN 设备需要）
- **Go 版本**: Go 1.21 或更高
- **依赖**: `github.com/songgao/water` (自动安装)

## 安装

### 1. 克隆仓库

```bash
git clone https://github.com/afoc/tls-vpn.git
cd tls-vpn
```

### 2. 安装依赖

```bash
go get github.com/songgao/water
```

或者使用 go mod:

```bash
go mod download
```

## 编译

```bash
go build -o vpn "TLS VPN 系统.go"
```

## 使用方法

### 首次运行 - 证书生成

首次运行时，程序会自动生成并保存证书到 `./certs/` 目录：

```bash
sudo ./vpn server
```

证书文件：
```
./certs/
├── ca.crt         # CA证书
├── ca.key         # CA私钥 (权限 600)
├── server.crt     # 服务器证书
├── server.key     # 服务器私钥 (权限 600)
├── client.crt     # 客户端证书
└── client.key     # 客户端私钥 (权限 600)
```

**重要**: 证书文件会被自动保存，之后运行会重用这些证书。

### 启动服务器

服务器会创建 `tun0` 设备并配置为 `10.8.0.1/24`：

```bash
sudo ./vpn server
```

服务器日志示例：
```
2024/01/07 10:00:00 初始化证书管理器...
2024/01/07 10:00:00 从文件加载CA证书: ./certs/ca.crt
2024/01/07 10:00:00 从文件加载服务器证书: ./certs/server.crt
2024/01/07 10:00:00 从文件加载客户端证书: ./certs/client.crt
2024/01/07 10:00:01 创建TUN设备: tun0
2024/01/07 10:00:01 配置TUN设备 tun0: IP=10.8.0.1/24, MTU=1500
2024/01/07 10:00:01 已启用IP转发 (原始值: 0)
2024/01/07 10:00:01 服务器TUN设备已初始化: 10.8.0.1
2024/01/07 10:00:01 VPN服务器启动，监听地址: [::]:8080
```

### 启动客户端

客户端会创建 `tun0` 设备并从服务器获取 IP 地址（例如 `10.8.0.2/24`）：

```bash
sudo ./vpn client
```

客户端日志示例：
```
2024/01/07 10:00:10 初始化证书管理器...
2024/01/07 10:00:10 从文件加载CA证书: ./certs/ca.crt
2024/01/07 10:00:11 创建TUN设备: tun0
2024/01/07 10:00:11 客户端TUN设备已创建，等待IP分配...
2024/01/07 10:00:11 成功连接到VPN服务器，使用TLS 1.3协议
2024/01/07 10:00:11 分配的VPN IP: 10.8.0.2
2024/01/07 10:00:11 VPN客户端已连接，开始数据传输...
2024/01/07 10:00:11 配置TUN设备 tun0: IP=10.8.0.2/24, MTU=1500
2024/01/07 10:00:11 客户端TUN设备已配置: 10.8.0.2/24
```

### 使用认证 (可选)

如需额外的安全层，可以启用预共享密钥认证：

```bash
# 服务器端
VPN_AUTH_KEY=your-secret-key sudo -E ./vpn server

# 客户端
VPN_AUTH_KEY=your-secret-key sudo -E ./vpn client
```

**注意**: 使用 `sudo -E` 保留环境变量。

### 停止服务

使用 `Ctrl+C` 或发送 SIGTERM 信号：

```bash
# 优雅关闭
sudo pkill -SIGTERM vpn
```

停止时会自动：
- 恢复原始 IP 转发设置
- 清理 TUN 设备
- 等待所有 goroutine 退出
- 关闭所有连接

## 测试

### 基本连通性测试

1. **从客户端 ping 服务器**:
   ```bash
   ping 10.8.0.1
   ```

2. **从服务器 ping 客户端**:
   ```bash
   ping 10.8.0.2
   ```

### 查看 TUN 设备

```bash
# 查看接口配置
ip addr show tun0

# 查看路由表
ip route show

# 查看接口统计
ip -s link show tun0
```

### 抓包分析

```bash
# 在 TUN 设备上抓包
sudo tcpdump -i tun0 -n

# 在物理接口上抓包（查看加密的 TLS 流量）
sudo tcpdump -i eth0 port 8080 -n
```

## 高级配置

### 配置 NAT（允许客户端访问互联网）

在服务器上执行：

```bash
# 启用 IP 转发（程序会自动执行）
sudo sysctl -w net.ipv4.ip_forward=1

# 配置 NAT（假设外网接口是 eth0）
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# 允许转发
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### 客户端添加默认路由（所有流量通过 VPN）

```bash
# 添加默认路由
sudo ip route add default via 10.8.0.1 dev tun0

# 或者只路由特定网段
sudo ip route add 192.168.1.0/24 via 10.8.0.1 dev tun0
```

### 修改服务器监听地址和端口

修改 `TLS VPN 系统.go` 中的 `DefaultConfig`：

```go
var DefaultConfig = VPNConfig{
    ServerAddress:    "your.server.ip",  // 客户端连接的服务器地址
    ServerPort:       8080,               // 服务器端口
    Network:          "10.8.0.0/24",     // VPN 网络
    MTU:              1500,
    KeepAliveTimeout: 90 * time.Second,
    ReconnectDelay:   5 * time.Second,
    MaxConnections:   100,
    SessionTimeout:   5 * time.Minute,
}
```

### 修改 MTU

如果遇到 MTU 相关的问题，可以调整 MTU 大小：

```go
MTU: 1400,  // 降低 MTU 以适应网络环境
```

或者在运行时手动调整：

```bash
sudo ip link set dev tun0 mtu 1400
```

## 架构说明

### 网络拓扑

```
客户端 (10.8.0.2)
    |
    | TLS 1.3 加密隧道 (TCP:8080)
    |
服务器 (10.8.0.1)
    |
    | NAT (可选)
    |
互联网
```

### 数据流向

#### 客户端到服务器
1. 应用程序 → TUN 设备 (tun0)
2. VPN 客户端读取 IP 包
3. 通过 TLS 隧道发送到服务器
4. 服务器写入 TUN 设备
5. 服务器内核路由 IP 包

#### 服务器到客户端
1. 服务器内核路由决策
2. IP 包写入 TUN 设备
3. VPN 服务器读取 IP 包
4. 根据目标 IP 查找对应客户端会话
5. 通过 TLS 隧道发送到客户端
6. 客户端写入 TUN 设备

### 协议格式

消息格式（5 字节头 + 变长数据）：
```
+--------+--------+--------+--------+--------+--------+
| Type   |       Length (4 bytes)        |  Payload ...
| 1 byte |         Big Endian           |   Variable
+--------+--------+--------+--------+--------+--------+
```

消息类型：
- `0x00`: 数据包 (IP 包)
- `0x01`: 心跳
- `0x02`: IP 地址分配
- `0x03`: 认证
- `0x04`: 控制消息

## 故障排除

### 问题: 需要 root 权限

**错误**: `需要root权限运行，请使用sudo`

**解决**: 使用 `sudo` 运行程序：
```bash
sudo ./vpn server
# 或
sudo ./vpn client
```

### 问题: TUN 设备创建失败

**错误**: `创建TUN设备失败: operation not permitted`

**可能原因**:
1. 没有 root 权限
2. 内核不支持 TUN 模块

**解决**:
```bash
# 检查 TUN 模块
lsmod | grep tun

# 如果没有，加载模块
sudo modprobe tun

# 检查 /dev/net/tun 是否存在
ls -l /dev/net/tun
```

### 问题: 地址已在使用

**错误**: `设置IP地址失败: RTNETLINK answers: File exists`

**原因**: TUN 设备已经配置了 IP 地址

**解决**:
```bash
# 删除已存在的 IP 地址
sudo ip addr del 10.8.0.1/24 dev tun0

# 或者删除并重新创建设备
sudo ip link delete tun0
```

### 问题: 连接超时

**症状**: 客户端无法连接到服务器

**检查清单**:
1. 服务器是否正在运行
2. 防火墙是否允许端口 8080
3. 服务器地址配置是否正确

```bash
# 检查服务器是否监听
sudo netstat -tlnp | grep 8080

# 检查防火墙
sudo iptables -L -n | grep 8080

# 允许端口
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

### 问题: 无法 ping 通

**症状**: 建立连接后无法 ping 通对端

**检查**:
1. TUN 设备是否 UP
```bash
ip link show tun0
```

2. IP 地址是否正确配置
```bash
ip addr show tun0
```

3. 路由表是否正确
```bash
ip route show
```

4. IP 转发是否启用（服务器）
```bash
cat /proc/sys/net/ipv4/ip_forward
```

### 问题: 性能问题

**优化建议**:
1. 调整 MTU 大小
2. 检查网络延迟和丢包率
3. 考虑使用更快的加密套件（已使用 TLS 1.3）

```bash
# 测试延迟
ping -c 10 10.8.0.1

# 测试带宽
iperf3 -s  # 服务器
iperf3 -c 10.8.0.1  # 客户端
```

## 安全注意事项

1. **证书管理**: 
   - 证书会自动生成并保存到 `./certs/` 目录
   - 私钥文件权限自动设为 600
   - 生产环境应使用受信任的 CA 签发的证书
   - 定期检查证书有效期，系统会在证书30天内过期时发出警告
   
2. **认证**:
   - 可选的预共享密钥认证提供额外安全层
   - 建议使用至少32字符的强密钥
   - 通过环境变量 `VPN_AUTH_KEY` 设置密钥
   
3. **系统配置**:
   - IP 转发设置会在程序退出时自动恢复
   - TUN 设备会被正确清理
   - 所有 goroutine 会被正确等待和清理
   
4. **防火墙**: 限制服务器只允许必要的端口访问

5. **日志**: 定期审查日志文件，监控异常活动

6. **更新**: 保持 Go 和依赖库更新到最新版本

7. **权限**: 仅在必要时运行，运行后考虑降低权限

## 最近更新

### 安全性和健壮性改进 (2026-01)

1. **系统配置自动恢复**: 
   - IP 转发设置在退出时自动恢复到原始值
   - 防止留下安全隐患

2. **证书持久化**:
   - 证书自动保存到 `./certs/` 目录
   - 支持从文件加载证书，避免每次重新生成
   - 证书验证，包括有效期检查

3. **预共享密钥认证**:
   - 可选的额外认证层
   - 通过环境变量 `VPN_AUTH_KEY` 配置

4. **并发安全**:
   - 添加适当的互斥锁保护共享资源
   - IP 到 Session 的映射加速查找（O(1) 而非 O(n)）
   - 修复会话遍历时的竞态条件

5. **资源泄漏防护**:
   - 使用 `sync.WaitGroup` 跟踪所有 goroutine
   - 使用 `context.Context` 控制 goroutine 生命周期
   - 确保所有资源在退出时正确清理

6. **健壮的 TUN 设备清理**:
   - 检查设备是否存在再清理
   - 详细的错误日志
   - 正确处理各种异常情况

详细信息请参阅 [FIXES.md](FIXES.md)

## 开发

### 项目结构

```
tls-vpn/
├── TLS VPN 系统.go  # 主程序文件
├── go.mod          # Go 模块定义
├── go.sum          # 依赖校验和
├── README.md       # 本文档
├── FIXES.md        # 详细的修复文档
├── test_fixes.sh   # 自动化测试脚本
└── certs/          # 证书目录 (自动生成，不提交到版本控制)
    ├── ca.crt
    ├── ca.key
    ├── server.crt
    ├── server.key
    ├── client.crt
    └── client.key
```

### 主要组件

- **CertificateManager**: 证书管理，支持证书持久化和加载
- **VPNServer**: VPN 服务器，处理客户端连接和数据包路由
- **VPNClient**: VPN 客户端，连接服务器和处理数据包
- **IPPool**: IP 地址池，管理客户端 IP 分配
- **VPNSession**: 会话管理，跟踪客户端连接状态
- **Message**: 消息编解码，定义通信协议

### 测试

运行自动化测试：

```bash
./test_fixes.sh
```

### 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

[MIT License](LICENSE)

## 参考

- [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
- [TUN/TAP Interface](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
- [github.com/songgao/water](https://github.com/songgao/water)
