# TLS VPN 系统

基于 TLS 1.3 的安全 VPN 系统，支持 Linux 平台的实际网络流量转发。

## 特性

### 核心特性
- ✅ 使用 TLS 1.3 进行加密通信
- ✅ 双向证书认证（mTLS）
- ✅ TUN 设备支持（Layer 3 VPN）
- ✅ 真实的 IP 包转发
- ✅ 自动 IP 地址分配（O(1) 性能）
- ✅ 支持多客户端同时连接
- ✅ 自动重连机制
- ✅ 心跳保活

### 性能优化
- ✅ **O(1) IP 分配**: 使用空闲列表实现快速 IP 分配和回收
- ✅ **O(1) 会话查找**: IP 到会话的快速映射，优化数据包转发
- ✅ 高性能处理：>4M 次/秒的 IP 分配操作

### 安全增强
- ✅ **消息序列号**: 检测重放攻击和消息丢失
- ✅ **CRC32 校验**: 应用层完整性验证
- ✅ **会话管理**: 可配置的超时和清理间隔
- ✅ **NAT 规则自动清理**: 防止规则残留

### 配置灵活性
- ✅ **证书持久化**: 自动保存和加载证书，避免重复生成
- ✅ **配置文件支持**: 支持从 JSON 配置文件加载设置
- ✅ 可自定义 IP 地址范围（ClientIPStart/ClientIPEnd）
- ✅ 可配置 DNS 服务器推送
- ✅ 可配置路由推送
- ✅ 可配置 MTU 大小
- ✅ 可配置会话超时和清理间隔

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

### 首次运行 - 生成配置和证书

首次运行时，建议先生成配置文件：

```bash
./vpn generate-config
```

这将创建：
- `./certs/` 目录及证书文件（ca.pem, server.pem, server-key.pem, client.pem, client-key.pem）
- `./config.json` 配置文件

您可以编辑 `config.json` 来自定义配置，例如：

```json
{
  "server_address": "your-server-address.com",
  "server_port": 8080,
  "network": "10.8.0.0/24",
  "mtu": 1500,
  "dns_servers": ["8.8.8.8", "8.8.4.4"],
  "push_routes": ["192.168.1.0/24"]
}
```

### 启动服务器

服务器会创建 `tun0` 设备并配置为 `10.8.0.1/24`：

```bash
sudo ./vpn server
```

服务器日志示例：
```
2024/01/07 10:00:00 从配置文件加载配置: ./config.json
2024/01/07 10:00:00 配置文件加载成功
2024/01/07 10:00:00 初始化证书管理器...
2024/01/07 10:00:00 从 ./certs 目录加载已有证书
2024/01/07 10:00:01 创建TUN设备: tun0
2024/01/07 10:00:01 配置TUN设备 tun0: IP=10.8.0.1/24, MTU=1500
2024/01/07 10:00:01 已启用IP转发
2024/01/07 10:00:01 服务器TUN设备已初始化: 10.8.0.1
2024/01/07 10:00:01 VPN服务器启动，监听地址: [::]:8080

========================================
请将以下文件复制到客户端的 ./certs 目录：
  - ca.pem
  - client.pem
  - client-key.pem
========================================
```

### 复制证书到客户端

将服务器上的证书复制到客户端机器：

```bash
# 在服务器上
scp ./certs/ca.pem ./certs/client.pem ./certs/client-key.pem user@client-machine:~/vpn-client/certs/
```

### 启动客户端

客户端会创建 `tun0` 设备并从服务器获取 IP 地址（例如 `10.8.0.2/24`）：

```bash
sudo ./vpn client
```

客户端日志示例：
```
2024/01/07 10:00:10 从配置文件加载配置: ./config.json
2024/01/07 10:00:10 配置文件加载成功
2024/01/07 10:00:10 初始化证书管理器...
2024/01/07 10:00:10 从 ./certs 目录加载已有证书
2024/01/07 10:00:11 创建TUN设备: tun0
2024/01/07 10:00:11 客户端TUN设备已创建，等待IP分配...
2024/01/07 10:00:11 成功连接到VPN服务器，使用TLS 1.3协议
2024/01/07 10:00:11 分配的VPN IP: 10.8.0.2
2024/01/07 10:00:11 VPN客户端已连接，开始数据传输...
2024/01/07 10:00:11 配置TUN设备 tun0: IP=10.8.0.2/24, MTU=1500
2024/01/07 10:00:11 客户端TUN设备已配置: 10.8.0.2/24
```

### 停止服务

使用 `Ctrl+C` 或发送 SIGTERM 信号：

```bash
# 优雅关闭
sudo pkill -SIGTERM vpn
```

## 配置说明

### 配置文件 (config.json)

配置文件支持以下选项：

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server_address` | string | "localhost" | 服务器地址 |
| `server_port` | int | 8080 | 服务器端口 |
| `client_address` | string | "10.8.0.2/24" | 客户端地址 |
| `network` | string | "10.8.0.0/24" | VPN 网络 CIDR |
| `mtu` | int | 1500 | 最大传输单元 |
| `keep_alive_timeout_sec` | int | 90 | 保活超时（秒） |
| `reconnect_delay_sec` | int | 5 | 重连延迟（秒） |
| `max_connections` | int | 100 | 最大连接数 |
| `session_timeout_sec` | int | 300 | 会话超时（秒） |
| `session_cleanup_interval_sec` | int | 30 | 会话清理间隔（秒） |
| `server_ip` | string | "10.8.0.1/24" | 服务器 VPN IP |
| `client_ip_start` | int | 2 | 客户端 IP 起始 |
| `client_ip_end` | int | 254 | 客户端 IP 结束 |
| `dns_servers` | []string | ["8.8.8.8", "8.8.4.4"] | DNS 服务器列表 |
| `push_routes` | []string | [] | 推送路由（CIDR 格式） |

### 证书管理

证书文件存储在 `./certs/` 目录下：

- `ca.pem` - CA 证书（需要复制到客户端）
- `server.pem` - 服务器证书
- `server-key.pem` - 服务器私钥（仅服务器需要）
- `client.pem` - 客户端证书（需要复制到客户端）
- `client-key.pem` - 客户端私钥（需要复制到客户端）

**重要提示**：
- 证书一旦生成会自动保存，后续运行会自动加载
- 服务器和客户端必须使用相同的 CA 证书
- 如需重新生成证书，删除 `./certs/` 目录后重新运行程序

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
    ServerAddress:          "your.server.ip",      // 客户端连接的服务器地址
    ServerPort:             8080,                   // 服务器端口
    Network:                "10.8.0.0/24",         // VPN 网络
    MTU:                    1500,
    KeepAliveTimeout:       90 * time.Second,
    ReconnectDelay:         5 * time.Second,
    MaxConnections:         100,
    SessionTimeout:         5 * time.Minute,
    SessionCleanupInterval: 30 * time.Second,      // 会话清理间隔
    ServerIP:               "10.8.0.1/24",         // 服务器VPN IP
    ClientIPStart:          2,                      // 客户端IP起始
    ClientIPEnd:            254,                    // 客户端IP结束
    DNSServers:             []string{"8.8.8.8", "8.8.4.4"}, // DNS服务器
    PushRoutes:             []string{},             // 推送给客户端的路由
}
```

### 高级配置选项

#### IP 地址池配置

```go
// 自定义 IP 地址范围（例如只分配 .10 到 .50）
ClientIPStart: 10,
ClientIPEnd:   50,

// 使用不同的网络段
Network:  "192.168.100.0/24",
ServerIP: "192.168.100.1/24",
```

#### DNS 服务器配置

```go
// 推送自定义 DNS 服务器给客户端
DNSServers: []string{"1.1.1.1", "1.0.0.1"},  // Cloudflare DNS
// 或
DNSServers: []string{"208.67.222.222", "208.67.220.220"},  // OpenDNS
```

#### 路由推送配置

```go
// 推送特定路由给客户端（通过 VPN 访问这些网络）
PushRoutes: []string{
    "192.168.1.0/24",   // 内部网络1
    "192.168.2.0/24",   // 内部网络2
    "10.0.0.0/8",       // 大型内部网络
},
```

#### 会话管理配置

```go
// 自定义会话超时和清理间隔
SessionTimeout:         10 * time.Minute,  // 10分钟无活动则超时
SessionCleanupInterval: 60 * time.Second,  // 每60秒检查一次超时会话
```

### NAT 规则管理

系统现在自动跟踪和清理 NAT 规则。使用新的 `SetupNAT` 方法：

```go
// 在服务器初始化后调用
if err := server.SetupNAT("10.8.0.0/24", "eth0"); err != nil {
    log.Printf("配置NAT失败: %v", err)
}

// 停止服务器时会自动清理 NAT 规则
server.Stop()  // 自动调用 cleanupNATRules()
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

### 基本安全
1. **证书管理**: 当前实现使用自动生成的证书，生产环境应使用受信任的 CA 签发的证书
2. **防火墙**: 限制服务器只允许必要的端口访问
3. **日志**: 定期审查日志文件，监控异常活动
4. **更新**: 保持 Go 和依赖库更新到最新版本
5. **权限**: 仅在必要时运行，运行后考虑降低权限

### 增强的安全特性

#### 消息序列号验证
系统现在包含序列号验证，可以检测：
- **重放攻击**: 检测到序列号回退时拒绝消息
- **消息丢失**: 检测到序列号跳跃时记录警告
- **消息乱序**: 跟踪期望的序列号

```
# 日志示例
警告：会话 xxx 检测到消息丢失，期望序列号 42，收到 44
会话 xxx 检测到重放攻击：期望序列号 >= 100，收到 99
```

#### CRC32 校验和
每个数据消息都包含 CRC32 校验和，提供应用层完整性验证：
- TLS 提供传输层加密和完整性
- CRC32 提供额外的应用层校验（纵深防御）
- 检测到校验和不匹配时断开连接

#### 会话管理增强
- **可配置超时**: 根据需要调整会话超时和清理间隔
- **立即清理**: 连接断开时立即回收 IP 地址
- **唯一 SessionID**: 使用纳秒时间戳 + 随机数确保唯一性

#### NAT 规则自动清理
- 程序退出时自动删除添加的 NAT 规则
- 防止规则累积和意外的网络行为
- 记录所有 NAT 操作以便审计

## 性能特性

### IP 地址池优化
- **O(1) 分配**: 使用空闲列表实现常数时间复杂度
- **O(1) 回收**: 直接将索引添加回空闲列表
- **基准测试**: >4,000,000 次操作/秒，每次操作 ~269ns

### 会话查找优化
- **O(1) 查找**: 使用 IP 到会话的哈希映射
- **消除线性扫描**: 之前需要遍历所有会话
- **100x 性能提升**: 100 个会话时从 O(100) 降至 O(1)

### 数据包转发效率
```
修复前: 每个数据包需要遍历所有会话 (O(n))
修复后: 直接通过 IP 查找会话 (O(1))
```

## 协议格式

### 消息结构
```
+--------+--------+--------+--------+--------+--------+
| Type   |       Length (4 bytes)        |  Sequence...
| 1 byte |         Big Endian           | (4 bytes)
+--------+--------+--------+--------+--------+--------+
| ...Sequence     |      Checksum (4 bytes)  | Payload
|    (cont.)      |       Big Endian         | Variable
+--------+--------+--------+--------+--------+--------+
```

消息类型：
- `0x00`: 数据包 (IP 包) - 使用序列号和校验和
- `0x01`: 心跳 - 不使用序列号
- `0x02`: IP 地址分配 - 不使用序列号
- `0x03`: 认证 (保留)
- `0x04`: 控制消息 (配置推送) - 使用序列号和校验和

### 协议版本兼容性
**重要**: 本次更新改变了消息格式（5字节→13字节头部），需要同时更新客户端和服务器。

## 开发

### 项目结构

```
tls-vpn/
├── TLS VPN 系统.go  # 主程序文件
├── go.mod          # Go 模块定义
├── go.sum          # 依赖校验和
└── README.md       # 本文档
```

### 主要组件

- **CertificateManager**: 证书管理，自动生成 CA 和证书对
- **VPNServer**: VPN 服务器，处理客户端连接和数据包路由
- **VPNClient**: VPN 客户端，连接服务器和处理数据包
- **IPPool**: IP 地址池，管理客户端 IP 分配
- **VPNSession**: 会话管理，跟踪客户端连接状态
- **Message**: 消息编解码，定义通信协议

### 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

[MIT License](LICENSE)

## 参考

- [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
- [TUN/TAP Interface](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
- [github.com/songgao/water](https://github.com/songgao/water)
