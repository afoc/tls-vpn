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

### 启动服务器

服务器会创建 `tun0` 设备并配置为 `10.8.0.1/24`：

```bash
sudo ./vpn server
```

服务器日志示例：
```
2024/01/07 10:00:00 初始化证书管理器...
2024/01/07 10:00:01 创建TUN设备: tun0
2024/01/07 10:00:01 配置TUN设备 tun0: IP=10.8.0.1/24, MTU=1500
2024/01/07 10:00:01 已启用IP转发
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

1. **证书管理**: 当前实现使用自动生成的证书，生产环境应使用受信任的 CA 签发的证书
2. **防火墙**: 限制服务器只允许必要的端口访问
3. **日志**: 定期审查日志文件，监控异常活动
4. **更新**: 保持 Go 和依赖库更新到最新版本
5. **权限**: 仅在必要时运行，运行后考虑降低权限

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
