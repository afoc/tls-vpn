# TLS VPN 系统配置示例

## 默认配置

服务器地址: localhost
服务器端口: 8080
VPN 网络: 10.8.0.0/24
MTU: 1500
保活超时: 90 秒
重连延迟: 5 秒
最大连接数: 100
会话超时: 5 分钟

## 修改配置

要修改配置，请编辑 `TLS VPN 系统.go` 文件中的 `DefaultConfig` 变量：

```go
var DefaultConfig = VPNConfig{
    ServerAddress:    "localhost",        // 服务器地址
    ServerPort:       8080,               // 服务器端口
    ClientAddress:    "10.8.0.2/24",     // 客户端地址（未使用）
    Network:          "10.8.0.0/24",     // VPN 网络段
    MTU:              1500,               // 最大传输单元
    KeepAliveTimeout: 90 * time.Second,  // 连接保活超时
    ReconnectDelay:   5 * time.Second,   // 重连延迟
    MaxConnections:   100,                // 最大连接数
    SessionTimeout:   5 * time.Minute,   // 会话超时
}
```

## 生产环境建议

### 服务器配置

1. **更改监听地址**: 在 `NewVPNServer` 调用中修改 `:8080` 为 `0.0.0.0:8080` 以监听所有接口
2. **增加连接数**: 根据需要调整 `MaxConnections`
3. **配置防火墙**: 只允许必要的端口访问
4. **启用日志轮转**: 使用系统日志或日志轮转工具

### 客户端配置

1. **设置服务器地址**: 修改 `ServerAddress` 为实际的服务器 IP 或域名
2. **调整超时**: 根据网络状况调整 `KeepAliveTimeout` 和 `ReconnectDelay`
3. **配置路由**: 根据需要配置默认路由或特定路由

### 网络配置

1. **MTU 优化**: 
   - 默认值 1500 适合大多数网络
   - 如遇到性能问题，尝试降低到 1400 或 1300
   - 使用 `ping -M do -s <size>` 测试最佳 MTU

2. **IP 地址段**:
   - 避免与现有网络冲突
   - 常用私有地址段: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

3. **NAT 配置**:
   ```bash
   # 在服务器上执行
   sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
   sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
   sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
   ```

4. **持久化配置**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install iptables-persistent
   sudo netfilter-persistent save
   
   # CentOS/RHEL
   sudo service iptables save
   ```

## 安全配置

1. **证书管理**: 
   - 当前使用自动生成的证书
   - 生产环境应使用正式 CA 签发的证书
   - 考虑实现证书轮换机制

2. **访问控制**:
   - 使用防火墙限制访问来源
   - 实现 IP 白名单机制
   - 添加用户认证层

3. **监控和日志**:
   - 记录所有连接和断开事件
   - 监控异常流量模式
   - 设置告警机制

4. **系统加固**:
   - 及时更新系统和依赖
   - 最小化系统权限
   - 使用 SELinux 或 AppArmor

## 性能优化

1. **Go 运行时优化**:
   ```bash
   # 设置 Go 运行时参数
   GOMAXPROCS=4 ./vpn server
   ```

2. **系统参数优化**:
   ```bash
   # 增加文件描述符限制
   ulimit -n 65535
   
   # 调整 TCP 参数
   sudo sysctl -w net.core.rmem_max=26214400
   sudo sysctl -w net.core.wmem_max=26214400
   sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 26214400"
   sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 26214400"
   ```

3. **TUN 设备优化**:
   ```bash
   # 启用 offload 功能（如果支持）
   sudo ethtool -K tun0 rx off tx off
   ```

## 故障转移

1. **服务器高可用**:
   - 使用负载均衡器
   - 配置多个服务器实例
   - 实现会话持久化

2. **客户端重连**:
   - 已内置自动重连机制
   - 调整 `ReconnectDelay` 以平衡恢复速度和服务器负载

## 监控指标

建议监控以下指标：

1. 活跃连接数
2. 数据传输速率
3. 丢包率
4. 延迟
5. CPU 和内存使用率
6. TUN 设备统计信息

使用以下命令查看：

```bash
# 连接数
netstat -tn | grep :8080 | wc -l

# TUN 设备统计
ip -s link show tun0

# 系统资源
top -p $(pgrep vpn)
```
