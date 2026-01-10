# TLS-VPN 使用示例

本文档展示如何使用新的证书持久化和配置文件功能，在两台不同的机器上部署 VPN 服务。

## 场景：在两台机器间建立 VPN 连接

假设你有两台机器：
- **服务器**: `server.example.com` (公网 IP: 1.2.3.4)
- **客户端**: 你的本地机器

## 步骤 1：在服务器上设置

### 1.1 编译程序

```bash
cd tls-vpn
go build -o vpn "TLS VPN 系统.go"
```

### 1.2 生成配置文件和证书

```bash
./vpn generate-config
```

输出：
```
2024/01/07 10:00:00 配置文件不存在，使用默认配置
2024/01/07 10:00:00 提示: 可以创建 ./config.json 文件来自定义配置
2024/01/07 10:00:00 初始化证书管理器...
2024/01/07 10:00:00 证书文件不存在，生成新证书...
2024/01/07 10:00:07 证书已生成并保存到 ./certs 目录
2024/01/07 10:00:07 示例配置文件已生成: ./config.json
2024/01/07 10:00:07 请根据需要修改配置文件后重新运行程序
```

### 1.3 修改配置文件（可选）

编辑 `config.json`，根据需要调整配置：

```json
{
  "server_address": "server.example.com",
  "server_port": 8080,
  "client_address": "10.8.0.2/24",
  "network": "10.8.0.0/24",
  "mtu": 1500,
  "keep_alive_timeout_sec": 90,
  "reconnect_delay_sec": 5,
  "max_connections": 100,
  "session_timeout_sec": 300,
  "session_cleanup_interval_sec": 30,
  "server_ip": "10.8.0.1/24",
  "client_ip_start": 2,
  "client_ip_end": 254,
  "dns_servers": [
    "8.8.8.8",
    "8.8.4.4"
  ],
  "push_routes": []
}
```

### 1.4 启动服务器

```bash
sudo ./vpn server
```

输出：
```
2024/01/07 10:05:00 从配置文件加载配置: ./config.json
2024/01/07 10:05:00 配置文件加载成功
2024/01/07 10:05:00 初始化证书管理器...
2024/01/07 10:05:00 从 ./certs 目录加载已有证书
2024/01/07 10:05:01 创建TUN设备: tun0
2024/01/07 10:05:01 配置TUN设备 tun0: IP=10.8.0.1/24, MTU=1500
2024/01/07 10:05:01 已启用IP转发
2024/01/07 10:05:01 服务器TUN设备已初始化: 10.8.0.1
2024/01/07 10:05:01 VPN服务器启动，监听地址: [::]:8080

========================================
请将以下文件复制到客户端的 ./certs 目录：
  - ca.pem
  - client.pem
  - client-key.pem
========================================
```

## 步骤 2：准备客户端

### 2.1 复制证书文件到客户端

在服务器上，将必要的证书文件打包：

```bash
tar czf vpn-client-certs.tar.gz certs/ca.pem certs/client.pem certs/client-key.pem
```

将文件传输到客户端：

```bash
scp vpn-client-certs.tar.gz user@client-machine:~/
```

在客户端机器上：

```bash
cd tls-vpn
mkdir -p certs
cd ~/
tar xzf vpn-client-certs.tar.gz -C tls-vpn/
```

### 2.2 复制并修改配置文件（可选）

如果你在服务器上修改了配置文件，也需要复制到客户端：

```bash
# 在服务器上
scp config.json user@client-machine:~/tls-vpn/

# 在客户端上，修改 server_address
cd tls-vpn
# 编辑 config.json，将 server_address 改为实际的服务器地址
```

示例客户端 `config.json`：

```json
{
  "server_address": "1.2.3.4",  // 或 "server.example.com"
  "server_port": 8080,
  "client_address": "10.8.0.2/24",
  "network": "10.8.0.0/24",
  "mtu": 1500,
  "keep_alive_timeout_sec": 90,
  "reconnect_delay_sec": 5,
  "max_connections": 100,
  "session_timeout_sec": 300,
  "session_cleanup_interval_sec": 30,
  "server_ip": "10.8.0.1/24",
  "client_ip_start": 2,
  "client_ip_end": 254,
  "dns_servers": [
    "8.8.8.8",
    "8.8.4.4"
  ],
  "push_routes": []
}
```

### 2.3 启动客户端

```bash
cd tls-vpn
sudo ./vpn client
```

输出：
```
2024/01/07 10:10:00 从配置文件加载配置: ./config.json
2024/01/07 10:10:00 配置文件加载成功
2024/01/07 10:10:00 初始化证书管理器...
2024/01/07 10:10:00 从 ./certs 目录加载已有证书
2024/01/07 10:10:01 创建TUN设备: tun0
2024/01/07 10:10:01 客户端TUN设备已创建，等待IP分配...
2024/01/07 10:10:01 成功连接到VPN服务器，使用TLS 1.3协议
2024/01/07 10:10:01 分配的VPN IP: 10.8.0.2
2024/01/07 10:10:01 VPN客户端已连接，开始数据传输...
2024/01/07 10:10:01 配置TUN设备 tun0: IP=10.8.0.2/24, MTU=1500
2024/01/07 10:10:01 客户端TUN设备已配置: 10.8.0.2/24
```

## 步骤 3：测试连接

### 3.1 从客户端 ping 服务器

```bash
ping 10.8.0.1
```

### 3.2 从服务器 ping 客户端

```bash
ping 10.8.0.2
```

## 常见问题

### Q1: 证书文件在哪里？

证书文件位于 `./certs/` 目录下：
- `ca.pem` - CA 证书
- `server.pem` - 服务器证书
- `server-key.pem` - 服务器私钥
- `client.pem` - 客户端证书
- `client-key.pem` - 客户端私钥

### Q2: 如何重新生成证书？

删除 `./certs/` 目录，然后重新运行：

```bash
rm -rf ./certs
./vpn generate-config
```

**注意**：重新生成证书后，需要重新复制到所有客户端。

### Q3: 客户端报错 "certificate signed by unknown authority"

这表示客户端使用的证书与服务器不匹配。确保：
1. 客户端的 `./certs/` 目录包含从服务器复制的证书
2. 服务器没有重新生成证书（如果重新生成，需要重新复制到客户端）

### Q4: 如何修改 VPN 网络配置？

编辑 `config.json` 文件，修改相关参数，然后重启程序。例如：

```json
{
  "network": "10.9.0.0/24",
  "server_ip": "10.9.0.1/24",
  "client_ip_start": 2,
  "client_ip_end": 254
}
```

### Q5: 如何配置多个客户端？

每个客户端使用相同的证书文件（ca.pem, client.pem, client-key.pem），服务器会自动为每个客户端分配不同的 IP 地址（从 10.8.0.2 到 10.8.0.254）。

### Q6: 配置文件支持注释吗？

标准的 JSON 格式不支持注释。如果需要添加说明，可以在配置文件旁边创建一个 `config.md` 文件来记录配置说明。

## 进阶用法

### 配置路由推送

如果你想让客户端通过 VPN 访问服务器端的内网（例如 192.168.1.0/24），可以在服务器的 `config.json` 中添加：

```json
{
  "push_routes": ["192.168.1.0/24"]
}
```

### 配置自定义 DNS

```json
{
  "dns_servers": ["10.8.0.1", "1.1.1.1"]
}
```

### 限制客户端数量

```json
{
  "max_connections": 10
}
```

### 调整 MTU

如果遇到连接问题，可以尝试降低 MTU：

```json
{
  "mtu": 1400
}
```

## 生产环境建议

1. **防火墙配置**：确保服务器防火墙允许 8080 端口（或你配置的端口）
2. **证书安全**：妥善保管私钥文件（*-key.pem），建议设置文件权限为 600
3. **日志管理**：建议将日志重定向到文件：`sudo ./vpn server > vpn.log 2>&1 &`
4. **系统服务**：考虑使用 systemd 将 VPN 配置为系统服务
5. **备份证书**：定期备份 `./certs/` 目录
