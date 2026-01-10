# 路由配置指南

本文档介绍 TLS VPN 系统的灵活路由配置功能。

## 概述

TLS VPN 支持两种路由模式：
- **分流模式（split）**：只有特定网段通过 VPN 转发（默认）
- **全流量代理模式（full）**：所有互联网流量通过 VPN 转发

## 配置选项

在 `config.json` 文件中，可以配置以下路由相关选项：

### 客户端配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `route_mode` | string | "split" | 路由模式："split"（分流）或 "full"（全流量） |
| `exclude_routes` | []string | [] | 排除的路由列表（仅在 full 模式下使用） |
| `redirect_gateway` | bool | false | 是否重定向默认网关 |
| `redirect_dns` | bool | false | 是否劫持 DNS（使用服务器推送的 DNS） |
| `push_routes` | []string | [] | 推送给客户端的路由列表（CIDR 格式） |
| `dns_servers` | []string | ["8.8.8.8", "8.8.4.4"] | DNS 服务器列表 |

### 服务器配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enable_nat` | bool | true | 是否启用 NAT |
| `nat_interface` | string | "" | NAT 出口网卡（空字符串表示自动检测） |

## 使用场景

### 场景 1：分流模式（默认）

只有特定网段通过 VPN，适合访问内网资源。

**配置示例：**
```json
{
  "route_mode": "split",
  "push_routes": ["192.168.1.0/24", "10.0.0.0/8"],
  "redirect_gateway": false,
  "redirect_dns": false
}
```

**效果：**
- 访问 192.168.1.0/24 和 10.0.0.0/8 网段时走 VPN
- 其他流量走本地默认网关
- DNS 使用本地配置

### 场景 2：全流量代理模式

所有互联网流量通过 VPN，适合翻墙或完全隐藏流量。

**配置示例：**
```json
{
  "route_mode": "full",
  "exclude_routes": [],
  "redirect_gateway": true,
  "redirect_dns": true,
  "dns_servers": ["8.8.8.8", "1.1.1.1"]
}
```

**效果：**
- 所有流量（0.0.0.0/0）走 VPN
- DNS 使用服务器推送的 DNS（8.8.8.8 和 1.1.1.1）
- 到 VPN 服务器的连接除外（自动添加直连路由）

### 场景 3：全流量代理 + 排除特定网段

大部分流量走 VPN，但排除某些网段。

**配置示例：**
```json
{
  "route_mode": "full",
  "exclude_routes": ["192.168.1.0/24", "10.0.0.0/8"],
  "redirect_gateway": true,
  "redirect_dns": true
}
```

**效果：**
- 所有流量走 VPN
- 192.168.1.0/24 和 10.0.0.0/8 网段直连（不走 VPN）
- DNS 使用 VPN 的 DNS

### 场景 4：自定义 NAT 配置（服务器端）

服务器使用特定网卡作为 NAT 出口。

**配置示例：**
```json
{
  "enable_nat": true,
  "nat_interface": "eth0"
}
```

**效果：**
- VPN 流量经过 NAT 后从 eth0 出口
- 自动添加 iptables 规则

## 路由模式详解

### 分流模式（split）

分流模式只添加 `push_routes` 中配置的路由。

**路由配置：**
```
# 只有以下路由走 VPN
192.168.1.0/24 via 10.8.0.1 dev tun0
10.0.0.0/8 via 10.8.0.1 dev tun0
```

**优点：**
- 不影响其他网络流量
- 适合访问特定内网
- 性能开销小

**缺点：**
- 需要明确知道要访问的网段
- 无法隐藏所有流量

### 全流量代理模式（full）

全流量模式使用 `0.0.0.0/1` 和 `128.0.0.0/1` 覆盖所有 IP 地址。

**路由配置：**
```
# 覆盖所有 IP（优先级高于默认路由）
0.0.0.0/1 via 10.8.0.1 dev tun0
128.0.0.0/1 via 10.8.0.1 dev tun0

# VPN 服务器直连
<server_ip>/32 via <default_gateway> dev <default_interface>

# 排除的网段（如果配置）
192.168.1.0/24 via <default_gateway> dev <default_interface>
```

**优点：**
- 所有流量加密
- 隐藏真实 IP
- 可以穿透防火墙

**缺点：**
- 性能开销大
- 网络延迟增加
- 需要服务器有良好的带宽

## 技术细节

### 路由优先级

Linux 路由选择基于最长前缀匹配：
1. `/32`（单个 IP）> `/24`（子网）> `/1`（大网段）> `/0`（默认路由）
2. 相同前缀长度的路由，先添加的优先

### 自动路由保护

客户端自动添加到 VPN 服务器的直连路由，防止连接断开：
```bash
# 自动添加
<vpn_server_ip>/32 via <local_gateway> dev <local_interface>
```

### DNS 劫持

启用 `redirect_dns` 后：
1. 备份 `/etc/resolv.conf` 到 `/etc/resolv.conf.vpn-backup`
2. 写入新的 DNS 配置
3. 断开连接时自动恢复

### NAT 配置

服务器端自动配置 NAT 规则：
```bash
# MASQUERADE 规则
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# FORWARD 规则
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

停止服务器时自动清理这些规则。

## 故障排除

### 客户端无法连接

**问题：** 配置路由后无法连接到 VPN 服务器

**解决：**
- 检查是否自动添加了服务器直连路由
- 查看日志：`已添加路由: <server_ip>/32`
- 手动添加：`ip route add <server_ip>/32 via <gateway>`

### DNS 无法解析

**问题：** 启用 DNS 劫持后无法解析域名

**解决：**
1. 检查 DNS 服务器是否可达：`ping 8.8.8.8`
2. 查看 DNS 配置：`cat /etc/resolv.conf`
3. 手动恢复：`cp /etc/resolv.conf.vpn-backup /etc/resolv.conf`

### 路由未生效

**问题：** 添加路由后流量仍不走 VPN

**解决：**
1. 查看路由表：`ip route show`
2. 检查路由优先级：更具体的路由优先
3. 验证 TUN 设备：`ip addr show tun0`
4. 检查日志中的路由添加信息

### NAT 不工作

**问题：** 服务器端 NAT 未生效，客户端无法访问互联网

**解决：**
1. 检查 NAT 规则：`iptables -t nat -L -n -v`
2. 检查 FORWARD 规则：`iptables -L FORWARD -n -v`
3. 检查 IP 转发：`cat /proc/sys/net/ipv4/ip_forward`（应该是 1）
4. 手动启用：`sysctl -w net.ipv4.ip_forward=1`

### 清理残留路由

如果程序异常退出，路由可能不会被清理：

```bash
# 查看路由表
ip route show

# 删除特定路由
ip route del 0.0.0.0/1 dev tun0
ip route del 128.0.0.0/1 dev tun0

# 恢复 DNS
cp /etc/resolv.conf.vpn-backup /etc/resolv.conf
```

## 最佳实践

1. **测试环境先验证**
   - 在测试环境验证路由配置
   - 使用 `ping` 和 `traceroute` 验证路由

2. **保留备用连接**
   - 全流量模式下保留 SSH 或其他管理连接
   - 使用 `screen` 或 `tmux` 会话

3. **逐步配置**
   - 先使用分流模式测试连通性
   - 确认正常后再切换到全流量模式

4. **监控日志**
   - 关注路由添加和删除日志
   - 检查 DNS 配置变更日志

5. **定期清理**
   - 正常关闭程序以确保路由清理
   - 定期检查是否有残留的 iptables 规则

## 示例配置

### 企业内网访问

```json
{
  "route_mode": "split",
  "push_routes": [
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8"
  ],
  "redirect_dns": true,
  "dns_servers": ["10.0.0.1"]
}
```

### 完全代理

```json
{
  "route_mode": "full",
  "exclude_routes": [],
  "redirect_gateway": true,
  "redirect_dns": true,
  "dns_servers": ["8.8.8.8", "1.1.1.1"]
}
```

### 智能分流

```json
{
  "route_mode": "full",
  "exclude_routes": [
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8"
  ],
  "redirect_gateway": true,
  "redirect_dns": true
}
```

## 安全建议

1. **DNS 泄漏防护**
   - 启用 `redirect_dns` 防止 DNS 泄漏
   - 使用可信的 DNS 服务器

2. **路由泄漏防护**
   - 全流量模式下检查是否有意外的直连路由
   - 使用 `ip route show` 定期检查

3. **防火墙配置**
   - 配置防火墙只允许到 VPN 服务器的连接
   - 阻止其他直连流量

4. **Kill Switch**
   - 考虑实现 Kill Switch 功能
   - VPN 断开时自动阻止所有流量

## 参考

- [Linux 路由表管理](https://man7.org/linux/man-pages/man8/ip-route.8.html)
- [iptables NAT 配置](https://www.netfilter.org/documentation/HOWTO/NAT-HOWTO.html)
- [DNS 配置](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)
