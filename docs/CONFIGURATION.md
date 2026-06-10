# 配置说明

## 快速启动

```bash
# 编译部署
sudo bash deploy/setup_scanner.sh

# 启动扫描（以 SSH 为例）
systemctl start scanner@SSH

# 查看状态
systemctl status scanner@SSH
journalctl -u scanner@SSH -f
curl http://localhost:9080/metrics
```

---

## 配置文件

`config/scanner_config_prod.json`，部署时复制到 `/opt/scanner/config/scanner_config.json`。

### scanner 主配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `io_thread_count` | int | 6 | IO 线程数，每个线程一个 io_context |
| `probe_timeout_ms` | int | 3000 | 单次探测超时(ms) |
| `dns_timeout_ms` | int | 2000 | DNS 超时(ms) |
| `max_work_count` | int | 0 | 最大并发 session 数，0=自动计算 |
| `only_success` | bool | true | 仅输出成功结果 |
| `batch_size` | int | 80000 | 暂未使用 |
| `result_batch_size` | int | 2000 | 每次写入磁盘的最大结果数 |
| `targets_max_size` | int | 0 | 目标队列上限，0=自动(3×max_work_count) |
| `result_queue_max_size` | int | 0 | 结果队列上限，0=自动(max_work_count/2) |
| `metrics_port` | int | 9080 | Metrics HTTP 端口 |
| `bind_ips` | string[] | [] | 多 IP 绑定，空=默认路由 IP |
| `enable_zmap_filter` | bool | false | 启用 ZMap 预过滤 |
| `zmap_port` | int | 0 | ZMap 扫描端口，0=不使用 |

### protocols 配置

```json
"protocols": {
  "SMTP":  { "enabled": false },
  "POP3":  { "enabled": false },
  "IMAP":  { "enabled": false },
  "HTTP":  { "enabled": false },
  "FTP":   { "enabled": false },
  "TELNET":{ "enabled": false },
  "SSH":   { "enabled": true },
  "REDIS": { "enabled": false },
  "RTSP":  { "enabled": false },
  "SIP":   { "enabled": false },
  "MYSQL": { "enabled": false }
}
```

### vendor 配置

```json
"vendor": {
  "enabled": false,
  "pattern_file": "./config/vendors.json",
  "similarity_threshold": 0.7
}
```

### dns 配置

```json
"dns": {
  "resolver_type": "null",
  "timeout_ms": 5000,
  "max_mx_records": 16
}
```

纯 IP 扫描建议用 `"null"`，跳过 DNS。

### output 配置

```json
"output": {
  "format": ["json"],
  "write_mode": "stream",
  "directory": "./output",
  "enable_json": true,
  "enable_csv": false,
  "enable_report": false,
  "to_console": false
}
```

---

## ResourceGuard 资源守护

启动时自动检测系统限制，防止 scanner 打满端口或 conntrack 表导致 SSH 断连。

### 检测项目

| 资源 | 数据源 | 安全上限计算 |
|------|--------|------------|
| 临时端口 | `/proc/sys/net/ipv4/ip_local_port_range` | `ports × 0.75 × bind_ips数量` |
| 可用内存 | `sysinfo()` | `内存MB / 0.08` |
| Conntrack | `/proc/sys/net/netfilter/nf_conntrack_max` | `(conntrack_max - 1000) / 4` |

### 行为

- `max_work_count=0`：取三者最小值自动设置
- `max_work_count>0`：显式值，超限自动 cap（打印 WARNING），不拒绝启动
- 三项全部无法检测（非 Linux）：**拒绝启动**，必须显式设 `max_work_count`

### 扩大 conntrack

```bash
echo 'net.netfilter.nf_conntrack_max = 524288' >> /etc/sysctl.d/99-scanner.conf
sysctl -p /etc/sysctl.d/99-scanner.conf
```

---

## 多 IP 绑定

每个 IP 有独立的临时端口池，两 IP 翻倍并发上限。Scanner 内 Round-Robin 分配。

```json
"bind_ips": ["192.3.199.159", "192.3.199.163"]
```

---

## ZMap 预过滤

先用 ZMap 快速扫端口，只对开放的 IP 做精细指纹识别。

### 前提

```bash
sudo apt install zmap
```

### 配置

```json
"enable_zmap_filter": true,
"zmap_port": 22
```

### 行为

1. 检查 `<output_dir>/zmap_port<port>.txt` 是否存在
2. 不存在 → `system("zmap -p <port> -r 100000 ...")` → 写入 `.tmp` → 成功后 rename
3. 存在 → 直接用作输入

### 速率参考（1.6B IP，单端口）

| pps | 耗时 |
|-----|------|
| 100K (默认) | ~4.4h |
| 500K | ~53min |
| 1M | ~27min |

---

## Metrics 监控

```bash
curl http://localhost:9080/metrics
```

```json
{
  "queues":    {"targets": 60000, "results": 0,  "pending": 0},
  "io_pool":   [3333, 3333, 3333, 3333, 3334, 3333],
  "sessions":  {"active": 20000, "total": 20000},
  "progress":  {"processed": 12703817, "successful": 223528},
  "rate":      {"targets_per_sec": 6479},
  "uptime_sec": 422,
  "protocols": {"SSH": 246541}
}
```

- `queues.pending`：已产出但等待 seq 排序提交的结果数（高值可能表示 stall）
- `io_pool`：每个 IO 线程当前负载（约等于 max_work_count / io_thread_count）
- `rate`：每秒处理的目标数

---

## 死绳开关 (Dead-man Switch)

防止 scanner 耗尽 conntrack/端口后 SSH 断连无法恢复。由外部心跳 + 本地 watchdog 组成。

### 架构

```
阿里云 ──(SSH 心跳, 每30s touch 文件)──→ 美国服务器
                                            │
                                     watchdog 每 60s 检查
                                     /tmp/aliyun_heartbeat
                                     超过 120s 未更新
                                            │
                                     systemctl stop scanner@*
```

### 阿里云端

```bash
cp deploy/ssh-heartbeat@.* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ssh-heartbeat@192.3.199.163.timer
```

### 美国服务器端（部署脚本自动安装）

```bash
# 手动安装
cp deploy/scanner-watchdog.* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now scanner-watchdog.timer
```

### 测试

```bash
# 1. 阿里云停心跳
systemctl stop ssh-heartbeat@192.3.199.163.timer

# 2. 2 分钟后美国服务器确认 scanner 被杀
journalctl -u scanner-watchdog.service -f
# 预期: FATAL: Heartbeat stale (XXXs > 120s), stopping all scanners

# 3. 恢复心跳
systemctl start ssh-heartbeat@192.3.199.163.timer
```

---

## 可注入线程入口（分布式预留）

Scanner 的输入/结果线程通过 `std::function<void()>` 回调启动，默认绑定本地文件 I/O，可通过 `set_input_producer` / `set_result_consumer` 替换为网络分发实现，无需重新编译 `scanner_core`。

```cpp
// 本地模式（默认）
//   input 线程 → 读文件 → targets_ 队列 → scan_loop → result 线程 → 写文件

// 分布式模式（伪代码）
scanner.set_input_producer([&]() {
    while (!done) {
        auto task = http_get("http://master:8080/next_task");
        scanner.push_targets_to_queue(task);
    }
});
scanner.set_result_consumer([&]() {
    while (!done) {
        ScanReport r;
        if (result_queue_.try_pop(r)) http_post("http://master:8080/result", r);
    }
});
scanner.start("");  // 空路径，生产者自行决定数据源
```

**为何不搞文件系统抽象层**：

| 场景 | 特点 | 抽象需求 |
|------|------|---------|
| Scanner | 任务式（start→扫完→退出），输入输出流式一次性，丢数据可重扫 | `std::function` 回调足够 |
| SMTP/Mail 服务 | 持续运行，每封邮件必须**逐条确认落盘**才能回 250 OK | 文件系统/DB 抽象驱动 |

Scanner 没有"确认后不可丢"的持久化语义——checkpoint 只加速恢复，结果丢几行无非重扫。

---

## 生产部署完整流程

```bash
# 美国服务器
cd ~/protocol_scanner && git pull
rm -rf build
sudo bash deploy/setup_scanner.sh

# 手动调配置（如需要）
vim /opt/scanner/config/scanner_config.json

# 启动
systemctl start scanner@SSH
```
