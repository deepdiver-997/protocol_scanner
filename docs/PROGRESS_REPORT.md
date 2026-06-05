# Protocol Scanner — 开发进展汇报

> 指导教师报告用 · 2025年6月

---

## 已完成工作

### 1. 多协议 Banner 扫描平台

| 协议 | 端口 | 探测交互 | 信息量 |
|------|:----:|---------|:-----:|
| SMTP | 25/465/587 | EHLO + 解析 20+ 特性 | ⭐⭐⭐ |
| POP3 | 110/995 | CAPA + STLS | ⭐⭐⭐ |
| IMAP | 143/993 | CAPABILITY + STARTTLS | ⭐⭐⭐ |
| HTTP | 80/443/8080 | HEAD + Server 响应头 | ⭐⭐⭐ |
| FTP | 21/990 | 220 + FEAT 扩展特性 | ⭐⭐⭐ |
| SSH | 22 | 版本行提取 (software + version) | ⭐⭐⭐ |
| Telnet | 23 | Banner + IAC 协商过滤 | ⭐⭐⭐ |
| Redis | 6379/6380 | PING + INFO server | ⭐⭐⭐ |
| RTSP | 554 | OPTIONS + Server 头 | ⭐⭐⭐ |
| SIP | 5060/5061 | OPTIONS + Server/User-Agent 头 | ⭐⭐⭐ |
| MySQL | 3306 | 二进制握手包版本提取 | ⭐⭐⭐ |

### 2. 异步架构

- 单 `IoThreadPool`，负载均衡 `TrackingExecutor`
- `ScanSession` 固定池复用，generation 计数器防并发竞争
- 断点恢复、滚动进度文件、c-ares DNS（可选）
- 分布式扩展架构（`Orchestrator` + `KafkaTransport`）

### 3. Banner 指纹聚类管道 (Python)

基于学长的论文方法实现：

| 步骤 | 算法 | 论文位置 |
|------|------|---------|
| 标准化 | 域名/时间/随机ID 替换 | Algorithm 3-1 |
| 聚类 | 贪心阈值聚类 + K-Medoids | Algorithm 3-2 + 3.2.3 |
| 标注 | LLM 自动标注 + 人工抽检 | 3.1.3 节 |
| C++ 交付 | `--format fingerprint` 每 probe 一行 JSONL | — |

实测 5000 条 SSH banner → 102 个模板，OpenSSH 各版本和 Dropbear 完全分离。

### 4. 深度探测框架

基于 OpenSSH/vsftpd/telnetd 源码分析的安全策略探测：

| 探针 | 探测方法 | 实测结果 |
|------|---------|---------|
| OpenSSH MaxAuthTries | 连续错误密码 → 断开时机 | `max_auth_tries=6` |
| OpenSSH LoginGraceTime | 连接后等待 → 超时断开 | `login_grace_time=120s` |
| vsftpd max_clients | 并发连接 → 拒绝比例 | — |

### 5. 测试体系

| 层面 | 框架 | 覆盖 |
|------|------|------|
| Parser 单元测试 | Catch2 | 98 assertions, 7 test cases |
| 编排集成测试 | 手动 probe_test | 直调 probe / Session 生命周期 / Scanner 全流程 |
| 深度探测测试 | deep_probe CLI | 3 种策略验证 |

---

## 当前状态

- 11 个协议 Banner 探测完成，4 个数据库协议调研完成
- 指纹管道已从真实数据生成 102 个模板（`fingerprint_v2/scripts/fingerprint.db`）
- 数据库可交接任务二同学做 MCP Banner 查询

---

## 后续计划

- MCP 服务封装（任务二）：基于 fingerprint.db 实现 Banner 查询接口
- vendors.json 扩充到 100+ 规则
- 安全策略探测对 vsftpd/telnetd 的实际验证
