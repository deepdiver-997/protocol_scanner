# TODO — 实验室实训任务盘点

## 总进度

| 任务 | 状态 | 优先级 |
|------|------|:------:|
| 任务1: 多协议大规模网络测绘基础平台 | ✅ 基本完成 | — |
| 任务2: SSH/FTP/Telnet 大规模测绘 | ✅ 探测代码完成 | — |
| 任务3: 协议软件指纹提取与指纹库 | ⏳ SSH 版本提取完成，vendors.json 待扩充 | 🟡 P1 |
| 任务4: 协议探测可行性调研 | ⏳ 文档待完成 | 🟡 P1 |
| 任务5: 安全策略探测分析 | ⏳ 文档待完成 | 🟡 P1 |

---

## 已完成工作清单

### 代码

- [x] **FTP FEAT 命令交互** — async_probe 追加 FEAT 读取链，解析 9 个扩展特性
- [x] **SSH 版本号结构化提取** — parse_capabilities 解析 SSH-2.0-OpenSSH_8.9p1
- [x] **Redis 新协议** — PING → +PONG → INFO server → version
- [x] **banner_truncated 截断检测** — 所有协议标记截断
- [x] **scan_loop 并发修复** — generation 计数器 + callback 直接入全局队列

### 文档

- [x] 项目结构整理（根目录 .md 移到 docs/）
- [x] 与 SMTP Banner 项目对比分析
- [x] 架构决策记录（BufferPool、session 复用、generation 计数器等 5 条 ADR）

---

## 🟡 P1 — 任务4: 协议探测可行性调研

**老师的要求**: 不是全部实现，而是**调研分析**每个协议：
- 有哪些常见软件实现？
- Banner 暴露了什么信息（版本号、软件名、能力列表）？
- 值不值得做指纹探测？

### 待分析协议

| 协议 | 端口 | 文档章节 |
|------|:----:|---------|
| POP3 | 110/995 | docs/protocol_feasibility_analysis.md |
| IMAP | 143/993 | (同上) |
| Radmin | 4899 | (同上) |
| LDAP | 389/636 | (同上) |
| SIP | 5060 | (同上) |
| CVS | 2401 | (同上) |
| RTSP | 554 | (同上) |
| MySQL | 3306 | (同上) |
| PostgreSQL | 5432 | (同上) |
| MS-SQL | 1433 | (同上) |
| Oracle | 1521 | (同上) |
| MongoDB | 27017 | (同上) |
| Redis | 6379 | ✅ 已实现 |
| Firebird | 3050 | (同上) |
| CouchDB | 5984 | (同上) |

---

## 🟡 P1 — 任务5: 安全策略探测分析

**老师的要求**: 以 OpenSSH 为例——假设服务端配置了"1分钟内同一 IP 登录 n 次则封禁"，我们的扫描器在发现 22 端口运行 OpenSSH 后，**怎么探测到这个安全策略？**

### 分析框架

| 软件 | 源码 | 分析要点 |
|------|------|---------|
| **OpenSSH** | openssh-portable | `auth2.c`, `auth-passwd.c`: MaxAuthTries, MaxStartups, LoginGraceTime, 封禁信号 |
| **vsftpd** | vsftpd | `login.c`, `secutil.c`: max_clients, max_per_ip, pam 集成 |
| **telnetd** | inetutils | `telnetd.c`: login 调用链, utmpx 记录 |

### 输出文档

`docs/auth_mechanism_analysis.md`，内容包括：
1. 每个软件的认证流程（从 connect 到 accept/reject）
2. 可探测的安全策略参数及其在代码中的位置
3. 探测方法建议（比如：故意发错误密码，观察响应延迟/断开模式）

---

## 🟢 P2 — 待办

- [ ] 扩充 vendors.json（SSH/FTP/Telnet 各到 15+ 条规则）
- [ ] 新增 Radmin/CVS/Firebird 等简单 banner 协议

---

## 进度记录

| 日期 | 完成内容 |
|------|---------|
| 2025-06 | 代码：FTP FEAT、SSH 版本提取、Redis 协议、scan_loop 并发修复 |
| 2025-06 | 文档：项目结构整理、ADRs、与 SMTP 项目对比 |
| 2025-06 | 新学期任务明确：任务4 为可行性调研文档，任务5 为安全策略分析 |
