# TODO — 实验室实训任务盘点

## 总进度

| 任务 | 状态 | 优先级 |
|------|------|:------:|
| 任务1: 多协议大规模网络测绘基础平台 | ✅ 基本完成 | — |
| 任务2: SSH/FTP/Telnet 大规模测绘 | ⏳ 部分完成，Telnet 待增强 | 🟡 P1 |
| 任务3: 协议软件指纹提取与指纹库 | ⏳ SSH 版本提取完成，vendors.json 待扩充 | 🟡 P1 |
| 任务4: 探索更多协议 | ⏳ Redis 已完成，10个协议待新增 | 🔴 P0 |
| 任务5: 源码分析（认证机制、防暴力攻击） | ❌ 待完成 | 🟡 P1 |

---

## ✅ 已完成工作清单

### 2025-06 迭代

- [x] **FTP FEAT 命令交互** — `async_probe` 追加 FEAT 读取链，解析 UTF8/AUTH TLS/SIZE/MDTM 等 9 个扩展特性
- [x] **SSH 版本号结构化提取** — `parse_capabilities` 解析 `SSH-2.0-OpenSSH_8.9p1`，提取 software、version、protocol_version 字段
- [x] **Redis 新协议** — PING → +PONG 验证 + INFO server 提取 redis_version
- [x] **banner_truncated 截断检测** — 所有单次读取的协议（SSH/Telnet/POP3/HTTP/FTP）增加截断标记
- [x] **CMake Boost 检测修复** — CMake 4.0 改用 CONFIG 模式 + `/opt/homebrew/Cellar/boost` 路径兜底
- [x] **项目结构整理** — 根目录 .md 移到 docs/，.gitignore 改为本地 `.git/info/exclude`
- [x] **scan_loop 并发修复** — generation 计数器防旧 callback 污染 reset 后的 session 计数
- [x] **scan_loop 简化** — probe callback 直接入全局 `result_queue_`，去掉 session 结果转发层
- [x] **架构决策** — session 复用 vs. 每 probe 独立方案论证，确认保持复用

---

## 🟡 P1 — 任务2: SSH/FTP/Telnet 探测增强

### 已完成

| 协议 | 改进 | 状态 |
|------|------|:----:|
| **FTP** | 220 banner → FEAT → 解析 AUTH TLS/UTF8/SIZE 等 | ✅ |
| **SSH** | 版本行提取 software + version + protocol_version | ✅ |

### 待完成

| 协议 | 改进 | 优先级 |
|------|------|:----:|
| **Telnet** | 过滤 IAC 选项协商字节，提取纯文本 login prompt | 🟡 可选 |

---

## 🟡 P1 — 任务3: 指纹库扩充

### 已完成

- [x] SSH 版本号提取（`attrs.ssh.software`, `attrs.ssh.version`）
- [x] SSH 测试通过（`OpenSSH 8.9p1`，19ms）

### 待完成

| 改进项 | 说明 | 优先级 |
|-------|------|:----:|
| 扩充 vendors.json | SSH/FTP/Telnet 各到 15+ 条规则 | 🟡 |
| Python fingerprint pipeline | 利用实际扫描数据自动生成指纹规则 | 🟢 |

---

## 🔴 P0 — 任务4: 探索更多协议

### 已完成

| 协议 | 端口 | 探测方式 | 状态 |
|------|:----:|---------|:----:|
| **Redis** | 6379/6380 | PING → +PONG → INFO server → version | ✅ |

### 待新增

**第一批：banner-only / 简单交互（6个）**

| 协议 | 端口 | 探测方式 | 优先级 |
|------|:----:|---------|:----:|
| **SIP** | 5060 | 连 → 发 `OPTIONS` → 收响应 | 🔴 |
| **RTSP** | 554 | 连 → 发 `OPTIONS` → 收响应 | 🔴 |
| **Radmin** | 4899 | 连 → 读 banner | 🔴 |
| **CVS** | 2401 | 连 → 读 banner | 🔴 |
| **Firebird** | 3050 | 连 → 读 banner | 🔴 |
| **LDAP** | 389/636 | 连 → 读 banner | 🔴 |

**第二批：数据库二进制协议（3个，每协议 2-3 天）**

| 协议 | 端口 | 说明 |
|------|:----:|------|
| **MySQL** | 3306 | 解析二进制握手包，提取版本字符串 |
| **PostgreSQL** | 5432 | 解析二进制启动包 |
| **MongoDB** | 27017 | 发 ismaster 命令 |

---

## 🟡 P1 — 任务5: 源码分析与文档

### 需要分析的软件

| 软件 | 源码地址 | 分析要点 |
|------|---------|---------|
| **OpenSSH** | https://github.com/openssh/openssh-portable | `auth-passwd.c`, `auth2.c` (认证流程、MaxAuthTries) |
| **vsftpd** | https://github.com/yoones/vsftpd | `login.c`, `secutil.c` (认证机制、chroot) |
| **telnetd** | 各发行版 inetutils 包 | `telnetd.c` (login 调用链) |

### 输出文档

`docs/auth_mechanism_analysis.md`，包含：

1. 各协议认证流程
2. 口令校验的代码路径
3. 防暴力攻击机制

---

## 架构决策记录

参见 `docs/ARCHITECTURE.md` 的"架构决策记录"章节，包含：

- 全局 BufferPool vs. 每 Session 独立缓冲区的论证
- session 复用 vs. 每 probe 独立 session 的讨论
- 水平扩展设计（分布式模式）

---

## 进度记录

| 日期 | 完成内容 |
|------|---------|
| 2025-05 | 初始版本：FTP FEAT、SSH 版本提取、Redis 协议 |
| 2025-06 | scan_loop 并发修复、generation 计数器、项目结构整理、架构决策文档 |
