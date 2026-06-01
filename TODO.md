# TODO — 实验室实训任务盘点

## 总进度

| 任务 | 状态 | 优先级 |
|------|------|:------:|
| 任务1: 多协议大规模网络测绘基础平台 | ✅ 基本完成 | — |
| 任务2: SSH/FTP/Telnet 大规模测绘 | ⏳ 需要增强协议交互深度 | 🔴 P0 |
| 任务3: 协议软件指纹提取与指纹库 | ⏳ 需要扩充 + 版本号提取 | 🔴 P0 |
| 任务4: 探索更多协议 | 🔴 11个协议待新增 | 🔴 P0 |
| 任务5: 源码分析（认证机制、防暴力攻击） | ❌ 待完成 | 🟡 P1 |

---

## 🔴 P0 — 任务2: SSH/FTP/Telnet 探测增强

当前问题：SSH/FTP/Telnet 的 `async_probe` 只做了"连上读 banner"就结束，没有进一步交互提取特性。

### 需要改的文件

| 协议 | 文件 | 改进内容 | 参考模式 |
|------|------|---------|---------|
| **FTP** | `src/scanner/protocols/ftp_protocol.cpp` | 收 220 → **发 FEAT → 解析扩展特性** | 照抄 SMTP 的 EHLO 链 |
| **SSH** | `src/scanner/protocols/ssh_protocol.cpp` | 版本行提取软件名+版本号到结构化字段 | 实现 `parse_capabilities` |
| **Telnet** | `src/scanner/protocols/telnet_protocol.cpp` | 过滤 IAC 选项字节，提取纯文本 banner | 已有代码的增强 |

### 补充数据结构

`include/scanner/protocols/protocol_base.h` 中 `ProtocolAttributes` 需要加：

```cpp
// SSH 属性
struct {
    std::string version_string;  // "SSH-2.0-OpenSSH_8.9p1"
    std::string software;        // "OpenSSH"
    std::string version;         // "8.9p1"
    std::string protocol_version; // "2.0"
} ssh;

// FTP 属性
struct {
    // FEAT 解析结果
    bool auth_tls = false;
    bool auth_ssl = false;
    bool utf8 = false;
    bool size_cmd = false;
    bool mdtm = false;
    std::string features;        // 原始 FEAT 响应
} ftp;

// Telnet 属性
struct {
    std::string login_prompt;    // "login:" 等
    std::string negotiated_opts; // 协商的终端选项
} telnet;
```

---

## 🔴 P0 — 任务3: 指纹库扩充

### 3.1 扩充 vendors.json（SSH/FTP/Telnet 到各 15+ 条）

当前分布：

| 协议 | 当前条数 | 目标 |
|:----:|:-------:|:----:|
| SSH | 3 (OpenSSH/Dropbear/libssh) | 15+ |
| FTP | 5 | 15+ |
| Telnet | 2 | 10+ |

需增加的指纹（示例）：

- **SSH**: TinySSH, OpenSSH_for_Windows, CiscoSSH, PuTTY, SSH Tectia, ApacheMINA, JSch, paramiko, libssh2, Golang crypto/ssh, Erlang ssh
- **FTP**: Microsoft FTP, glFTPd, wu-ftpd, RaidenFTPD, BulletProof, WarFTPD, Gene6, Titan, CrushFTP, Cerberus, zFTPServer, Xlight
- **Telnet**: Linux telnetd, Solaris telnetd, FreeBSD telnetd, Huawei, ZTE, Juniper, HP, IBM, 3COM, D-Link, Zyxel

### 3.2 Python 指纹 pipeline 完善

| 改进项 | 文件 | 说明 |
|-------|------|------|
| SSH 版本号聚合 | `fingerprint/build_fingerprint_stage3.py` | 按 software + version 聚类 |
| 指纹库输出格式 | — | 生成可直接被 C++ vendor_detector 加载的 JSON |

### 3.3 版本号提取

修改 SSH/FTP/Telnet 的 `parse_capabilities`，把版本号填入 `ProtocolAttributes` 的新字段。

---

## 🔴 P0 — 任务4: 新增 11 个协议

### 第一批：banner-only / 简单交互（6个，每协议 ≤ 1 天）

| 协议 | 端口 | 文件前缀 | 探测方式 |
|------|:----:|---------|---------|
| **Redis** | 6379 | `redis_protocol` | 连 → 发 `PING\r\n` → 收 `+PONG\r\n` |
| **SIP** | 5060 | `sip_protocol` | 连 → 发 `OPTIONS sip:localhost SIP/2.0\r\n...` → 收响应 |
| **RTSP** | 554 | `rtsp_protocol` | 连 → 发 `OPTIONS rtsp://localhost RTSP/1.0\r\n...` → 收响应 |
| **Radmin** | 4899 | `radmin_protocol` | 连 → 读 banner |
| **CVS** | 2401 | `cvs_protocol` | 连 → 读 banner |
| **Firebird** | 3050 | `firebird_protocol` | 连 → 读 banner |

### 第二批：HTTP 派生 + 中等难度（2个）

| 协议 | 端口 | 说明 |
|------|:----:|------|
| **LDAP** | 389/636 | 连 → 读 banner |
| **CouchDB** | 5984 | HTTP GET `/`, 复用 http_protocol 逻辑 |

### 第三批：数据库二进制协议（3个，每协议 2-3 天）

| 协议 | 端口 | 说明 |
|------|:----:|------|
| **MySQL** | 3306 | 解析二进制握手包，提取版本字符串 |
| **PostgreSQL** | 5432 | 解析二进制启动包 |
| **MongoDB** | 27017 | 发 ismaster 命令（BSON 解析） |

> **建议策略：先做完第一批再去写文档和源码分析，数据库协议最后做。**

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

1. 各协议认证流程（流程图 → 文字）
2. 口令校验的代码路径
3. 防暴力攻击机制（`MaxAuthTries`, `MaxStartups`, `AllowUsers`, fail2ban 配合、`pam_tally2` 等）
4. 安全建议小结

---

## 🟢 P2 — 工程清理与文档更新

- [x] 移动根目录 .md 到 docs/（除 README.md）
- [x] 补充本项目与 SMTP Banner 的对比文档
- [ ] ARCHITECTURE.md 补充 scanner_core 静态库和分布式组件
- [ ] README.md 更新协议列表和功能描述
- [ ] 整理 fingerprint 目录的 README

---

## 进度记录

| 日期 | 完成内容 |
|------|---------|
| — | 初始状态 |
