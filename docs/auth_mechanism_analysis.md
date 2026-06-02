# 安全策略探测分析报告

> 目标：分析 OpenSSH/vsftpd/telnetd 的源码认证流程和安全策略，
> 研究如何从扫描器角度探测这些策略配置。
> 对应任务：实验室实训任务5

---

## 核心思路

老师要求的不是"读源码写总结"，而是：
1. 假设一台服务器运行了 OpenSSH，配置了"1分钟内同一 IP 尝试 n 次封禁"
2. 我们的扫描器**怎么通过外部探测发现这个策略的存在？**
3. 从源码中找到这个策略对应的代码逻辑和可观测的信号

方法：故意发送错误认证请求，观察服务器行为的变化。

---

## 1. OpenSSH

### 源码结构

```
openssh-portable/
├── auth2.c              # 协议层认证分发 (SSH2)
├── auth-passwd.c        # 密码认证实现
├── auth-pam.c           # PAM 集成
├── sshd_config          # 服务端配置
├── sshd.c               # 主循环 (连接处理)
├── servconf.c           # 配置解析
```

### 认证流程

```
客户端连接 (port 22)
  → 服务端发版本行 "SSH-2.0-OpenSSH_8.9p1"
  → 密钥交换 (KEX) ← 此处可观测加密算法套件
  → 用户认证 (UserAuth)
    ├── 方法1: publickey (客户端发公钥)
    ├── 方法2: password   (客户端发用户名+密码)
    └── 方法3: keyboard-interactive (挑战-响应)
```

### 安全策略配置项

| 配置项 | 默认值 | 位置 | 作用 |
|--------|--------|------|------|
| `MaxAuthTries` | 6 | `sshd_config` | 单连接最大认证尝试次数 |
| `MaxStartups` | 10:30:100 | `sshd_config` | 最大并发未认证连接数 |
| `LoginGraceTime` | 120s | `sshd_config` | 认证超时时间 |
| `MaxSessions` | 10 | `sshd_config` | 单连接最大 session 数 |
| `PermitRootLogin` | prohibit-password | `sshd_config` | root 登录限制 |

### 关键代码分析: MaxAuthTries

**文件**: `auth2.c`

```c
// auth2.c 中的认证状态机
struct Authctxt {
    int success;              // 是否认证成功
    int attempt;              // 当前连接已尝试次数
    int max_tries;            // MaxAuthTries
    int expired;              // 是否超时
    // ...
};

// 每次认证尝试后
void userauth_finish(Authctxt *authctxt, int authenticated, const char *method) {
    authctxt->attempt++;
    
    if (authenticated) {
        // 认证成功 → 放行
        return;
    }
    
    // 检查是否超过 MaxAuthTries
    if (authctxt->attempt >= authctxt->max_tries) {
        // 超过最大尝试次数 → 断开连接
        packet_disconnect("Too many authentication failures");
    }
}
```

**可观测信号**: 
- 正常失败: 服务器回复 `SSH_MSG_USERAUTH_FAILURE`
- `MaxAuthTries` 触发后: 服务器断开 TCP 连接（无任何 SSH 消息）
- **探测方法**: 同个连接内连续发错误密码，第 N+1 次后连接被立即断开

### 关键代码分析: MaxStartups

**文件**: `sshd.c`

```c
// sshd.c 主循环中的连接限流
// MaxStartups = "start:rate:full"
// 当并发未认证连接数达到 start 后，
// 每 rate 个连接中拒绝 1 个
// 达到 full 后，全部拒绝

int max_startups_begin = 10;   // 开始限流的连接数
int max_startups_rate = 30;    // 拒绝比例分母
int max_startups_full = 100;   // 完全拒绝的连接数

// 决定是否接受新连接
if (nc > max_startups_full) {
    refuse_connection(p);       // 拒绝
} else if (nc > max_startups_begin) {
    // 按概率拒绝
    if (arc4random_uniform(max_startups_rate) == 0) {
        refuse_connection(p);   // 按比例拒绝
    }
}
```

**可观测信号**:
- 正常: TCP 连接成功，收到 SSH 版本行
- 限流触发后: TCP 连接被**直接拒绝**（无版本行，甚至无 TCP SYN-ACK）
- **探测方法**: 同时开大量连接（>MaxStartups），观察部分连接被直接拒绝

### 关键代码分析: LoginGraceTime

**文件**: `sshd.c`

```c
// sshd.c 中为每个连接设置认证超时
alarm(options.login_grace_time);  // 默认 120 秒
// 如果在超时内未完成认证:
signal_alarm(...) → 断开连接
```

**可观测信号**:
- 正常: 连接保持
- 超时后: TCP 连接被服务端主动关闭
- **探测方法**: 连接后不发任何认证请求，等待连接断开

### 探测方案总结

| 策略 | 探测方法 | 预期结果 | 可探测的配置 |
|------|---------|---------|-------------|
| MaxAuthTries | 同一连接内重复发错误密码 | 第 N+1 次断开连接 | 精确探测 MaxAuthTries 值 |
| MaxStartups | 同时建立大量连接 | 部分连接被直接拒绝 | 估算并发阈值 |
| LoginGraceTime | 连接后等待 | 超过 T 秒后断开 | 估算超时时间 |

---

## 2. vsftpd

### 源码结构

```
vsftpd/
├── login.c          # 认证逻辑
├── secutil.c        # 安全限制
├── ftpcmd.y         # FTP 命令解析
├── tunables.h       # 所有配置项定义
├── main.c           # 主循环
```

### 认证流程

```
客户端连接 (port 21)
  → 服务端发 "220 (vsFTPd 3.0.3)"
  → 客户端发 "USER anonymous"
  → 服务端发 "331 Please specify the password."
  → 客户端发 "PASS password"
  → 服务端发 "230 Login successful." 或 "530 Login incorrect."
```

### 安全策略配置项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `max_clients` | 0 (不限) | 最大并发客户端数 |
| `max_per_ip` | 0 (不限) | 同 IP 最大连接数 |
| `anon_max_rate` | 0 (不限) | 匿名用户最大传输速率 |
| `local_max_rate` | 0 (不限) | 本地用户最大传输速率 |
| `pam_service_name` | ftp | PAM 认证服务名 |

### 关键代码分析: 认证失败处理

**文件**: `login.c`

```c
// login.c 中处理密码验证
enum e_login_result login_or_bypass() {
    // 调用 PAM 验证
    if (pam_password_check() == kPamFail) {
        // 密码错误
        return kLoginFail;
    }
    // ...
}
```

**可观测信号**:
- 密码错误: 服务器返回 `530 Login incorrect`
- **无 MaxAuthTries 等效机制** — vsftpd 本身不限制尝试次数
- 限制通常由 PAM (`pam_tally2`) 或 fail2ban 实现
- 探测时需区分是 vsftpd 本身拒绝还是外部机制拒绝

### 关键代码分析: max_clients / max_per_ip

**文件**: `main.c`, `secutil.c`

```c
// main.c 中检查连接数
if (tunables_max_clients > 0 && current_clients >= tunables_max_clients) {
    // 超过最大客户端数，拒绝
}

// secutil.c 中检查同 IP 连接数
if (tunables_max_per_ip > 0) {
    // 统计同 IP 连接数
    if (count >= tunables_max_per_ip) {
        // 拒绝           
    }
}
```

**可观测信号**:
- 正常: 220 欢迎语
- 超限后: TCP 连接被拒绝（无 220 响应或直接 RST）

---

## 3. telnetd

### 源码结构

```
inetutils/telnetd/
├── telnetd.c          # 主程序
├── utility.c          # 工具函数
├── state.c            # Telnet 状态机
└── sys_term.c         # 终端/登录处理
```

### 认证流程

```
客户端连接 (port 23)
  → Telnet 选项协商 (IAC WILL/WONT/DO/DONT)
  → 服务端发 "login:"
  → 客户端输用户名
  → 服务端发 "Password:"
  → 客户端输密码
  → 登录成功 → shell 或登录失败 → "Login incorrect"
```

### 安全机制

Telnetd 本身几乎**没有内置的防暴力攻击机制**。安全性依靠：
1. `login` 程序（`/bin/login`）内置的延迟和日志
2. PAM (`pam_tally2` / `pam_unix`)
3. `hosts.allow` / `hosts.deny` (tcp_wrappers)
4. 防火墙 / fail2ban

### 关键代码分析: login 调用

**文件**: `telnetd.c` → `sys_term.c`

```c
// sys_term.c 中启动 login 进程
// telnetd 本身不验证密码，而是启动 /bin/login
// login 程序通过 PAM 或 /etc/passwd 验证

pid = fork();
if (pid == 0) {
    // 子进程: 启动 login
    execl("/bin/login", "login", "-p", "-h", hostname, NULL);
}
```

**可观测信号**:
- Telnet 无法在协议层区分"密码错误"和"用户不存在"——这由 login 程序决定
- 部分系统对失败登录有延迟（故意 sleep 1-3 秒）
- **探测方法**: 测量"输入密码→收到失败响应"的时间，推断是否存在延迟策略

---

## 综合探测方法论

### 通用探测框架

```
Step 1: 发现服务
  → 扫描器确认 22/21/23 端口开放
  → 读取 banner → 确认软件名+版本

Step 2: 安全策略预判
  → 根据软件名+版本，查表获取已知默认配置
  → OpenSSH 8.9 默认 MaxAuthTries=6, MaxStartups=10:30:100

Step 3: 策略探测
  ├── 主动探测:
  │   ├── 发送错误认证请求 → 观察断开时机 → 推算 MaxAuthTries
  │   ├── 建立大量并发连接 → 观察拒绝比例 → 推算 MaxStartups
  │   └── 连接后等待 → 观察超时断开 → 推算 LoginGraceTime
  └── 被动探测:
      ├── 响应延迟分析（失败响应比成功响应慢？）
      └── 错误消息文本差异（不同软件的错误消息不同）

Step 4: 指纹入库
  → 记录 IP + 安全策略参数 → 用于后续扫描策略调整
  → 例如：已知某 IP 的 OpenSSH MaxStartups=10，扫描器应控制并发连接数
```

### 局限与风险

1. **误判风险**: 安全策略可能由外部机制（fail2ban、防火墙、WAF）实现，不是目标软件自身
2. **触发封禁**: 主动探测本身可能触发安全策略，导致扫描器 IP 被封
3. **速率限制**: 应该使用慢速扫描，避免被识别为攻击

---

## 参考资源

- OpenSSH 源码: https://github.com/openssh/openssh-portable
- vsftpd 源码: https://github.com/yoones/vsftpd
- inetutils (telnetd): https://github.com/guillemj/inetutils
- fail2ban: https://github.com/fail2ban/fail2ban
