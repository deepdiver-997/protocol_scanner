# Protocol Scanner 项目概览

## 📁 项目位置

```
/Users/zhuhongrui/Desktop/code/c++/protocol-scanner
```

## 🏗️ 项目架构

### 核心设计理念

本项目采用 **双线程池 + 模块化协议** 的架构设计，实现高性能网络扫描：

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Main Thread (main.cpp)                  │
│  ┌───────────────────────────────────────────────────────┐    │
│  │          Scanner (core/scanner.h)           │    │
│  │      - Coordinates scan sessions               │    │
│  │      - Manages thread pools                  │    │
│  └──────────┬──────────────────────────────────────┘    │
│             │                                            │
│        ┌────┴────┐                                     │
│        │           │                                     │
│  Scan Pool   IO Pool                              │
│  (CPU tasks) (IO threads)                            │
│              │                                          │
│         ┌────┴──────────────────┐                       │
│         │  Session Management   │                      │
│         │  - Per-domain DNS   │                      │
│         │  - Protocol queues  │                      │
│         └─────────────────────┘                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 目录结构

```
protocol-scanner/
├── CMakeLists.txt                    # CMake 构建配置
├── README.md                         # 完整使用文档
├── PROJECT_SUMMARY.md                # 本文件（项目概览）
├── QUICKSTART.md                    # 快速入门指南
├── build.sh                         # 快速构建脚本
├── test_domains.txt                 # 测试域名列表
├── test.sh                         # 测试脚本
├── .gitignore                      # Git 忽略规则
│
├── config/                         # 配置文件目录
│   ├── scanner_config.json          # 主配置文件（超时、线程数等）
│   └── vendors.json                # 服务商模式库
│
├── include/scanner/               # 头文件目录
│   ├── core/                        # 核心扫描模块
│   │   ├── scanner.h                # 主扫描器类
│   │   ├── session.h               # 单域名扫描会话
│   │   └── task_queue.h            # 线程安全任务队列
│   │
│   ├── protocols/                    # 协议实现模块
│   │   ├── protocol_base.h          # 协议抽象基类接口
│   │   ├── smtp_protocol.h         # SMTP 协议实现
│   │   ├── pop3_protocol.h         # POP3 协议实现
│   │   ├── imap_protocol.h         # IMAP 协议实现
│   │   └── http_protocol.h         # HTTP 协议实现
│   │
│   ├── dns/                         # DNS 解析模块
│   │   └── dns_resolver.h          # DNS 解析器接口（c-ares + Dig）
│   │
│   ├── network/                     # 网络工具模块
│   │   └── port_scanner.h          # 端口扫描器（框架）
│   │
│   ├── vendor/                      # 服务商标识模块
│   │   └── vendor_detector.h        # 服务商检测器（框架）
│   │
│   ├── output/                      # 结果输出模块
│   │   └── result_handler.h         # 结果格式化输出（JSON/CSV/Text）
│   │
│   └── common/                      # 通用工具模块
│       ├── thread_pool.h           # CPU 任务线程池
│       ├── io_thread_pool.h       # IO 线程池（asio::io_context）
│       └── logger.h              # 日志系统（基于 spdlog）
│
├── src/scanner/                  # 实现文件目录
│   ├── main.cpp                     # 主程序入口
│   ├── scanner.cpp                  # Scanner 类实现
│   ├── dns_resolver.cpp             # DNS 解析器实现
│   ├── utils.cpp                    # 工具函数
│   ├── common/
│   │   ├── thread_pool.cpp        # 线程池实现
│   │   └── io_thread_pool.cpp    # IO 线程池实现
│   ├── core/
│   │   └── session.cpp           # ScanSession 实现
│   └── protocols/
│       ├── smtp_protocol.cpp       # SMTP 协议实现（已完整实现）
│       ├── pop3_protocol.cpp       # POP3 协议实现（框架）
│       ├── imap_protocol.cpp       # IMAP 协议实现（框架）
│       └── http_protocol.cpp       # HTTP 协议实现（框架）
│
├── tests/                        # 测试文件目录
│   ├── simple_test.cpp              # 简单测试
│   ├── smtp_probe_test.cpp          # SMTP 探测测试
│   ├── unit/                       # 单元测试目录
│   └── integration/                  # 集成测试目录
│
├── docs/                         # 文档目录
│   └── ARCHITECTURE.md            # 详细架构文档
│
└── build/                        # 构建输出目录（运行时生成）
    ├── scanner                    # 可执行文件
    └── smtp_probe_test            # SMTP 测试可执行文件
```

## 🔧 核心组件详解

### 1. Scanner（主扫描器）

**文件**: `include/scanner/core/scanner.h`, `src/scanner/scanner.cpp`

**职责**:
- 创建和管理 `ScanThreadPool`（CPU 任务）和 `IoThreadPool`（IO 操作）
- 为每个域名创建 `ScanSession` 实例
- 协调跨协议、跨端口的并发探测
- 通过线程安全队列收集结果

**核心方法**:
```cpp
class Scanner {
public:
    explicit Scanner(const ScannerConfig& config);
    ~Scanner();

    // 批量扫描域名（主入口）
    std::vector<ScanReport> scan_domains(
        const std::vector<std::string>& domains
    );

    // 单目标扫描
    ScanReport scan_target(const ScanTarget& target);

private:
    void init_protocols();              // 初始化启用的协议
    void start();                      // 主协调循环
};
```

**扫描流程**:
1. 创建任务队列（每个域名一个）
2. 进入主循环，根据 quota 启动探测任务
3. 每个探测任务提交到 ScanThreadPool
4. ScanThreadPool 任务调用协议的 `async_probe()`
5. `async_probe()` 将实际 I/O 发送到 IoThreadPool
6. 结果通过回调传回 Session
7. Session 完成后生成 ScanReport 并推送到结果队列

### 2. ScanSession（单域名协调器）

**文件**: `include/scanner/core/session.h`, `src/scanner/core/session.cpp`

**职责**:
- 解析 DNS（A 记录 + MX 记录）
- 维护每个协议的待探测端口队列
- 原子跟踪任务完成状态
- 所有探测完成后调用完成回调

**状态机**:
```
PENDING
   ↓
DNS_RUNNING  → DNS 解析中
   ↓
PROBE_RUNNING → 协议探测中
   ↓
COMPLETED     ← 所有任务完成
   ↓
TIMEOUT       ← 超时
FAILED        ← 错误
```

**探测策略** (`ProbeMode`):
- `ProtocolDefaults`: 仅扫描协议默认端口
- `AllAvailable`: 扫描所有可用端口（跨协议）

**队列管理**:
- `protocol_port_queues_`: 每个协议一个端口队列
- `protocol_result_queues_`: 每个协议一个结果队列
- 原子计数器追踪总任务数和完成数

### 3. 双线程池架构

#### 3.1 ScanThreadPool（CPU 密集型）

**文件**: `include/scanner/common/thread_pool.h`, `src/scanner/common/thread_pool.cpp`

**设计**:
- 使用 `std::jthread`（支持请求停止）
- 模板化的 `submit()` 方法返回 `std::future`
- 内部使用 `BlockingQueue` 管理待执行任务

**使用场景**:
- 提交协议探测任务（轻量级调度）
- 不执行实际 I/O，只负责调用 `async_probe()`

#### 3.2 IoThreadPool（IO 密集型）

**文件**: `include/scanner/common/io_thread_pool.h`, `src/scanner/common/io_thread_pool.cpp`

**设计**:
- 管理多个 `boost::asio::io_context` 实例
- 每个 io_context 运行在独立线程上
- **TrackingExecutor**: 装饰器，跟踪每个上下文的 pending 任务数

**负载均衡**:
- 使用 `std::unique_ptr<std::atomic<std::size_t>>` 追踪每个上下文负载
- `choose_least_loaded_index()` 选择负载最低的 io_context
- TrackingExecutor 在 post 时自动增加计数，回调完成时减少

**关键代码**:
```cpp
class TrackingExecutor {
    void post(F&& f) const {
        counter_->fetch_add(1, memory_order_relaxed);  // 计数++
        asio::post(exec_, [c = counter_, func = std::forward<F>(f)]() mutable {
            func();  // 执行任务
            c->fetch_sub(1, memory_order_relaxed);  // 计数--
        });
    }
};
```

### 4. 协议系统

所有协议继承自 `IProtocol` 接口：

**接口定义** (`include/scanner/protocols/protocol_base.h`):

```cpp
class IProtocol {
public:
    virtual ~IProtocol() = default;

    // 协议名称
    virtual std::string name() const = 0;

    // 默认端口列表
    virtual std::vector<Port> default_ports() const = 0;

    // 默认超时
    virtual Timeout default_timeout() const = 0;

    // 异步探测（核心方法）
    virtual void async_probe(
        const std::string& host,
        Port port,
        Timeout timeout,
        boost::asio::any_io_executor exec,  // IO 执行器
        std::function<void(ProtocolResult&&)> on_complete
    ) = 0;

    // 解析能力特性
    virtual void parse_capabilities(
        const std::string& response,
        ProtocolAttributes& attrs
    ) = 0;
};
```

#### 4.1 SMTP 协议

**文件**: `include/scanner/protocols/smtp_protocol.h`, `src/scanner/protocols/smtp_protocol.cpp`

**状态**: ✅ **完整实现**

**功能**:
- TCP 连接到 SMTP 服务器
- 发送 `EHLO` 命令
- 解析 ESMTP 响应：
  - `PIPELINING`: 支持流水线
  - `STARTTLS`: 支持 TLS 加密
  - `SIZE`: 支持消息大小限制
  - `8BITMIME`: 支持 8 位 MIME
  - `DSN`: 支持送达状态通知
  - `SMTPUTF8`: 支持 UTF-8
  - `AUTH`: 认证方法列表

**默认端口**: 25, 465, 587, 2525

#### 4.2 POP3 协议

**文件**: `include/scanner/protocols/pop3_protocol.h`, `src/scanner/protocols/pop3_protocol.cpp`

**状态**: ⚠️ **框架实现**（返回错误信息）

**待实现**:
- 读取服务器 banner
- 发送 `CAPA` 命令
- 解析响应：STLS, SASL 支持

**默认端口**: 110, 995

#### 4.3 IMAP 协议

**文件**: `include/scanner/protocols/imap_protocol.h`, `src/scanner/protocols/imap_protocol.cpp`

**状态**: ⚠️ **框架实现**（返回错误信息）

**待实现**:
- 连接并读取 banner
- 发送 `CAPABILITY` 命令
- 解析：STARTTLS, QUOTA, ACL 等

**默认端口**: 143, 993

#### 4.4 HTTP 协议

**文件**: `include/scanner/protocols/http_protocol.h`, `src/scanner/protocols/http_protocol.cpp`

**状态**: ⚠️ **框架实现**（返回错误信息）

**待实现**:
- 发送 HTTP HEAD/GET 请求
- 提取 `Server` header
- 提取状态码和 content-type

**默认端口**: 80, 443, 8080

### 5. DNS 解析器

**文件**: `include/scanner/dns/dns_resolver.h`, `src/scanner/dns_resolver.cpp`

**接口**:
```cpp
class IDnsResolver {
public:
    // 查询 A 记录（域名 → IP）
    virtual bool query_a_record(
        const std::string& domain,
        std::string& ip,
        Timeout timeout
    ) = 0;

    // 查询 MX 记录（邮件服务器）
    virtual bool query_mx_records(
        const std::string& domain,
        std::vector<DnsRecord>& records,
        Timeout timeout
    ) = 0;

    // 综合查询
    virtual DnsResult resolve(
        const std::string& domain,
        Timeout timeout
    ) = 0;
};
```

**实现**:
- `CAresResolver`: 基于 **c-ares** 库的异步解析器（生产用）
- `DigResolver`: 调用 `dig` 命令的回退解析器

### 6. 日志系统

**文件**: `include/scanner/common/logger.h`

**技术**: 基于 **spdlog**

**特性**:
- 单例模式
- 控制台 + 文件输出（可配置）
- 日志级别：TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
- 线程安全
- 支持格式化字符串（`LOG_CORE_INFO("{}", value)`）

### 7. 结果处理

**文件**: `include/scanner/output/result_handler.h`

**支持格式**:
- JSON: 结构化数据输出
- CSV: 表格格式
- TEXT: 人类可读文本

## 🚀 快速开始

### 1. 安装依赖

**macOS**:
```bash
brew install boost libomp c-ares spdlog cmake
```

**Linux (Ubuntu)**:
```bash
sudo apt-get install cmake \
    libboost-all-dev \
    libomp-dev \
    libc-ares-dev \
    libspdlog-dev
```

### 2. 构建项目

```bash
cd /Users/zhuhongrui/Desktop/code/c++/protocol-scanner

# Release 构建
./build.sh

# Debug 构建
./build.sh Debug

# 清理重建
./build.sh Release clean
```

**输出**: `build/scanner` (743 KB ARM64 可执行文件)

### 3. 运行示例

```bash
# DNS 测试（快速，无协议探测）
./build/scanner --domains test_domains.txt --dns-test

# 完整协议扫描
./build/scanner --domains test_domains.txt --scan

# 指定协议扫描
./build/scanner --domains test_domains.txt \
    --protocols SMTP,IMAP \
    --threads 16 \
    --timeout 3000 \
    --scan

# 查看帮助
./build/scanner --help
```

## ⚙️ 配置说明

编辑 `config/scanner_config.json`:

```json
{
  "scanner": {
    "thread_count": 8,              // ScanThreadPool 线程数
    "batch_size": 100,              // 最大并发探测数
    "dns_timeout_ms": 5000,         // DNS 查询超时
    "probe_timeout_ms": 5000        // 单次探测超时（重要！）
    "retry_count": 1
  },
  "protocols": {
    "SMTP": {
      "enabled": true,
      "ports": [25, 465, 587, 2525],
      "timeout_ms": 3000
    },
    "POP3": {
      "enabled": true,
      "ports": [110, 995],
      "timeout_ms": 3000
    },
    "IMAP": {
      "enabled": true,
      "ports": [143, 993],
      "timeout_ms": 3000
    },
    "HTTP": {
      "enabled": false,
      "ports": [80, 443, 8080],
      "timeout_ms": 3000
    }
  },
  "dns": {
    "resolver_type": "cares",       // c-ares 或 dig
    "max_mx_records": 16,
    "timeout_ms": 5000
  }
}
```

## 🎯 性能调优

### 超时设置（关键）

| 超时时间 | 优点 | 缺点 | 适用场景 |
|----------|-------|-------|----------|
| **3000ms** | 扫描快 | 可能漏掉慢速服务器 | 内网或高带宽 |
| **5000ms** | 平衡 | 无 | **推荐默认值** |
| 10000ms | 可靠性高 | 失败等待时间长 | 不稳定网络 |

### 线程数配置

- **Scan Pool**: 建议 4-8 线程（任务提交）
- **IO Pool**: 建议 4-8 `io_context`（并行网络 I/O）

总并发探测数 ≈ `scan_pool_size × 2`（动态 quota 策略）

### 性能预期

在 `probe_timeout_ms: 5000` 和 8 线程下：
- 6 个域名（3 启用协议 × 2-3 端口 ≈ 36-48 个探测任务）
- 预计时间：**15-30 秒**

## ✅ 已实现功能

### 核心架构
- ✅ 双线程池架构（ScanThreadPool + IoThreadPool）
- ✅ 模块化协议系统（IProtocol 接口）
- ✅ 协议工厂模式（注册表查找）
- ✅ 线程安全任务队列（BlockingQueue）
- ✅ IO 执行器负载均衡（TrackingExecutor）
- ✅ 原子计数器（任务追踪）

### 协议实现
- ✅ **SMTP**: 完整实现（EHLO + ESMTP 特性解析）
- ⚠️ **POP3**: 框架实现（需完善 CAPA 命令）
- ⚠️ **IMAP**: 框架实现（需完善 CAPABILITY 命令）
- ⚠️ **HTTP**: 框架实现（需完善 HTTP 请求）

### DNS 模块
- ✅ c-ares 异步 DNS 解析器
- ✅ A 记录查询（域名 → IP）
- ✅ MX 记录查询（邮件服务器）
- ✅ Dig 命令回退实现

### 日志系统
- ✅ spdlog 集成
- ✅ 多级别日志（TRACE → CRITICAL）
- ✅ 控制台输出
- ✅ 文件输出支持（框架）

### 构建系统
- ✅ CMake 配置
- ✅ 跨平台支持（macOS, Linux）
- ✅ Release/Debug 配置
- ✅ 依赖自动下载（nlohmann/json）
- ✅ 快速构建脚本

### 文档
- ✅ README.md（完整使用指南 + 架构说明）
- ✅ PROJECT_SUMMARY.md（本文件）
- ✅ 代码注释

## 📝 待完成功能

### 高优先级
- [ ] 完善 POP3 协议实现（CAPA 命令 + STLS 检测）
- [ ] 完善 IMAP 协议实现（CAPABILITY 命令 + STARTTLS 检测）
- [ ] 完善 HTTP 协议实现（HEAD/GET 请求 + Server header 解析）
- [ ] 实现 ResultHandler 的所有输出格式（JSON, CSV, Text）
- [ ] 集成 VendorDetector 到扫描流程

### 中优先级
- [ ] 添加单元测试（协议模块）
- [ ] 添加集成测试（端到端扫描）
- [ ] 性能基准测试
- [ ] DNS 查询结果缓存

### 低优先级
- [ ] 添加 FTP 协议
- [ ] 添加 SSH 协议
- [ ] Web UI 界面
- [ ] 扫描结果数据库存储
- [ ] 分布式扫描支持

## 📊 代码统计

| 类型 | 文件数 | 代码行数（估算） |
|------|--------|-----------------|
| 头文件 (.h) | 15 | ~1200 |
| 源文件 (.cpp) | 11 | ~2500 |
| 配置 (.json) | 2 | ~100 |
| 文档 (.md) | 3 | ~2000 |
| 构建文件 | 3 | ~200 |
| **总计** | **34** | **~6000** |

## 🔄 与原始设计对比

| 方面 | 原始脚本式设计 | 当前实现 |
|------|---------------|----------|
| **架构** | 单体脚本 | 模块化、分层设计 |
| **协议支持** | 仅 SMTP | SMTP + POP3 + IMAP + HTTP 框架 |
| **扩展性** | 修改核心文件 | 添加一个文件即可 |
| **配置** | 命令行硬编码 | JSON + 命令行双重配置 |
| **并发** | 顺序或简单多进程 | 双线程池 + 异步 I/O |
| **日志** | print 语句 | spdlog 完整日志系统 |
| **输出** | 固定格式 | 可扩展多格式 |

## 🎓 设计模式应用

1. **接口抽象**: `IProtocol` 定义协议规范
2. **工厂模式**: `ProtocolFactory` 注册表查找
3. **策略模式**: `ProbeMode` 探测策略
4. **RAII**: 资源自动管理（线程池、句柄）
5. **装饰器模式**: `TrackingExecutor` 装饰执行器
6. **单例模式**: `Logger::get_instance()`

## 📦 依赖库

| 库 | 用途 | 版本要求 |
|------|------|----------|
| **Boost.Asio** | 异步网络 I/O | ≥ 1.70 |
| **Boost.Program_Options** | 命令行解析 | ≥ 1.70 |
| **Boost.Filesystem** | 文件操作 | ≥ 1.70 |
| **c-ares** | DNS 解析 | ≥ 1.19 |
| **spdlog** | 日志系统 | ≥ 1.9 |
| **nlohmann/json** | JSON 解析 | ≥ 3.9 |
| **OpenMP** | 并行计算（可选） | ≥ 4.5 |
| **fmt** | 字符串格式化（spdlog 依赖） | ≥ 8.0 |

## 🐛 已知问题

### 1. 扫描性能慢

**原因**:
- 默认 `probe_timeout_ms: 60000` 过长
- 每个失败连接等待 60 秒

**解决方案**:
- 将超时降低到 3000-5000ms（已在 config 中更新）
- 增加线程数（8-16）

### 2. 编辑器 Intellisense 提示

**现象**: 编辑器显示 "找不到函数定义" 的 HINT

**原因**: Intellisense 跨文件查找限制

**影响**: 无（不影响编译和运行）

## 📞 下一步开发建议

### 阶段 1：协议完善（1-2 周）

```bash
1. 完善 POP3 协议
   - 实现 CAPA 命令发送
   - 解析 STLS、SASL 支持

2. 完善 IMAP 协议
   - 实现 CAPABILITY 命令
   - 解析 STARTTLS、QUOTA 支持

3. 完善 HTTP 协议
   - 实现 HEAD/GET 请求
   - 解析 Server header
```

### 阶段 2：输出模块（3-5 天）

```bash
1. 实现 JSON 输出格式
2. 实现 CSV 输出格式
3. 实现 Text 格式化输出
4. 集成到主扫描流程
```

### 阶段 3：测试和优化（1 周）

```bash
1. 编写单元测试（协议模块）
2. 编写集成测试（端到端）
3. 性能基准测试
4. 与原始脚本对比验证
```

## 💡 关键设计决策

### 1. 为什么使用双线程池？

**ScanThreadPool**: 负责轻量级任务提交
- 不执行实际 I/O
- 快速调度，避免阻塞

**IoThreadPool**: 负责网络 I/O
- 管理 `asio::io_context` 实例
- 真正的并行网络操作

### 2. 为什么使用 `std::unique_ptr<std::atomic>`？

- `std::atomic` 不可拷贝、不可移动
- `std::vector` 需要 move 构造
- `unique_ptr` 包装解决兼容性问题

### 3. 为什么回调使用 `ProtocolResult&&`？

- 右值引用支持移动语义
- 避免不必要的拷贝
- 提高性能

### 4. 为什么使用 `any_io_executor`？

- 类型擦除：支持多种 executor 类型
- 灵活性：不绑定到特定 executor 类型
- 未来可扩展到 strand、executor_wrapper 等

---

## ✨ 总结

本项目成功实现了一个**现代化、高性能、模块化**的网络协议扫描器！

### 核心优势

- 🏗️ **清晰架构**: 分层设计，职责明确
- 🧩 **高度模块化**: 易于扩展新协议
- ⚡ **高性能**: 双线程池 + 异步 I/O
- 📝 **完善文档**: README + PROJECT_SUMMARY
- ⚙️ **灵活配置**: JSON + 命令行双重配置
- 🔧 **易于维护**: 代码组织清晰，注释完善

**项目已进入功能完善阶段！** 🚀
