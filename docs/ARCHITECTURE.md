# Protocol Scanner Architecture

## Overview

Protocol Scanner is a high-performance, modular network protocol scanner designed for large-scale network service discovery and fingerprinting across multiple protocols.

## Core Design Principles

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
2. **Interface-Based Design**: Protocol implementations use abstract interfaces (`IProtocol`)
3. **Dual-Layer Threading**: IO-bound and CPU-bound workloads separated into different thread pools
4. **Configuration-Driven**: Behavior controlled through JSON configuration files
5. **Extensibility**: Adding new protocols requires minimal code changes (one class + one macro)
6. **Checkpoint & Resume**: Progress is persisted periodically for crash recovery

---

## Build Architecture

The project builds **three executables** from a shared static library:

```
┌──────────────────────────────────────────────┐
│                 scanner_core (STATIC LIB)    │
│  Core | Protocols | DNS | Network | Output  │
│  Common | Vendor | Distributed              │
└──────────────────────────────────────────────┘
          ↗               ↑               ↖
   ┌──────────┐   ┌──────────────┐   ┌──────────────┐
   │  scanner  │   │  scanner_   │   │  scanner_    │
   │ (main)    │   │ distributed │   │   ingest     │
   └──────────┘   └──────────────┘   └──────────────┘
```

- **`scanner`** — 主 CLI 入口，单机扫描模式
- **`scanner_distributed`** — 分布式工作节点入口
- **`scanner_ingest`** — 数据摄入入口

---

## Module Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          CLI Layer                              │
│  main.cpp / distributed_main.cpp / distributed_ingest_main.cpp  │
│  (boost::program_options → ScannerConfig)                       │
└──────────────────────────────────────────────────────────────────┘
                                ↓
┌──────────────────────────────────────────────────────────────────┐
│                        Core Layer                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐     │
│  │   Scanner    │  │ ScanSession  │  │ ProgressManager   │     │
│  │  (orchestr.) │  │ (per-target  │  │ (checkpoint/      │     │
│  │              │  │  lifecycle)  │  │  resume)          │     │
│  └──────┬───────┘  └──────┬───────┘  └───────────────────┘     │
│         │                 │                                      │
│  ┌──────┴──────────────────┴────────────────────────────────┐   │
│  │               Thread Pools                               │   │
│  │  ┌────────────────────┐  ┌───────────────────────────┐   │   │
│  │  │   IoThreadPool     │  │     ThreadPool (CPU)      │   │   │
│  │  │  (Boost.Asio iocp) │  │  (task queue + workers)   │   │   │
│  │  └────────────────────┘  └───────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                                ↓
┌──────────────────────────────────────────────────────────────────┐
│                      Protocol Layer                             │
│  ┌────────────────────────────────────────────────────────┐     │
│  │              IProtocol Interface                       │     │
│  │  async_probe() | parse_capabilities() | default_ports()│     │
│  └────┬──────┬──────┬──────┬──────┬──────┬──────┬────────┘     │
│       ↓      ↓      ↓      ↓      ↓      ↓      ↓              │
│  ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐            │
│  │SMTP│ │POP3│ │IMAP│ │HTTP│ │FTP │ │SSH │ │Telnet           │
│  └────┘ └────┘ └────┘ └────┘ └────┘ └────┘ └────┘            │
│        (each registered via REGISTER_PROTOCOL macro)            │
└──────────────────────────────────────────────────────────────────┘
                                ↓
┌──────────────────────────────────────────────────────────────────┐
│                  Infrastructure Layer                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │   DNS    │  │   Port   │  │  Vendor  │  │   Buffer     │   │
│  │ Resolver │  │  Scanner │  │ Detector │  │    Pool      │   │
│  │ (c-ares  │  │(Boost    │  │ (regex)  │  │ (1KB fixed,  │   │
│  │ / dig)   │  │ Asio)    │  │          │  │  3000 pool)  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                     │
│  │  Logger  │  │  Result  │  │  Config  │                     │
│  │ (spdlog) │  │ Handler  │  │ (JSON)   │                     │
│  └──────────┘  └──────────┘  └──────────┘                     │
└──────────────────────────────────────────────────────────────────┘
                                ↓
┌──────────────────────────────────────────────────────────────────┐
│              Distributed Layer (可选)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │ Orchestrator │  │  Distributed │  │  ProgressStore     │    │
│  │ (task disp.) │  │  BatchQueue  │  │  (persist state)   │    │
│  └──────────────┘  └──────────────┘  └────────────────────┘    │
│  ┌──────────────┐  ┌──────────────┐                             │
│  │  KafkaTrans  │  │  TaskCodec   │                             │
│  │  port (opt.)  │  │  (serialize) │                             │
│  └──────────────┘  └──────────────┘                             │
└──────────────────────────────────────────────────────────────────┘
```

---

## Module Details

### Core Module (`core/`)

**Files:**
- `scanner.h/cpp` — Main scanner orchestration: input streaming, session management, result aggregation
- `session.h/cpp` — Per-target lifecycle: DNS → probe → completion, with state machine and port queues
- `task_queue.h` — Thread-safe blocking queue template (`TaskQueue<T>`)
- `progress_manager.h/cpp` — Checkpoint persistence for crash recovery
- `crash_inspector.h/cpp` — Startup diagnostics: detect unclean shutdowns, validate checkpoint integrity

**Key Responsibilities:**
- Coordinate end-to-end scanning lifecycle for each target
- Manage thread pools (IO + CPU)
- Track progress and save checkpoints

### Protocol Module (`protocols/`)

**Files:**
- `protocol_base.h` — `IProtocol` abstract interface + `ProtocolFactory` + `REGISTER_PROTOCOL` macro
- `probe_context.h` — Shared probe context struct（用于共享上下文方案）
- `smtp_protocol.h/cpp` — SMTP/ESMTP (port 25/465/587/2525), EHLO + capabilities
- `pop3_protocol.h/cpp` — POP3 (port 110/995), CAPA + STLS
- `imap_protocol.h/cpp` — IMAP (port 143/993), CAPABILITY + STARTTLS
- `http_protocol.h/cpp` — HTTP/HTTPS (port 80/443/8080/8443), GET + Server header
- `ftp_protocol.h/cpp` — FTP (port 21/990), banner + FEAT
- `ssh_protocol.h/cpp` — SSH (port 22), version banner
- `telnet_protocol.h/cpp` — Telnet (port 23), banner + IAC negotiation

**Key Design:**
- Each protocol is a standalone `IProtocol` subclass owning its socket + timer lifecycle
- All I/O is asynchronous (Boost.Asio completion handlers/callbacks)
- Memory is managed via `BufferPool` (fixed-size 1KB buffers, RAII `BufferHandle`)
- New protocols can be added without touching existing code

### DNS Module (`dns/`)

**Files:**
- `dns_resolver.h/cpp` — `IDnsResolver` interface + `DnsResolverFactory`
- `DigResolver` — Calls system `dig` command, parses output
- `CAresResolver` — Uses `c-ares` library for fully asynchronous DNS

**Key Capabilities:**
- A record resolution
- MX record resolution (with priority)
- Domain/IP format validation
- Configurable timeout per query
- Factory pattern: runtime selection via config `"dns_resolver_type": "cares" | "dig"`

### Common Module (`common/`)

**Files:**
- `logger.h` — Module-level logging macros (`LOG_SMTP_DEBUG`, `LOG_CORE_INFO`, etc.), backed by spdlog
- `thread_pool.h/cpp` — `ThreadPool` (CPU-bound tasks) + `BlockingQueue<T>` (thread-safe producer/consumer)
- `io_thread_pool.h/cpp` — `IoThreadPool` (multiple Boost.Asio `io_context`s with load tracking)
- `buffer_pool.h` — `BufferPool` (fixed-size 1KB buffer pool, RAII handle, hit-rate statistics)

**IoThreadPool Load Tracking:**
```cpp
// 自动选择负载最轻的 io_context
asio::io_context& get_context();   // round-robin
TrackingExecutor get_tracking_executor();  // 带 pending 计数
```

### Vendor Module (`vendor/`)

**Files:**
- `vendor_detector.h/cpp` — Regex-based banner → vendor matching

**Key Capabilities:**
- Load vendor patterns from `vendors.json`
- Detect vendor from banner text (regex)
- Extract version strings
- Generate statistics (vendor frequency)
- Add new patterns dynamically

**Current Coverage:** 26 vendor patterns (OpenSSH, Dropbear, vsftpd, Postfix, Exim, etc.)

### Output Module (`output/`)

**Files:**
- `result_handler.h/cpp` — Format and write results

**Output Formats:**
- **JSON** — Structured per-target results (machine-readable)
- **CSV** — Tabular format (spreadsheet-compatible)
- **TEXT** — Human-readable per-target summary
- **REPORT** — Aggregated summary with statistics

**Write Modes:**
- **stream** — Real-time append to file (default, low memory)
- **final** — Batch write at end (used with --only-final)

### Distributed Module (`distributed/`)

**Files:**
- `orchestrator.h/cpp` — Task distribution and worker coordination
- `distributed_queue.h/cpp` — `DistributedBatchQueue` (ready/inflight/failed/done state machine)
- `kafka_transport.h/cpp` — Kafka message transport (optional, controlled by `SCANNER_ENABLE_KAFKA`)
- `task_codec.h/cpp` — Task serialization/deserialization
- `progress_store.h/cpp` — Distributed progress persistence
- `ingestor.h/cpp` — Data ingestion for distributed mode
- `task_types.h` — Shared type definitions

**Key Concepts:**
- **Lease-based task assignment**: Workers lease tasks with timeout; expired leases are reclaimed
- **Backends**: File-based (default) or Kafka-based (with `librdkafka`)

---

## Data Flow (Single-Machine Mode)

```
1. CLI parses arguments → Loads JSON config → Scanner instantiation
   ↓
2. Scanner.init_protocols() → REGISTER_PROTOCOL 收集所有协议
   ↓
3. Scanner.start(domains_file)
   ├─ input_thread: 流式读取域名/目标
   │   → DNS 解析 → 创建 ScanSession
   │   → 入队到 targets_ 队列
   └─ scan_loop: 从 targets_ 取出 session
       → session.start_all_pending_probes()
         → IoThreadPool 分配 executor
         → 对每个协议的每个端口调用 async_probe
           → 连接 → 读写 → parse_capabilities
           → 结果入 session 的结果队列
       → session.ready_to_release() → 收集结果
         → 放入 result_queue_
   ↓
4. result_handler_thread: 从 result_queue_ 取结果
   → VendorDetector 匹配厂商
   → ResultHandler 格式化 (JSON/CSV/TEXT)
   → 流式写入文件 / 输出到控制台
   ↓
5. Scanner.get_results() → 等待全部完成 → 输出统计
```

---

## Key Data Structures

### `ProtocolAttributes`
Per-protocol structured attributes (banner, capabilities, auth methods, etc.) with sub-structs for SMTP, POP3, IMAP, HTTP.

### `ScanSession`
Per-target lifecycle manager:
- DNS → protocol probes → completion
- Port queue per protocol
- Thread-safe result queue per protocol
- Atomic task counter for completion detection

### `ScannerConfig`
Central configuration struct with ~30 parameters controlling:
- Thread pool sizes (IO / CPU)
- Protocol enable/disable
- Timeouts (DNS / probe)
- Output format and write mode
- Checkpoint interval

---

## Extension Points

### Adding a New Protocol (3 steps)

1. **Create header** `include/scanner/protocols/xxx_protocol.h`
   - Inherit from `IProtocol`
   - Implement `name()`, `default_ports()`, `default_timeout()`, `async_probe()`, `parse_capabilities()`

2. **Create impl** `src/scanner/protocols/xxx_protocol.cpp`
   - Follow the `XXXProbeContext` pattern (RAII context with socket/timer/buffer/callback)
   - Use `BufferPool` for memory management

3. **Register** — Add `REGISTER_PROTOCOL(XxxProtocol, "XXX")` at file scope
   - Add source to `CMakeLists.txt` in `PROTOCOL_SRCS`

### Adding a New Output Format

- Implement a new method in `ResultHandler` (e.g. `to_protobuf()`)
- Add format enum in `OutputFormat`
- Wire into `switch` in `save_report()`

---

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| Boost.Asio | 1.80+ | Async I/O, timers, sockets |
| Boost.ProgramOptions | 1.80+ | CLI argument parsing |
| Boost.Filesystem | 1.80+ | Path manipulation |
| c-ares | 1.19+ | Async DNS resolution |
| fmt | 9.0+ | Formatting (spdlog dep) |
| nlohmann-json | 3.11+ | Config + output serialization |
| spdlog | 1.11+ | Structured logging |
| librdkafka | (optional) | Kafka transport for distributed mode |


---

## 架构决策记录 (ADR)

### ADR-1: 全局 BufferPool vs. 每 Session 独立缓冲区

**状态**: 采用全局 BufferPool

**问题**: 每个协议探测需要一个 1KB 缓冲区。是使用全局池还是让每个 ScanSession 自己管理缓冲区？

**考量**:
- 一个 session 的多个协议 probe 是**并发**的（SSH + FTP + HTTP 同时跑），不可能共用一个缓冲区
- 即使 session 自管，也需要一个迷你池——不如直接用全局池
- 全局池 3000 个预分配 1KB buffer，RAII `BufferHandle` 自动归还，命中率接近 100%
- mutex 开销仅 ~100ns/次，相比网络 I/O 完全可忽略

**结论**: 全局 `BufferPool` 是正确设计，不需要改为每 session 管理。

---

### ADR-2: Session 复用 vs. 每 Probe 独立执行单元

**状态**: 保持 session 复用（固定池）

**问题**: 当一个 session 包含 SSH(19ms) 和 HTTP(5s timeout) 时，HTTP 是否拖慢 SSH 的吞吐？

**分析**:
- 瓶颈是 HTTP 的 5s timeout，不是 session 复用方式
- 1000 target × HTTP 5s / 10 并发 = 500s，SSH 那 2s 完全是噪声
- 无论 session 复用还是每 probe 独立，总时间相同，因为最慢的协议决定了整体进度
- session 复用的好处：进度追踪简单、断点恢复清晰、target 派发统一

**结论**: 当前 session 复用架构合理。不需要拆成每协议独立 session。如果某个场景只需 SSH，用 `--enable-ssh` 单独跑即可。

---

### ADR-3: generation 计数器解决 reset 并发竞争

**状态**: 已实现

**问题**: `ScanSession::reset()` 复用 session 对象时，旧 probe 的异步 callback 仍持有 `this` 指针。在 reset 后触发会导致任务计数混乱（`tasks_completed++`加到新 session 上）。

**方案**: 每 reset 递增 `generation_` 原子计数器。probe callback 在提交时捕获当前 gen，触发时比对——不匹配则忽略。

```cpp
// session.h
std::atomic<uint64_t> generation_{0};

// session.cpp: reset() 时递增
generation_.fetch_add(1, std::memory_order_release);

// 提交 probe 时捕获 gen
auto gen = generation_.load(std::memory_order_acquire);
scan_pool.submit([this, gen, ...]() {
    proto_ptr->async_probe(..., [this, gen](ProtocolResult&& r) {
        if (generation_.load(std::memory_order_acquire) != gen) return;  // 过期
        // 正常处理结果
    });
});
```

---

### ADR-4: Probe callback 直接入全局结果队列

**状态**: 已实现

**问题**: 原设计中 probe callback 入 session 本地结果队列 → scan_loop 轮询 `ready_to_release()` → 手动取出转发到全局队列。多了一层无必要的轮询和转发。

**方案**: probe callback 中最慢的那个（最后一个完成）直接组装 `ScanReport` 并 push 到全局 `result_queue_`。scan_loop 不再转发结果，只负责 session 复用。

```cpp
// 最后一个完成的 probe callback:
if (completed >= total) {
    ScanReport rep;
    rep.target = target_;
    { std::lock_guard results_mutex; rep.protocols = std::move(results_); }
    grq->push(std::move(rep));  // 直接入全局队列
}
```

**效果**: 去掉 50+ 行结果转发逻辑，减少一次线程间数据搬移。

---

### ADR-5: 水平扩展方案 — 分布式模式

**状态**: 已实现（可选）

**问题**: 单机扫描受限于带宽和文件描述符，无法覆盖全球 IPv4 空间。

**方案**: 提供分布式架构（位于 `distributed/` 目录）：

- **Orchestrator**: 任务分发和工作节点协调
- **DistributedBatchQueue**: 四状态队列（ready/inflight/failed/done），租约机制防重复
- **KafkaTransport**: 可选 Kafka 消息后端
- **ProgressStore**: 进度持久化
- **TaskCodec**: 任务序列化

构建三个独立可执行文件：
- `scanner` — 单机模式入口
- `scanner_distributed` — 分布式工作节点
- `scanner_ingest` — 数据摄入

三者在 `scanner_core` 静态库上共享核心探测逻辑。

---

## 性能模型

### 单机吞吐量估算

```
吞吐量 = 并发数 / 平均探测时间

假设:
- 并发 session: 500 (受 RLIMIT_NOFILE 限制)
- SSH 平均探测时间: 50ms (含网络往返)
- HTTP 平均探测时间: 200ms
- FTP 平均探测时间: 100ms

SSH-only:  500 / 0.05 = 10,000 targets/sec
HTTP-only: 500 / 0.2  =  2,500 targets/sec
FTP-only:  500 / 0.1  =  5,000 targets/sec
混合:      500 / 0.35 ≈  1,428 targets/sec (最慢协议主导)
```

实际瓶颈通常在网络带宽和 DNS 解析速度，而非 CPU 或内存。

---

## 关键指标 (SLA)

| 指标 | 目标 | 测量方式 |
|------|------|---------|
| 单目标 SSH 探测 | ≤ 100ms | 单元测试 |
| 单目标 HTTP 探测 | ≤ 300ms | 单元测试 |
| 100万 IP 扫描冷启动 | ≤ 1s | 基准测试 |
| 内存峰值 (100万 IP) | ≤ 200MB | 基准测试 |
| 断点恢复损失 | ≤ 1% 重扫率 | 混沌测试 |
