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
