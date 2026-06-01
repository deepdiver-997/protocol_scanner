# Protocol Scanner

🚀 **High-performance network protocol scanner** for detecting email services and other network services across large IP ranges.

**Current Performance:** 2600-3000 targets/sec on datacenter hardware (3s timeout per target)  
**Memory Efficiency:** 40-60MB peak for scanning 1.35B+ IP addresses  
**Startup Time:** <1 second (even for billion-item CIDR blocks)

## ✨ Key Features

- **🔍 Multi-Protocol Support**: SMTP, POP3, IMAP, HTTP, FTP, Telnet, SSH
- **🚀 Ultra-High Performance**: Dual-layer thread architecture (scan pool + I/O pool)
- **📊 Large-Scale Scanning**: Streaming CIDR parsing, no memory preload
- **🧩 Modular Design**: Easy to add new protocols via inheritance
- **🏢 Vendor Detection**: Auto-identifies Gmail, Outlook, QQ, 163, etc.
- **⚙️ Auto-Configuration**: Intelligent thread pool sizing based on hardware
- **✅ Checkpoint & Resume**: Auto-recovery from interruptions
- **📝 Flexible Logging**: INFO/ERROR for production, DEBUG for development
- **📦 Multiple Output Formats**: JSON, CSV, text with streaming writes
- **🔧 Cross-Platform**: Optimized builds for Linux and macOS

## 📋 Quick Start

### Prerequisites

**macOS:**
```bash
brew install boost c-ares fmt nlohmann-json spdlog cmake
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libboost-all-dev libc-ares-dev libfmt-dev nlohmann-json3-dev libspdlog-dev cmake
```

### Build

```bash
# Clone and enter project
cd protocol-scanner

# Release build (max performance, no logging)
./build.sh Release

# Production build with monitoring (INFO + ERROR logs)
./build.sh InfoRelease

# Debug build (full logging for development)
./build.sh Debug

# Clean rebuild
./build.sh Release clean
```

**Output:** `build/scanner` executable

### Basic Usage

```bash
# Scan from IP file (streaming parse, auto-checkpoint)
./build/scanner --domains ip_list.txt --scan

# Scan with custom settings
./build/scanner --domains ip_list.txt --scan \
  --threads 8 \
  --timeout 3000 \
  --protocols SMTP,IMAP \
  -o result.json \
  --format json

# DNS test only (fast, no TCP probes)
./build/scanner --domains ip_list.txt --dns-test

# Resume interrupted scan
./build/scanner --domains ip_list.txt --scan  # Auto-resumes from checkpoint

# Verbose output (debug mode only)
./build/scanner --domains test.txt --scan --verbose

# Custom configuration
./build/scanner --domains ip_list.txt --scan --config custom_config.json
```

### Supported Input Formats

```bash
# IPv4 addresses
192.168.1.1
10.0.0.1

# CIDR blocks (auto-expanded)
192.168.0.0/24
10.0.0.0/8

# Domain names (auto-DNS resolved)
example.com
mail.company.net

# Mixed file
192.168.1.1
10.0.0.0/24
example.com
```

### Output Formats

```bash
# JSON (structured, easy to parse)
./build/scanner --domains targets.txt --scan -f json -o results.json

# CSV (spreadsheet compatible)
./build/scanner --domains targets.txt --scan -f csv -o results.csv

# Text (human readable)
./build/scanner --domains targets.txt --scan -f text -o results.txt
```

## 🔧 Configuration

### Auto-Configuration (Default)

The scanner automatically calculates optimal settings based on hardware:

```json
{
  "max_work_count": 0,              // Auto = io_threads × 300
  "targets_max_size": 0,            // Auto = max_work_count × 3
  "result_queue_max_size": 0,       // Auto = max_work_count / 2
  "scan_timeout_ms": 3000,
  "io_threads": 4,
  "scan_threads": 8
}
```

**Result:** Optimal performance on all hardware without manual tuning

### Custom Configuration

Create `custom_config.json`:

```json
{
  "scan_timeout_ms": 5000,
  "io_threads": 8,
  "scan_threads": 16,
  "max_work_count": 2400,
  "targets_max_size": 8000,
  "result_queue_max_size": 1000,
  "protocols": ["SMTP", "IMAP", "HTTP"],
  "output_format": "json",
  "streaming_write": true
}
```

Run with custom config:
```bash
./build/scanner --domains targets.txt --scan --config custom_config.json
```

## 📊 Performance Characteristics

### Throughput by Build Type

| Build Type | Throughput | Use Case |
|------------|-----------|----------|
| **Release** | 2600-3000/sec | Maximum performance, zero logging |
| **InfoRelease** | 2500-2900/sec | Production with monitoring |
| **Debug** | 800-1200/sec | Development only |

### Memory Usage

```
Build Type     | Baseline | Per 100K Targets
Release        | 40MB     | +200MB
InfoRelease    | 45MB     | +210MB
Debug          | 60MB     | +250MB
```

### Scaling Example

Scanning 1.35 billion IPs from Japanese ISPs (JP_ip.txt):
```
Duration:     ~15 hours
Memory:       40-60MB peak (no growth over time)
CPU:          95-100% utilization (3-4 cores)
Checkpoints:  ~100 per hour for resume
Network I/O:  Sustained 1-5Mbps
```

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────┐
│           Main Scanner Loop                 │
│  ┌─────────────────────────────────────┐   │
│  │ Input Thread: Stream parse IPs      │   │
│  │ (CIDR → uint32 → queue)             │   │
│  └────────────┬────────────────────────┘   │
│               │                             │
│  ┌────────────┴────────────────────────┐   │
│  │    Targets Queue (configurable)     │   │
│  └────────────┬────────────────────────┘   │
│               │                             │
│  ┌────────────┴─────────────┬──────────┐   │
│  │                          │          │   │
│ Scan Pool              IO Pool    │
│ (Protocol probes)    (TCP/DNS)    │
│  │                          │          │   │
│  └────────────┬─────────────┴──────────┘   │
│               │                             │
│  ┌────────────┴────────────────────────┐   │
│  │   Results Queue (configurable)      │   │
│  └────────────┬────────────────────────┘   │
│               │                             │
│  ┌────────────┴────────────────────────┐   │
│  │ Output Thread: Stream write results │   │
│  │ (JSON/CSV/Text)                     │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘

Key Optimization: Streaming CIDR expansion (lazy evaluation)
- No pre-loading 1.35B IPs into memory
- Process as you go: parse → enqueue → scan
```

## 📁 Project Structure

```
protocol-scanner/
├── CMakeLists.txt                 # Build configuration (3 targets: scanner / scanner_distributed / scanner_ingest)
├── build.sh.in                    # Build script template
├── TODO.md                        # Task tracking list
├── README.md                      # This file
│
├── include/scanner/
│   ├── common/
│   │   ├── logger.h              # Compile-time conditional logging (spdlog)
│   │   ├── buffer_pool.h         # Fixed-size 1KB buffer pool with RAII handles
│   │   ├── thread_pool.h         # CPU-bound task thread pool
│   │   └── io_thread_pool.h      # I/O thread pool (Boost.Asio, load-balanced)
│   │
│   ├── core/
│   │   ├── scanner.h             # Main coordinator (orchestrates scan lifecycle)
│   │   ├── session.h             # Per-target lifecycle (DNS → probe → complete)
│   │   ├── task_queue.h          # Thread-safe blocking queue
│   │   ├── progress_manager.h    # Checkpoint/resume for crash recovery
│   │   └── crash_inspector.h     # Startup diagnostics & integrity check
│   │
│   ├── protocols/
│   │   ├── protocol_base.h       # IProtocol interface + ProtocolFactory + REGISTER_PROTOCOL macro
│   │   ├── probe_context.h       # Shared probe state (deprecated, per-protocol contexts preferred)
│   │   ├── smtp_protocol.h       # SMTP/ESMTP (EHLO + capabilities)
│   │   ├── pop3_protocol.h       # POP3 (CAPA + STLS)
│   │   ├── imap_protocol.h       # IMAP (CAPABILITY + STARTTLS)
│   │   ├── http_protocol.h       # HTTP/HTTPS (GET + Server header)
│   │   ├── ftp_protocol.h        # FTP (banner + FEAT)
│   │   ├── telnet_protocol.h     # Telnet (banner + IAC negotiation)
│   │   └── ssh_protocol.h        # SSH (version banner)
│   │
│   ├── dns/
│   │   ├── dns_resolver.h        # IDnsResolver interface + DnsResolverFactory (c-ares / dig)
│   │
│   ├── network/
│   │   ├── port_scanner.h        # TCP port probing (sync + async)
│   │   └── latency_manager.h     # Adaptive timeout management
│   │
│   ├── vendor/
│   │   └── vendor_detector.h     # Regex-based service vendor detection (vendors.json)
│   │
│   ├── output/
│   │   └── result_handler.h      # JSON/CSV/TEXT/REPORT output formatting
│   │
│   └── distributed/
│       ├── orchestrator.h        # Task distribution & worker coordination
│       ├── distributed_queue.h   # Batch queue (ready/inflight/failed/done)
│       ├── kafka_transport.h     # Kafka message transport (optional)
│       ├── task_codec.h          # Task serialization/deserialization
│       ├── progress_store.h      # Distributed progress persistence
│       ├── ingestor.h            # Data ingestion
│       └── task_types.h          # Shared type definitions
│
├── src/scanner/
│   ├── main.cpp                  # Entry point (single-machine mode)
│   ├── distributed_main.cpp      # Entry point (distributed worker mode)
│   ├── distributed_ingest_main.cpp # Entry point (data ingestion mode)
│   ├── scanner.cpp               # Main loop (scan_loop, session orchestration)
│   ├── dns_resolver.cpp
│   ├── utils.cpp
│   │
│   ├── common/
│   │   ├── thread_pool.cpp
│   │   └── io_thread_pool.cpp
│   │
│   ├── core/
│   │   ├── session.cpp
│   │   ├── crash_inspector.cpp
│   │   └── progress_manager.cpp
│   │
│   ├── protocols/
│   │   ├── smtp_protocol.cpp
│   │   ├── pop3_protocol.cpp
│   │   ├── imap_protocol.cpp
│   │   ├── http_protocol.cpp
│   │   ├── ftp_protocol.cpp
│   │   ├── telnet_protocol.cpp
│   │   └── ssh_protocol.cpp
│   │
│   ├── output/
│   │   └── result_handler.cpp
│   │
│   ├── vendor/
│   │   └── vendor_detector.cpp
│   │
│   └── distributed/
│       ├── distributed_queue.cpp
│       ├── orchestrator.cpp
│       ├── kafka_transport.cpp
│       ├── task_codec.cpp
│       ├── progress_store.cpp
│       └── ingestor.cpp
│
├── config/
│   ├── scanner_config.json        # Scanner configuration
│   ├── scanner_config_2gb_optimized.json  # Low-memory config
│   └── vendors.json               # Vendor fingerprint patterns
│
├── fingerprint/                   # Python fingerprint pipeline
│   ├── import_scan_raw.py
│   ├── prepare_fingerprint_stage1.py
│   ├── build_fingerprint_stage3.py
│   ├── build_dual_library_stage4.py
│   └── ...
│
├── docs/
│   ├── ARCHITECTURE.md           # System architecture documentation
│   ├── CONFIGURATION.md           # Configuration guide
│   ├── comparison_with_smtp_banner.md  # SMTP Banner项目对比分析
│   ├── CROSS_COMPILE.md           # Cross-compilation guide (Mac → Linux)
│   ├── PRODUCTION_BUILD.md        # Production build guide (3 modes)
│   ├── MEMORY_LEAK_FIXES.md       # Memory leak fix summary
│   ├── MEMORY_LEAK_FIXES_CHECKLIST.md  # Leak fix checklist
│   ├── QUICK_REFERENCE.md         # CLI quick reference
│   ├── LOGGING_GUIDE.md           # Logging system guide
│   ├── buffer_optimization.md
│   ├── memory_optimization_guide.md
│   └── ... (other analysis docs)
│
├── tests/
│   ├── chaos_distributed_local.sh # Distributed chaos test
│   └── ... (benchmarks)
│
└── result/                        # Output directory (gitignored)
│   ├── core/
│   │   ├── session.cpp
│   │   ├── progress_manager.cpp
│   │   └── crash_inspector.cpp   # Platform-specific (Linux/macOS)
│   │
│   ├── protocols/
│   │   ├── smtp_protocol.cpp
│   │   ├── pop3_protocol.cpp
│   │   ├── imap_protocol.cpp
│   │   ├── http_protocol.cpp
│   │   ├── ftp_protocol.cpp
│   │   ├── telnet_protocol.cpp
│   │   └── ssh_protocol.cpp
│   │
│   ├── vendor/
│   │   └── vendor_detector.cpp
│   │
│   └── output/
│       └── result_handler.cpp
│
├── config/
│   ├── scanner_config.json        # Default config
│   ├── scanner_config_2gb_optimized.json
│   └── vendors.json               # Vendor patterns
│
├── tests/
│   ├── run_io_thread_benchmark.sh # Performance test
│   └── test_cidr_input.txt        # Test data
│
├── data/
│   └── (Country IP databases)     # JP_ip.txt, US_ip.txt, etc.
│
└── build/
    └── scanner                    # Compiled executable
```

## 🔍 Supported Protocols

### Email Services

| Protocol | Port | Status | Vendor Detection |
|----------|------|--------|------------------|
| **SMTP** | 25, 587, 465 | ✅ Full support | Yes (Gmail, Outlook, etc.) |
| **IMAP** | 143, 993 | ✅ Full support | Yes |
| **POP3** | 110, 995 | ✅ Full support | Yes |
| **HTTP** | 80, 443 | ✅ Full support | Via server headers |

### Other Services

| Protocol | Port | Status | Notes |
|----------|------|--------|-------|
| **FTP** | 21 | ✅ Implemented | Server version detection |
| **Telnet** | 23 | ✅ Implemented | Server banner capture |
| **SSH** | 22 | ✅ Implemented | Version string extraction |

## 📈 Advanced Usage

### Resume from Checkpoint

```bash
# Initial scan (auto-creates checkpoint)
./build/scanner --domains targets.txt --scan -o results.json

# If interrupted (Ctrl+C), a progress file is created:
# results/targets.txt.progress.json

# Resume scanning (auto-detects checkpoint)
./build/scanner --domains targets.txt --scan -o results.json
# Continues from last checkpoint automatically
```

### Monitoring in Real-Time

**InfoRelease mode** provides INFO logs for monitoring:

```bash
# Build with logging
./build.sh InfoRelease

# Run with log file
./build/scanner --domains targets.txt --scan \
  --log-file /var/log/scanner.log

# Monitor in another terminal
tail -f /var/log/scanner.log
```

**Sample Output:**
```
[2025-01-13 10:30:45.123] [INFO] [CORE] Scanner started: 8 scan threads, 4 I/O threads
[2025-01-13 10:30:46.456] [INFO] [CORE] Loading targets: 100000 IPs from targets.txt
[2025-01-13 10:30:47.789] [INFO] [CORE] Scan in progress: 5234/100000 (5.23%), 1450 open ports
[2025-01-13 10:35:12.111] [INFO] [CORE] Scan completed: 100000 targets, 8450 open ports found
[2025-01-13 10:35:12.234] [ERROR] [NETWORK] Connection timeout: 192.168.1.5:22 after 3000ms
```

### Custom Protocol Implementation

To add a new protocol, inherit from `ProtocolBase`:

```cpp
// include/scanner/protocols/custom_protocol.h
class CustomProtocol : public ProtocolBase {
public:
    std::string protocol_name() const override { return "CUSTOM"; }
    std::vector<uint16_t> default_ports() const override { return {9000}; }
    
    void probe_async(const ProbeContext& ctx) override {
        // Your async probe logic here
        auto callback = [this, ctx](const std::error_code& ec, ...) {
            if (!ec) {
                ctx.on_success("CUSTOM", "version string", ctx.port);
            }
        };
        // Start async operation
    }
};
```

Register in [src/scanner/scanner.cpp](src/scanner/scanner.cpp):
```cpp
protocols_.push_back(std::make_unique<CustomProtocol>());
```

## 🚀 Production Deployment

See [PRODUCTION_BUILD.md](PRODUCTION_BUILD.md) for complete deployment guide.

### Three Build Options

```bash
# Maximum Performance (no logging)
./build.sh Release

# Production Monitoring (INFO + ERROR)
./build.sh InfoRelease

# Development / Debugging (all logs)
./build.sh Debug
```

### Server Deployment

```bash
# Copy binary to server
scp build/scanner user@server:/opt/scanner/

# Create directories
ssh user@server 'mkdir -p /var/log/scanner /var/lib/scanner'

# Run with monitoring
ssh user@server '/opt/scanner/scanner \
  --domains /data/ips.txt \
  --scan \
  --log-file /var/log/scanner/scan.log \
  --progress-file /var/lib/scanner/scan.progress'

# Monitor
ssh user@server 'tail -f /var/log/scanner/scan.log'
```

## 🔨 Build Modes Comparison

| Feature | Release | InfoRelease | Debug |
|---------|---------|-------------|-------|
| **Throughput** | 2600-3000/s | 2500-2900/s | 800-1200/s |
| **Memory** | 40-60MB | 45-70MB | 60-90MB |
| **Logging** | None | INFO+ERROR | All Levels |
| **Binary Size** | ~15MB | ~16MB | ~25MB |
| **Startup** | <1ms | <1ms | 50-100ms |
| **Use Case** | Pure performance | Monitoring | Development |

### Logging Architecture

Using compile-time conditional logging (`if constexpr`):

- **Release:** All INFO statements optimized out (zero overhead)
- **InfoRelease:** INFO + ERROR compiled in
- **Debug:** All levels (TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL)

Result: **No runtime logging checks**, all decisions at compile-time.

## 🐛 Troubleshooting

### Build Issues

```bash
# Check dependencies
brew list boost c-ares fmt nlohmann-json spdlog  # macOS
apt list --installed | grep -E 'boost|c-ares|fmt|nlohmann'  # Ubuntu

# Rebuild with verbose output
cmake --build build --verbose

# Check compiler flags
cmake -S . -B build -DCMAKE_VERBOSE_MAKEFILE=ON
```

### Runtime Issues

```bash
# Check configuration
cat config/scanner_config.json

# Verify network connectivity
ping -c 1 <target_ip>
nc -zv <target_ip> 25  # Test specific port

# Enable debug logging
./build.sh Debug
./build/scanner --domains test.txt --scan --verbose
```

### Performance Issues

If throughput < 1000/sec:
1. Check timeout setting (default 3000ms, increase to 5000ms for unreliable networks)
2. Check thread count (`--threads` flag)
3. Run debug build to identify bottlenecks
4. See [PERF_ANALYSIS.md](docs/ARCHITECTURE.md) for optimization details

## 📚 Documentation

- **[README.md](README.md)** (this file) - Overview and quick start
- **[PRODUCTION_BUILD.md](PRODUCTION_BUILD.md)** - Deployment guide with 3 build modes
- **[PRODUCTION_BUILD_REFACTORING.md](PRODUCTION_BUILD_REFACTORING.md)** - Technical details of logging refactor
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Detailed architecture design
- **[config/scanner_config.json](config/scanner_config.json)** - Configuration reference

## 📝 License

See [LICENSE](LICENSE) file.

## 🤝 Contributing

Contributions welcome! To add a new protocol:

1. Create header in `include/scanner/protocols/`
2. Create implementation in `src/scanner/protocols/`
3. Register in [src/scanner/scanner.cpp](src/scanner/scanner.cpp)
4. Update configuration in [config/vendors.json](config/vendors.json)
5. Run tests: `./tests/run_io_thread_benchmark.sh`

---

**Last Updated:** January 2025  
**Performance Tested:** 2600-3000 IPs/sec on 2-core 3GB datacenter VM  
**Status:** Production Ready ✅

# Resume from checkpoint (automatic)
# Simply run the same command again - the scanner detects the progress file and resumes
./build/scanner --domains large_list.txt --scan -o ./result
# Output: [info] Checkpoint loaded: 192.168.1.100 (processed: 5000, successful: 1200)

# Clear checkpoint and restart from beginning
rm result/large_list.txt.progress.json
./build/scanner --domains large_list.txt --scan -o ./result
```

#### Checkpoint File Format

Progress files are saved as `{output_dir}/{input_filename}.progress.json`:

```json
{
  "last_ip": "192.168.1.100",
  "processed_count": 5000,
  "successful_count": 1200,
  "timestamp": "2024-01-19 14:30:45",
  "input_file_hash": "c8f0_1705680645_18446744073709551615"
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `last_ip` | string | Last processed IP/domain (resume point) |
| `processed_count` | integer | Total targets processed (including failed) |
| `successful_count` | integer | Number of successful probes |
| `timestamp` | string | UTC timestamp of last save (YYYY-MM-DD HH:MM:SS) |
| `input_file_hash` | string | File fingerprint (size + mtime + header CRC). Prevents resuming with modified input files |

**Features**:
- ✅ **Automatic Detection**: No command-line flags needed - resume happens automatically
- ✅ **File Validation**: If input file changes (hash mismatch), checkpoint is ignored and scan restarts
- ✅ **Periodic Saving**: Checkpoint saved every N operations (configurable via `checkpoint_interval`)
- ✅ **Thread-Safe**: Internal locking ensures safe concurrent access
- ✅ **Auto-Skip**: Resumes skip all processed targets transparently

**Configuration** (in `config/scanner_config.json`):
```json
{
  "scanner": {
    "checkpoint_interval": 1000      // Save progress every 1000 operations
  }
}
```

### Input File Formats

The scanner supports multiple input formats:

#### 1. Domain Names (One per line)
```
gmail.com
outlook.com
qq.com
163.com
example.com
```

#### 2. IP Addresses (Auto-detected, no DNS lookup)
```
8.8.8.8
114.114.114.114
1.1.1.1
```

#### 3. Mixed Domains and IPs
```
# Google DNS
8.8.8.8
# Baidu
baidu.com
# Cloudflare DNS  
1.1.1.1
# Alibaba
alibaba.com
```

#### 4. IP Ranges (CSV format: start_ip,end_ip)
```
192.168.1.1,192.168.1.10
10.0.0.0,10.0.0.255
```

**Smart Features**:
- **Auto IP Detection**: If input is valid IPv4, skips DNS resolution (faster)
- **Comments**: Lines starting with `#` or `;` are ignored
- **Whitespace**: Leading/trailing whitespace is automatically trimmed
- **Large Scale**: Producer-consumer architecture with backpressure handles 1M+ targets
- **Memory Efficient**: Targets queue size limited to `targets_max_size` (default: 1M)

## Architecture Overview

### Core Design

This project uses a **dual-thread-pool architecture** for optimal performance:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Main Thread                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Scanner Orchestrator                 │    │
│  └───────────────┬─────────────────────────────────┘    │
│                  │                                       │
│         ┌────────┴────────┐                              │
│         │                 │                              │
│    Scan Pool       IO Pool                        │
│  (CPU threads)   (IO threads)                         │
└─────────────────────────────────────────────────────────────────┘
```

### Component Hierarchy

```
protocol-scanner/
├── include/scanner/
│   ├── core/
│   │   ├── scanner.h          # Main orchestrator class
│   │   ├── session.h         # Per-domain scan session
│   │   └── task_queue.h     # Thread-safe task queue
│   ├── protocols/
│   │   ├── protocol_base.h   # Abstract interface
│   │   ├── smtp_protocol.h   # SMTP implementation
│   │   ├── pop3_protocol.h   # POP3 implementation
│   │   ├── imap_protocol.h   # IMAP implementation
│   │   └── http_protocol.h   # HTTP implementation
│   ├── dns/
│   │   └── dns_resolver.h   # DNS resolver interface
│   ├── common/
│   │   ├── thread_pool.h      # CPU-bound thread pool
│   │   ├── io_thread_pool.h  # IO-bound thread pool
│   │   └── logger.h         # Logging utilities
│   ├── output/
│   │   └── result_handler.h  # Output formatting
│   └── vendor/
│       └── vendor_detector.h # Vendor identification
├── src/scanner/           # Implementation files
├── config/                # Configuration files
│   ├── scanner_config.json
│   └── vendors.json
└── build/                 # Build artifacts
```

## Core Components

### 0. ProgressManager (Checkpoint & Resume)

**File**: `include/scanner/core/progress_manager.h`

The ProgressManager handles **automatic checkpoint and resume** functionality:

**Key Responsibilities**:
- Save scan progress periodically to `{output_dir}/{input_filename}.progress.json`
- Load and validate checkpoint when scan restarts
- Detect input file changes using file hash to prevent stale checkpoints
- Enable transparent resume from last processed target

**Checkpoint Structure**:

```json
{
  "last_ip": "192.168.1.100",           // Last processed target (resume point)
  "processed_count": 5000,               // Total targets scanned
  "successful_count": 1200,              // Successful probes found
  "timestamp": "2024-01-19 14:30:45",   // UTC save time
  "input_file_hash": "c8f0_1705680645_..." // File fingerprint for validation
}
```

**Field Descriptions**:

| Field | Purpose |
|-------|---------|
| `last_ip` | The exact IP/domain to resume from. Scans skip all targets until reaching this point. |
| `processed_count` | Total targets processed (both successful and failed). Used for progress reporting. |
| `successful_count` | Count of successful protocol connections found. Updated in real-time. |
| `timestamp` | ISO timestamp of last checkpoint save. Helps track scan timeline. |
| `input_file_hash` | Fingerprint combining file size + modification time + header CRC. **If input file is modified, hash won't match and resume is disabled (full restart required).** |

**Usage Pattern**:

```
Scan Started
    ↓
Check for existing checkpoint → Found
    ↓
Load checkpoint, skip to last_ip
    ↓
Resume scanning from next target
    ↓
Every N operations: Save new checkpoint (update counts)
    ↓
Scan Complete → Delete checkpoint file
```

**Key Features**:
- ✅ **Automatic Detection**: No flags needed - runs transparently
- ✅ **Validation**: File hash prevents using stale checkpoints with modified inputs
- ✅ **Atomic Operations**: Thread-safe with mutex protection
- ✅ **Configurable Interval**: Control checkpoint frequency via `checkpoint_interval` config

**Example**: Resuming a 100k target scan after interruption:
```bash
# First run interrupted after 5000 targets
./build/scanner --domains 100k_ips.txt --scan -o ./result
# Creates: result/100k_ips.txt.progress.json

# Second run resumes automatically from target 5001
./build/scanner --domains 100k_ips.txt --scan -o ./result
# [info] Checkpoint loaded: 192.168.1.100 (processed: 5000, successful: 1200)
```

### 1. Scanner (Main Orchestrator)

**File**: `include/scanner/core/scanner.h`

The Scanner class is the main entry point that:
- Manages **scan pool** (for CPU tasks) and **IO pool** (for network I/O)
- Creates `ScanSession` instances for each domain
- Coordinates concurrent probing across multiple protocols and ports
- Collects results via thread-safe queue

**Key Methods**:
- `scan_domains()`: Batch scan multiple domains
- `init_protocols()`: Initialize enabled protocol handlers
- `start()`: Main coordination loop

### 2. ScanSession (Per-Domain Coordinator)

**File**: `include/scanner/core/session.h`

Each domain gets its own ScanSession that:
- Resolves DNS (A + MX records)
- Maintains per-protocol probe queues
- Tracks task completion status atomically
- Calls completion callback when all probes finish

**State Machine**:
```
PENDING → DNS_RUNNING → PROBE_RUNNING → COMPLETED
                ↓              ↓
              TIMEOUT         FAILED
```

### 3. Thread Pools

#### ScanThreadPool (CPU-bound)
**File**: `include/scanner/common/thread_pool.h`

- Generic thread pool using `std::jthread`
- Submits probe tasks to protocol handlers
- Each task runs async_probe() which posts to IO executor

#### IoThreadPool (IO-bound)
**File**: `include/scanner/common/io_thread_pool.h`

- Manages multiple `asio::io_context` instances
- One io_context per IO thread for parallel network operations
- **TrackingExecutor**: Decorates executor to track pending tasks for load balancing

**Load Balancing**:
- Tracks pending tasks per io_context via `std::atomic<std::size_t>`
- `choose_least_loaded_index()` selects least busy context

### 4. Protocol Implementations

All protocols implement the `IProtocol` interface:

```cpp
class IProtocol {
public:
    virtual std::string name() const = 0;
    virtual std::vector<Port> default_ports() const = 0;
    virtual Timeout default_timeout() const = 0;
    
    virtual void async_probe(
        const std::string& host,
        Port port,
        Timeout timeout,
        boost::asio::any_io_executor exec,
        std::function<void(ProtocolResult&&)> on_complete
    ) = 0;
};
```

#### SMTP Protocol
**File**: `include/scanner/protocols/smtp_protocol.h`

- Connects and sends `EHLO` command
- Parses ESMTP capabilities (PIPELINING, STARTTLS, SIZE, AUTH, etc.)
- Default ports: 25, 465, 587, 2525

#### POP3 Protocol
**File**: `include/scanner/protocols/pop3_protocol.h`

- Connects and reads server banner
- Parses CAPA response (STLS, SASL support)
- Default ports: 110, 995

#### IMAP Protocol
**File**: `include/scanner/protocols/imap_protocol.h`

- Connects and sends `CAPABILITY` command
- Parses capabilities (STARTTLS, QUOTA, ACL, etc.)
- Default ports: 143, 993

#### HTTP Protocol
**File**: `include/scanner/protocols/http_protocol.h`

- Sends HTTP HEAD/GET request
- Extracts Server header for vendor detection
- Default ports: 80, 443, 8080

### 5. DNS Resolver

**File**: `include/scanner/dns/dns_resolver.h`

Uses **c-ares** library for async DNS resolution:
- `CAresResolver`: Production async resolver
- `DigResolver`: Fallback command-line resolver

**Supported Queries**:
- A records (domain → IP)
- MX records (mail servers)

**Optimization Features**:
- **Auto IP Detection**: Detects pre-resolved IPv4 addresses and skips DNS queries entirely
  - Input: `8.8.8.8` → Skips DNS, goes directly to protocol probes
  - Input: `baidu.com` → Performs DNS resolution, then protocol probes
- **Async Resolution**: Non-blocking c-ares callback mechanism
- **Timeout Management**: Configurable DNS timeout with automatic retries
- **Memory Safe**: Uses heap-allocated shared_ptr for async callback context

### 6. Logging System

**File**: `include/scanner/common/logger.h`

Built on **spdlog**:
- Console + optional file logging
- Log levels: TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
- Thread-safe singleton instance

## Configuration

Edit `config/scanner_config.json`:

```json
{
  "scanner": {
    "io_thread_count": 12,          // IO 线程（网络 I/O）推荐 8-16
    "cpu_thread_count": 4,          // CPU 线程（轻量封装）推荐 4-8
    "thread_count": 8,              // 废弃：保持兼容
    "batch_size": 2000,             // 单批并发，推荐 1000-3000
    "dns_timeout_ms": 1000,
    "probe_timeout_ms": 5000,        // 推荐 5000 (5s)，平衡速度与准确性
                                     // 0=动态超时(仅适合高质量网络)
    "retry_count": 1,
    "only_success": true,            // 仅输出成功结果
    "max_work_count": 5000           // 推荐 3000-5000，⚠️ 不要设为 0
                                     // 系统会自动根据 FD 上限调整此值
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
    "resolver_type": "cares",
    "max_mx_records": 16,
    "timeout_ms": 5000
  }
}
```

**Output 配置**
```json
"output": {
  "format": ["text", "csv"],   // 允许多格式，首个为主输出
  "write_mode": "stream",      // stream: 边扫边写；final: 扫描结束一次写
  "directory": "./result",
  "enable_json": true,
  "enable_csv": true,
  "enable_report": false,
  "to_console": false
}
```

**Logging 配置**
```json
"logging": {
  "level": "INFO",
  "console_enabled": false,
  "file_enabled": false,
  "file_path": "./scanner.log"
}
```

**Vendor 配置**
```json
"vendor": {
  "enabled": true,
  "pattern_file": "./config/vendors.json",  // 默认路径
  "similarity_threshold": 0.7
}
```

## Performance Tuning

### Timeout Settings

**Recommended: `probe_timeout_ms: 5000` (5 seconds)**

Based on extensive benchmarks, 5s timeout provides the best balance:

| Timeout | Speed (targets/s) | Accuracy | Use Case |
|---------|------------------|----------|----------|
| 2-3s | ⚡ Fast (800+) | ⚠️ Low (misses slow servers) | Quick recon only |
| **5s** | ✅ **Fast (700-900)** | ✅ **High** | **Recommended for most scenarios** |
| 10s | 🐌 Slow (450-500) | ✅✅ Highest | High-accuracy audits, poor networks |
| 0 (dynamic) | ⚡⚡ Very Fast (800+) | ⚠️⚠️ Very Low* | Good networks only* |

*Dynamic timeout (0) is **2x faster but detects only ~3-5% of targets** compared to fixed 5s timeout. Only use in excellent network conditions.

### Thread Count

- **Scan Pool**: 4-8 threads (CPU-bound task submission)
- **IO Pool**: 4-8 io_context instances (parallel network ops)

### Concurrency & Batch Size

Concurrency is controlled by the following parameters:

- **max_work_count**: The HARD limit on the number of active, concurrent targets being scanned.
  - **Recommended Values** (based on 65k IP benchmark):
    - Small scans (<10k IPs): 1000-2000
    - Medium scans (10k-100k IPs): **3000-5000** ✅ **Optimal**
    - Large scans (>100k IPs): 5000-8000
  - **⚠️ DO NOT set to 0**: This auto-sets to 50,000 which is TOO HIGH and causes:
    - Resource contention (slower performance)
    - Port exhaustion (TIME_WAIT)
    - Lower accuracy due to packet loss
    - Benchmark: 0 → 119s vs 5000 → 71s (same input)
  - **Formula**: `max_work_count ≤ (FD_limit - 150) / num_enabled_protocols`
    - Each session uses 1 FD per enabled protocol
    - Reserve ~150 FDs for system/libs/logging
    - Example: FD=65535, 3 protocols → max ~21,795 sessions
  - **Auto-Adjustment**: If your configured value exceeds system limits, it will be auto-capped with a warning.
  
- **batch_size**: Controls how many new tasks are dispatched to the thread pool in one loop iteration.
  - Small (100-500): Conservative
  - Medium (1000-2000): **Balanced (Recommended)**
  - Large (5000+): Aggressive, ensure adequate `max_work_count`

**Tip**: If you see low CPU/Network usage, first increase `max_work_count`. Simply increasing thread count often helps less than increasing the concurrency window.

### Protocol Selection Impact

The number of enabled protocols directly affects scan speed:

| Protocols Enabled | Speed (65k IPs) | Detections | Notes |
|-------------------|----------------|------------|-------|
| 1 protocol (FTP) | 81-119s | 360-1599 | Fastest, limited coverage |
| 2 protocols (FTP+TELNET) | **71s** ✅ | 1599 | **Best speed/coverage balance** |
| 3 protocols (FTP+SSH+TELNET) | 89s | 1756 | Most comprehensive |

**Recommendations**:
- **Speed priority**: Enable only protocols you care about (e.g., just FTP or SSH)
- **Coverage priority**: Enable all relevant protocols, accept slower speed
- **Balanced**: Start with 2-3 most common protocols, add more if needed

*Benchmark conditions: probe_timeout=5s, max_work_count=5000, 65536 IPs*

### Dynamic Timeout (Adaptive RTT)

Set `probe_timeout_ms: 0` to enable dynamic timeout based on RTT (Round-Trip Time):
- Uses EWMA (Exponential Weighted Moving Average) per /24 subnet
- Automatically adapts: fast networks get shorter timeouts, slow networks get longer
- Default range: 800ms - 4000ms (can be adjusted in `latency_manager.h`)
- **Pros**: ⚡ Fast (800+ targets/sec, ~30% faster than 5s)
- **Cons**: ⚠️ **VERY LOW accuracy** (~3-5% detection rate vs 5s timeout)
  - Benchmark: Dynamic=56 detected vs Fixed 5s=1756 detected (same input)

**When to use**:
- ✅ Local network / data center scans (low latency, high quality)
- ✅ Quick reconnaissance where speed >> accuracy
- ❌ **NOT recommended for Internet scans** (too many false negatives)
- ❌ Production audits or compliance scans (use fixed 5-10s)

**Recommendation**: Start with fixed 5s timeout. Only switch to dynamic if:
1. Network quality is excellent (LAN/DC)
2. You've verified detection rates are acceptable for your use case
3. Speed is critical and you can tolerate missing 95% of targets

### DNS Optimization

For better performance when scanning large IP lists:

```bash
# Pre-resolved IPs (no DNS overhead, fastest)
# Example: AD.csv with 1M IPs
./build/scanner --domains ad.csv --scan

# Mixed domains and IPs (auto-optimized)
# IPs skip DNS, domains perform resolution
./build/scanner --domains mixed.txt --scan

# Pure domains (performs DNS for all)
./build/scanner --domains domains.txt --scan
```

**Typical Performance**:
- Pure IPs: ~10,000-50,000 targets/sec (network-limited)
- Mixed: ~5,000-20,000 targets/sec (DNS adds latency)
- Pure domains: ~1,000-5,000 targets/sec (DNS resolution bottleneck)

### Input File Best Practices

For large-scale scans (1M+ targets):

1. **Use pre-resolved IPs when possible**
   ```
   # Fast: Direct IP addresses
   192.168.1.1
   192.168.1.2
   ```

2. **Batch by network/country**
   ```
   # Use IP ranges instead of individual IPs
   # Format: start_ip,end_ip (auto-expands)
   192.168.1.0,192.168.1.255
   ```

3. **Tune targets_max_size in config**
   ```json
   "scanner": {
     "targets_max_size": 1000000  // Adjust based on available memory
   }
   ```

4. **Monitor memory usage**
   - Each target in queue: ~100-200 bytes
   - 1M targets = ~100-200 MB queue memory
   - Actual memory will be higher due to protocol objects

## Build Options

### Disable Logging for Production

For maximum performance in production environments, you can disable logging at compile time:

```bash
# Build without logging support
EXTRA_CMAKE_ARGS="-DENABLE_LOGGING=OFF" ./build.sh Release clean
```

Benefits:
- Zero runtime logging overhead
- Smaller binary size
- No dependency on spdlog at runtime

Note: When logging is disabled, all LOG_* macros become no-ops.

### Custom CMake Options

You can pass additional CMake options via `EXTRA_CMAKE_ARGS`:

```bash
# Enable logging (default)
EXTRA_CMAKE_ARGS="-DENABLE_LOGGING=ON" ./build.sh

# Custom install prefix
EXTRA_CMAKE_ARGS="-DCMAKE_INSTALL_PREFIX=/usr/local" ./build.sh

# Multiple options
EXTRA_CMAKE_ARGS="-DENABLE_LOGGING=OFF -DCMAKE_BUILD_TYPE=Release" ./build.sh
```

## Adding New Protocols

1. **Create protocol header** (`include/scanner/protocols/your_protocol.h`):

```cpp
#pragma once
#include "protocol_base.h"
#include <boost/asio.hpp>

namespace scanner {

class YourProtocol : public IProtocol {
public:
    std::string name() const override { return "YOUR_PROTOCOL"; }
    std::vector<Port> default_ports() const override { return {123, 456}; }
    Timeout default_timeout() const override { return Timeout(3000); }
    
    void async_probe(
        const std::string& host,
        Port port,
        Timeout timeout,
        boost::asio::any_io_executor exec,
        std::function<void(ProtocolResult&&)> on_complete
    ) override;

    void parse_capabilities(
        const std::string& response,
        ProtocolAttributes& attrs
    ) override;
};

} // namespace scanner
```

2. **Implement** (`src/scanner/protocols/your_protocol.cpp`):

```cpp
#include "scanner/protocols/your_protocol.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>

namespace scanner {

void YourProtocol::async_probe(...) {
    // Use boost::asio for async operations
    // Call on_complete(std::move(result)) when done
}
} // namespace scanner
```

3. **Register in Scanner** (`src/scanner/scanner.cpp`):

```cpp
void Scanner::init_protocols() {
    // ... existing protocols ...
    if (config_.enable_your_protocol) 
        protocols_.push_back(std::make_unique<YourProtocol>());
}
```

4. **Add to CMakeLists.txt**:

```cmake
set(PROTOCOL_SRCS
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/your_protocol.cpp
    # ... other protocols
)
```

## Output Format

### Text Output

```
Scan Results
============
example.com (93.184.216.34)
  [SMTP] mx1.example.com:25 -> OK
    banner: 220 mx1.example.com ESMTP
    features: PIPELINING=1, STARTTLS=1, SIZE=10240000, AUTH=PLAIN LOGIN
  [IMAP] mail.example.com:143 -> OK
    banner: * OK IMAP4rev1 Server
```

### Command Line Options

```
  -h, --help          Show help
  -v, --version       Show version
  -d, --domains FILE   Domain list file (required)
  --scan              Run full protocol scan
  --dns-test          DNS test only (no probing)
  -t, --threads N     Number of threads (default: 4)
  --timeout MS         Probe timeout in ms (default: 5000)
  --protocols LIST     Comma-separated: SMTP,POP3,IMAP,HTTP
  --no-smtp           Disable SMTP
  --no-pop3           Disable POP3
  --no-imap           Disable IMAP
  --enable-http        Enable HTTP
  --only-success       Only output successful probes (hide failures)
  --verbose            Debug logging
  -q, --quiet         Suppress non-error output
  -o, --output DIR     Output directory for results
  -f, --format FORMAT  Output format: text, json, csv, report
```

## Dependencies

- **C++20** compiler (Clang 12+, GCC 10+)
- **Boost.Asio** 1.70+ (system, program_options, filesystem)
- **OpenMP** (libomp on macOS) - optional
- **nlohmann/json** (single header, auto-downloaded)
- **c-ares** (DNS resolution)
- **spdlog** (logging)

### Install on macOS

```bash
brew install boost libomp c-ares spdlog cmake
```

### Install on Linux (Ubuntu)

```bash
sudo apt-get install cmake \
    libboost-all-dev \
    libomp-dev \
    libc-ares-dev \
    libspdlog-dev
```

## System Requirements & Limits

To run this scanner at high concurrency (e.g., >1000 targets), you should be aware of OS limits.

### Automatic System Limit Detection

**The scanner now automatically detects and adjusts to system limits:**

- **FD Auto-Raising**: On startup, the scanner attempts to raise the soft FD limit to the hard limit, and if possible, up to 65535.
- **Auto-Capping max_work_count**: If configured `max_work_count` exceeds available file descriptors, it will be automatically reduced with a warning in logs.
- **Smart Recommendations**: The scanner calculates usable FDs (total - reserved for system/libs) and suggests safe `max_work_count` values.

**Logs will show:**
```
[info] Successfully raised FD limit from 256 to 65535
[info] System FD Limit: 65535 (Usable: 65385)
[info] Auto-setting max_work_count to 5000 based on system FD limit
```

### macOS Limits (Manual Tuning)

While auto-detection handles most cases, you may still need manual tuning for extreme concurrency:

1. **File Descriptors (FD)**:
   The scanner will try to raise this automatically, but you can pre-set it:
   ```bash
   # Check current limit
   ulimit -n
   # Increase to max (only valid for current shell)
   ulimit -n 65535
   # Note: restart current shell or run command in new terminal after setting this
   ```

2. **Ephemeral Ports**:
   By default, macOS only allows ports 49152-65535 (~16k ports) for outgoing connections.
   ```bash
   # Check range
   sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last
   # approx 16383 ports available
   ```
   If you have >16k in-flight connections (or in TIME_WAIT), you will run out of ports.
   **Solution**: Increase range (requires sudo):
   ```bash
   sudo sysctl -w net.inet.ip.portrange.first=10000
   ```

3. **TIME_WAIT State (MSL)**:
   Closed connections stay in TIME_WAIT for 2*MSL (default 15000ms * 2 = 30s).
   High concurrency scans generate tons of TIME_WAIT sockets, exhausting ports.
   ```bash
   # Check MSL (default 15000 = 15s)
   sysctl net.inet.tcp.msl
   # Reduce to 1s to recycle ports faster (risky but effective for scanning)
   sudo sysctl -w net.inet.tcp.msl=1000
   ```

### Hardware Network Limits

- **Router NAT Table**: Home routers often crash or drop packets if NAT table exceeds ~2000-4000 concurrent sessions.
- **ISP Limits**: Some ISPs block high-rate SYN packets (scan detection).

## Troubleshooting

### Slow Scan Performance

If scanning is slow:
1. Reduce `probe_timeout_ms` (default: 5000ms)
2. Increase `thread_count` (up to CPU core count × 2)
3. Reduce `batch_size` to limit concurrent probes
4. Check network connectivity/firewall

### Connection Refused

Many targets returning connection refused is normal - they may not have the service running.

### DNS Resolution Failures

- Check `dns_timeout_ms` in config
- Ensure network DNS servers are reachable
- Try `--dns-test` mode to verify DNS resolver

## License

This project is licensed under the **Polyform Noncommercial License 1.0.0**.

- **Personal/Research Use**: Free and unrestricted.
- **Commercial Use**: Requires explicit written authorization or a separate commercial license.

See the [LICENSE](LICENSE) file for the full license text.

### Third-Party Licenses

This project uses the following open-source libraries:

- **Boost C++ Libraries**: [Boost Software License 1.0](https://www.boost.org/LICENSE_1_0.txt)
- **nlohmann/json**: [MIT License](https://github.com/nlohmann/json/blob/develop/LICENSE.MIT)
- **c-ares**: [MIT License](https://github.com/c-ares/c-ares/blob/master/LICENSE.md)
- **spdlog**: [MIT License](https://github.com/gabime/spdlog/blob/v1.x/LICENSE)
- **fmt**: [MIT License](https://github.com/fmtlib/fmt/blob/master/LICENSE)

