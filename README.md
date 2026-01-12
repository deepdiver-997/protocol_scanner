# Protocol Scanner

A high-performance, modular network protocol scanner for email services and other network services.

## Features

- 🔍 **Multi-Protocol Support**: SMTP, POP3, IMAP, HTTP
- 🚀 **High Performance**: Thread pool + IO thread pool dual-layer architecture
- 🧩 **Modular Architecture**: Easy to add new protocols via inheritance
- 📊 **Multiple Output Formats**: JSON, CSV, Text
- 🏢 **Vendor Detection**: Identify email service providers (Gmail, Outlook, QQ, etc.)
- ⚙️ **Configurable**: JSON-based configuration
- 📝 **Comprehensive Logging**: spdlog-based logging system
- 🎯 **DNS Resolution**: c-ares based DNS resolver with MX record support

## Quick Start

### Build

```bash
# Navigate to project directory
cd /path/to/protocol-scanner

# Quick build (Release mode)
./build.sh

# Debug build
./build.sh Debug

# Clean build
./build.sh Release clean

# Disable logging for maximum performance
EXTRA_CMAKE_ARGS="-DENABLE_LOGGING=OFF" ./build.sh Release clean
```

### Basic Usage

```bash
# DNS resolution test (fast, no protocol probing)
./build/scanner --domains test_domains.txt --dns-test

# Full protocol scan
./build/scanner --domains test_domains.txt --scan

# Scan with specific protocols
./build/scanner --domains test_domains.txt --protocols SMTP,IMAP --scan

# Scan with custom threads and timeout
./build/scanner --domains test_domains.txt --threads 16 --timeout 3000 --scan

# Verbose output
./build/scanner --domains test_domains.txt --scan --verbose

# Only show successful connections (hide failures)
./build/scanner --domains test_domains.txt --scan --only-success

# Output to JSON file
./build/scanner --domains test_domains.txt --scan -f json -o ./result

# Output to CSV file
./build/scanner --domains test_domains.txt --scan -f csv -o ./result

# Quick smoke test (pre-configured test file)
./tests/run_smoke.sh
```

### Example Domain File

```
gmail.com
outlook.com
qq.com
163.com
example.com
```

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
    "thread_count": 8,              // Scan pool threads
    "batch_size": 100,              // Max concurrent probes
    "dns_timeout_ms": 5000,         // DNS query timeout
    "probe_timeout_ms": 5000,       // Single probe timeout
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
    "resolver_type": "cares",
    "max_mx_records": 16,
    "timeout_ms": 5000
  }
}
```

## Performance Tuning

### Timeout Settings

The default `probe_timeout_ms: 5000` is reasonable for most scenarios:

| Timeout | Pros | Cons |
|---------|-------|-------|
| 3000ms  | Fast scan | May miss slow servers |
| 5000ms  | **Balanced** | None |
| 10000ms | More reliable | Slow on failures |

### Thread Count

- **Scan Pool**: 4-8 threads (CPU-bound task submission)
- **IO Pool**: 4-8 io_context instances (parallel network ops)

Total concurrent probes = `scan_pool_size × 2` (quota heuristic)

### Batch Size

Controls max in-flight probes:
- Small (10-50): Low memory, less parallelism
- Medium (100-500): **Balanced**
- Large (1000+): High parallelism, more memory usage

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

