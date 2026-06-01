# Protocol Scanner - Production Build Guide

## Overview

The scanner provides three build modes to suit different deployment scenarios:

### 1. **Release Mode** (Production - Silent)
```bash
./build.sh Release
```
- **Logging:** Completely disabled (compiled out)
- **Performance:** Maximum optimization (-O3, -DNDEBUG)
- **Binary Size:** Smallest
- **Use Case:** High-performance production deployments with zero logging overhead

**Binary Location:** `build/scanner`

### 2. **InfoRelease Mode** (Production - Monitoring)
```bash
./build.sh InfoRelease
```
- **Logging:** INFO + ERROR levels only (compiled in)
- **Performance:** Maximum optimization (-O3, -DNDEBUG)
- **Overhead:** Minimal (logging compiled with constant-folding on INFO statements)
- **Use Case:** Production with operational monitoring and observability

**Binary Location:** `build/scanner`

**Sample Logs:**
```
[INFO] [CORE] Scanner started: 4 scan threads, 1 I/O thread
[INFO] [CORE] Loading domains from: ip_list.txt
[INFO] [CORE] Scan completed: 125000 targets, 342 open ports found
[ERROR] [NETWORK] Connection timeout to 192.168.1.1:22 after 3000ms
```

### 3. **Debug Mode** (Development)
```bash
./build.sh Debug
```
- **Logging:** All levels (TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL)
- **Optimization:** Minimal (-O0, -g)
- **Debug Symbols:** Included
- **Use Case:** Development, debugging, and troubleshooting

**Binary Location:** `build/scanner`

**Sample Logs:**
```
[TRACE] [NETWORK] Attempting TCP connect to 192.168.1.1:22
[DEBUG] [CORE] Session created for target 192.168.1.1
[DEBUG] [DNS] Resolving scan.example.com...
[INFO] [CORE] Scan started at 2025-01-13 10:30:45 UTC
[WARN] [NETWORK] Retransmit for SMTP probe on 192.168.1.5:25
[ERROR] [FILE_IO] Failed to read checkpoint from scan.progress: Permission denied
```

## Clean Rebuild

To start fresh with a specific build type:

```bash
./build.sh Release clean
./build.sh InfoRelease clean
./build.sh Debug clean
```

The `clean` parameter removes the `build/` directory and rebuilds everything.

## Platform-Specific Optimizations

### Linux
- `-mtune=generic`: Portable across CPU architectures
- `-fno-plt`: Faster Position Independent Code (PIC)
- `-pipe`: Use pipes instead of temp files during compilation

### macOS
- `-march=native`: Use native CPU instructions
- Optimized for Apple Silicon (ARM64) and Intel (x86-64)

## Deployment Recommendations

### High-Volume Scanning (>10,000 targets/sec)
Use **Release** mode:
```bash
./build.sh Release
./build/scanner --domains /path/to/ips.txt --scan --timeout 3000 --threads 8
```

### Monitored Production (Balance Performance & Observability)
Use **InfoRelease** mode with centralized logging:
```bash
./build.sh InfoRelease
./build/scanner --domains /path/to/ips.txt --scan \
  --log-file /var/log/scanner/output.log \
  --progress-file /var/lib/scanner/scan.progress
```

### Development & Troubleshooting
Use **Debug** mode with verbose output:
```bash
./build.sh Debug
./build/scanner --domains /path/to/test_ips.txt --scan --timeout 5000
```

## Build Configuration Defaults

| Parameter | Release | InfoRelease | Debug |
|-----------|---------|-------------|-------|
| Optimization | `-O3` | `-O3` | `-O0` |
| Debug Info | None | None | `-g` |
| Logging | Disabled | INFO+ERROR | All Levels |
| Binary Size | ~15MB | ~16MB | ~25MB |
| Startup Time | <1ms | <1ms | 50-100ms |
| Memory Overhead | Minimal | Minimal | +20MB for debug info |

## Logging Architecture

The scanner uses compile-time conditional logging:

- **DEBUG/TRACE logs:** Only compiled in Debug mode (optimized out in Release/InfoRelease)
- **INFO logs:** Compiled into InfoRelease and Debug, optimized out in Release
- **ERROR/CRITICAL logs:** Always compiled in (present in all modes)

This approach ensures **zero performance penalty** for disabled log levels.

## Custom Build Configuration

To disable all logging in Release mode (maximum security/performance):

```bash
EXTRA_CMAKE_ARGS="-DENABLE_LOGGING=OFF" ./build.sh Release
```

To enable a custom CMake option:

```bash
EXTRA_CMAKE_ARGS="-DCUSTOM_OPTION=VALUE" ./build.sh Release
```

## Verification

Verify your build mode by checking the binary:

```bash
# Check for logging capability
strings build/scanner | grep "Memory\|Scan completed" > /dev/null && echo "Logging enabled" || echo "Logging disabled"

# Measure binary size
ls -lh build/scanner

# Quick functionality test
./build/scanner --help
```

## Performance Metrics

### Release Build (IP throughput on 2-core 3GB VM with 3s timeout)
- Expected: 2600-3000 IPs/sec
- Memory: 40-60MB peak
- CPU: 95-100% utilized

### InfoRelease Build (with INFO logging to disk)
- Expected: 2500-2900 IPs/sec (5-10% slower due to logging I/O)
- Memory: 45-70MB peak
- CPU: 95-100% utilized

### Debug Build
- Expected: 800-1200 IPs/sec (test only)
- Memory: 60-90MB peak
- CPU: 95-100% utilized
