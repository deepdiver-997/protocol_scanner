#include "scanner/core/resource_guard.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <unistd.h>
#include <sys/sysctl.h>

#ifdef __linux__
#include <sys/sysinfo.h>
#endif

namespace scanner {

static uint32_t read_linux_ephemeral_ports() {
    std::ifstream f("/proc/sys/net/ipv4/ip_local_port_range");
    if (!f) return 0;
    uint32_t lo, hi;
    f >> lo >> hi;
    return hi - lo + 1;
}

static uint64_t read_linux_mem_available_mb() {
#ifdef __linux__
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        return (si.freeram + si.bufferram) * si.mem_unit / (1024 * 1024);
    }
#endif
    return 0;
}

bool ResourceGuard::check(size_t max_work_count, std::ostream& out) {
    bool ok = true;

    // 1. 临时端口数 (Linux only)
    uint32_t ports = read_linux_ephemeral_ports();
    if (ports > 0) {
        size_t safe = static_cast<size_t>(ports * 0.75);
        out << "[guard] ephemeral ports: " << ports
            << " → safe concurrency ≤ " << safe << std::endl;
        if (max_work_count > safe) {
            out << "[guard] WARNING: max_work_count=" << max_work_count
                << " exceeds safe limit " << safe
                << " — system may become unreachable!" << std::endl;
            ok = false;
        }
    }

    // 2. 可用内存 (session 预估 ~80KB 每个)
    uint64_t avail_mb = read_linux_mem_available_mb();
    if (avail_mb > 0) {
        size_t mem_safe = static_cast<size_t>(avail_mb / 0.08);  // 80KB per session
        out << "[guard] available memory: " << avail_mb
            << " MB → safe concurrency ≤ " << mem_safe << std::endl;
        if (max_work_count > mem_safe) {
            out << "[guard] WARNING: max_work_count=" << max_work_count
                << " may exhaust memory!" << std::endl;
            ok = false;
        }
    }

    return ok;
}

size_t ResourceGuard::safe_max_work_count() {
    size_t by_ports = std::min<size_t>(
        static_cast<size_t>(read_linux_ephemeral_ports() * 0.75), SIZE_MAX / 2);
    size_t by_mem = static_cast<size_t>(read_linux_mem_available_mb() / 0.08);
    size_t safe = std::min(by_ports, by_mem);
    if (safe == 0) safe = 5000; // fallback
    return safe;
}

} // namespace scanner
