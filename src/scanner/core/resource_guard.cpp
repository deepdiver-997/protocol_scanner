#include "scanner/core/resource_guard.h"
#include <cstdint>
#include <fstream>
#include <sstream>

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

ResourceGuard::Limits ResourceGuard::probe_limits(size_t bind_ip_count) {
    Limits L;
    L.ephemeral_ports = read_linux_ephemeral_ports();
    L.avail_mem_mb    = read_linux_mem_available_mb();

    size_t ip_count = bind_ip_count > 0 ? bind_ip_count : 1;
    if (L.ephemeral_ports > 0) {
        // 每个 IP 有独立的临时端口池；预留 25% 给系统
        L.max_safe_by_port = static_cast<size_t>(L.ephemeral_ports * 0.75 * ip_count);
    }
    if (L.avail_mem_mb > 0) {
        // 每个 session 约 80KB（socket buffer + session struct + buffer）
        L.max_safe_by_mem = static_cast<size_t>(L.avail_mem_mb / 0.08);
    }
    return L;
}

std::string ResourceGuard::validate(size_t max_work_count, size_t bind_ip_count) {
    Limits L = probe_limits(bind_ip_count);

    // 非 Linux 系统跳过端口和内存检查
    if (L.ephemeral_ports == 0 && L.avail_mem_mb == 0) {
        return "";  // 无法检测，放行
    }

    if (L.max_safe_by_port > 0 && max_work_count > L.max_safe_by_port) {
        std::ostringstream oss;
        oss << "max_work_count=" << max_work_count
            << " exceeds ephemeral port limit ("
            << L.ephemeral_ports << " ports available, safe ≤ "
            << L.max_safe_by_port << "). "
            << "Reduce max_work_count or increase ip_local_port_range.";
        return oss.str();
    }

    if (L.max_safe_by_mem > 0 && max_work_count > L.max_safe_by_mem) {
        std::ostringstream oss;
        oss << "max_work_count=" << max_work_count
            << " may exhaust memory ("
            << L.avail_mem_mb << " MB available, safe ≤ "
            << L.max_safe_by_mem << "). "
            << "Reduce max_work_count.";
        return oss.str();
    }

    return "";  // OK
}

} // namespace scanner
