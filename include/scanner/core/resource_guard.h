#pragma once

#include <cstddef>
#include <string>

namespace scanner {

// 启动前安全校验：防止并发数过高导致系统不可达
class ResourceGuard {
public:
    struct Limits {
        size_t ephemeral_ports      = 0;   // 临时端口数
        size_t avail_mem_mb         = 0;   // 可用内存 MB
        size_t max_safe_by_port     = 0;   // 按端口的安全上限
        size_t max_safe_by_mem      = 0;   // 按内存的安全上限
        size_t conntrack_max        = 0;   // 连接跟踪表上限
        size_t max_safe_by_conntrack = 0;  // 按 conntrack 的安全上限
    };

    // 读取系统资源限制，用于日志输出
    // bind_ip_count: 多 IP 绑定数量，每个 IP 有独立的端口池
    static Limits probe_limits(size_t bind_ip_count = 0);

    // 验证配置的 max_work_count 是否安全
    // 返回空字符串表示通过，否则返回错误描述
    static std::string validate(size_t max_work_count, size_t bind_ip_count = 0);
};

} // namespace scanner
