#pragma once

#include "dns_resolver.h"

namespace scanner {

// =====================
// Dig 命令解析器实现 默认不使用减少外部调用开销
// =====================

class DigResolver : public IDnsResolver {
public:
    DigResolver() = default;
    virtual ~DigResolver() = default;

    bool query_a_record(
        const std::string& domain,
        std::string& ip,
        Timeout timeout = Timeout(5000)
    ) override;

    bool query_mx_records(
        const std::string& domain,
        std::vector<DnsRecord>& records,
        Timeout timeout = Timeout(5000)
    ) override;

    DnsResult resolve(
        const std::string& domain,
        Timeout timeout = Timeout(5000)
    ) override;

private:
    // 调用 dig 命令并解析输出
    bool execute_dig(
        const std::string& domain,
        const std::string& query_type,
        std::vector<std::string>& lines
    );

    // 解析 A 记录输出
    bool parse_a_record(
        const std::vector<std::string>& lines,
        std::string& ip
    );

    // 解析 MX 记录输出
    bool parse_mx_records(
        const std::vector<std::string>& lines,
        std::vector<DnsRecord>& records
    );

    // 检查是否超时
    bool is_timeout_line(const std::string& line) const;
};

} // namespace scanner
