#pragma once

#include "dns_resolver.h"

namespace scanner {

// =====================
// Null 解析器（纯 IP 输入时使用，无外部依赖）
// =====================

class NullResolver : public IDnsResolver {
public:
    NullResolver() = default;
    ~NullResolver() override = default;

    bool query_a_record(const std::string&, std::string&, Timeout) override { return false; }
    bool query_mx_records(const std::string&, std::vector<DnsRecord>&, Timeout) override { return false; }
    DnsResult resolve(const std::string&, Timeout) override { return DnsResult{}; }
};

} // namespace scanner
