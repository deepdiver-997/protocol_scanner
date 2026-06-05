#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>

#include "../protocols/protocol_base.h"

namespace scanner {

using Timeout = std::chrono::milliseconds;

// =====================
// DNS 查询结果
// =====================

struct DnsRecord {
    std::string name;      // 记录名称
    std::string type;      // 记录类型 (A, MX, AAAA, CNAME)
    std::string value;     // 记录值
    int ttl;              // 生存时间
    int priority;         // 优先级 (仅 MX 记录)
};

struct DnsResult {
    std::string domain;           // 查询域名
    std::string ip;             // IP 地址 (A 记录)
    std::vector<DnsRecord> dns_records; // DNS 记录列表
    std::string error;          // 错误信息
    bool success = false;        // 是否成功
};

// =====================
// DNS 解析器接口
// =====================

class IDnsResolver {
public:
    virtual ~IDnsResolver() = default;

    // 查询 A 记录
    virtual bool query_a_record(
        const std::string& domain,
        std::string& ip,
        Timeout timeout = Timeout(5000)
    ) = 0;

    // 查询 MX 记录
    virtual bool query_mx_records(
        const std::string& domain,
        std::vector<DnsRecord>& records,
        Timeout timeout = Timeout(5000)
    ) = 0;

    // 综合查询
    virtual DnsResult resolve(
        const std::string& domain,
        Timeout timeout = Timeout(5000)
    ) = 0;

    // 检查域名格式
    static bool is_valid_domain(const std::string& domain);

    // 检查 IP 格式
    static bool is_valid_ip(const std::string& ip);
};

// =====================
// DNS 解析器工厂
// =====================

class DnsResolverFactory {
public:
    enum class ResolverType {
        NULL_RESOLVER, // 无解析，直接返回空（输入纯 IP 时）
        DIG,           // 使用 dig 命令
        C_ARES,        // 使用 c-ares 库
        ASIO           // 使用 Boost.Asio
    };

    static std::unique_ptr<IDnsResolver> create(
        ResolverType type = ResolverType::C_ARES
    );
};

} // namespace scanner

// 子类头文件
#include "null_resolver.h"
#include "dig_resolver.h"
#include "cares_resolver.h"
