#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <ares.h>

#include "../protocols/protocol_base.h"

namespace scanner {

// Forward declaration
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
        DIG,       // 使用 dig 命令
        C_ARES,    // 使用 c-ares 库
        ASIO       // 使用 Boost.Asio
    };

    static std::unique_ptr<IDnsResolver> create(
        ResolverType type = ResolverType::C_ARES
    );
};

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

// =====================
// c-ares 解析器实现
// =====================

namespace scanner {

class CAresResolver : public IDnsResolver {
public:
    CAresResolver();
    virtual ~CAresResolver();

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
    ares_channel channel_ = nullptr;
    bool init_channel();
    void destroy_channel();
    bool run_event_loop(Timeout timeout, std::atomic<bool>& done);
};

} // namespace scanner
