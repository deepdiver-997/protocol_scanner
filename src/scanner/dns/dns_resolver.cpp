#include "scanner/dns/dns_resolver.h"
#include "scanner/common/logger.h"
#include <regex>

namespace scanner {

// =====================
// 静态方法实现
// =====================

bool IDnsResolver::is_valid_domain(const std::string& domain) {
    if (domain.empty() || domain.length() > 253) {
        return false;
    }

    static const std::regex domain_regex(
        R"(^([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$)"
    );
    return std::regex_match(domain, domain_regex);
}

bool IDnsResolver::is_valid_ip(const std::string& ip) {
    // IPv4 格式检查
    static const std::regex ipv4_regex(
        R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );
    // IPv6 格式检查（简化版）
    static const std::regex ipv6_regex(
        R"(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)"
    );
    return std::regex_match(ip, ipv4_regex) || std::regex_match(ip, ipv6_regex);
}

// =====================
// DNS 解析器工厂实现
// =====================

std::unique_ptr<IDnsResolver> DnsResolverFactory::create(
    DnsResolverFactory::ResolverType type
) {
    switch (type) {
        case DnsResolverFactory::ResolverType::NULL_RESOLVER:
            return std::make_unique<NullResolver>();
        case DnsResolverFactory::ResolverType::DIG:
            return std::make_unique<DigResolver>();
        case DnsResolverFactory::ResolverType::C_ARES:
#ifdef SCANNER_NO_CARES
            LOG_DNS_WARN("c-ares not available, falling back to dig resolver");
            return std::make_unique<DigResolver>();
#else
            return std::make_unique<CAresResolver>();
#endif
        case DnsResolverFactory::ResolverType::ASIO:
#ifdef SCANNER_NO_CARES
            LOG_DNS_WARN("Asio resolver not implemented, falling back to dig");
            return std::make_unique<DigResolver>();
#else
            LOG_DNS_WARN("Asio resolver not implemented yet, falling back to c-ares");
            return std::make_unique<CAresResolver>();
#endif
        default:
#ifdef SCANNER_NO_CARES
            return std::make_unique<DigResolver>();
#else
            return std::make_unique<CAresResolver>();
#endif
    }
}

} // namespace scanner
