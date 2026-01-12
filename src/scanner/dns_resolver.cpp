#include "scanner/dns/dns_resolver.h"
#include "scanner/common/logger.h"
#include <sstream>
#include <regex>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <array>
#include <memory>

namespace scanner {

// =====================
// 静态方法实现
// =====================

bool IDnsResolver::is_valid_domain(const std::string& domain) {
    if (domain.empty() || domain.length() > 253) {
        return false;
    }

    // 基本域名格式检查
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
        case DnsResolverFactory::ResolverType::DIG:
            return std::make_unique<DigResolver>();
        case DnsResolverFactory::ResolverType::C_ARES:
            return std::make_unique<CAresResolver>();
        case DnsResolverFactory::ResolverType::ASIO:
            LOG_DNS_WARN("Asio resolver not implemented yet, falling back to c-ares");
            return std::make_unique<CAresResolver>();
        default:
            return std::make_unique<CAresResolver>();
    }
}

// =====================
// DigResolver 实现
// =====================

bool DigResolver::execute_dig(
    const std::string& domain,
    const std::string& query_type,
    std::vector<std::string>& lines
) {
    try {
        // 构建命令: dig +short +noquestion +nocomments domain query_type
        std::string cmd = "dig +short +noquestion +nocomments " + domain + " " + query_type;

        // 使用 popen 执行命令
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            LOG_DNS_ERROR("Failed to execute dig command");
            return false;
        }

        // 读取输出
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            std::string line(buffer);
            // 去除换行符
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
                line.pop_back();
            }
            if (!line.empty()) {
                lines.push_back(line);
            }
        }

        int exit_code = pclose(pipe);

        if (exit_code != 0) {
            LOG_DNS_WARN("dig command failed with exit code: {}", exit_code);
            return false;
        }

        LOG_DNS_TRACE("dig {} {} returned {} lines", domain, query_type, lines.size());
        return !lines.empty();

    } catch (const std::exception& e) {
        LOG_DNS_ERROR("Exception while executing dig: {}", e.what());
        return false;
    }
}

bool DigResolver::parse_a_record(
    const std::vector<std::string>& lines,
    std::string& ip
) {
    if (lines.empty()) {
        return false;
    }

    // A 记录通常直接返回 IP 地址
    // 如果有多行（多 IP），取第一个
    ip = lines[0];
    return IDnsResolver::is_valid_ip(ip);
}

bool DigResolver::parse_mx_records(
    const std::vector<std::string>& lines,
    std::vector<DnsRecord>& records
) {
    if (lines.empty()) {
        return false;
    }

    records.clear();

    // MX 记录格式: "priority mailserver.example.com"
    for (const auto& line : lines) {
        std::istringstream iss(line);
        int priority;
        std::string mail_server;

        if (iss >> priority >> mail_server) {
            DnsRecord record;
            record.type = "MX";
            record.value = mail_server;
            record.priority = priority;
            record.ttl = 0; // dig +short 不返回 TTL
            records.push_back(record);

            LOG_DNS_TRACE("Parsed MX: {} (priority {})", mail_server, priority);
        }
    }

    return !records.empty();
}

bool DigResolver::is_timeout_line(const std::string& line) const {
    // 检查是否包含超时相关的错误信息
    static const std::vector<std::string> timeout_keywords = {
        "timed out",
        "timeout",
        "connection timed out",
        "operation timed out"
    };

    std::string lower_line = line;
    std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (const auto& keyword : timeout_keywords) {
        if (lower_line.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool DigResolver::query_a_record(
    const std::string& domain,
    std::string& ip,
    Timeout timeout
) {
    if (!IDnsResolver::is_valid_domain(domain)) {
        LOG_DNS_WARN("Invalid domain: {}", domain);
        return false;
    }

    LOG_DNS_TRACE("Querying A record for {}", domain);

    std::vector<std::string> output;
    if (!execute_dig(domain, "A", output)) {
        LOG_DNS_WARN("Failed to query A record for {}", domain);
        return false;
    }

    if (parse_a_record(output, ip)) {
        LOG_DNS_DEBUG("A record for {}: {}", domain, ip);
        return true;
    }

    return false;
}

bool DigResolver::query_mx_records(
    const std::string& domain,
    std::vector<DnsRecord>& records,
    Timeout timeout
) {
    if (!IDnsResolver::is_valid_domain(domain)) {
        LOG_DNS_WARN("Invalid domain: {}", domain);
        return false;
    }

    LOG_DNS_TRACE("Querying MX records for {}", domain);

    std::vector<std::string> output;
    if (!execute_dig(domain, "MX", output)) {
        LOG_DNS_WARN("Failed to query MX records for {}", domain);
        return false;
    }

    if (parse_mx_records(output, records)) {
        LOG_DNS_DEBUG("Found {} MX records for {}", records.size(), domain);
        return true;
    }

    return false;
}

DnsResult DigResolver::resolve(
    const std::string& domain,
    Timeout timeout
) {
    DnsResult result;
    result.domain = domain;

    if (!IDnsResolver::is_valid_domain(domain)) {
        result.error = "Invalid domain format";
        result.success = false;
        LOG_DNS_WARN("Invalid domain: {}", domain);
        return result;
    }

    LOG_DNS_INFO("Resolving DNS for {}", domain);

    // 查询 A 记录
    if (!query_a_record(domain, result.ip, timeout)) {
        result.error = "Failed to query A record";
        result.success = false;
        LOG_DNS_WARN("A record query failed for {}", domain);
        return result;
    }

    // 查询 MX 记录
    if (!query_mx_records(domain, result.dns_records, timeout)) {
        LOG_DNS_WARN("MX record query failed for {}", domain);
        // MX 记录查询失败不影响整体成功状态
    }

    result.success = true;
    LOG_DNS_INFO("DNS resolution completed for {}: IP={}, DNS record count={}",
             domain, result.ip, result.dns_records.size());

    return result;
}

} // namespace scanner

// =====================
// CAresResolver 实现
// =====================

#include <atomic>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
#include <ares_dns.h>

namespace scanner {

CAresResolver::CAresResolver() {
    init_channel();
}

CAresResolver::~CAresResolver() {
    destroy_channel();
}

bool CAresResolver::init_channel() {
    ares_options opts{};
    int optmask = 0; // use system defaults
    int status = ares_init_options(&channel_, &opts, optmask);
    if (status != ARES_SUCCESS) {
        LOG_DNS_ERROR("c-ares init failed: {}", ares_strerror(status));
        channel_ = nullptr;
        return false;
    }
    return true;
}

void CAresResolver::destroy_channel() {
    if (channel_) {
        ares_destroy(channel_);
        channel_ = nullptr;
    }
}

bool CAresResolver::run_event_loop(Timeout timeout, std::atomic<bool>& done) {
    if (!channel_) return false;

    auto start = std::chrono::steady_clock::now();
    while (!done.load()) {
        ares_socket_t socks[ARES_GETSOCK_MAXNUM];
        int bitmask = ares_getsock(channel_, socks, ARES_GETSOCK_MAXNUM);
        if (bitmask == 0) {
            // No sockets; may be finished
            break;
        }

        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        int nfds = 0;
        for (int i = 0; i < ARES_GETSOCK_MAXNUM; ++i) {
            if (ARES_GETSOCK_READABLE(bitmask, i)) {
                FD_SET(socks[i], &read_fds);
                nfds = std::max(nfds, (int)socks[i]);
            }
            if (ARES_GETSOCK_WRITABLE(bitmask, i)) {
                FD_SET(socks[i], &write_fds);
                nfds = std::max(nfds, (int)socks[i]);
            }
        }

        timeval tv{};
        timeval* tvp = nullptr;
        timeval tv_timeout{};
        if (timeout.count() > 0) {
            // Use c-ares recommended timeout but cap by remaining user timeout
            ares_timeout(channel_, nullptr, &tv_timeout);
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            auto remaining = (elapsed >= timeout) ? Timeout(0) : (timeout - elapsed);
            long usec = (long)remaining.count() * 1000L;
            tv.tv_sec = usec / 1000000L;
            tv.tv_usec = usec % 1000000L;
            // pick the smaller of ares suggested and remaining
            if (tv.tv_sec > tv_timeout.tv_sec ||
                (tv.tv_sec == tv_timeout.tv_sec && tv.tv_usec > tv_timeout.tv_usec)) {
                tv = tv_timeout;
            }
            tvp = &tv;
        }

        int sel = select(nfds + 1, &read_fds, &write_fds, nullptr, tvp);
        if (sel < 0) {
            if (errno == EINTR) continue;
            LOG_DNS_ERROR("select failed: {}", strerror(errno));
            return false;
        }

        ares_process(channel_, &read_fds, &write_fds);

        if (timeout.count() > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            if (elapsed >= timeout) {
                LOG_DNS_WARN("c-ares timeout reached");
                return false;
            }
        }
    }
    return true;
}

bool CAresResolver::query_a_record(
    const std::string& domain,
    std::string& ip,
    Timeout timeout
) {
    if (!IDnsResolver::is_valid_domain(domain)) {
        LOG_DNS_WARN("Invalid domain: {}", domain);
        return false;
    }
    if (!channel_ && !init_channel()) return false;

    std::atomic<bool> done{false};
    int query_status = ARES_EDESTRUCTION; // default error

    auto callback = [](void* arg, int status, int /*timeouts*/, struct hostent* host) {
        auto* ctx = static_cast<std::pair<std::string*, int*>*>(arg);
        *ctx->second = status;
        if (status == ARES_SUCCESS && host && host->h_addrtype == AF_INET && host->h_addr_list && host->h_addr_list[0]) {
            char buf[INET_ADDRSTRLEN];
            const char* res = inet_ntop(AF_INET, host->h_addr_list[0], buf, sizeof(buf));
            if (res) {
                *ctx->first = buf;
            }
        }
    };

    std::pair<std::string*, int*> ctx{&ip, &query_status};
    ares_gethostbyname(channel_, domain.c_str(), AF_INET, callback, &ctx);

    bool loop_ok = run_event_loop(timeout, done);
    // c-ares doesn't set 'done' automatically; check sockets until none
    done.store(true);

    if (!loop_ok) {
        LOG_DNS_WARN("A query timeout or loop error for {}", domain);
        return false;
    }
    if (query_status != ARES_SUCCESS) {
        LOG_DNS_WARN("A query failed for {}: {}", domain, ares_strerror(query_status));
        return false;
    }
    return IDnsResolver::is_valid_ip(ip);
}

bool CAresResolver::query_mx_records(
    const std::string& domain,
    std::vector<DnsRecord>& records,
    Timeout timeout
) {
    if (!IDnsResolver::is_valid_domain(domain)) {
        LOG_DNS_WARN("Invalid domain: {}", domain);
        return false;
    }
    if (!channel_ && !init_channel()) return false;

    records.clear();
    std::atomic<bool> done{false};
    int query_status = ARES_EDESTRUCTION;
    std::vector<DnsRecord> out_records;

    auto callback = [](void* arg, int status, int /*timeouts*/, unsigned char* abuf, int alen) {
        auto* ctx = static_cast<std::pair<std::vector<DnsRecord>*, int*>*>(arg);
        *ctx->second = status;
        if (status == ARES_SUCCESS) {
            struct ares_mx_reply* mx_out = nullptr;
            int parse = ares_parse_mx_reply(abuf, alen, &mx_out);
            if (parse == ARES_SUCCESS && mx_out) {
                for (auto* p = mx_out; p != nullptr; p = p->next) {
                    DnsRecord r;
                    r.name = ""; // not provided by parse
                    r.type = "MX";
                    r.value = p->host ? p->host : "";
                    r.ttl = 0; // not available via ares_parse_mx_reply
                    r.priority = p->priority;
                    ctx->first->push_back(std::move(r));
                }
                ares_free_data(mx_out);
            }
        }
    };

    std::pair<std::vector<DnsRecord>*, int*> ctx{&out_records, &query_status};
    ares_query(channel_, domain.c_str(), ARES_CLASS_IN, ARES_REC_TYPE_MX, callback, &ctx);

    bool loop_ok = run_event_loop(timeout, done);
    done.store(true);

    if (!loop_ok) {
        LOG_DNS_WARN("MX query timeout or loop error for {}", domain);
        return false;
    }

    if (query_status != ARES_SUCCESS) {
        LOG_DNS_WARN("MX query failed for {}: {}", domain, ares_strerror(query_status));
        return false;
    }

    records = std::move(out_records);
    return !records.empty();
}

DnsResult CAresResolver::resolve(
    const std::string& domain,
    Timeout timeout
) {
    DnsResult result;
    result.domain = domain;
    if (!IDnsResolver::is_valid_domain(domain)) {
        result.error = "Invalid domain format";
        result.success = false;
        LOG_DNS_WARN("Invalid domain: {}", domain);
        return result;
    }

    LOG_DNS_INFO("Resolving DNS (c-ares) for {}", domain);

    if (!query_a_record(domain, result.ip, timeout)) {
        result.error = "Failed to query A record";
        result.success = false;
        LOG_DNS_WARN("A record query failed for {}", domain);
        return result;
    }

    (void)query_mx_records(domain, result.dns_records, timeout);

    result.success = true;
    LOG_DNS_INFO("DNS resolution completed for {}: IP={}, MX count={}",
             domain, result.ip, result.dns_records.size());
    return result;
}

} // namespace scanner
