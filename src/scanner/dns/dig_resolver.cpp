#include "scanner/dns/dig_resolver.h"
#include "scanner/common/logger.h"
#include <sstream>
#include <algorithm>
#include <cstdlib>

namespace scanner {

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

    LOG_DNS_DEBUG("Resolving DNS for {}", domain);

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
    LOG_DNS_DEBUG("DNS resolution completed for {}: IP={}, DNS record count={}",
             domain, result.ip, result.dns_records.size());

    return result;
}

} // namespace scanner
