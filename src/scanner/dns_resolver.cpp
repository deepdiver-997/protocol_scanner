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
#include <sys/time.h>
#include <vector>
#include <poll.h>      // 使用 poll 替代 select
#include <ares.h>
#include <thread>
#include <chrono> 

#ifndef HAVE_ARES_PROCESS_FDS
// Compatibility macro for older c-ares versions if needed, 
// though we usually target newer ones now.
#endif

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

// 辅助宏
#ifndef POLLIN
#define POLLIN  0x001
#endif
#ifndef POLLOUT
#define POLLOUT 0x004
#endif

bool CAresResolver::run_event_loop(Timeout timeout, std::atomic<bool>& done) {
    if (!channel_) return false;

    auto start = std::chrono::steady_clock::now();
    while (!done.load()) {
        // 使用 ares_getsock 获取 socket 列表，避免使用 select (FD_SETSIZE 限制)
        ares_socket_t socks[ARES_GETSOCK_MAXNUM];
        int bitmask = ares_getsock(channel_, socks, ARES_GETSOCK_MAXNUM);

        if (bitmask == 0) {
            // 没有待处理的 socket，可能任务已完成
             if (done.load()) break;
             // 如果还没 done 但也没有 socket，稍微休眠一下防止死循环
             std::this_thread::sleep_for(std::chrono::milliseconds(1));
             continue;
        }

        // 构建 pollfd 数组
        std::vector<struct pollfd> pfd_vec;
        pfd_vec.reserve(ARES_GETSOCK_MAXNUM);

        for (int i = 0; i < ARES_GETSOCK_MAXNUM; ++i) {
            if (ARES_GETSOCK_READABLE(bitmask, i) || ARES_GETSOCK_WRITABLE(bitmask, i)) {
                struct pollfd pfd;
                pfd.fd = socks[i];
                pfd.events = 0;
                if (ARES_GETSOCK_READABLE(bitmask, i)) pfd.events |= POLLIN;
                if (ARES_GETSOCK_WRITABLE(bitmask, i)) pfd.events |= POLLOUT;
                pfd.revents = 0;
                pfd_vec.push_back(pfd);
            }
        }

        if (pfd_vec.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        // 计算超时
        int timeout_ms = 1000; // 默认 poll 超时
        timeval tv_timeout;
        if (ares_timeout(channel_, nullptr, &tv_timeout) != nullptr) {
             timeout_ms = (tv_timeout.tv_sec * 1000) + (tv_timeout.tv_usec / 1000);
        }

        // 结合用户设定的总超时
        if (timeout.count() > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            auto remaining = (elapsed >= timeout) ? 0 : (timeout - elapsed).count();
            if (remaining == 0) {
                LOG_DNS_WARN("c-ares timeout reached in loop");
                return false; 
            }
            if (remaining < timeout_ms) {
                timeout_ms = static_cast<int>(remaining);
            }
        }

        // 执行 poll
        int poll_res = poll(pfd_vec.data(), pfd_vec.size(), timeout_ms);

        if (poll_res < 0) {
            if (errno == EINTR) continue;
            LOG_DNS_ERROR("poll failed: {}", strerror(errno));
            return false;
        }

        // 处理结果 (使用 ares_process_fd 替代 ares_process 以兼容 poll 结果)
        for (const auto& pfd : pfd_vec) {
            if (pfd.revents != 0) {
                ares_process_fd(channel_, 
                    (pfd.revents & POLLIN) ? pfd.fd : ARES_SOCKET_BAD,
                    (pfd.revents & POLLOUT) ? pfd.fd : ARES_SOCKET_BAD);
            }
        }
        // 对于超时的处理，ares_process_fd(..., ARES_SOCKET_BAD, ARES_SOCKET_BAD) 
        // 可以触发 c-ares 内部的超时回调，但 c-ares 通常建议我们在没有任何事件时
        // 也要调用一次 process。这里我们在循环中如果 poll 返回 0 (超时)
        // 可以调用一次处理超时。
        if (poll_res == 0) {
            ares_process_fd(channel_, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        }
        
        if (timeout.count() > 0) {
             auto check_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
             if (check_elapsed >= timeout) return false;
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

    // 上下文：保存结果与完成标记
    struct AddrinfoCtx {
        std::shared_ptr<std::pair<std::string, int>> data;
        std::atomic<bool>* done;
    };

    // 使用 shared_ptr 确保回调时内存仍然有效
    auto data = std::make_shared<std::pair<std::string, int>>();
    data->second = ARES_EDESTRUCTION;

    auto* ctx_ptr = new AddrinfoCtx{data, &done};

    // Replace deprecated ares_gethostbyname with ares_getaddrinfo
    struct ares_addrinfo_hints hints = {};
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = ARES_AI_CANONNAME;

    ares_getaddrinfo(channel_, domain.c_str(), nullptr, &hints, [](void* arg, int status, int /*timeouts*/, struct ares_addrinfo* result) {
        auto* ctx = static_cast<AddrinfoCtx*>(arg);
        if (!ctx || !ctx->data) return;

        ctx->data->second = status;
        if (status == ARES_SUCCESS && result) {
            // Traverse the list
            for (auto* node = result->nodes; node != nullptr; node = node->ai_next) {
                if (node->ai_family == AF_INET) {
                    char buf[INET_ADDRSTRLEN];
                    auto* addr = reinterpret_cast<struct sockaddr_in*>(node->ai_addr);
                    const char* res = inet_ntop(AF_INET, &(addr->sin_addr), buf, sizeof(buf));
                    if (res) {
                        ctx->data->first = buf;
                        break; // Just get the first one
                    }
                }
            }
            ares_freeaddrinfo(result);
        }
        // 标记完成
        if (ctx->done) ctx->done->store(true);
        delete ctx;
    }, ctx_ptr);

    bool loop_ok = run_event_loop(timeout, done);
    // c-ares doesn't set 'done' automatically; check sockets until none
    done.store(true);

    if (!loop_ok) {
        LOG_DNS_WARN("A record query timeout or loop error for {}", domain);
        return false;
    }

    if (data->second != ARES_SUCCESS) {
        LOG_DNS_WARN("A record query failed for {}: {}", domain, ares_strerror(data->second));
        return false;
    }

    ip = std::move(data->first);
    return !ip.empty();
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

    // 上下文：保存结果与完成标记（旧回调，返回原始报文）
    struct MxCtx {
        std::shared_ptr<std::pair<std::vector<DnsRecord>, int>> data;
        std::atomic<bool>* done;
    };

    auto data = std::make_shared<std::pair<std::vector<DnsRecord>, int>>();
    data->second = ARES_EDESTRUCTION;

    auto callback = [](void* arg, int status, int /*timeouts*/, unsigned char* abuf, int alen) {
        auto* ctx = static_cast<MxCtx*>(arg);
        if (!ctx || !ctx->data) return;

        ctx->data->second = status;
        if (status == ARES_SUCCESS) {
            struct ares_mx_reply* mx_out = nullptr;
            // 抑制旧解析 API 的弃用告警
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Wdeprecated-declarations"
            int parse = ares_parse_mx_reply(abuf, alen, &mx_out);
            #pragma clang diagnostic pop
            if (parse == ARES_SUCCESS && mx_out) {
                for (auto* p = mx_out; p != nullptr; p = p->next) {
                    DnsRecord r;
                    r.type = "MX";
                    r.value = p->host ? p->host : "";
                    r.ttl = 0;
                    r.priority = p->priority;
                    ctx->data->first.push_back(std::move(r));
                }
                ares_free_data(mx_out);
            }
        }
        if (ctx->done) ctx->done->store(true);
        delete ctx;
    };

    auto* ctx_ptr = new MxCtx{data, &done};

    // 抑制 ares_search 的弃用告警，后续待迁移到 dnsrec 查询生成
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    ares_search(channel_, domain.c_str(), ARES_CLASS_IN, ARES_REC_TYPE_MX, callback, ctx_ptr);
    #pragma clang diagnostic pop

    bool loop_ok = run_event_loop(timeout, done);
    done.store(true);

    if (!loop_ok) {
        LOG_DNS_WARN("MX query timeout or loop error for {}", domain);
        return false;
    }

    records = std::move(data->first);
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
