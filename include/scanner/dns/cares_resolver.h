#pragma once

#include "dns_resolver.h"

#include <ares.h>
#include <mutex>
#include <atomic>

namespace scanner {

// =====================
// c-ares 解析器实现
// =====================

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
    std::atomic<int> pending_requests_{0};
    std::mutex channel_mutex_;
    std::atomic<bool> shutting_down_{false};

    bool init_channel();
    void destroy_channel();
    bool run_event_loop(Timeout timeout, std::atomic<bool>& done);

    ares_channel get_channel();
    void increment_pending();
    void decrement_pending();
    void cancel_all_queries();
};

} // namespace scanner
