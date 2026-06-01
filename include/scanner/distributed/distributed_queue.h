#pragma once

#include "scanner/distributed/task_types.h"

#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace scanner::distributed {

class DistributedBatchQueue {
public:
    explicit DistributedBatchQueue(size_t max_size);

    bool enqueue(BatchTask task);
    std::optional<LeaseGrant> lease_one(const std::string& worker_id, uint64_t lease_ms);
    bool ack(uint64_t batch_id, const std::string& lease_token, const std::string& worker_id);

    // 失败后根据重试次数决定回队列还是终态失败。
    bool fail_and_requeue_or_mark_failed(
        uint64_t batch_id,
        const std::string& lease_token,
        const std::string& worker_id,
        bool* moved_to_failed);

    size_t reclaim_expired_leases();

    size_t max_size() const;
    size_t ready_size() const;
    size_t inflight_size() const;
    size_t failed_size() const;

    std::optional<uint64_t> min_ready_batch_id() const;
    std::optional<BatchTask> pop_failed_once();

private:
    struct InflightEntry {
        BatchTask task;
        std::string lease_token;
    };

    static uint64_t now_unix_ms();
    static std::string make_lease_token(uint64_t batch_id, const std::string& worker_id, uint32_t attempt);

    mutable std::mutex mu_;
    const size_t max_size_;

    std::deque<BatchTask> ready_;
    std::unordered_map<uint64_t, InflightEntry> inflight_;
    std::deque<BatchTask> failed_;
    std::unordered_map<uint64_t, BatchTask> done_;
};

}  // namespace scanner::distributed
