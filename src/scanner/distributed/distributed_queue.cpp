#include "scanner/distributed/distributed_queue.h"

#include <chrono>

namespace scanner::distributed {

DistributedBatchQueue::DistributedBatchQueue(size_t max_size) : max_size_(max_size) {}

bool DistributedBatchQueue::enqueue(BatchTask task) {
    std::lock_guard<std::mutex> lock(mu_);
    if (ready_.size() + inflight_.size() >= max_size_) {
        return false;
    }
    task.status = BatchStatus::kReady;
    task.lease_owner.clear();
    task.lease_expire_unix_ms = 0;
    ready_.push_back(std::move(task));
    return true;
}

std::optional<LeaseGrant> DistributedBatchQueue::lease_one(const std::string& worker_id, uint64_t lease_ms) {
    std::lock_guard<std::mutex> lock(mu_);
    if (ready_.empty()) {
        return std::nullopt;
    }

    BatchTask task = std::move(ready_.front());
    ready_.pop_front();

    task.status = BatchStatus::kLeased;
    task.lease_owner = worker_id;
    task.attempt += 1;
    task.lease_expire_unix_ms = now_unix_ms() + lease_ms;

    const std::string token = make_lease_token(task.batch_id, worker_id, task.attempt);
    const uint64_t batch_id = task.batch_id;
    inflight_[batch_id] = InflightEntry{std::move(task), token};

    LeaseGrant grant;
    grant.batch_id = batch_id;
    grant.lease_token = token;
    grant.task = inflight_[batch_id].task;
    return grant;
}

bool DistributedBatchQueue::ack(uint64_t batch_id, const std::string& lease_token, const std::string& worker_id) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = inflight_.find(batch_id);
    if (it == inflight_.end()) {
        return false;
    }
    if (it->second.lease_token != lease_token || it->second.task.lease_owner != worker_id) {
        return false;
    }

    it->second.task.status = BatchStatus::kDone;
    done_[batch_id] = std::move(it->second.task);
    inflight_.erase(it);
    return true;
}

bool DistributedBatchQueue::fail_and_requeue_or_mark_failed(
    uint64_t batch_id,
    const std::string& lease_token,
    const std::string& worker_id,
    bool* moved_to_failed) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = inflight_.find(batch_id);
    if (it == inflight_.end()) {
        return false;
    }
    if (it->second.lease_token != lease_token || it->second.task.lease_owner != worker_id) {
        return false;
    }

    BatchTask task = std::move(it->second.task);
    inflight_.erase(it);

    task.lease_owner.clear();
    task.lease_expire_unix_ms = 0;

    if (task.attempt >= task.max_attempts) {
        task.status = BatchStatus::kFailed;
        failed_.push_back(std::move(task));
        if (moved_to_failed != nullptr) {
            *moved_to_failed = true;
        }
    } else {
        task.status = BatchStatus::kReady;
        ready_.push_back(std::move(task));
        if (moved_to_failed != nullptr) {
            *moved_to_failed = false;
        }
    }

    return true;
}

size_t DistributedBatchQueue::reclaim_expired_leases() {
    std::lock_guard<std::mutex> lock(mu_);
    const uint64_t now = now_unix_ms();
    size_t reclaimed = 0;

    for (auto it = inflight_.begin(); it != inflight_.end();) {
        if (it->second.task.lease_expire_unix_ms > now) {
            ++it;
            continue;
        }

        BatchTask task = std::move(it->second.task);
        task.status = BatchStatus::kReady;
        task.lease_owner.clear();
        task.lease_expire_unix_ms = 0;
        ready_.push_back(std::move(task));

        it = inflight_.erase(it);
        ++reclaimed;
    }

    return reclaimed;
}

size_t DistributedBatchQueue::max_size() const {
    return max_size_;
}

size_t DistributedBatchQueue::ready_size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return ready_.size();
}

size_t DistributedBatchQueue::inflight_size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return inflight_.size();
}

size_t DistributedBatchQueue::failed_size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return failed_.size();
}

std::optional<uint64_t> DistributedBatchQueue::min_ready_batch_id() const {
    std::lock_guard<std::mutex> lock(mu_);
    if (ready_.empty()) {
        return std::nullopt;
    }

    uint64_t min_id = ready_.front().batch_id;
    for (const auto& t : ready_) {
        if (t.batch_id < min_id) {
            min_id = t.batch_id;
        }
    }
    return min_id;
}

std::optional<BatchTask> DistributedBatchQueue::pop_failed_once() {
    std::lock_guard<std::mutex> lock(mu_);
    if (failed_.empty()) {
        return std::nullopt;
    }
    BatchTask out = std::move(failed_.front());
    failed_.pop_front();
    return out;
}

uint64_t DistributedBatchQueue::now_unix_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::string DistributedBatchQueue::make_lease_token(uint64_t batch_id, const std::string& worker_id, uint32_t attempt) {
    return std::to_string(batch_id) + ":" + worker_id + ":" + std::to_string(attempt);
}

}  // namespace scanner::distributed
