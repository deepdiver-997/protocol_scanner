#pragma once

#include <cstdint>
#include <string>

namespace scanner::distributed {

enum class BatchStatus {
    kReady,
    kLeased,
    kDone,
    kFailed,
};

struct BatchTask {
    uint64_t batch_id = 0;
    std::string input_path;
    uint64_t line_begin = 0;
    uint64_t line_end = 0;

    uint32_t attempt = 0;
    uint32_t max_attempts = 3;

    BatchStatus status = BatchStatus::kReady;
    std::string lease_owner;
    uint64_t lease_expire_unix_ms = 0;
};

struct LeaseGrant {
    uint64_t batch_id = 0;
    std::string lease_token;
    BatchTask task;
};

}  // namespace scanner::distributed
