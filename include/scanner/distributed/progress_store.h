#pragma once

#include "scanner/distributed/task_types.h"

#include <filesystem>
#include <mutex>
#include <string>

namespace scanner::distributed {

// 进度持久化：
// 1) 保存“当前可确认最小序号 - 1”的水位线。
// 2) 记录超过最大重试次数的批任务，后续可作为重放输入。
class HdfsProgressStore {
public:
    explicit HdfsProgressStore(std::filesystem::path base_dir);

    bool persist_watermark(uint64_t watermark_seq_minus_one);
    bool load_watermark(uint64_t* watermark_seq_minus_one) const;
    bool append_failed_batch(const BatchTask& task, const std::string& reason);

    std::filesystem::path watermark_file_path() const;
    std::filesystem::path failed_file_path() const;

private:
    bool ensure_dir_locked();

    mutable std::mutex mu_;
    std::filesystem::path base_dir_;
    bool dir_ready_ = false;
};

}  // namespace scanner::distributed
