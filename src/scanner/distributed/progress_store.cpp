#include "scanner/distributed/progress_store.h"

#include <fstream>

#include <nlohmann/json.hpp>

namespace scanner::distributed {

HdfsProgressStore::HdfsProgressStore(std::filesystem::path base_dir)
    : base_dir_(std::move(base_dir)) {}

bool HdfsProgressStore::persist_watermark(uint64_t watermark_seq_minus_one) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!ensure_dir_locked()) {
        return false;
    }

    nlohmann::json j;
    j["watermark_seq_minus_one"] = watermark_seq_minus_one;

    std::ofstream ofs(watermark_file_path(), std::ios::trunc);
    if (!ofs.is_open()) {
        return false;
    }
    ofs << j.dump(2) << '\n';
    return static_cast<bool>(ofs);
}

bool HdfsProgressStore::load_watermark(uint64_t* watermark_seq_minus_one) const {
    if (watermark_seq_minus_one == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mu_);
    std::ifstream ifs(watermark_file_path());
    if (!ifs.is_open()) {
        return false;
    }

    nlohmann::json j;
    try {
        ifs >> j;
    } catch (...) {
        return false;
    }

    if (!j.contains("watermark_seq_minus_one") || !j["watermark_seq_minus_one"].is_number_unsigned()) {
        return false;
    }

    *watermark_seq_minus_one = j["watermark_seq_minus_one"].get<uint64_t>();
    return true;
}

bool HdfsProgressStore::append_failed_batch(const BatchTask& task, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!ensure_dir_locked()) {
        return false;
    }

    nlohmann::json line;
    line["batch_id"] = task.batch_id;
    line["input_path"] = task.input_path;
    line["line_begin"] = task.line_begin;
    line["line_end"] = task.line_end;
    line["attempt"] = task.attempt;
    line["max_attempts"] = task.max_attempts;
    line["reason"] = reason;

    std::ofstream ofs(failed_file_path(), std::ios::app);
    if (!ofs.is_open()) {
        return false;
    }
    ofs << line.dump() << '\n';
    return static_cast<bool>(ofs);
}

std::filesystem::path HdfsProgressStore::watermark_file_path() const {
    return base_dir_ / "queue_progress.json";
}

std::filesystem::path HdfsProgressStore::failed_file_path() const {
    return base_dir_ / "failed_batches.jsonl";
}

bool HdfsProgressStore::ensure_dir_locked() {
    if (dir_ready_) {
        return true;
    }

    std::error_code ec;
    std::filesystem::create_directories(base_dir_, ec);
    dir_ready_ = !ec;
    return dir_ready_;
}

}  // namespace scanner::distributed
