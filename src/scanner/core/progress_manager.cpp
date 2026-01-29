#include "scanner/core/progress_manager.h"
#include "scanner/common/logger.h"
#include <fstream>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace scanner {

namespace fs = std::filesystem;

std::string ProgressManager::compute_file_hash(const std::string& filepath) {
    // 简单 hash：文件大小 + 修改时间 + 前 1KB 内容的 CRC32
    // 足以判断输入文件是否有变化
    try {
        auto fstat = fs::last_write_time(filepath);
        auto fsize = fs::file_size(filepath);
        
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "";
        
        // 读前 1KB
        std::string header(std::min(size_t(1024), fsize), '\0');
        file.read(&header[0], header.size());
        
        // 简单 hash：size + mtime + header CRC
        std::stringstream ss;
        ss << std::hex << fsize << "_" 
           << std::chrono::duration_cast<std::chrono::seconds>(fstat.time_since_epoch()).count() << "_"
           << std::hash<std::string>{}(header);
        return ss.str();
    } catch (const std::exception& e) {
        LOG_CORE_WARN("Failed to compute file hash: {}", e.what());
        return "";
    }
}

ProgressManager::ProgressManager(const std::string& input_path, const std::string& output_dir) {
    // 生成进度文件名：input.txt.progress.json
    std::string input_filename = fs::path(input_path).filename().string();
    checkpoint_file_ = output_dir;
    if (!checkpoint_file_.empty() && checkpoint_file_.back() != '/') {
        checkpoint_file_ += "/";
    }
    checkpoint_file_ += input_filename + ".progress.json";
    
    LOG_CORE_INFO("Checkpoint file: {}", checkpoint_file_);
}

bool ProgressManager::save_checkpoint(const CheckpointInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        // 保障 processed_count 不倒退：与上次加载值取最大
        size_t processed_to_store = std::max(info.processed_count, last_loaded_processed_count_);
        nlohmann::json j;
        j["last_ip"] = info.last_ip;
        j["processed_count"] = processed_to_store;
        j["successful_count"] = info.successful_count;
        j["timestamp"] = info.timestamp;
        j["input_file_hash"] = info.input_file_hash;
        j["input_file_offset"] = info.input_file_offset;
        j["last_processed_ip_uint"] = info.last_processed_ip_uint;  // 新增：保存 uint32 形式
        
        std::ofstream ofs(checkpoint_file_);
        if (!ofs) {
            LOG_CORE_WARN("Failed to open checkpoint file for writing: {}", checkpoint_file_);
            return false;
        }
        
        ofs << j.dump(2);
        ofs.close();
        
        LOG_CORE_DEBUG("Checkpoint saved: {} ({} processed, {} successful)", 
                      info.last_ip, processed_to_store, info.successful_count);
        return true;
    } catch (const std::exception& e) {
        LOG_CORE_ERROR("Failed to save checkpoint: {}", e.what());
        return false;
    }
}

bool ProgressManager::load_checkpoint(CheckpointInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        if (!fs::exists(checkpoint_file_)) {
            LOG_CORE_INFO("No checkpoint file found: {}", checkpoint_file_);
            return false;
        }
        
        std::ifstream ifs(checkpoint_file_);
        if (!ifs) {
            LOG_CORE_WARN("Failed to open checkpoint file for reading: {}", checkpoint_file_);
            return false;
        }
        
        nlohmann::json j;
        ifs >> j;
        ifs.close();
        
        info.last_ip = j.value("last_ip", "");
        info.processed_count = j.value("processed_count", 0);
        info.successful_count = j.value("successful_count", 0);
        info.timestamp = j.value("timestamp", "");
        info.input_file_hash = j.value("input_file_hash", "");
        info.input_file_offset = j.value("input_file_offset", 0);
        info.last_processed_ip_uint = j.value("last_processed_ip_uint", 0);  // 新增：加载 uint32 形式
        last_loaded_processed_count_ = info.processed_count;
        
        LOG_CORE_INFO("Checkpoint loaded: {} (processed: {}, successful: {})", 
                     info.last_ip, info.processed_count, info.successful_count);
        // Even with logging disabled, emit a console hint so systemd/journalctl can capture it.
        std::cout << "[checkpoint] loaded file=" << checkpoint_file_ 
              << " last_ip=" << info.last_ip
              << " processed=" << info.processed_count
              << " successful=" << info.successful_count
              << " file_offset=" << info.input_file_offset << std::endl;
        return true;
    } catch (const std::exception& e) {
        LOG_CORE_ERROR("Failed to load checkpoint: {}", e.what());
        return false;
    }
}

void ProgressManager::clear_checkpoint() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        if (fs::exists(checkpoint_file_)) {
            fs::remove(checkpoint_file_);
            LOG_CORE_INFO("Checkpoint cleared: {}", checkpoint_file_);
        }
    } catch (const std::exception& e) {
        LOG_CORE_WARN("Failed to clear checkpoint: {}", e.what());
    }
}

bool ProgressManager::has_valid_checkpoint() const {
    try {
        return fs::exists(checkpoint_file_) && fs::file_size(checkpoint_file_) > 0;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace scanner
