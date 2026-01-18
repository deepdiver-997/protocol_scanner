#pragma once

#include <string>
#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>

namespace scanner {

// 扫描进度信息
struct CheckpointInfo {
    std::string last_ip;              // 最后处理的 IP
    size_t processed_count = 0;       // 已处理的目标数
    size_t successful_count = 0;      // 成功的目标数
    std::string timestamp;            // 时间戳
    std::string input_file_hash;      // 输入文件的 hash（防止混用）
};

// 进度管理器：负责保存和恢复断点信息
class ProgressManager {
public:
    ProgressManager(const std::string& input_path, const std::string& output_dir);
    
    // 保存进度
    bool save_checkpoint(const CheckpointInfo& info);
    
    // 加载进度
    bool load_checkpoint(CheckpointInfo& info);
    
    // 删除进度文件（扫描完成后）
    void clear_checkpoint();
    
    // 获取进度文件路径
    std::string get_checkpoint_file() const { return checkpoint_file_; }
    
    // 检查是否存在有效的进度文件
    bool has_valid_checkpoint() const;

    // 计算文件 hash（用于验证输入文件是否变化）
    static std::string compute_file_hash(const std::string& filepath);

private:
    std::string checkpoint_file_;
    std::mutex mutex_;
};

} // namespace scanner
