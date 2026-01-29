#pragma once

#include <array>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>

namespace scanner {

// =====================
// 固定大小缓冲区（用于协议探测）
// =====================
// 协议探测只需要很小的缓冲区：
// - SSH/FTP/Telnet banner: ~50-200 bytes
// - POP3 banner: ~50-100 bytes  
// - SMTP EHLO: ~200-500 bytes (多行响应)
// - IMAP CAPABILITY: ~200-500 bytes (多行响应)
// - HTTP headers: ~200-2KB
// 
// 使用 1024 字节可以覆盖所有场景，相比 streambuf 的动态分配：
// - 节省内存：streambuf 默认 512 bytes 起步，但可能扩展到数KB
// - 减少碎片：固定大小，无动态扩展
// - 提高性能：栈分配或内存池分配
constexpr size_t PROTOCOL_BUFFER_SIZE = 1024;  // 统一使用 1KB，覆盖所有协议

using FixedBuffer = std::array<char, PROTOCOL_BUFFER_SIZE>;

// =====================
// 简单内存池（可选优化）
// =====================
// 用于 3000 个并发连接的场景，减少频繁 new/delete 开销
// 特点：
// - 线程安全
// - 预分配固定数量的缓冲区
// - RAII 自动归还
// - 统计命中率

class BufferPool {
public:
    // 预分配缓冲区数量（建议设置为最大并发连接数）
    explicit BufferPool(size_t pool_size = 3000) : pool_size_(pool_size) {
        pool_.reserve(pool_size);
        for (size_t i = 0; i < pool_size; ++i) {
            pool_.emplace_back(std::make_unique<FixedBuffer>());
        }
        available_count_.store(pool_size, std::memory_order_relaxed);
    }

    ~BufferPool() = default;

    // 禁止拷贝
    BufferPool(const BufferPool&) = delete;
    BufferPool& operator=(const BufferPool&) = delete;

    // RAII 包装器：自动归还缓冲区
    class BufferHandle {
    public:
        BufferHandle(std::unique_ptr<FixedBuffer> buffer, BufferPool* pool)
            : buffer_(std::move(buffer)), pool_(pool) {}

        ~BufferHandle() {
            if (buffer_ && pool_) {
                pool_->return_buffer(std::move(buffer_));
            }
        }

        // 禁止拷贝，允许移动
        BufferHandle(const BufferHandle&) = delete;
        BufferHandle& operator=(const BufferHandle&) = delete;
        BufferHandle(BufferHandle&&) = default;
        BufferHandle& operator=(BufferHandle&&) = default;

        FixedBuffer* get() { return buffer_.get(); }
        const FixedBuffer* get() const { return buffer_.get(); }
        FixedBuffer* operator->() { return buffer_.get(); }
        const FixedBuffer* operator->() const { return buffer_.get(); }
        FixedBuffer& operator*() { return *buffer_; }
        const FixedBuffer& operator*() const { return *buffer_; }

    private:
        std::unique_ptr<FixedBuffer> buffer_;
        BufferPool* pool_;
    };

    // 获取缓冲区（如果池为空，创建新的）
    BufferHandle acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!pool_.empty()) {
            auto buffer = std::move(pool_.back());
            pool_.pop_back();
            available_count_.fetch_sub(1, std::memory_order_relaxed);
            hit_count_.fetch_add(1, std::memory_order_relaxed);
            return BufferHandle(std::move(buffer), this);
        }
        
        // 池为空，创建新缓冲区（会被统计为 miss）
        miss_count_.fetch_add(1, std::memory_order_relaxed);
        return BufferHandle(std::make_unique<FixedBuffer>(), this);
    }

    // 归还缓冲区
    void return_buffer(std::unique_ptr<FixedBuffer> buffer) {
        if (!buffer) return;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        // 如果池未满，归还；否则丢弃（让它自动析构）
        if (pool_.size() < pool_size_) {
            pool_.push_back(std::move(buffer));
            available_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // 统计信息
    struct Stats {
        size_t pool_size;
        size_t available;
        size_t hit_count;
        size_t miss_count;
        double hit_rate;
    };

    Stats get_stats() const {
        Stats stats;
        stats.pool_size = pool_size_;
        stats.available = available_count_.load(std::memory_order_relaxed);
        stats.hit_count = hit_count_.load(std::memory_order_relaxed);
        stats.miss_count = miss_count_.load(std::memory_order_relaxed);
        
        size_t total = stats.hit_count + stats.miss_count;
        stats.hit_rate = total > 0 ? static_cast<double>(stats.hit_count) / total : 0.0;
        
        return stats;
    }

    // 获取当前可用数量
    size_t available() const {
        return available_count_.load(std::memory_order_relaxed);
    }

private:
    const size_t pool_size_;
    std::vector<std::unique_ptr<FixedBuffer>> pool_;
    std::mutex mutex_;
    
    // 统计计数器（无锁）
    std::atomic<size_t> available_count_{0};
    std::atomic<size_t> hit_count_{0};
    std::atomic<size_t> miss_count_{0};
};

// =====================
// 全局缓冲池（单例）
// =====================
inline BufferPool& get_global_buffer_pool(int max_size = 3000) {
    // 根据配置的 max_work_count 调整池大小
    // 默认 3000 (假设每个连接需要1个缓冲区)
    static BufferPool pool(max_size);
    return pool;
}

} // namespace scanner
