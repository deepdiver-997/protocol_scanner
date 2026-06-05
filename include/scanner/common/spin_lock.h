#pragma once

#include <atomic>

namespace scanner {

// 简单自旋锁，替代 std::mutex 用于短临界区
class SpinLock {
public:
    void lock() {
        while (flag_.test_and_set(std::memory_order_acquire)) {
            // 自旋等待
        }
    }
    void unlock() {
        flag_.clear(std::memory_order_release);
    }
    bool try_lock() {
        return !flag_.test_and_set(std::memory_order_acquire);
    }

private:
    std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
};

} // namespace scanner
