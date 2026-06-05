#pragma once

#include "scanner/common/spin_lock.h"
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <future>
#include <thread>
#include <functional>
#include <atomic>
#include <type_traits>

namespace scanner {

// 线程安全队列（自旋锁），用于线程池任务或结果传递
template <typename T>
class BlockingQueue {
public:
    BlockingQueue() : stopped_(false) {}

    void push(const T& value) {
        {
            std::lock_guard<SpinLock> lock(mutex_);
            queue_.push(value);
        }
    }

    void push(T&& value) {
        {
            std::lock_guard<SpinLock> lock(mutex_);
            queue_.push(std::move(value));
        }
    }

    // 弹出元素（自旋等待）；stopped_ 时返回 false
    bool pop(T& out) {
        while (true) {
            {
                std::lock_guard<SpinLock> lock(mutex_);
                if (!queue_.empty()) {
                    out = std::move(queue_.front());
                    queue_.pop();
                    return true;
                }
                if (stopped_) return false;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }

    // 非阻塞弹出
    bool try_pop(T& out) {
        std::lock_guard<SpinLock> lock(mutex_);
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    void stop() {
        std::lock_guard<SpinLock> lock(mutex_);
        stopped_ = true;
    }

    bool empty() const {
        std::lock_guard<SpinLock> lock(mutex_);
        return queue_.empty();
    }

    std::size_t size() const {
        std::lock_guard<SpinLock> lock(mutex_);
        return queue_.size();
    }

private:
    mutable SpinLock mutex_;
    std::queue<T> queue_;
    bool stopped_;
};

// 简单固定大小线程池
class ThreadPool {
public:
    explicit ThreadPool(std::size_t thread_count = std::thread::hardware_concurrency());
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    // 提交任务，返回 future
    template <class F, class... Args>
    auto submit(F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>> {
        using ReturnT = std::invoke_result_t<F, Args...>;

        auto task = std::make_shared<std::packaged_task<ReturnT()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );

        std::future<ReturnT> res = task->get_future();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_) {
                throw std::runtime_error("ThreadPool stopped");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        cv_.notify_one();
        return res;
    }

    // 请求停止并加入所有线程
    void shutdown();

    std::size_t size() const { return workers_.size(); }

private:
    void worker_loop();

    std::vector<std::jthread> workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};
};

} // namespace scanner
