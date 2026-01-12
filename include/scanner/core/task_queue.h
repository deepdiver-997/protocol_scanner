#pragma once

#include "../protocols/protocol_base.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>

namespace scanner {

// =====================
// 线程安全的任务队列
// =====================

template<typename T>
class TaskQueue {
public:
    TaskQueue() = default;
    ~TaskQueue() = default;

    // 禁止拷贝和移动
    TaskQueue(const TaskQueue&) = delete;
    TaskQueue& operator=(const TaskQueue&) = delete;

    // 推送任务
    void push(const T& task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(task);
        }
        cond_.notify_one();
    }

    void push(T&& task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(task));
        }
        cond_.notify_one();
    }

    // 弹出任务（阻塞）
    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_.wait(lock, [this] { return !queue_.empty() || stopped_; });

        if (stopped_ && queue_.empty()) {
            return T{}; // 返回默认构造值
        }

        T task = std::move(queue_.front());
        queue_.pop();
        return task;
    }

    // 尝试弹出任务（非阻塞）
    bool try_pop(T& task) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) {
            return false;
        }
        task = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    // 停止队列
    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopped_ = true;
        }
        cond_.notify_all();
    }

    // 队列是否为空
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    // 队列大小
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cond_;
    std::queue<T> queue_;
    bool stopped_ = false;
};

} // namespace scanner
