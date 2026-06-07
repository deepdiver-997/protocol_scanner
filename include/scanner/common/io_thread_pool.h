#pragma once

#include <boost/asio.hpp>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>

namespace scanner {

namespace asio = boost::asio;

class IoThreadPool {
public:
    explicit IoThreadPool(std::size_t io_count = std::thread::hardware_concurrency());
    ~IoThreadPool();

    IoThreadPool(const IoThreadPool&) = delete;
    IoThreadPool& operator=(const IoThreadPool&) = delete;

    std::size_t size() const { return contexts_.size(); }

    // ---- 负载感知的 context 分配 (供 scan_loop 使用) ----
    // 分配一个 io_context，返回 index，同时递增该 context 的负载计数
    int acquire_context();
    // 释放一个 io_context，递减负载计数
    void release_context(int idx);
    // 根据 index 获取 executor
    asio::any_io_executor executor_for(int idx) { return contexts_[idx]->get_executor(); }

    // 实时负载（metrics 用）：每个 context 当前有多少 probe 在用
    std::vector<std::size_t> io_loads() const {
        std::vector<std::size_t> counts;
        counts.reserve(pending_tasks_.size());
        for (const auto& c : pending_tasks_) {
            counts.push_back(c->load(std::memory_order_relaxed));
        }
        return counts;
    }

    // 累计分配次数（用于验证 round-robin 是否均匀）
    std::vector<std::size_t> assign_counts() const {
        std::vector<std::size_t> counts;
        counts.reserve(assign_counts_.size());
        for (const auto& c : assign_counts_) {
            counts.push_back(c->load(std::memory_order_relaxed));
        }
        return counts;
    }

    // 返回负载最小的 io_context 引用（不跟踪任务）
    asio::io_context& get_context();

    // 返回带负载计数的执行器；使用该执行器的 post/dispatch 会自动维护负载
    class TrackingExecutor {
    public:
        TrackingExecutor(asio::any_io_executor exec, std::unique_ptr<std::atomic<std::size_t>>& counter)
            : exec_(std::move(exec)), counter_(counter.get()) {}

        template <typename F>
        void post(F&& f) const {
            counter_->fetch_add(1, std::memory_order_relaxed);
            asio::post(exec_, [c = counter_, func = std::forward<F>(f)]() mutable {
                try { func(); } catch (...) {}
                c->fetch_sub(1, std::memory_order_relaxed);
            });
        }

        template <typename F>
        void dispatch(F&& f) const {
            counter_->fetch_add(1, std::memory_order_relaxed);
            asio::dispatch(exec_, [c = counter_, func = std::forward<F>(f)]() mutable {
                try { func(); } catch (...) {}
                c->fetch_sub(1, std::memory_order_relaxed);
            });
        }

        template <typename F>
        void defer(F&& f) const {
            counter_->fetch_add(1, std::memory_order_relaxed);
            asio::defer(exec_, [c = counter_, func = std::forward<F>(f)]() mutable {
                try { func(); } catch (...) {}
                c->fetch_sub(1, std::memory_order_relaxed);
            });
        }

        asio::any_io_executor underlying_executor() const { return exec_; }
        std::size_t pending() const { return counter_->load(std::memory_order_relaxed); }

    private:
        asio::any_io_executor exec_;
        std::atomic<std::size_t>* counter_;  // Non-owning pointer
    };

    TrackingExecutor get_tracking_executor();

    // 停止并等待线程退出
    void shutdown();

private:
    std::size_t choose_least_loaded_index() const;

    std::vector<std::unique_ptr<asio::io_context>> contexts_;
    std::vector<std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>>> guards_;
    std::vector<std::thread> threads_;
    std::vector<std::unique_ptr<std::atomic<std::size_t>>> pending_tasks_;
    std::vector<std::unique_ptr<std::atomic<std::size_t>>> assign_counts_;  // per-context probe assignment count

    mutable std::atomic<std::size_t> rr_{0};
};

} // namespace scanner
