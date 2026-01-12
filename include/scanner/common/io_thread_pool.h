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

    mutable std::atomic<std::size_t> rr_{0};
};

} // namespace scanner
