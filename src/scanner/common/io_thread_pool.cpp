#include "scanner/common/io_thread_pool.h"

namespace scanner {

IoThreadPool::IoThreadPool(std::size_t io_count) {
    if (io_count == 0) io_count = 1;
    contexts_.reserve(io_count);
    guards_.reserve(io_count);
    threads_.reserve(io_count);

    for (std::size_t i = 0; i < io_count; ++i) {
        contexts_.emplace_back(std::make_unique<asio::io_context>());
        guards_.emplace_back(std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(contexts_.back()->get_executor()));
        pending_tasks_.emplace_back(std::make_unique<std::atomic<std::size_t>>(0));
    }
    for (std::size_t i = 0; i < io_count; ++i) {
        threads_.emplace_back([ctx = contexts_[i].get()]() {
            try {
                ctx->run();
            } catch (...) {
            }
        });
    }
}

IoThreadPool::~IoThreadPool() {
    shutdown();
}

asio::io_context& IoThreadPool::get_context() {
    auto idx = choose_least_loaded_index();
    return *contexts_[idx];
}

IoThreadPool::TrackingExecutor IoThreadPool::get_tracking_executor() {
    auto idx = choose_least_loaded_index();
    return TrackingExecutor(contexts_[idx]->get_executor(), pending_tasks_[idx]);
}

std::size_t IoThreadPool::choose_least_loaded_index() const {
    std::size_t idx = 0;
    std::size_t min_load = (std::numeric_limits<std::size_t>::max)();
    for (std::size_t i = 0; i < pending_tasks_.size(); ++i) {
        auto load = pending_tasks_[i]->load(std::memory_order_relaxed);
        if (load < min_load) {
            min_load = load;
            idx = i;
        }
    }
    if (min_load == (std::numeric_limits<std::size_t>::max)()) {
        // fallback RR when no tracking has occurred
        auto current = rr_.fetch_add(1, std::memory_order_relaxed);
        idx = current % contexts_.size();
    }
    return idx;
}

void IoThreadPool::shutdown() {
    // stop work guards first to allow run() to finish when queues drain
    for (auto& g : guards_) {
        if (g) g->reset();
    }
    for (auto& c : contexts_) {
        if (c) c->stop();
    }
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    guards_.clear();
    contexts_.clear();
    threads_.clear();
    pending_tasks_.clear();
}

} // namespace scanner
