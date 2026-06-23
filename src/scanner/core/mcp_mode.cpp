#include "scanner/core/mcp_mode.h"
#include "scanner/deep_probe/deep_probe_registry.h"
#include "scanner/common/logger.h"
#include "scanner/common/io_thread_pool.h"
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <sstream>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

MCPContext::MCPContext(uint16_t port, size_t num_slots)
    : port_(port), num_slots_(num_slots), slots_(num_slots) {}

MCPContext::~MCPContext() { stop(); }

void MCPContext::stop() {
    stop_ = true;
    if (acceptor_) {
        boost::system::error_code ec;
        acceptor_->close(ec);
        acceptor_.reset();
    }
    mcp_io_ctx_.stop();
}

// ---- 深度探测触发：投递到 IO 线程池执行，结果回写 mcp_io_ctx_ ----
void MCPContext::maybe_start_deep_probes(size_t slot_id, Scanner* scanner) {
    auto& slot = slots_[slot_id];
    ScanReport rep;
    {
        std::lock_guard<std::mutex> lock(slot.result_mutex);
        rep = slot.result;  // copy
    }

    // 收集所有匹配协议的探测
    struct Pending {
        IDeepProbe* probe;
        uint16_t port;
    };
    std::vector<Pending> to_run;

    for (const auto& pr : rep.protocols) {
        if (!pr.accessible) continue;
        auto probes = DeepProbeRegistry::instance().probes_for(pr.protocol);
        for (auto* p : probes) {
            to_run.push_back({p, pr.port});
        }
    }

    if (to_run.empty()) return;

    int pending = static_cast<int>(to_run.size());
    slot.deep_probes_pending.store(pending, std::memory_order_release);
    slot.status.store(3, std::memory_order_release);

    auto* io_pool = scanner->io_pool();

    for (auto& dp : to_run) {
        int ctx_id = io_pool->acquire_context();
        asio::post(io_pool->executor_for(ctx_id),
            [this, slot_id, ip = rep.target.get_ip_string(), port = dp.port,
             probe = dp.probe, io_pool, ctx_id]() {
                // 阻塞调用跑在 IO 线程上（MCP 低并发，可接受）
                std::string result = probe->probe(ip, port);
                io_pool->release_context(ctx_id);

                // 结果回写必须在 mcp_io_ctx_ 线程，避免 slot 竞争
                asio::post(mcp_io_ctx_, [this, slot_id, result]() {
                    auto& sl = slots_[slot_id];
                    std::lock_guard<std::mutex> lock(sl.result_mutex);
                    sl.deep_probe_results[result] = result;
                    int remain = sl.deep_probes_pending.fetch_sub(1, std::memory_order_acq_rel) - 1;
                    if (remain == 0) {
                        sl.status.store(2, std::memory_order_release);
                    }
                });
            });
    }
}

// ---- 请求处理 ----
std::string MCPContext::handle_request(const std::string& json_line, Scanner* scanner) {
    try {
        auto req = nlohmann::json::parse(json_line);

        // ---- get 查询已有槽位结果 ----
        if (req.contains("get")) {
            size_t slot_id = req["get"].get<size_t>();
            if (slot_id >= num_slots_) {
                return "{\"error\":\"invalid slot\"}\n";
            }
            auto& slot = slots_[slot_id];
            int st = slot.status.load(std::memory_order_acquire);

            if (st == 2 || st == 3) {
                nlohmann::json resp;
                resp["status"] = (st == 3) ? "deep_probing" : "done";
                resp["slot"] = slot_id;
                {
                    std::lock_guard<std::mutex> lock(slot.result_mutex);
                    resp["result"] = slot.result.target.get_ip_string();
                    if (!slot.result.protocols.empty()) {
                        auto& p = slot.result.protocols[0];
                        resp["protocol"] = p.protocol;
                        resp["accessible"] = p.accessible;
                        resp["banner"] = p.attrs.banner;
                        if (!p.error.empty()) resp["error"] = p.error;
                    }
                    if (!slot.deep_probe_results.empty()) {
                        nlohmann::json dp;
                        for (const auto& [name, val] : slot.deep_probe_results) {
                            dp[name] = val;
                        }
                        resp["deep_probes"] = dp;
                    }
                }
                return resp.dump() + "\n";
            } else if (st == 1) {
                return "{\"status\":\"pending\",\"slot\":" + std::to_string(slot_id) + "}\n";
            } else {
                return "{\"error\":\"slot not in use\"}\n";
            }
        }

        // ---- target 提交新扫描任务 ----
        if (req.contains("target")) {
            size_t slot_idx = num_slots_;
            bool found = false;

            auto find_free = [this, &req, scanner, &slot_idx, &found](size_t start) {
                for (size_t i = start; i < num_slots_ && !found; ++i) {
                    int expected = 0;
                    if (slots_[i].status.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) {
                        slots_[i].target_ip = req["target"].get<std::string>();
                        slots_[i].seq = i;
                        slots_[i].deep_probe_results.clear();
                        slots_[i].deep_probes_pending.store(0);
                        ScanTarget t;
                        t.set_ip(slots_[i].target_ip);
                        t.seq = i;
                        scanner->push_targets_to_queue(std::move(t));
                        slot_idx = i;
                        found = true;
                    }
                }
            };

            find_free(last_stop_);
            if (!found) find_free(0);

            if (found) {
                last_stop_ = slot_idx;
                nlohmann::json resp;
                resp["slot"] = slot_idx;
                resp["seq"] = slot_idx;
                resp["target"] = slots_[slot_idx].target_ip;
                return resp.dump() + "\n";
            }
            return "{\"error\":\"no free slots\"}\n";
        }

        return "{\"error\":\"unknown request, use {\\\"target\\\":\\\"ip\\\"} or {\\\"get\\\":id}\"}\n";
    } catch (const std::exception& e) {
        return std::string("{\"error\":\"") + e.what() + "\"}\n";
    }
}

// ---- 单连接处理 ----
void MCPContext::do_session(tcp::socket socket, Scanner* scanner) {
    auto sock = std::make_shared<tcp::socket>(std::move(socket));
    auto buf = std::make_shared<asio::streambuf>();
    asio::async_read_until(*sock, *buf, '\n',
        [this, scanner, sock, buf]
        (boost::system::error_code ec, size_t /*n*/) {
            if (ec) return;
            std::istream is(buf.get());
            std::string line;
            std::getline(is, line);
            std::string resp = handle_request(line, scanner);
            auto out = std::make_shared<std::string>(std::move(resp));
            asio::async_write(*sock, asio::buffer(*out),
                [out, sock](boost::system::error_code, size_t) {
                    // sock RAII 析构
                });
        });
}

// ---- 异步 accept 循环 ----
void MCPContext::start_async_accept(Scanner* scanner) {
    acceptor_->async_accept(
        [this, scanner](boost::system::error_code ec, tcp::socket socket) {
            if (!ec) {
                do_session(std::move(socket), scanner);
            }
            if (!stop_) {
                start_async_accept(scanner);
            }
        });
}

// ---- 输入回调：acceptor + work_guard + run_for 循环 ----
Scanner::InputFunc MCPContext::make_input_producer(Scanner* scanner) {
    return [this, scanner]() {
        tcp::endpoint ep(tcp::v4(), port_);
        acceptor_ = std::make_unique<tcp::acceptor>(mcp_io_ctx_, ep, true);
        acceptor_->listen(16);

        // work_guard 防止 run() 在无任务时退出
        auto work_guard = asio::make_work_guard(mcp_io_ctx_);

        std::cout << "[mcp] TCP server listening on port " << port_ << std::endl;
        LOG_CORE_INFO("[mcp] Listening on port {}", port_);

        start_async_accept(scanner);

        // 循环 run_for，每次返回时检查退出标志
        while (!stop_) {
            mcp_io_ctx_.run_for(std::chrono::milliseconds(500));
        }
    };
}

// ---- 结果回调：轮询 result_queue → 回填 slot → 触发深度探测 ----
Scanner::ResultFunc MCPContext::make_result_consumer(Scanner* scanner) {
    return [this, scanner]() {
        while (!stop_) {
            ScanReport rep;
            if (!scanner->result_queue().try_pop(rep)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            size_t slot_id = rep.target.seq;
            if (slot_id < num_slots_) {
                auto& slot = slots_[slot_id];
                {
                    std::lock_guard<std::mutex> lock(slot.result_mutex);
                    slot.result = std::move(rep);
                }
                slot.status.store(2, std::memory_order_release);

                maybe_start_deep_probes(slot_id, scanner);
            }
        }
    };
}

} // namespace scanner
