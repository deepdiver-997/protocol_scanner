#include "scanner/core/mcp_mode.h"
#include "scanner/common/logger.h"
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <sstream>

namespace scanner {

MCPContext::MCPContext(uint16_t port, size_t num_slots)
    : port_(port), num_slots_(num_slots), slots_(num_slots) {}

MCPContext::~MCPContext() { stop(); }

void MCPContext::stop() {
    stop_ = true;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
    }
}

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
            if (st == 2) {
                // 已完成，返回结果
                nlohmann::json resp;
                resp["status"] = "done";
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
            // 线性扫描找空闲槽位
            auto get_free = [this, &req, scanner] (size_t start_) -> size_t {
                for (size_t i = start_; i < num_slots_; ++i) {
                    int expected = 0;
                    if (slots_[i].status.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) {
                        slots_[i].target_ip = req["target"].get<std::string>();
                        slots_[i].seq = i;  // seq = slot index，结果回填时 O(1) 定位
    
                        // 构造 ScanTarget 并推入生产队列
                        ScanTarget t;
                        t.set_ip(slots_[i].target_ip);
                        t.seq = i;
                        scanner->push_targets_to_queue(std::move(t));
                        return i;
                    }
                }
                return -1;
            };
            size_t i = get_free(this->last_stop_);
            if (i == -1) {
                for (int j = 0;j < 3;++j) {
                    i = get_free(0);
                    if (i != -1) break;
                }
            }
            if (i != -1) {
                last_stop_ = i;
                nlohmann::json resp;
                resp["slot"] = i;
                resp["seq"] = i;
                resp["target"] = slots_[i].target_ip;
                return resp.dump() + "\n";
            }
            return "{\"error\":\"no free slots\"}\n";
        }

        return "{\"error\":\"unknown request, use {\\\"target\\\":\\\"ip\\\"} or {\\\"get\\\":id}\"}\n";
    } catch (const std::exception& e) {
        return std::string("{\"error\":\"") + e.what() + "\"}\n";
    }
}

int MCPContext::accept_loop(Scanner* scanner) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        LOG_CORE_ERROR("[mcp] socket() failed");
        return -1;
    }

    int opt = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (::bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_CORE_ERROR("[mcp] bind(:{}) failed", port_);
        ::close(listen_fd_);
        return -1;
    }
    ::listen(listen_fd_, 16);

    std::cout << "[mcp] TCP server listening on port " << port_ << std::endl;
    LOG_CORE_INFO("[mcp] Listening on port {}", port_);

    while (!stop_) {
        int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) {
            if (stop_) break;
            continue;
        }

        // 简单的单行 JSON 协议：读一行 → 处理 → 返回一行
        char buf[4096];
        ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            std::string resp = handle_request(std::string(buf, n), scanner);
            ::send(fd, resp.data(), resp.size(), 0);
        }
        ::close(fd);
    }
    return 0;
}

Scanner::InputFunc MCPContext::make_input_producer(Scanner* scanner) {
    return [this, scanner]() {
        accept_loop(scanner);
    };
}

Scanner::ResultFunc MCPContext::make_result_consumer(Scanner* scanner) {
    return [this, scanner]() {
        while (!stop_) {
            ScanReport rep;
            if (!scanner->result_queue().try_pop(rep)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            // seq = slot_index → O(1) 回填
            size_t slot_id = rep.target.seq;
            if (slot_id < num_slots_) {
                auto& slot = slots_[slot_id];
                {
                    std::lock_guard<std::mutex> lock(slot.result_mutex);
                    slot.result = std::move(rep);
                }
                slot.status.store(2, std::memory_order_release);
            }
        }
    };
}

} // namespace scanner
