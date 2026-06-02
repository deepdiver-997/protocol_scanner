#include "scanner/protocols/ssh_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/read.hpp>
#include <cstring>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct SshProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;  // 使用内存池管理的固定缓冲区
    size_t bytes_read{0};
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    SshProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
        : socket(std::move(exec)), 
          timer(socket.get_executor()), 
          buffer(get_global_buffer_pool().acquire()),  // 从池中获取缓冲区
          timeout(t), 
          on_complete(std::move(cb)) {}

    void finish_success() {
        result.accessible = true;
        auto end = std::chrono::steady_clock::now();
        result.attrs.response_time_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start_time).count();
        complete();
    }

    void finish_error(const std::string& msg) {
        result.error = msg;
        complete();
    }

    void complete() {
        if (completed) return;
        completed = true;
        LOG_CORE_DEBUG("[SSH] complete() called, about to invoke on_complete callback");
        boost::system::error_code ec;
        (void)timer.cancel();
        socket.close(ec);
        if (on_complete) {
            LOG_CORE_DEBUG("[SSH] Invoking on_complete callback");
            on_complete(std::move(result));
            LOG_CORE_DEBUG("[SSH] on_complete callback returned");
        } else {
            LOG_CORE_DEBUG("[SSH] on_complete is null!");
        }
    }
};

void SshProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete
) {
    auto ctx = std::make_shared<SshProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    ctx->socket.open(tcp::v4());
    asio::socket_base::reuse_address reuse_opt(true);
    asio::socket_base::receive_buffer_size recv_buf(8 * 1024);   // 8 KB (sufficient for SSH banner)
    asio::socket_base::send_buffer_size send_buf(4 * 1024);      // 4 KB
    asio::ip::tcp::no_delay no_delay_opt(true);
    boost::system::error_code set_ec;
    ctx->socket.set_option(reuse_opt, set_ec);
    ctx->socket.set_option(recv_buf, set_ec);
    ctx->socket.set_option(send_buf, set_ec);
    ctx->socket.set_option(no_delay_opt, set_ec);

    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([this, ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("SSH probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [this, ctx](const boost::system::error_code& ec) {
        LOG_CORE_DEBUG("[SSH] async_connect callback called for {}:{}, ec={}", ctx->result.host, ctx->result.port, ec.message());
        if (ec) {
            ctx->finish_error("Connection failed: " + ec.message());
            return;
        }

        // SSH 协议在建立 TCP 连接后会立即发送版本标识行，以 "\n" 结尾
        // 使用固定缓冲区读取（最多 PROTOCOL_BUFFER_SIZE 字节）
        ctx->socket.async_read_some(
            asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
            [this, ctx](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                LOG_CORE_DEBUG("[SSH] async_read_some callback called for {}:{}, bytes={}, ec={}", ctx->result.host, ctx->result.port, bytes_transferred, ec.message());
                if (ec) {
                    ctx->finish_error("Read SSH version failed: " + ec.message());
                    return;
                }
                
                ctx->bytes_read = bytes_transferred;
                
                // 检查缓冲区是否被填满（可能被截断）
                if (bytes_transferred >= ctx->buffer->size()) {
                    ctx->result.attrs.banner_truncated = true;
                }
                
                // 查找换行符
                auto* data = ctx->buffer->data();
                auto* newline = static_cast<const char*>(std::memchr(data, '\n', bytes_transferred));
                
                std::string banner;
                if (newline) {
                    // 找到换行符，提取到换行符为止
                    banner.assign(data, newline - data);
                } else {
                    // 未找到换行符，取全部数据
                    banner.assign(data, bytes_transferred);
                }
                
                // 移除尾部的 \r
                if (!banner.empty() && banner.back() == '\r') {
                    banner.pop_back();
                }
                
                ctx->result.attrs.banner = banner;
                parse_capabilities(banner, ctx->result.attrs);
                LOG_CORE_DEBUG("[SSH] Calling finish_success for {}:{} with banner: {}", ctx->result.host, ctx->result.port, banner);
                ctx->finish_success();
            });
    });
    LOG_CORE_DEBUG("[SSH] async_probe submitted for {}:{}", target, port);
}

void SshProtocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    // SSH banner format: "SSH-{proto_ver}-{software_id}[ {comments}]"
    // Examples: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    //           "SSH-2.0-dropbear_2022.82"
    //           "SSH-1.99-OpenSSH_3.8.1p1"
    if (response.size() < 6 || response.compare(0, 4, "SSH-") != 0) {
        return;
    }

    attrs.ssh.version_string = response;

    // Extract protocol version: SSH-{version}-...
    auto first_dash = response.find('-');
    auto second_dash = response.find('-', first_dash + 1);
    if (first_dash == std::string::npos || second_dash == std::string::npos) {
        return;
    }
    attrs.ssh.protocol_version = response.substr(first_dash + 1, second_dash - first_dash - 1);

    // Extract software identifier: after second dash, before space or end
    auto space_pos = response.find(' ', second_dash + 1);
    std::string sw_id;
    if (space_pos != std::string::npos) {
        sw_id = response.substr(second_dash + 1, space_pos - second_dash - 1);
    } else {
        sw_id = response.substr(second_dash + 1);
    }

    if (sw_id.empty()) return;

    // Split by underscore: OpenSSH_8.9p1 -> software="OpenSSH", version="8.9p1"
    auto underscore = sw_id.find('_');
    if (underscore != std::string::npos) {
        attrs.ssh.software = sw_id.substr(0, underscore);
        attrs.ssh.version = sw_id.substr(underscore + 1);
    } else {
        // No underscore (e.g. Cisco-1.25), try last dash
        auto last_dash = sw_id.rfind('-');
        if (last_dash != std::string::npos && last_dash > 0) {
            attrs.ssh.software = sw_id.substr(0, last_dash);
            attrs.ssh.version = sw_id.substr(last_dash + 1);
        } else {
            attrs.ssh.software = sw_id;
        }
    }
}

} // namespace scanner
