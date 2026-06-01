#include "scanner/protocols/ftp_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <cstring>
#include <sstream>

namespace scanner {

// 前向声明
void parse_ftp_features(const std::string& features, ProtocolAttributes& attrs);

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct FtpProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    size_t buffer_offset{0};
    std::string features_accum;   // 累积 FEAT 响应行
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};
    bool feat_sent{false};        // 标记是否已发送 FEAT

    FtpProbeContext(boost::asio::any_io_executor exec, Timeout t,
                    std::function<void(ProtocolResult&&)> cb)
        : socket(std::move(exec)), timer(socket.get_executor()),
          buffer(get_global_buffer_pool().acquire()),
          timeout(t), on_complete(std::move(cb)) {}

    void finish_success() {
        result.accessible = true;
        // 将累积的 FEAT 特性写回 attrs
        if (!features_accum.empty()) {
            parse_ftp_features(features_accum, result.attrs);
        }
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
        boost::system::error_code ec;
        (void)timer.cancel();
        socket.close(ec);
        if (on_complete) {
            on_complete(std::move(result));
        }
    }
};

void FtpProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete
) {
    auto ctx = std::make_shared<FtpProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    ctx->socket.open(tcp::v4());
    asio::socket_base::reuse_address reuse_opt(true);
    asio::socket_base::receive_buffer_size recv_buf(8 * 1024);
    asio::socket_base::send_buffer_size send_buf(4 * 1024);
    asio::ip::tcp::no_delay no_delay_opt(true);
    boost::system::error_code set_ec;
    ctx->socket.set_option(reuse_opt, set_ec);
    ctx->socket.set_option(recv_buf, set_ec);
    ctx->socket.set_option(send_buf, set_ec);
    ctx->socket.set_option(no_delay_opt, set_ec);

    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("FTP probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    // ========== 定义 FEAT 读取器（递归读取多行响应） ==========
    auto read_feat = std::make_shared<std::function<void()>>();
    *read_feat = [ctx, read_feat]() {
        // 如果缓冲区已消费完，发起新一轮读取
        if (ctx->buffer_offset >= ctx->bytes_read) {
            if (ctx->bytes_read >= ctx->buffer->size()) {
                // 缓冲区满了还没结束——终止，用已解析的内容
                ctx->finish_success();
                return;
            }
            ctx->socket.async_read_some(
                asio::buffer(ctx->buffer->data() + ctx->bytes_read,
                           ctx->buffer->size() - ctx->bytes_read),
                [ctx, read_feat](const boost::system::error_code& ec, std::size_t bytes) {
                    if (ec) {
                        // 读到 EOF 也算完成
                        ctx->finish_success();
                        return;
                    }
                    ctx->bytes_read += bytes;
                    (*read_feat)();
                });
            return;
        }

        // 从 buffer_offset 开始查找一行
        auto* data = ctx->buffer->data() + ctx->buffer_offset;
        size_t remaining = ctx->bytes_read - ctx->buffer_offset;
        std::string_view sv(data, remaining);
        auto pos = sv.find("\r\n");

        if (pos == std::string_view::npos) {
            // 没有完整行，继续读
            if (ctx->bytes_read >= ctx->buffer->size()) {
                ctx->finish_success();
            } else {
                (*read_feat)();
            }
            return;
        }

        std::string line(data, pos);
        ctx->buffer_offset += pos + 2;  // 跳过 \r\n

        // 如果是末尾行 "211 "（以 211 空格开头），结束响应
        if (line.size() >= 4 && line.compare(0, 4, "211 ") == 0) {
            ctx->finish_success();
            return;
        }

        // 如果是中间行（以空格开头），提取特性名
        if (!line.empty() && line[0] == ' ') {
            std::string feat = line.substr(1);
            // 去除尾部可能存在的注释
            auto space_pos = feat.find(' ');
            if (space_pos != std::string::npos) {
                feat = feat.substr(0, space_pos);
            }
            if (!feat.empty()) {
                if (!ctx->features_accum.empty())
                    ctx->features_accum += ", ";
                ctx->features_accum += feat;
            }
        }
        // 忽略 211-Extensions（首行）和空行

        // 继续读下一行
        (*read_feat)();
    };

    // ========== 定义 FEAT 命令发送器 ==========
    auto send_feat = [ctx, read_feat]() {
        static const std::string feat_cmd = "FEAT\r\n";
        asio::async_write(
            ctx->socket, asio::buffer(feat_cmd),
            [ctx, read_feat](const boost::system::error_code& write_ec, std::size_t) {
                if (write_ec) {
                    // FEAT 发不出去也不影响——banner 已经有了
                    ctx->finish_success();
                    return;
                }
                ctx->feat_sent = true;
                // 重置缓冲区偏移，准备读取 FEAT 响应
                ctx->buffer_offset = 0;
                ctx->bytes_read = 0;
                (*read_feat)();
            });
    };

    // ========== 主流程：连接 → 读 Banner → 发 FEAT → 读 FEAT 响应 ==========
    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [this, ctx, send_feat](const boost::system::error_code& ec) {
        if (ec) {
            ctx->finish_error("Connection failed: " + ec.message());
            return;
        }

        // 读完欢迎 banner 后再发 FEAT
        ctx->socket.async_read_some(
            asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
            [this, ctx, send_feat](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (ec && ec != asio::error::eof) {
                    ctx->finish_error("Read banner failed: " + ec.message());
                    return;
                }

                ctx->bytes_read = bytes_transferred;
                auto* data = ctx->buffer->data();

                // 提取第一行作为 banner
                std::string_view sv(data, bytes_transferred);
                auto pos = sv.find("\r\n");

                std::string line;
                if (pos != std::string_view::npos) {
                    line.assign(data, pos);
                } else {
                    auto* lf = static_cast<const char*>(std::memchr(data, '\n', bytes_transferred));
                    if (lf) {
                        line.assign(data, lf - data);
                        if (!line.empty() && line.back() == '\r') line.pop_back();
                    } else {
                        line.assign(data, bytes_transferred);
                    }
                }

                ctx->result.attrs.banner = line;
                parse_capabilities(line, ctx->result.attrs);

                // banner 读完后发 FEAT
                send_feat();
            });
    });
}

void FtpProtocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    // 空实现——FEAT 通过 features_accum 在 context 中传递
    // 实际解析在 async_probe 完成后由外部统一处理
    (void)response;
    (void)attrs;
}

// =====================
// FTP 特性解析工具函数
// =====================

void parse_ftp_features(const std::string& features, ProtocolAttributes& attrs) {
    if (features.empty()) return;
    attrs.ftp.features = features;

    std::istringstream iss(features);
    std::string feat;
    while (std::getline(iss, feat, ',')) {
        // 去除首尾空格
        auto trim_start = feat.find_first_not_of(" ");
        if (trim_start == std::string::npos) continue;
        auto trim_end = feat.find_last_not_of(" ");
        feat = feat.substr(trim_start, trim_end - trim_start + 1);

        // 统一转大写（部分服务器返回 "utf8" 小写）
        for (auto& c : feat) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));

        if (feat == "UTF8")         attrs.ftp.utf8 = true;
        else if (feat == "AUTH TLS")   attrs.ftp.auth_tls = true;
        else if (feat == "AUTH SSL")   attrs.ftp.auth_ssl = true;
        else if (feat == "SIZE")       attrs.ftp.size_cmd = true;
        else if (feat == "MDTM")       attrs.ftp.mdtm = true;
        else if (feat == "MLSD" || feat == "MLST") attrs.ftp.mldst = true;
        else if (feat == "TVFS")       attrs.ftp.tvfs = true;
        else if (feat == "XCRC")       attrs.ftp.xcrc = true;
        else if (feat == "XCUP")       attrs.ftp.xcup = true;
    }
}

} // namespace scanner