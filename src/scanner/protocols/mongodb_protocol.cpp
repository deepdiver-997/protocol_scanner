#include "scanner/protocols/mongodb_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <cstring>
#include <arpa/inet.h>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct MongoProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    MongoProbeContext(boost::asio::any_io_executor exec, Timeout t,
                      std::function<void(ProtocolResult&&)> cb)
        : socket(std::move(exec)), timer(socket.get_executor()),
          buffer(get_global_buffer_pool().acquire()),
          timeout(t), on_complete(std::move(cb)) {}

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
        boost::system::error_code ec;
        (void)timer.cancel();
        socket.close(ec);
        if (on_complete) on_complete(std::move(result));
    }
};

// ========== 最简 BSON 解析 ==========

// 在 BSON 字节流中扫描，查找指定 key，返回其 string 值
std::string bson_get_string(const char* data, size_t len, const std::string& key) {
    if (len < 5) return "";
    // 跳过 doc_size (4 bytes)
    const char* p = data + 4;
    const char* end = data + len;

    while (p < end - 1) {
        uint8_t type = static_cast<uint8_t>(*p++);
        if (type == 0) break; // 文档结束
        const char* keystart = p;
        while (p < end && *p != '\0') ++p;
        if (p >= end) break;
        std::string_view k(keystart, p - keystart);
        ++p; // 跳过 key 的 \0

        if (k == key && type == 0x02) { // string
            if (p + 4 > end) break;
            int32_t slen;
            std::memcpy(&slen, p, 4);
            p += 4;
            if (slen <= 1 || p + slen - 1 > end) break;
            std::string val(p, slen - 1); // 不包括结尾 \0
            return val;
        } else if (k == key && type == 0x10) { // int32 — 不作为字符串返回
            // 调用方用 bson_get_int32 处理
        }

        // 跳过 value
        switch (type) {
        case 0x01: p += 8; break;                    // double
        case 0x02: { // string
            if (p + 4 > end) return "";
            int32_t slen;
            std::memcpy(&slen, p, 4);
            p += 4 + slen;
            break;
        }
        case 0x03: case 0x04: { // embedded doc / array
            if (p + 4 > end) return "";
            int32_t doc_len;
            std::memcpy(&doc_len, p, 4);
            p += doc_len;
            break;
        }
        case 0x05: case 0x06: case 0x07: case 0x12: p += 8;  break; // 64-bit
        case 0x08: p += 1; break;  // bool
        case 0x09: p += 8; break;  // datetime
        case 0x0A: p += 0; break;  // null - no value
        case 0x10: p += 4; break;  // int32
        case 0x11: case 0x13: p += 8; break;  // int64, decimal128
        default:   return "";      // unknown type, bail
        }
    }
    return "";
}

int bson_get_int32(const char* data, size_t len, const std::string& key) {
    if (len < 5) return 0;
    const char* p = data + 4;
    const char* end = data + len;

    while (p < end - 1) {
        uint8_t type = static_cast<uint8_t>(*p++);
        if (type == 0) break;
        const char* keystart = p;
        while (p < end && *p != '\0') ++p;
        if (p >= end) break;
        std::string_view k(keystart, p - keystart);
        ++p;

        if (k == key && type == 0x10) {
            if (p + 4 > end) break;
            int32_t val;
            std::memcpy(&val, p, 4);
            return val;
        }

        // 跳过 value（同上）
        switch (type) {
        case 0x01: p += 8; break;
        case 0x02:
            if (p + 4 > end) return 0;
            { int32_t slen; std::memcpy(&slen, p, 4); p += 4 + slen; }
            break;
        case 0x03: case 0x04:
            if (p + 4 > end) return 0;
            { int32_t doc_len; std::memcpy(&doc_len, p, 4); p += doc_len; }
            break;
        case 0x05: case 0x06: case 0x07: case 0x09: case 0x12: p += 8; break;
        case 0x08: p += 1; break;
        case 0x0A: break;
        case 0x10: p += 4; break;
        case 0x11: case 0x13: p += 8; break;
        default:   return 0;
        }
    }
    return 0;
}

// ========== OP_MSG 构造 ==========

static std::string build_is_master_msg() {
    // BSON: {"isMaster": 1, "helloOk": true, "$db": "admin"}
    // msgHeader (16) + flagBits (4) + sectionKind (1) + BSON

    // BSON
    std::string bson;
    auto append_int32 = [&](const std::string& k, int32_t v) {
        bson += '\x10';
        bson += k;
        bson += '\0';
        bson.append(reinterpret_cast<const char*>(&v), 4);
    };
    auto append_bool = [&](const std::string& k, bool v) {
        bson += '\x08';
        bson += k;
        bson += '\0';
        bson += static_cast<char>(v ? 1 : 0);
    };
    auto append_string = [&](const std::string& k, const std::string& v) {
        bson += '\x02';
        bson += k;
        bson += '\0';
        int32_t slen = static_cast<int32_t>(v.size() + 1);
        bson.append(reinterpret_cast<const char*>(&slen), 4);
        bson += v;
        bson += '\0';
    };

    append_int32("isMaster", 1);
    append_bool("helloOk", true);
    append_string("$db", "admin");
    bson += '\0'; // terminator

    int32_t doc_size = static_cast<int32_t>(bson.size() + 4); // +4 for doc_size itself
    std::string bson_with_len;
    bson_with_len.append(reinterpret_cast<const char*>(&doc_size), 4);
    bson_with_len += bson;

    // OP_MSG: MsgHeader + flagBits + sections
    int32_t total_len = 16 + 4 + 1 + static_cast<int32_t>(bson_with_len.size());
    int32_t request_id = 1;
    int32_t response_to = 0;
    int32_t op_code = 2013; // OP_MSG
    int32_t flag_bits = 0;  // body section only
    uint8_t section_kind = 0;

    std::string msg;
    msg.reserve(total_len);
    msg.append(reinterpret_cast<const char*>(&total_len), 4);
    msg.append(reinterpret_cast<const char*>(&request_id), 4);
    msg.append(reinterpret_cast<const char*>(&response_to), 4);
    msg.append(reinterpret_cast<const char*>(&op_code), 4);
    msg.append(reinterpret_cast<const char*>(&flag_bits), 4);
    msg.append(reinterpret_cast<const char*>(&section_kind), 1);
    msg += bson_with_len;
    return msg;
}

// ========== async_probe ==========

void MongoProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete,
    const std::string& bind_ip
) {
    auto ctx = std::make_shared<MongoProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    ctx->socket.open(tcp::v4());
    asio::socket_base::reuse_address reuse_opt(true);
    asio::socket_base::receive_buffer_size recv_buf(16 * 1024);
    asio::socket_base::send_buffer_size send_buf(4 * 1024);
    asio::ip::tcp::no_delay no_delay_opt(true);
    boost::system::error_code set_ec;
    ctx->socket.set_option(reuse_opt, set_ec);
    ctx->socket.set_option(recv_buf, set_ec);
    ctx->socket.set_option(send_buf, set_ec);
    ctx->socket.set_option(no_delay_opt, set_ec);

    // 绑定到指定本地 IP（多 IP 场景下分散临时端口池）
    if (!bind_ip.empty()) {
        boost::system::error_code bind_ec;
        ctx->socket.bind(tcp::endpoint(asio::ip::make_address(bind_ip, bind_ec), 0), bind_ec);
        if (bind_ec) {
            ctx->finish_error("Bind failed: " + bind_ec.message());
            return;
        }
    }

    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) ctx->finish_error("MongoDB probe timed out");
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) { ctx->finish_error("Invalid address"); return; }

    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [ctx](const boost::system::error_code& ec) {
        if (ec) { ctx->finish_error("Connect failed: " + ec.message()); return; }

        static const std::string is_master = build_is_master_msg();
        asio::async_write(ctx->socket, asio::buffer(is_master),
            [ctx](const boost::system::error_code& ec, std::size_t) {
                if (ec) { ctx->finish_error("isMaster write failed: " + ec.message()); return; }

                ctx->socket.async_read_some(
                    asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
                    [ctx](const boost::system::error_code& ec, std::size_t n) {
                        if (ec) { ctx->finish_error("Read failed: " + ec.message()); return; }

                        ctx->bytes_read = n;

                        // 检查是否像 MongoDB 响应（opCode=2013 的 OP_MSG）
                        if (n < 20) { ctx->finish_error("Response too short"); return; }

                        int32_t msg_len, op_code;
                        std::memcpy(&msg_len, ctx->buffer->data(), 4);
                        std::memcpy(&op_code, ctx->buffer->data() + 12, 4);

                        if (op_code != 2013) {
                            ctx->finish_error("Not MongoDB (opCode="
                                + std::to_string(op_code) + ")");
                            return;
                        }

                        // BSON 从 offset 21 开始: header(16) + flags(4) + kind(1)
                        const char* bson_start = ctx->buffer->data() + 21;
                        size_t bson_len = n - 21;

                        std::string version = bson_get_string(bson_start, bson_len, "version");
                        int32_t max_wire = bson_get_int32(bson_start, bson_len, "maxWireVersion");

                        ctx->result.attrs.mongo.version = version;
                        ctx->result.attrs.mongo.max_wire_version = max_wire;
                        ctx->result.attrs.mongo.is_master = true;
                        ctx->result.attrs.banner = version;
                        ctx->result.attrs.vendor = "MongoDB " + version;
                        ctx->finish_success();
                    });
            });
    });
}

void MongoProtocol::parse_capabilities(const std::string&, ProtocolAttributes&) {
    // 解析在 async_probe 回调整合中完成
}

} // namespace scanner
