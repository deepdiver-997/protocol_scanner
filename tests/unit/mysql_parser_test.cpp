#include <catch2/catch_test_macros.hpp>
#include "scanner/protocols/protocol_parsers.h"
#include <cstring>
#include <string>

using namespace scanner;

// 构造完整 MySQL 握手包（含 4 字节包头）
// 包头格式: 3 字节 payload 长度 (LE) + 1 字节序列号 (0)
static std::string make_packet(uint8_t proto_ver, const std::string& version,
                                const std::string& auth_plugin = "") {
    // payload 部分
    std::string payload;
    payload += static_cast<char>(proto_ver);
    payload += version;
    payload += '\0';                             // version null terminator
    payload += std::string(4, '\0');             // connection ID
    payload += std::string(8, '\0');             // auth-plugin-data-part-1
    payload += '\0';                             // filler
    payload += std::string(2, '\0');             // capability flags lower
    payload += '\x08';                           // character set (utf8mb4)
    payload += std::string(2, '\0');             // status flags
    payload += std::string(2, '\0');             // capability flags upper
    payload += '\x15';                           // auth-plugin-data-len = 21
    payload += std::string(10, '\0');            // reserved
    // auth-plugin-data-part-2 + auth plugin name
    if (!auth_plugin.empty()) {
        // auth-plugin-data-len=21, so part2 = 21-8 = 13 bytes
        payload += std::string(13, '\0');        // auth-data-part-2
        payload += auth_plugin;
        payload += '\0';
    }

    // 构造包头
    uint32_t plen = static_cast<uint32_t>(payload.size());
    std::string pkt;
    pkt += static_cast<char>(plen & 0xFF);
    pkt += static_cast<char>((plen >> 8) & 0xFF);
    pkt += static_cast<char>((plen >> 16) & 0xFF);
    pkt += '\x00';                               // sequence number = 0
    pkt += payload;
    return pkt;
}

TEST_CASE("MySQL handshake parsing", "[mysql][parser]") {

    SECTION("MySQL 8.0.35") {
        auto raw = make_packet(10, "8.0.35", "caching_sha2_password");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        REQUIRE(info.protocol_version == 10);
        REQUIRE(info.version == "8.0.35");
        REQUIRE(info.version_string == "8.0.35");
        REQUIRE(info.auth_plugin == "caching_sha2_password");
    }

    SECTION("MySQL 5.7.42-log") {
        auto raw = make_packet(10, "5.7.42-log", "mysql_native_password");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        REQUIRE(info.protocol_version == 10);
        REQUIRE(info.version == "5.7.42-log");
        REQUIRE(info.auth_plugin == "mysql_native_password");
    }

    SECTION("MariaDB 10.5.12") {
        auto raw = make_packet(10, "10.5.12-MariaDB-log", "mysql_native_password");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        REQUIRE(info.version == "10.5.12-MariaDB-log");
    }

    SECTION("Percona Server") {
        auto raw = make_packet(10, "8.0.35-27-Percona Server (GPL)", "caching_sha2_password");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        REQUIRE(info.protocol_version == 10);
        REQUIRE(info.version.find("Percona") != std::string::npos);
    }

    SECTION("Empty data") {
        auto info = parse_mysql_handshake("", 0);
        REQUIRE(info.version.empty());
        REQUIRE(info.protocol_version == 0);
    }

    SECTION("Only 4-byte header (no payload)") {
        const char hdr[] = {'\x00', '\x00', '\x00', '\x00'};
        auto info = parse_mysql_handshake(hdr, 4);
        REQUIRE(info.version.empty());
        REQUIRE(info.protocol_version == 0);
    }

    SECTION("Header only, truncated before protocol_version") {
        const char hdr[] = {'\x04', '\x00', '\x00', '\x00'};
        auto info = parse_mysql_handshake(hdr, 4);
        REQUIRE(info.version.empty());
    }

    SECTION("Non-MySQL protocol_version (not 10)") {
        auto raw = make_packet(9, "9.0.0-broken");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        // parser 不校验协议版本——留给调用方判断
        REQUIRE(info.protocol_version == 9);
        REQUIRE(info.version == "9.0.0-broken");
    }

    SECTION("Empty version string") {
        auto raw = make_packet(10, "");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        REQUIRE(info.protocol_version == 10);
        REQUIRE(info.version.empty());
        REQUIRE(info.version_string.empty());
    }

    SECTION("Auth plugin at end of handshake") {
        auto raw = make_packet(10, "5.7.38", "mysql_native_password");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        REQUIRE(info.version == "5.7.38");
        REQUIRE(info.auth_plugin == "mysql_native_password");
    }

    SECTION("MySQL 5.0.96 (old, short handshake)") {
        auto raw = make_packet(10, "5.0.96-log");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        REQUIRE(info.version == "5.0.96-log");
        REQUIRE(info.protocol_version == 10);
    }

    SECTION("Version with underscore and build tag") {
        auto raw = make_packet(10, "8.0.28-0ubuntu0.20.04.3");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        REQUIRE(info.version == "8.0.28-0ubuntu0.20.04.3");
    }
}
