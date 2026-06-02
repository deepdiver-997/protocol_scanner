#include <catch2/catch_test_macros.hpp>
#include "scanner/protocols/protocol_parsers.h"

using namespace scanner;

// Helper: build a synthetic MySQL handshake packet
static std::string make_handshake(uint8_t proto_ver, const std::string& version) {
    std::string pkt;
    pkt += static_cast<char>(proto_ver);     // protocol version
    pkt += version;                          // version string
    pkt += '\0';                             // null terminator
    pkt += std::string(4, '\0');             // connection ID (dummy)
    pkt += std::string(8, '\0');             // auth-plugin-data-part-1
    pkt += '\0';                             // filler
    pkt += std::string(2, '\x00');           // capability flags lower
    pkt += '\x00';                           // character set
    pkt += std::string(2, '\x00');           // status flags
    pkt += std::string(2, '\x00');           // capability flags upper
    pkt += '\x00';                           // auth-plugin-data-len
    pkt += std::string(10, '\x00');          // reserved
    return pkt;
}

TEST_CASE("MySQL handshake parsing", "[mysql][parser]") {

    SECTION("MySQL 8.0.35") {
        auto raw = make_handshake(10, "8.0.35");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        CHECK(info.protocol_version == 10);
        CHECK(info.version == "8.0.35");
        CHECK(info.version_string == "8.0.35");
    }

    SECTION("MySQL 5.7.42") {
        auto raw = make_handshake(10, "5.7.42-log");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        CHECK(info.protocol_version == 10);
        CHECK(info.version == "5.7.42-log");
    }

    SECTION("MariaDB 10.5.12") {
        auto raw = make_handshake(10, "10.5.12-MariaDB-log");
        auto info = parse_mysql_handshake(raw.data(), raw.size());
        CHECK(info.version == "10.5.12-MariaDB-log");
    }

    SECTION("Empty/invalid data") {
        auto info = parse_mysql_handshake("", 0);
        CHECK(info.version.empty());
        CHECK(info.protocol_version == 0);
    }

    SECTION("Too short data") {
        auto info = parse_mysql_handshake("\x0a", 1);
        CHECK(info.version.empty());
        CHECK(info.protocol_version == 10);
    }
}
