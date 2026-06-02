#include <catch2/catch_test_macros.hpp>
#include "scanner/protocols/protocol_parsers.h"

using namespace scanner;

// =====================
// SSH 版本行解析
// =====================

TEST_CASE("SSH version parsing", "[ssh][parser]") {

    SECTION("OpenSSH with comments") {
        auto info = parse_ssh_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15");
        CHECK(info.software == "OpenSSH");
        CHECK(info.version == "8.9p1");
        CHECK(info.protocol_version == "2.0");
        CHECK(info.version_string == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15");
    }

    SECTION("Dropbear") {
        auto info = parse_ssh_version("SSH-2.0-dropbear_2022.82");
        CHECK(info.software == "dropbear");
        CHECK(info.version == "2022.82");
        CHECK(info.protocol_version == "2.0");
    }

    SECTION("Cisco (no underscore, uses dash)") {
        auto info = parse_ssh_version("SSH-1.99-Cisco-1.25");
        CHECK(info.software == "Cisco");
        CHECK(info.version == "1.25");
        CHECK(info.protocol_version == "1.99");
    }

    SECTION("libssh") {
        auto info = parse_ssh_version("SSH-2.0-libssh_0.9.6");
        CHECK(info.software == "libssh");
        CHECK(info.version == "0.9.6");
    }

    SECTION("Invalid banner returns defaults") {
        auto info = parse_ssh_version("");
        CHECK(info.software.empty());
        CHECK(info.version.empty());
    }

    SECTION("Non-SSH string returns defaults") {
        auto info = parse_ssh_version("HTTP/1.1 200 OK");
        CHECK(info.software.empty());
    }
}

// =====================
// FTP FEAT 响应解析
// =====================

TEST_CASE("FTP FEAT parsing", "[ftp][parser]") {

    SECTION("vsftpd features") {
        auto info = parse_ftp_feat("AUTH TLS, AUTH SSL, SIZE, MDTM, UTF8");
        CHECK(info.auth_tls == true);
        CHECK(info.auth_ssl == true);
        CHECK(info.size_cmd == true);
        CHECK(info.mdtm == true);
        CHECK(info.utf8 == true);
        CHECK(info.tvfs == false);
    }

    SECTION("ProFTPD features") {
        auto info = parse_ftp_feat("UTF8, AUTH TLS, SIZE, MDTM, MLSD, TVFS");
        CHECK(info.utf8 == true);
        CHECK(info.auth_tls == true);
        CHECK(info.size_cmd == true);
        CHECK(info.mdtm == true);
        CHECK(info.mldst == true);
        CHECK(info.tvfs == true);
    }

    SECTION("Empty features") {
        auto info = parse_ftp_feat("");
        CHECK(info.utf8 == false);
        CHECK(info.size_cmd == false);
    }

    SECTION("Single feature") {
        auto info = parse_ftp_feat("UTF8");
        CHECK(info.utf8 == true);
        CHECK(info.auth_tls == false);
    }
}
