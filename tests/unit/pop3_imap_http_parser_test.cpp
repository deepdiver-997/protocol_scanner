#include <catch2/catch_test_macros.hpp>
#include "scanner/protocols/protocol_parsers.h"

using namespace scanner;

TEST_CASE("POP3 greeting parsing", "[pop3][parser]") {

    SECTION("Dovecot with CAPA") {
        std::string resp =
            "+OK Dovecot (Ubuntu) ready\r\n"
            "USER\r\n"
            "TOP\r\n"
            "PIPELINING\r\n"
            "UIDL\r\n"
            ".\r\n";
        auto info = parse_pop3_greeting(resp);
        CHECK(info.banner.find("Dovecot") != std::string::npos);
        CHECK(info.user == true);
        CHECK(info.top == true);
        CHECK(info.pipelining == true);
        CHECK(info.uidl == true);
        CHECK(info.stls == false);
    }

    SECTION("Exchange with STLS") {
        std::string resp =
            "+OK Microsoft Exchange POP3 ready\r\n"
            "STLS\r\n"
            "USER\r\n"
            ".\r\n";
        auto info = parse_pop3_greeting(resp);
        CHECK(info.banner.find("Exchange") != std::string::npos);
        CHECK(info.stls == true);
        CHECK(info.user == true);
    }

    SECTION("Minimal greeting") {
        auto info = parse_pop3_greeting("+OK Hello there\r\n");
        CHECK(info.banner == "+OK Hello there");
        CHECK(info.user == false);
        CHECK(info.top == false);
    }
}

TEST_CASE("IMAP capability parsing", "[imap][parser]") {

    SECTION("Dovecot full capability") {
        std::string greeting =
            "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS "
            "ID ENABLE IDLE STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready\r\n";
        auto info = parse_imap_capability(greeting);
        CHECK(info.imap4rev1 == true);
        CHECK(info.starttls == true);
        CHECK(info.auth_plain == true);
        CHECK(info.auth_login == true);
        CHECK(info.idle == true);
        CHECK(info.quota == false);
    }

    SECTION("Exchange 2019") {
        std::string greeting =
            "* OK [CAPABILITY IMAP4 IMAP4rev1 AUTH=NTLM AUTH=GSSAPI "
            "STARTTLS] Microsoft Exchange 2019 ready\r\n";
        auto info = parse_imap_capability(greeting);
        CHECK(info.imap4rev1 == true);
        CHECK(info.starttls == true);
        CHECK(info.auth_plain == false);
        CHECK(info.auth_login == false);
    }

    SECTION("No capability line") {
        auto info = parse_imap_capability("* OK IMAP server ready\r\n");
        CHECK(info.imap4rev1 == false);
        CHECK(info.banner.find("ready") != std::string::npos);
    }
}

TEST_CASE("HTTP response parsing", "[http][parser]") {

    SECTION("nginx") {
        std::string resp =
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.18.0\r\n"
            "Content-Type: text/html\r\n"
            "\r\n";
        auto info = parse_http_response(resp);
        CHECK(info.status_code == 200);
        CHECK(info.server == "nginx/1.18.0");
        CHECK(info.content_type == "text/html");
    }

    SECTION("Apache with 404") {
        std::string resp =
            "HTTP/1.1 404 Not Found\r\n"
            "Server: Apache/2.4.41 (Ubuntu)\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "\r\n";
        auto info = parse_http_response(resp);
        CHECK(info.status_code == 404);
        CHECK(info.server.find("Apache") != std::string::npos);
    }

    SECTION("Empty response") {
        auto info = parse_http_response("");
        CHECK(info.status_code == 0);
        CHECK(info.server.empty());
    }

    SECTION("No Server header") {
        std::string resp =
            "HTTP/1.1 301 Moved\r\n"
            "Location: https://example.com\r\n"
            "\r\n";
        auto info = parse_http_response(resp);
        CHECK(info.status_code == 301);
        CHECK(info.server.empty());
    }
}
