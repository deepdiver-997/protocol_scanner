#include <catch2/catch_test_macros.hpp>
#include "scanner/protocols/protocol_parsers.h"

using namespace scanner;

TEST_CASE("SMTP banner parsing", "[smtp][parser]") {

    SECTION("Postfix with all features") {
        std::string banner =
            "250-mail.example.com\r\n"
            "250-PIPELINING\r\n"
            "250-SIZE 35882577\r\n"
            "250-VRFY\r\n"
            "250-ETRN\r\n"
            "250-STARTTLS\r\n"
            "250-ENHANCEDSTATUSCODES\r\n"
            "250-8BITMIME\r\n"
            "250-DSN\r\n"
            "250-SMTPUTF8\r\n"
            "250 CHUNKING\r\n";

        auto info = parse_smtp_banner(banner);

        REQUIRE(info.pipelining == true);
        REQUIRE(info.starttls == true);
        REQUIRE(info.size_supported == true);
        REQUIRE(info.size_limit == 35882577);
        REQUIRE(info._8bitmime == true);
        REQUIRE(info.dsn == true);
        REQUIRE(info.utf8 == true);
    }

    SECTION("QQ Mail with AUTH") {
        std::string banner =
            "250-smtp.qq.com\r\n"
            "250-PIPELINING\r\n"
            "250-SIZE 73400320\r\n"
            "250-AUTH LOGIN PLAIN\r\n"
            "250-AUTH=LOGIN PLAIN\r\n"
            "250-MAILCOMPRESS\r\n"
            "250 8BITMIME\r\n";

        auto info = parse_smtp_banner(banner);

        REQUIRE(info.pipelining == true);
        REQUIRE(info.size_supported == true);
        REQUIRE(info.size_limit == 73400320);
        REQUIRE(info.auth_methods == "LOGIN PLAIN");
        REQUIRE(info._8bitmime == true);
    }

    SECTION("Exchange minimal banner") {
        std::string banner =
            "250-PIPELINING\r\n"
            "250-SIZE\r\n"
            "250-8BITMIME\r\n"
            "250 BINARYMIME\r\n";

        auto info = parse_smtp_banner(banner);

        REQUIRE(info.pipelining == true);
        REQUIRE(info.size_supported == false);  // SIZE without value
        REQUIRE(info._8bitmime == true);
        REQUIRE(info.starttls == false);
        REQUIRE(info.dsn == false);
    }

    SECTION("Empty banner returns defaults") {
        auto info = parse_smtp_banner("");

        REQUIRE(info.pipelining == false);
        REQUIRE(info.starttls == false);
        REQUIRE(info.size_supported == false);
    }

    SECTION("Gmail banner") {
        std::string banner =
            "250-mx.google.com at your service\r\n"
            "250-SIZE 35882577\r\n"
            "250-8BITMIME\r\n"
            "250-STARTTLS\r\n"
            "250-ENHANCEDSTATUSCODES\r\n"
            "250-PIPELINING\r\n"
            "250-CHUNKING\r\n"
            "250 SMTPUTF8\r\n";

        auto info = parse_smtp_banner(banner);

        REQUIRE(info.starttls == true);
        REQUIRE(info.pipelining == true);
        REQUIRE(info.utf8 == true);
        REQUIRE(info.size_limit == 35882577);
    }
}
