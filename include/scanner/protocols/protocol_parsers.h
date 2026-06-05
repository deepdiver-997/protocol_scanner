#pragma once

#include <cstdint>
#include <string>
#include <cstddef>

namespace scanner {

// =====================
// SMTP
// =====================

struct SmtpBannerInfo {
    bool pipelining = false;
    bool starttls = false;
    bool size_supported = false;
    size_t size_limit = 0;
    bool utf8 = false;
    bool _8bitmime = false;
    bool dsn = false;
    std::string auth_methods;
};

SmtpBannerInfo parse_smtp_banner(const std::string& ehlo_response);

// =====================
// SSH
// =====================

struct SshVersionInfo {
    std::string version_string;
    std::string software;
    std::string version;
    std::string protocol_version;
};

SshVersionInfo parse_ssh_version(const std::string& banner);

// =====================
// FTP
// =====================

struct FtpFeatInfo {
    std::string features;
    bool utf8 = false;
    bool auth_tls = false;
    bool auth_ssl = false;
    bool size_cmd = false;
    bool mdtm = false;
    bool mldst = false;
    bool tvfs = false;
};

FtpFeatInfo parse_ftp_feat(const std::string& features_csv);

// =====================
// POP3
// =====================

struct Pop3GreetingInfo {
    std::string banner;
    bool stls = false;
    bool sasl = false;
    bool user = false;
    bool top = false;
    bool pipelining = false;
    bool uidl = false;
    std::string capabilities; // raw capability list
};

Pop3GreetingInfo parse_pop3_greeting(const std::string& response);

// =====================
// IMAP
// =====================

struct ImapCapabilityInfo {
    std::string banner;
    bool imap4rev1 = false;
    bool starttls = false;
    bool auth_plain = false;
    bool auth_login = false;
    bool idle = false;
    bool quota = false;
    bool acl = false;
    bool unselect = false;
    bool uidplus = false;
    std::string capabilities; // raw capability string
};

ImapCapabilityInfo parse_imap_capability(const std::string& greeting);

// =====================
// HTTP
// =====================

struct HttpResponseInfo {
    std::string status_line;
    int status_code = 0;
    std::string server;
    std::string content_type;
};

HttpResponseInfo parse_http_response(const std::string& response);

// =====================
// MySQL
// =====================

struct MysqlHandshakeInfo {
    std::string version_string;
    std::string version;
    uint8_t protocol_version = 0;
    std::string auth_plugin;
    uint32_t capability_flags = 0;
};

// 输入: MySQL 握手包原始字节（binary）
// 解析协议版本(1B) → 服务器版本(null-terminated) → 能力标志
MysqlHandshakeInfo parse_mysql_handshake(const char* data, size_t len);

} // namespace scanner