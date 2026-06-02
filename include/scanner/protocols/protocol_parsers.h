#pragma once

#include <string>
#include <cstddef>

namespace scanner {

// =====================
// SMTP banner 解析器
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
// SSH 版本行解析器
// =====================
// 输入: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
// 输出: { version_string, software, version, protocol_version }

struct SshVersionInfo {
    std::string version_string;
    std::string software;
    std::string version;
    std::string protocol_version;
};

SshVersionInfo parse_ssh_version(const std::string& banner);

// =====================
// FTP FEAT 响应解析器
// =====================
// 输入: "AUTH TLS, UTF8, SIZE, MDTM"
// 输出: 各 feature 的 bool 值

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

} // namespace scanner