#include "scanner/protocols/protocol_parsers.h"
#include <sstream>
#include <algorithm>

namespace scanner {

// =====================
// SMTP
// =====================

SmtpBannerInfo parse_smtp_banner(const std::string& ehlo_response) {
    SmtpBannerInfo info;
    if (ehlo_response.empty()) return info;
    std::istringstream stream(ehlo_response);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() < 4 || line.compare(0, 3, "250") != 0) continue;
        std::string cap = line.substr(4);
        if (cap.empty()) continue;
        if (cap == "PIPELINING") info.pipelining = true;
        else if (cap == "STARTTLS") info.starttls = true;
        else if (cap == "8BITMIME") info._8bitmime = true;
        else if (cap == "DSN") info.dsn = true;
        else if (cap == "SMTPUTF8") info.utf8 = true;
        else if (cap.compare(0, 4, "SIZE") == 0 && cap.size() > 5) {
            info.size_supported = true;
            try { info.size_limit = std::stoull(cap.substr(5)); }
            catch (...) {}
        }
        else if (cap.compare(0, 4, "AUTH") == 0 && cap.size() > 5)
            info.auth_methods = cap.substr(5);
    }
    return info;
}

// =====================
// SSH
// =====================

SshVersionInfo parse_ssh_version(const std::string& banner) {
    SshVersionInfo info;
    if (banner.size() < 6 || banner.compare(0, 4, "SSH-") != 0) return info;
    info.version_string = banner;
    auto d1 = banner.find('-');
    auto d2 = banner.find('-', d1 + 1);
    if (d1 == std::string::npos || d2 == std::string::npos) return info;
    info.protocol_version = banner.substr(d1 + 1, d2 - d1 - 1);
    auto sp = banner.find(' ', d2 + 1);
    std::string sw = (sp != std::string::npos)
        ? banner.substr(d2 + 1, sp - d2 - 1) : banner.substr(d2 + 1);
    if (sw.empty()) return info;
    auto us = sw.find('_');
    if (us != std::string::npos) {
        info.software = sw.substr(0, us);
        info.version = sw.substr(us + 1);
    } else {
        auto ld = sw.rfind('-');
        if (ld != std::string::npos && ld > 0) {
            info.software = sw.substr(0, ld);
            info.version = sw.substr(ld + 1);
        } else info.software = sw;
    }
    return info;
}

// =====================
// FTP
// =====================

FtpFeatInfo parse_ftp_feat(const std::string& csv) {
    FtpFeatInfo info;
    if (csv.empty()) return info;
    info.features = csv;
    std::istringstream iss(csv);
    std::string f;
    while (std::getline(iss, f, ',')) {
        auto s = f.find_first_not_of(" ");
        if (s == std::string::npos) continue;
        auto e = f.find_last_not_of(" ");
        f = f.substr(s, e - s + 1);
        for (auto& c : f) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
        if (f == "UTF8")         info.utf8 = true;
        else if (f == "AUTH TLS")   info.auth_tls = true;
        else if (f == "AUTH SSL")   info.auth_ssl = true;
        else if (f == "SIZE")       info.size_cmd = true;
        else if (f == "MDTM")       info.mdtm = true;
        else if (f == "MLSD" || f == "MLST") info.mldst = true;
        else if (f == "TVFS")       info.tvfs = true;
    }
    return info;
}

// =====================
// POP3
// =====================

Pop3GreetingInfo parse_pop3_greeting(const std::string& response) {
    Pop3GreetingInfo info;
    std::istringstream stream(response);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.find("+OK") == 0 && info.banner.empty()) {
            info.banner = line;
            continue;
        }
        // CAPA 响应行（无 +OK 前缀的特性行）
        if (line == "STLS")       info.stls = true;
        else if (line == "SASL")  info.sasl = true;
        else if (line == "USER")  info.user = true;
        else if (line == "TOP")   info.top = true;
        else if (line == "PIPELINING") info.pipelining = true;
        else if (line == "UIDL")  info.uidl = true;
    }
    if (!info.banner.empty() || response.find("+OK") != std::string::npos) {
        info.capabilities = response;
    }
    return info;
}

// =====================
// IMAP
// =====================

ImapCapabilityInfo parse_imap_capability(const std::string& greeting) {
    ImapCapabilityInfo info;
    // 提取第一行作为 banner
    auto crlf = greeting.find("\r\n");
    info.banner = (crlf != std::string::npos) ? greeting.substr(0, crlf) : greeting;

    // 从 CAPABILITY 列表中提取特性
    auto cap_start = greeting.find("CAPABILITY");
    if (cap_start == std::string::npos) return info;
    auto cap_end = greeting.find("\r\n", cap_start);
    if (cap_end == std::string::npos) cap_end = greeting.size();
    std::string caps = greeting.substr(cap_start + 10, cap_end - cap_start - 10);

    // 去掉尾部 "]"
    auto bracket = caps.find(']');
    if (bracket != std::string::npos) caps = caps.substr(0, bracket);
    info.capabilities = caps;

    std::istringstream iss(caps);
    std::string cap;
    while (iss >> cap) {
        if (cap == "IMAP4rev1")      info.imap4rev1 = true;
        else if (cap == "STARTTLS")  info.starttls = true;
        else if (cap == "AUTH=PLAIN") info.auth_plain = true;
        else if (cap == "AUTH=LOGIN") info.auth_login = true;
        else if (cap == "IDLE")      info.idle = true;
        else if (cap == "QUOTA")     info.quota = true;
        else if (cap == "ACL")       info.acl = true;
        else if (cap == "UNSELECT")  info.unselect = true;
        else if (cap == "UIDPLUS")   info.uidplus = true;
    }
    return info;
}

// =====================
// HTTP
// =====================

HttpResponseInfo parse_http_response(const std::string& response) {
    HttpResponseInfo info;
    if (response.empty()) return info;

    // 状态行: "HTTP/1.1 200 OK\r\n..."
    auto crlf = response.find("\r\n");
    if (crlf != std::string::npos) {
        info.status_line = response.substr(0, crlf);
        // 提取状态码
        auto s1 = info.status_line.find(' ');
        if (s1 != std::string::npos) {
            auto s2 = info.status_line.find(' ', s1 + 1);
            if (s2 != std::string::npos) {
                try { info.status_code = std::stoi(info.status_line.substr(s1 + 1, s2 - s1 - 1)); }
                catch (...) {}
            }
        }
    }

    // 逐行解析头部
    std::istringstream stream(response);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.compare(0, 7, "Server:") == 0 || line.compare(0, 7, "server:") == 0) {
            info.server = line.substr(7);
            auto sp = info.server.find_first_not_of(" ");
            if (sp != std::string::npos) info.server = info.server.substr(sp);
        }
        else if (line.compare(0, 13, "Content-Type:") == 0 || line.compare(0, 13, "content-type:") == 0) {
            info.content_type = line.substr(13);
            auto sp = info.content_type.find_first_not_of(" ");
            if (sp != std::string::npos) info.content_type = info.content_type.substr(sp);
        }
    }
    return info;
}

// =====================
// MySQL
// =====================

MysqlHandshakeInfo parse_mysql_handshake(const char* data, size_t len) {
    MysqlHandshakeInfo info;
    // MySQL 协议有 4 字节包头（3 字节 payload 长度 LE + 1 字节序列号）
    constexpr size_t header_size = 4;
    if (len <= header_size) return info;

    const char* payload = data + header_size;
    size_t plen = len - header_size;
    if (plen < 1) return info;

    // Payload Byte 0: protocol version (0x0a = 10 for MySQL 5.x/8.x)
    info.protocol_version = static_cast<uint8_t>(payload[0]);
    if (plen < 2) return info;

    // Payload Bytes 1+: null-terminated version string
    size_t version_end = 1;
    while (version_end < plen && payload[version_end] != '\0') ++version_end;
    if (version_end > 1) {
        info.version_string = std::string(payload + 1, version_end - 1);
        info.version = info.version_string;
    }

    // After version string null: 4 bytes connection ID, 8 bytes auth data...
    size_t cap_offset = version_end + 1 + 4 + 8; // null + conn_id + auth-part1
    if (cap_offset + 2 <= plen) {
        info.capability_flags = static_cast<uint32_t>(
            static_cast<uint8_t>(payload[cap_offset]) |
            (static_cast<uint8_t>(payload[cap_offset + 1]) << 8)
        );
    }

    // Auth plugin name (at end of handshake, variable offset)
    size_t auth_plugin_offset = version_end + 1 + 4 + 8 + 2 + 1 + 2 + 2 + 1 + 10;
    if (auth_plugin_offset < plen) {
        size_t aplen = static_cast<uint8_t>(payload[version_end + 1 + 4 + 8 + 2 + 1 + 2 + 2 + 1]);
        if (aplen > 0) {
            auth_plugin_offset = version_end + 1 + 4 + 8 + 2 + 1 + 2 + 2 + 1 + 10 + aplen - 8;
            size_t ap_name_start = auth_plugin_offset + (aplen - 8);
            if (ap_name_start < plen) {
                size_t ap_end = ap_name_start;
                while (ap_end < plen && payload[ap_end] != '\0') ++ap_end;
                if (ap_end > ap_name_start) {
                    info.auth_plugin = std::string(payload + ap_name_start, ap_end - ap_name_start);
                }
            }
        }
    }

    return info;
}

} // namespace scanner