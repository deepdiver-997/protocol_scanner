#include "scanner/output/result_handler.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <unordered_map>

namespace scanner {

// -------------- 内部辅助 --------------

static inline const char* bool_str(bool v) { return v ? "1" : "0"; }
static std::string sanitize_utf8(const std::string& input);

// -------------- 构造函数 --------------

ResultHandler::ResultHandler() {
    using json = nlohmann::json;

    attr_writers_["SMTP"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["pipelining"] = pr.attrs.smtp.pipelining;
        a["starttls"] = pr.attrs.smtp.starttls;
        a["size_supported"] = pr.attrs.smtp.size_supported;
        a["size_limit"] = pr.attrs.smtp.size_limit;
        a["utf8"] = pr.attrs.smtp.utf8;
        a["8bitmime"] = pr.attrs.smtp._8bitmime;
        a["dsn"] = pr.attrs.smtp.dsn;
        a["auth_methods"] = sanitize_utf8(pr.attrs.smtp.auth_methods);
        jp["smtp"] = a;
    };
    attr_writers_["POP3"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["stls"] = pr.attrs.pop3.stls;
        a["sasl"] = pr.attrs.pop3.sasl;
        a["user"] = pr.attrs.pop3.user;
        a["top"] = pr.attrs.pop3.top;
        a["pipelining"] = pr.attrs.pop3.pipelining;
        a["uidl"] = pr.attrs.pop3.uidl;
        a["capabilities"] = sanitize_utf8(pr.attrs.pop3.capabilities);
        jp["pop3"] = a;
    };
    attr_writers_["IMAP"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["starttls"] = pr.attrs.imap.starttls;
        a["quota"] = pr.attrs.imap.quota;
        a["acl"] = pr.attrs.imap.acl;
        a["imap4rev1"] = pr.attrs.imap.imap4rev1;
        a["auth_plain"] = pr.attrs.imap.auth_plain;
        a["auth_login"] = pr.attrs.imap.auth_login;
        a["idle"] = pr.attrs.imap.idle;
        a["unselect"] = pr.attrs.imap.unselect;
        a["uidplus"] = pr.attrs.imap.uidplus;
        a["capabilities"] = sanitize_utf8(pr.attrs.imap.capabilities);
        jp["imap"] = a;
    };
    attr_writers_["HTTP"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["server"] = sanitize_utf8(pr.attrs.http.server);
        a["content_type"] = sanitize_utf8(pr.attrs.http.content_type);
        a["status_code"] = pr.attrs.http.status_code;
        jp["http"] = a;
    };
    attr_writers_["MYSQL"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["version"] = sanitize_utf8(pr.attrs.mysql.version);
        a["protocol_version"] = pr.attrs.mysql.protocol_version;
        a["auth_plugin"] = sanitize_utf8(pr.attrs.mysql.auth_plugin);
        a["capability_flags"] = pr.attrs.mysql.capability_flags;
        jp["mysql"] = a;
    };
    attr_writers_["SSH"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["version_string"] = sanitize_utf8(pr.attrs.ssh.version_string);
        a["software"] = sanitize_utf8(pr.attrs.ssh.software);
        a["version"] = sanitize_utf8(pr.attrs.ssh.version);
        a["protocol_version"] = sanitize_utf8(pr.attrs.ssh.protocol_version);
        jp["ssh"] = a;
    };
    attr_writers_["FTP"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["features"] = sanitize_utf8(pr.attrs.ftp.features);
        a["utf8"] = pr.attrs.ftp.utf8;
        a["auth_tls"] = pr.attrs.ftp.auth_tls;
        a["auth_ssl"] = pr.attrs.ftp.auth_ssl;
        a["size_cmd"] = pr.attrs.ftp.size_cmd;
        a["mdtm"] = pr.attrs.ftp.mdtm;
        a["mldst"] = pr.attrs.ftp.mldst;
        a["tvfs"] = pr.attrs.ftp.tvfs;
        a["xcrc"] = pr.attrs.ftp.xcrc;
        a["xcup"] = pr.attrs.ftp.xcup;
        jp["ftp"] = a;
    };
    // 以下协议无专用结构体，仅需占位通过启动校验
    attr_writers_["PGSQL"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["version"] = sanitize_utf8(pr.attrs.pgsql.version);
        a["protocol_version"] = pr.attrs.pgsql.protocol_version;
        jp["pgsql"] = a;
    };
    attr_writers_["MONGO"] = [](json& jp, const ProtocolResult& pr) {
        json a;
        a["version"] = sanitize_utf8(pr.attrs.mongo.version);
        a["max_wire_version"] = pr.attrs.mongo.max_wire_version;
        a["is_master"] = pr.attrs.mongo.is_master;
        jp["mongodb"] = a;
    };
    attr_writers_["TELNET"] = [](json&, const ProtocolResult&) {};
    attr_writers_["REDIS"] = [](json&, const ProtocolResult&) {};
    attr_writers_["RTSP"]  = [](json&, const ProtocolResult&) {};
    attr_writers_["SIP"]   = [](json&, const ProtocolResult&) {};
}

bool ResultHandler::has_protocol_formatter(const std::string& name) const {
    return attr_writers_.find(name) != attr_writers_.end();
}

// Replace invalid UTF-8 byte sequences with '?' to keep JSON serialization robust.
static std::string sanitize_utf8(const std::string& input) {
    std::string out;
    out.reserve(input.size());

    const auto* s = reinterpret_cast<const unsigned char*>(input.data());
    const size_t n = input.size();
    size_t i = 0;

    while (i < n) {
        unsigned char c = s[i];

        if (c <= 0x7F) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }

        // 2-byte sequence: C2-DF 80-BF
        if (c >= 0xC2 && c <= 0xDF) {
            if (i + 1 < n && (s[i + 1] & 0xC0) == 0x80) {
                out.push_back(static_cast<char>(s[i]));
                out.push_back(static_cast<char>(s[i + 1]));
                i += 2;
            } else {
                out.push_back('?');
                ++i;
            }
            continue;
        }

        // 3-byte sequence checks (avoid overlong + surrogates)
        if (c >= 0xE0 && c <= 0xEF) {
            if (i + 2 < n) {
                unsigned char c1 = s[i + 1];
                unsigned char c2 = s[i + 2];
                bool c1_ok = (c1 & 0xC0) == 0x80;
                bool c2_ok = (c2 & 0xC0) == 0x80;
                bool range_ok = true;
                if (c == 0xE0) range_ok = c1 >= 0xA0;
                if (c == 0xED) range_ok = c1 <= 0x9F;

                if (c1_ok && c2_ok && range_ok) {
                    out.push_back(static_cast<char>(s[i]));
                    out.push_back(static_cast<char>(s[i + 1]));
                    out.push_back(static_cast<char>(s[i + 2]));
                    i += 3;
                } else {
                    out.push_back('?');
                    ++i;
                }
            } else {
                out.push_back('?');
                ++i;
            }
            continue;
        }

        // 4-byte sequence checks (U+10000..U+10FFFF)
        if (c >= 0xF0 && c <= 0xF4) {
            if (i + 3 < n) {
                unsigned char c1 = s[i + 1];
                unsigned char c2 = s[i + 2];
                unsigned char c3 = s[i + 3];
                bool c1_ok = (c1 & 0xC0) == 0x80;
                bool c2_ok = (c2 & 0xC0) == 0x80;
                bool c3_ok = (c3 & 0xC0) == 0x80;
                bool range_ok = true;
                if (c == 0xF0) range_ok = c1 >= 0x90;
                if (c == 0xF4) range_ok = c1 <= 0x8F;

                if (c1_ok && c2_ok && c3_ok && range_ok) {
                    out.push_back(static_cast<char>(s[i]));
                    out.push_back(static_cast<char>(s[i + 1]));
                    out.push_back(static_cast<char>(s[i + 2]));
                    out.push_back(static_cast<char>(s[i + 3]));
                    i += 4;
                } else {
                    out.push_back('?');
                    ++i;
                }
            } else {
                out.push_back('?');
                ++i;
            }
            continue;
        }

        // Invalid leading byte.
        out.push_back('?');
        ++i;
    }

    return out;
}

static bool has_emittable_protocols(const ScanReport& report, bool only_success) {
    if (!only_success) {
        return !report.protocols.empty();
    }
    for (const auto& pr : report.protocols) {
        if (pr.accessible) {
            return true;
        }
    }
    return false;
}

// -------------- 文本格式 --------------

std::string ResultHandler::to_text(const ScanReport& report) const {
    std::ostringstream oss;

    // 先收集需要输出的协议（应用 only_success 过滤）
    std::vector<ProtocolResult> filtered_protocols;
    for (const auto& pr : report.protocols) {
        if (only_success_ && !pr.accessible) {
            continue;
        }
        filtered_protocols.push_back(pr);
    }

    // 仅当有过滤后的协议结果时才输出目标行
    if (!filtered_protocols.empty()) {
        oss << report.target.domain << " (" << report.target.get_ip_string() << ")\n";
    }

    for (const auto& pr : filtered_protocols) {
        oss << "  [" << pr.protocol << "] " << pr.host << ":" << pr.port
            << " -> " << (pr.accessible ? "OK" : "FAIL");
        if (!pr.error.empty()) oss << " (" << pr.error << ")";
        oss << "\n";
        if (pr.accessible) {
            if (!pr.attrs.banner.empty()) oss << "    banner: " << pr.attrs.banner << "\n";
            if (!pr.attrs.vendor.empty()) oss << "    vendor: " << pr.attrs.vendor << "\n";
            if (pr.protocol == "SMTP") {
                oss << "    features: PIPELINING=" << bool_str(pr.attrs.smtp.pipelining)
                    << ", STARTTLS=" << bool_str(pr.attrs.smtp.starttls)
                    << ", 8BITMIME=" << bool_str(pr.attrs.smtp._8bitmime)
                    << ", DSN=" << bool_str(pr.attrs.smtp.dsn)
                    << ", SMTPUTF8=" << bool_str(pr.attrs.smtp.utf8)
                    << ", SIZE="
                    << (pr.attrs.smtp.size_supported ? std::to_string(pr.attrs.smtp.size_limit) : std::string("unsupported"))
                    << ", AUTH=" << (pr.attrs.smtp.auth_methods.empty() ? std::string("-") : pr.attrs.smtp.auth_methods)
                    << "\n";
            }
        }
    }
    return oss.str();
}

std::string ResultHandler::to_report(const ScanReport& report) const {
    // 暂时与 TEXT 一致，可按需扩展
    return to_text(report);
}

// -------------- required_format --------------

std::string ResultHandler::to_required(const ScanReport& report) const {
    std::ostringstream oss;

    // 仅保留需要输出的协议（尊重 only_success 筛选）
    for (const auto& pr : report.protocols) {
        if (only_success_ && !pr.accessible) continue;

        size_t seq = 0;
        std::string current_ip = report.target.get_ip_string();
        auto it = ip_to_seq_.find(current_ip);
        if (it != ip_to_seq_.end()) {
            seq = it->second;
        } else {
            seq = ++ip_seq_; // 新 IP 分配下一个序号
            ip_to_seq_.emplace(current_ip, seq);
        }

        oss << seq << ','
            << current_ip << ','
            << pr.port << ','
            << pr.attrs.banner
            << '\n';
    }

    return oss.str();
}

std::string ResultHandler::to_required(const std::vector<ScanReport>& reports) const {
    std::ostringstream oss;
    for (const auto& rep : reports) {
        std::string body = to_required(rep);
        oss << body;
    }
    return oss.str();
}

// -------------- CSV 格式 --------------

std::string ResultHandler::to_csv(const ScanReport& report) const {
    if (!has_emittable_protocols(report, only_success_)) {
        return "";
    }

    std::ostringstream oss;
    // header
    oss << "domain,ip,protocol,host,port,accessible,error,vendor,banner,response_time_ms,details\n";
    for (const auto& pr : report.protocols) {
        if (only_success_ && !pr.accessible) continue;

        std::string details = format_attributes(pr.attrs);
        // 简单转义逗号与引号
        auto esc = [](const std::string& s) {
            if (s.find_first_of(",\"\n") == std::string::npos) return s;
            std::string r = s; size_t pos = 0;
            while ((pos = r.find('"', pos)) != std::string::npos) { r.insert(pos, 1, '"'); pos += 2; }
            return '"' + r + '"';
        };
        oss << esc(report.target.domain) << ','
            << esc(report.target.get_ip_string()) << ','
            << esc(pr.protocol) << ','
            << esc(pr.host) << ','
            << pr.port << ','
            << (pr.accessible ? 1 : 0) << ','
            << esc(pr.error) << ','
            << esc(pr.attrs.vendor) << ','
            << esc(pr.attrs.banner) << ','
            << std::fixed << std::setprecision(2) << pr.attrs.response_time_ms << ','
            << esc(details) << '\n';
    }
    return oss.str();
}

std::string ResultHandler::to_csv(const std::vector<ScanReport>& reports) const {
    std::ostringstream oss;
    oss << "domain,ip,protocol,host,port,accessible,error,vendor,banner,response_time_ms,details\n";
    bool wrote_row = false;
    for (const auto& rep : reports) {
        ResultHandler tmp; 
        tmp.set_format(OutputFormat::CSV);
        tmp.set_only_success(only_success_);
        std::string body = tmp.to_csv(rep);
        if (body.empty()) {
            continue;
        }
        // 跳过重复 header：取第一行之后
        std::istringstream is(body);
        std::string line; bool first = true;
        while (std::getline(is, line)) {
            if (first) { first = false; continue; }
            if (!line.empty()) {
                oss << line << '\n';
                wrote_row = true;
            }
        }
    }
    if (!wrote_row) {
        return "";
    }
    return oss.str();
}

// -------------- JSON 格式 --------------

std::string ResultHandler::to_json(const ScanReport& report) const {
    if (!has_emittable_protocols(report, only_success_)) {
        return "";
    }

    nlohmann::json j;
    j["domain"] = sanitize_utf8(report.target.domain);
    j["ip"] = sanitize_utf8(report.target.get_ip_string());
    j["total_time_ms"] = report.total_time.count();
    j["protocols"] = nlohmann::json::array();
    for (const auto& pr : report.protocols) {
        if (only_success_ && !pr.accessible) continue;

        nlohmann::json jp;
        jp["protocol"] = sanitize_utf8(pr.protocol);
        jp["host"] = sanitize_utf8(pr.host);
        jp["port"] = pr.port;
        jp["accessible"] = pr.accessible;
        jp["error"] = sanitize_utf8(pr.error);
        jp["banner"] = sanitize_utf8(pr.attrs.banner);
        jp["vendor"] = sanitize_utf8(pr.attrs.vendor);
        jp["response_time_ms"] = pr.attrs.response_time_ms;
        // 协议专用属性通过注册的 formatter 输出
        auto it = attr_writers_.find(pr.protocol);
        if (it != attr_writers_.end()) {
            it->second(jp, pr);
        }
        j["protocols"].push_back(jp);
    }
    return j.dump(2);
}

std::string ResultHandler::to_json(const std::vector<ScanReport>& reports) const {
    nlohmann::json j = nlohmann::json::array();
    for (const auto& r : reports) {
        ResultHandler tmp; 
        tmp.set_format(OutputFormat::JSON);
        tmp.set_only_success(only_success_);
        std::string one = tmp.to_json(r);
        if (one.empty()) {
            continue;
        }
        j.push_back(nlohmann::json::parse(one));
    }
    return j.dump(2);
}

// -------------- 公共接口 --------------

void ResultHandler::save_report(const ScanReport& report, const std::string& filename) {
    std::ofstream ofs(filename);
    if (!ofs) return;
    ofs << report_to_string(report);
}

void ResultHandler::save_reports(
    const std::vector<ScanReport>& reports,
    const std::string& filename
) {
    std::ofstream ofs(filename);
    if (!ofs) return;
    ofs << reports_to_string(reports);
}

std::string ResultHandler::report_to_string(const ScanReport& report) const {
    switch (format_) {
        case OutputFormat::JSON:   return to_json(report);
        case OutputFormat::CSV:    return to_csv(report);
        case OutputFormat::REQUIRED: return to_required(report);
        case OutputFormat::REPORT: return to_report(report);
        case OutputFormat::TEXT:
        default:                   return to_text(report);
    }
}

std::string ResultHandler::reports_to_string(const std::vector<ScanReport>& reports) const {
    switch (format_) {
        case OutputFormat::JSON:   return to_json(reports);
        case OutputFormat::CSV:    return to_csv(reports);
        case OutputFormat::REQUIRED: return to_required(reports);
        case OutputFormat::REPORT:
        case OutputFormat::TEXT:
        default: {
            std::ostringstream oss;
            for (const auto& r : reports) {
                oss << report_to_string(r) << '\n';
            }
            return oss.str();
        }
    }
}

void ResultHandler::print_report(const ScanReport& report) const {
    std::cout << report_to_string(report) << std::endl;
}

void ResultHandler::print_summary(const std::vector<ScanReport>& reports) const {
    std::cout << reports_to_string(reports) << std::endl;
}

// -------------- 属性格式化 --------------

std::string ResultHandler::format_attributes(const ProtocolAttributes& attrs) const {
    std::ostringstream oss;
    if (!attrs.banner.empty()) {
        oss << "banner=" << attrs.banner << ';';
    }
    if (!attrs.vendor.empty()) {
        oss << "vendor=" << attrs.vendor << ';';
    }
    if (!attrs.smtp.auth_methods.empty() || attrs.smtp.pipelining || attrs.smtp.starttls) {
        oss << "smtp{"
            << "pipelining=" << (attrs.smtp.pipelining?"1":"0") << ','
            << "starttls=" << (attrs.smtp.starttls?"1":"0") << ','
            << "size_supported=" << (attrs.smtp.size_supported?"1":"0") << ','
            << "size_limit=" << attrs.smtp.size_limit << ','
            << "utf8=" << (attrs.smtp.utf8?"1":"0") << ','
            << "8bitmime=" << (attrs.smtp._8bitmime?"1":"0") << ','
            << "dsn=" << (attrs.smtp.dsn?"1":"0") << ','
            << "auth=" << attrs.smtp.auth_methods << "};";
    }
    if (!attrs.pop3.capabilities.empty()) {
        oss << "pop3{" << attrs.pop3.capabilities << "};";
    }
    if (!attrs.imap.capabilities.empty()) {
        oss << "imap{" << attrs.imap.capabilities << "};";
    }
    if (!attrs.http.server.empty() || !attrs.http.content_type.empty() || attrs.http.status_code != 0) {
        oss << "http{"
            << "server=" << attrs.http.server << ','
            << "type=" << attrs.http.content_type << ','
            << "code=" << attrs.http.status_code << "};";
    }
    return oss.str();
}

std::string ResultHandler::format_port_mask(uint8_t mask) const {
    std::ostringstream oss;
    for (int i = 7; i >= 0; --i) oss << ((mask >> i) & 1);
    return oss.str();
}

} // namespace scanner
