#include "scanner/output/result_handler.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <unordered_map>

namespace scanner {

// -------------- 内部辅助 --------------

static inline const char* bool_str(bool v) { return v ? "1" : "0"; }

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
        oss << report.target.domain << " (" << report.target.ip << ")\n";
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
    // 静态计数器：为每个唯一 IP 分配序号；单线程调用，无需原子
    static size_t ip_seq = 0;
    static std::unordered_map<std::string, size_t> ip_to_seq;

    std::ostringstream oss;

    // 仅保留需要输出的协议（尊重 only_success 筛选）
    for (const auto& pr : report.protocols) {
        if (only_success_ && !pr.accessible) continue;

        size_t seq = 0;
        auto it = ip_to_seq.find(report.target.ip);
        if (it != ip_to_seq.end()) {
            seq = it->second;
        } else {
            seq = ++ip_seq; // 新 IP 分配下一个序号
            ip_to_seq.emplace(report.target.ip, seq);
        }

        oss << seq << ','
            << report.target.ip << ','
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
            << esc(report.target.ip) << ','
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
    for (const auto& rep : reports) {
        ResultHandler tmp; 
        tmp.set_format(OutputFormat::CSV);
        tmp.set_only_success(only_success_);
        std::string body = tmp.to_csv(rep);
        // 跳过重复 header：取第一行之后
        std::istringstream is(body);
        std::string line; bool first = true;
        while (std::getline(is, line)) {
            if (first) { first = false; continue; }
            if (!line.empty()) oss << line << '\n';
        }
    }
    return oss.str();
}

// -------------- JSON 格式 --------------

std::string ResultHandler::to_json(const ScanReport& report) const {
    nlohmann::json j;
    j["domain"] = report.target.domain;
    j["ip"] = report.target.ip;
    j["total_time_ms"] = report.total_time.count();
    j["protocols"] = nlohmann::json::array();
    for (const auto& pr : report.protocols) {
        if (only_success_ && !pr.accessible) continue;

        nlohmann::json jp;
        jp["protocol"] = pr.protocol;
        jp["host"] = pr.host;
        jp["port"] = pr.port;
        jp["accessible"] = pr.accessible;
        jp["error"] = pr.error;
        jp["banner"] = pr.attrs.banner;
        jp["vendor"] = pr.attrs.vendor;
        jp["response_time_ms"] = pr.attrs.response_time_ms;
        // SMTP attrs
        if (pr.protocol == "SMTP") {
            nlohmann::json a;
            a["pipelining"] = pr.attrs.smtp.pipelining;
            a["starttls"] = pr.attrs.smtp.starttls;
            a["size_supported"] = pr.attrs.smtp.size_supported;
            a["size_limit"] = pr.attrs.smtp.size_limit;
            a["utf8"] = pr.attrs.smtp.utf8;
            a["8bitmime"] = pr.attrs.smtp._8bitmime;
            a["dsn"] = pr.attrs.smtp.dsn;
            a["auth_methods"] = pr.attrs.smtp.auth_methods;
            jp["smtp"] = a;
        }
        // POP3
        if (pr.protocol == "POP3") {
            nlohmann::json a;
            a["stls"] = pr.attrs.pop3.stls;
            a["sasl"] = pr.attrs.pop3.sasl;
            a["user"] = pr.attrs.pop3.user;
            a["top"] = pr.attrs.pop3.top;
            a["pipelining"] = pr.attrs.pop3.pipelining;
            a["uidl"] = pr.attrs.pop3.uidl;
            a["capabilities"] = pr.attrs.pop3.capabilities;
            jp["pop3"] = a;
        }
        // IMAP
        if (pr.protocol == "IMAP") {
            nlohmann::json a;
            a["starttls"] = pr.attrs.imap.starttls;
            a["quota"] = pr.attrs.imap.quota;
            a["acl"] = pr.attrs.imap.acl;
            a["imap4rev1"] = pr.attrs.imap.imap4rev1;
            a["auth_plain"] = pr.attrs.imap.auth_plain;
            a["auth_login"] = pr.attrs.imap.auth_login;
            a["idle"] = pr.attrs.imap.idle;
            a["unselect"] = pr.attrs.imap.unselect;
            a["uidplus"] = pr.attrs.imap.uidplus;
            a["capabilities"] = pr.attrs.imap.capabilities;
            jp["imap"] = a;
        }
        // HTTP
        if (pr.protocol == "HTTP") {
            nlohmann::json a;
            a["server"] = pr.attrs.http.server;
            a["content_type"] = pr.attrs.http.content_type;
            a["status_code"] = pr.attrs.http.status_code;
            jp["http"] = a;
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
        j.push_back(nlohmann::json::parse(tmp.to_json(r)));
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
