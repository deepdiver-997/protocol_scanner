#include "scanner/protocols/protocol_parsers.h"
#include <sstream>

namespace scanner {

SmtpBannerInfo parse_smtp_banner(const std::string& ehlo_response) {
    SmtpBannerInfo info;
    if (ehlo_response.empty()) return info;

    std::istringstream stream(ehlo_response);
    std::string line;
    while (std::getline(stream, line)) {
        // 去除尾部 \r
        if (!line.empty() && line.back() == '\r') line.pop_back();

        // 只处理 250 开头的行
        if (line.size() < 4 || line.compare(0, 3, "250") != 0) continue;

        // 去掉 "250" 前缀和可能的 "-" / " " 分隔符
        std::string cap;
        if (line.size() >= 4) {
            cap = line.substr(4);
        }

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
        else if (cap.compare(0, 4, "AUTH") == 0 && cap.size() > 5) {
            info.auth_methods = cap.substr(5);
        }
    }

    return info;
}

} // namespace scanner