#include "scanner/protocols/protocol_parsers.h"
#include <sstream>

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
        else if (cap.compare(0, 4, "AUTH") == 0 && cap.size() > 5) {
            info.auth_methods = cap.substr(5);
        }
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

    auto first_dash = banner.find('-');
    auto second_dash = banner.find('-', first_dash + 1);
    if (first_dash == std::string::npos || second_dash == std::string::npos) return info;

    info.protocol_version = banner.substr(first_dash + 1, second_dash - first_dash - 1);

    auto space_pos = banner.find(' ', second_dash + 1);
    std::string sw_id = (space_pos != std::string::npos)
        ? banner.substr(second_dash + 1, space_pos - second_dash - 1)
        : banner.substr(second_dash + 1);

    if (sw_id.empty()) return info;

    auto underscore = sw_id.find('_');
    if (underscore != std::string::npos) {
        info.software = sw_id.substr(0, underscore);
        info.version = sw_id.substr(underscore + 1);
    } else {
        auto last_dash = sw_id.rfind('-');
        if (last_dash != std::string::npos && last_dash > 0) {
            info.software = sw_id.substr(0, last_dash);
            info.version = sw_id.substr(last_dash + 1);
        } else {
            info.software = sw_id;
        }
    }
    return info;
}

// =====================
// FTP
// =====================

FtpFeatInfo parse_ftp_feat(const std::string& features_csv) {
    FtpFeatInfo info;
    if (features_csv.empty()) return info;
    info.features = features_csv;

    std::istringstream iss(features_csv);
    std::string feat;
    while (std::getline(iss, feat, ',')) {
        // trim spaces
        auto start = feat.find_first_not_of(" ");
        if (start == std::string::npos) continue;
        auto end = feat.find_last_not_of(" ");
        feat = feat.substr(start, end - start + 1);

        // uppercase for matching
        for (auto& c : feat) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));

        if (feat == "UTF8")         info.utf8 = true;
        else if (feat == "AUTH TLS")   info.auth_tls = true;
        else if (feat == "AUTH SSL")   info.auth_ssl = true;
        else if (feat == "SIZE")       info.size_cmd = true;
        else if (feat == "MDTM")       info.mdtm = true;
        else if (feat == "MLSD" || feat == "MLST") info.mldst = true;
        else if (feat == "TVFS")       info.tvfs = true;
    }
    return info;
}

} // namespace scanner