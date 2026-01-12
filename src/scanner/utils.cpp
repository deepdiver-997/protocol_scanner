#include "scanner/core/scanner.h"
#include "scanner/common/logger.h"
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

namespace scanner {

static inline std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> load_domains(const std::string& filename, size_t offset) {
    std::vector<std::string> domains;
    std::ifstream in(filename);
    if (!in) {
        LOG_FILE_IO_ERROR("Failed to open domains file: {}", filename);
        return domains;
    }
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty()) continue;
        // 跳过注释行
        if (!line.empty() && (line[0] == '#' || line[0] == ';')) continue;
        domains.push_back(line);
    }
    LOG_FILE_IO_INFO("Loaded {} domains from {}", domains.size(), filename);
    return domains;
}

} // namespace scanner
