#pragma once

#include <string>
#include <cstddef>

namespace scanner {

// =====================
// SMTP banner 解析器（纯函数）
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
    std::string vendor_hint;   // 从 banner 中提取的厂商线索
};

// 输入: EHLO 响应完整文本（多行 "250" 响应）
// 返回: 结构化解析结果
SmtpBannerInfo parse_smtp_banner(const std::string& ehlo_response);

} // namespace scanner