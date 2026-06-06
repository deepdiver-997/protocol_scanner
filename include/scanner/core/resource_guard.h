#pragma once

#include <cstddef>
#include <iosfwd>

namespace scanner {

// 启动前安全检查：防止并发数过高导致系统不可达
class ResourceGuard {
public:
    // 检查是否安全，输出诊断信息
    static bool check(size_t max_work_count, std::ostream& out);

    // 返回建议的安全并发数（临时端口 * 0.75 与 可用内存 / 80KB 取较小值）
    static size_t safe_max_work_count();
};

} // namespace scanner
