#pragma once

#include "scanner/deep_probe/deep_probe_interface.h"
#include <vector>
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>

namespace scanner {

/// 深度探测注册表 — 单例，管理所有 IDeepProbe 实现
class DeepProbeRegistry {
public:
    static DeepProbeRegistry& instance();

    void register_probe(std::unique_ptr<IDeepProbe> probe);

    /// 返回指定协议的所有深度探测
    std::vector<IDeepProbe*> probes_for(const std::string& protocol_name) const;

    bool empty() const;

private:
    DeepProbeRegistry() = default;
    std::unordered_map<std::string, std::vector<std::unique_ptr<IDeepProbe>>> registry_;
    mutable std::mutex mutex_;
};

/// 便捷宏：静态注册深度探测
#define REGISTER_DEEP_PROBE(ProbeClass) \
    namespace { \
        struct ProbeClass##_Registrar { \
            ProbeClass##_Registrar() { \
                DeepProbeRegistry::instance().register_probe( \
                    std::make_unique<ProbeClass>()); \
            } \
        }; \
        static ProbeClass##_Registrar g_##ProbeClass##_reg; \
    }

} // namespace scanner
