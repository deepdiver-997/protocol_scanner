#include "scanner/deep_probe/deep_probe_registry.h"

namespace scanner {

DeepProbeRegistry& DeepProbeRegistry::instance() {
    static DeepProbeRegistry inst;
    return inst;
}

void DeepProbeRegistry::register_probe(std::unique_ptr<IDeepProbe> probe) {
    std::lock_guard<std::mutex> lock(mutex_);
    registry_[probe->protocol_name()].push_back(std::move(probe));
}

std::vector<IDeepProbe*> DeepProbeRegistry::probes_for(const std::string& protocol_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = registry_.find(protocol_name);
    if (it == registry_.end()) return {};
    std::vector<IDeepProbe*> res;
    res.reserve(it->second.size());
    for (auto& p : it->second) res.push_back(p.get());
    return res;
}

bool DeepProbeRegistry::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return registry_.empty();
}

} // namespace scanner
