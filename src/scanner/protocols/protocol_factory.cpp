#include "scanner/protocols/protocol_base.h"
#include <mutex>

namespace scanner {

std::unordered_map<std::string, ProtocolFactory::ProtocolCreator> ProtocolFactory::registry_;
static std::mutex g_registry_mutex;

void ProtocolFactory::register_protocol(const std::string& name, ProtocolCreator creator) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    registry_[name] = std::move(creator);
}

std::unique_ptr<IProtocol> ProtocolFactory::create(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    auto it = registry_.find(name);
    if (it != registry_.end()) return it->second();
    return nullptr;
}

std::vector<std::string> ProtocolFactory::available_protocols() {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    std::vector<std::string> names;
    names.reserve(registry_.size());
    for (auto& [name, _] : registry_) names.push_back(name);
    return names;
}

bool ProtocolFactory::has_protocol(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    return registry_.find(name) != registry_.end();
}

} // namespace scanner
