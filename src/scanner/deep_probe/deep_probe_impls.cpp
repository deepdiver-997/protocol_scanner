#include "scanner/deep_probe/deep_probe_interface.h"
#include "scanner/deep_probe/deep_probe_registry.h"
#include "scanner/deep_probe/deep_probe.h"

namespace scanner {
namespace {

// ===================================================================
// OpenSSH 深度探测
// ===================================================================

class OpenSshMaxAuthTries final : public IDeepProbe {
    std::string name() const override { return "max_auth_tries"; }
    std::string protocol_name() const override { return "SSH"; }
    std::string probe(const std::string& ip, uint16_t port) override {
        return deep_probe::probe_openssh_max_auth_tries(ip, port);
    }
};
REGISTER_DEEP_PROBE(OpenSshMaxAuthTries)

class OpenSshMaxStartups final : public IDeepProbe {
    std::string name() const override { return "max_startups"; }
    std::string protocol_name() const override { return "SSH"; }
    std::string probe(const std::string& ip, uint16_t port) override {
        return deep_probe::probe_openssh_max_startups(ip, port);
    }
};
REGISTER_DEEP_PROBE(OpenSshMaxStartups)

class OpenSshLoginGraceTime final : public IDeepProbe {
    std::string name() const override { return "login_grace_time"; }
    std::string protocol_name() const override { return "SSH"; }
    std::string probe(const std::string& ip, uint16_t port) override {
        return deep_probe::probe_openssh_login_grace_time(ip, port);
    }
};
REGISTER_DEEP_PROBE(OpenSshLoginGraceTime)

// ===================================================================
// vsftpd 深度探测
// ===================================================================

class VsftpdMaxClients final : public IDeepProbe {
    std::string name() const override { return "max_clients"; }
    std::string protocol_name() const override { return "FTP"; }
    std::string probe(const std::string& ip, uint16_t port) override {
        return deep_probe::probe_vsftpd_max_clients(ip, port);
    }
};
REGISTER_DEEP_PROBE(VsftpdMaxClients)

// ===================================================================
// telnetd 深度探测
// ===================================================================

class TelnetdLoginDelay final : public IDeepProbe {
    std::string name() const override { return "login_delay"; }
    std::string protocol_name() const override { return "TELNET"; }
    std::string probe(const std::string& ip, uint16_t port) override {
        return deep_probe::probe_telnetd_login_delay(ip, port);
    }
};
REGISTER_DEEP_PROBE(TelnetdLoginDelay)

} // namespace
} // namespace scanner
