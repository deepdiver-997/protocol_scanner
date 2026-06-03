#include "scanner/deep_probe/deep_probe.h"
#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: deep_probe <ip> <port> [probe_type]\n"
                  << "  probe_type: max_auth_tries (default), max_startups, login_grace_time\n";
        return 1;
    }

    std::string ip = argv[1];
    uint16_t port = static_cast<uint16_t>(std::atoi(argv[2]));
    std::string type = (argc >= 4) ? argv[3] : "max_auth_tries";

    std::string result;
    if (type == "max_auth_tries") {
        result = scanner::deep_probe::probe_openssh_max_auth_tries(ip, port);
    } else if (type == "max_startups") {
        result = scanner::deep_probe::probe_openssh_max_startups(ip, port);
    } else if (type == "login_grace_time") {
        result = scanner::deep_probe::probe_openssh_login_grace_time(ip, port, 180);
    } else if (type == "max_clients") {
        result = scanner::deep_probe::probe_vsftpd_max_clients(ip, port);
    } else if (type == "login_delay") {
        result = scanner::deep_probe::probe_telnetd_login_delay(ip, port);
    } else {
        std::cerr << "Unknown probe: " << type << "\n"
                  << "Available: max_auth_tries, max_startups, login_grace_time,\n"
                  << "           max_clients (vsftpd), login_delay (telnetd)\n";
        return 1;
    }

    std::cout << ip << ":" << port << " " << type << " → " << result << std::endl;
    return 0;
}
