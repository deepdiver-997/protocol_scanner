#pragma once

#include <string>

namespace scanner::deep_probe {

// =====================
// OpenSSH Probes
// =====================

// 探测 MaxAuthTries: 同连接内重复发错误密码，观察第几次后断开
// 返回: "max_auth_tries=6"
std::string probe_openssh_max_auth_tries(const std::string& ip, uint16_t port, int max_probe = 20);

// 探测 MaxStartups: 同时建大量连接，观察能被接受的比例
// 返回: "max_startups_begin=10 max_startups_full=100"
std::string probe_openssh_max_startups(const std::string& ip, uint16_t port, int max_conn = 150);

// 探测 LoginGraceTime: 连接后等待，计时器断开时间
// 返回: "login_grace_time=120s"
std::string probe_openssh_login_grace_time(const std::string& ip, uint16_t port, int max_wait_sec = 180);

// =====================
// vsftpd Probes
// =====================

// 探测 max_clients: 最大并发客户端数
// 返回: "max_clients=50"
std::string probe_vsftpd_max_clients(const std::string& ip, uint16_t port, int max_conn = 200);

// =====================
// telnetd Probes
// =====================

// 探测登录失败延迟: 输入错误密码后服务器延迟多久返回
// 返回: "login_delay_ms=3000"
std::string probe_telnetd_login_delay(const std::string& ip, uint16_t port, int max_wait_ms = 10000);

} // namespace scanner::deep_probe