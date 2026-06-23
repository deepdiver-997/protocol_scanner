/// 集中 REGISTER_PROTOCOL 调用 — 解决静态库符号裁剪问题
/// scanner.cpp 引用 force_init_protocols()，保证所有协议 .o 被链接

#include "scanner/protocols/protocol_all.h"

namespace scanner {

REGISTER_PROTOCOL(SmtpProtocol,   "SMTP")
REGISTER_PROTOCOL(Pop3Protocol,   "POP3")
REGISTER_PROTOCOL(ImapProtocol,   "IMAP")
REGISTER_PROTOCOL(HttpProtocol,   "HTTP")
REGISTER_PROTOCOL(FtpProtocol,    "FTP")
REGISTER_PROTOCOL(TelnetProtocol, "TELNET")
REGISTER_PROTOCOL(SshProtocol,    "SSH")
REGISTER_PROTOCOL(RedisProtocol,  "REDIS")
REGISTER_PROTOCOL(RtspProtocol,   "RTSP")
REGISTER_PROTOCOL(SipProtocol,    "SIP")
REGISTER_PROTOCOL(MysqlProtocol,  "MYSQL")
REGISTER_PROTOCOL(PgsqlProtocol,  "PGSQL")
REGISTER_PROTOCOL(MongoProtocol,  "MONGO")

// scanner.cpp 调用此函数 → 链接器保留本文件 → 所有 REGISTER_PROTOCOL 生效
void force_init_protocols() {}

} // namespace scanner
