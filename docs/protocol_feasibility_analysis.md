# 协议探测可行性调研报告

> 目标：分析各协议 Banner 的信息量，评估指纹探测的价值
> 对应任务：实验室实训任务4

---

## 调研方法

对每个协议考察以下维度：

1. **协议类型** — 文本 / 二进制 / 混合
2. **常见软件实现** — 开源 / 商业
3. **Banner 示例** — 连上后服务器返回了什么
4. **信息量评级** — ⭐ 无版本号 / ⭐⭐ 有模糊版本 / ⭐⭐⭐ 精确版本+能力列表
5. **探测价值** — 是否值得在扫描器中实现

---

## 1. POP3 (110/995)

**协议类型**: 纯文本

**常见实现**: Dovecot, Courier, Qpopper, Microsoft Exchange, qmail-pop3d

**Banner 示例**:
```
+OK Dovecot (Ubuntu) ready
+OK Hello there.
+OK Qpopper (version 4.0.5) ready
```

**交互方式**: 连上后服务器主动发欢迎语。可发 `CAPA` 命令获取能力列表。

```
C: CAPA
S: +OK
S: TOP
S: USER
S: SASL PLAIN LOGIN
S: PIPELINING
S: UIDL
S: .
```

**信息量**: ⭐⭐⭐ — 欢迎语含软件名，CAPA 响应暴露完整能力列表

**探测价值**: 高。Dovecot 和 Exchange 的 banner 差异明显，CAPA 列表可用于精确指纹。

**已实现**: ✅ (pop3_protocol.cpp)

---

## 2. IMAP (143/993)

**协议类型**: 纯文本

**常见实现**: Dovecot, Courier, Cyrus, Microsoft Exchange, Zimbra

**Banner 示例**:
```
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready
* OK Microsoft Exchange Server 2019 IMAP4 service ready
```

**信息量**: ⭐⭐⭐ — 欢迎语直接暴露软件名、版本、能力列表（CAPABILITY）

**探测价值**: 极高。IMAP 的 capability 是结构化的，可直接解析为指纹特征。

**已实现**: ✅ (imap_protocol.cpp)

---

## 3. Radmin (4899)

**协议类型**: 二进制（自定义）

**常见实现**: Radmin Server (Famatech)

**Banner 示例**:
```
连接后服务器不发任何纯文本欢迎语，直接发二进制握手包
```

**信息量**: ⭐ — 纯二进制，无版本号暴露。需要通过握手包中的特定字节偏移来判断版本。

**探测价值**: 低。Radmin 是商业远程控制软件，互联网上暴露面小。无文本 banner，需实现二进制协议解析，收益低。

**建议**: 不实现。

---

## 4. LDAP (389/636)

**协议类型**: 二进制 (ASN.1 BER)

**常见实现**: OpenLDAP, 389 Directory Server, Active Directory, ApacheDS

**Banner 示例**:
```
TCP 连接建立后，服务器不发欢迎语。需要发 LDAP SearchRequest 才能得到响应。
```

**信息量**: ⭐ — 无 banner。需要实现 LDAP 协议交互才能获取服务器信息。

**探测价值**: 低。无文本 banner，实现 LDAP 查询复杂度高，且返回信息多为域名/组织名，非软件指纹。

**建议**: 可做简易版本（发匿名查询，解析 rootDSE 中的 `vendorVersion` 字段），但不列入优先级。

---

## 5. SIP (5060)

**协议类型**: 纯文本

**常见实现**: Asterisk, FreeSWITCH, OpenSIPS, Kamailio, Cisco CallManager, 3CX

**Banner 示例**:
```
SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.0.0.1:5060
Server: Asterisk PBX 16.2.0
```

**信息量**: ⭐⭐⭐ — `Server` 头直接暴露软件名和版本号

**探测方式**: 发 `OPTIONS` 请求即可收到响应

**探测价值**: 高。Asterisk 和 FreeSWITCH 的 banner 差异明显，版本号直接可用。

**建议**: 实现。端口 5060 UDP/TCP，发 `OPTIONS` 请求，解析 `Server` 头。

---

## 6. CVS (2401)

**协议类型**: 纯文本

**常见实现**: OpenCVS, CVSNT

**Banner 示例**:
```
cvs [pserver aborted]: bad auth protocol start: ...
(实际上连上后服务器等待客户端发 "BEGIN AUTH" 请求)
```

**信息量**: ⭐ — 无自动 banner。需要完成认证流程才能获得版本信息。

**探测价值**: 极低。CVS 基本已被 Git 取代，互联网暴露面极小。需要认证交互。

**建议**: 不实现。

---

## 7. RTSP (554)

**协议类型**: 纯文本

**常见实现**: Live555, GStreamer RTSP Server, Wowza, VLC, FFmpeg

**Banner 示例**:
```
RTSP/1.0 200 OK
Server: Live555 Streaming Media v2023.02.28
```

**信息量**: ⭐⭐⭐ — `Server` 头暴露软件名和精确版本号

**探测方式**: 发 `OPTIONS` 请求即可获得响应

**探测价值**: 高。Live555、Wowza、VLC 的 Server 头格式各不相同，可精确指纹。

**建议**: 实现。端口 554 TCP，发 `OPTIONS rtsp://localhost RTSP/1.0\r\n\r\n`。

---

## 8. MySQL (3306)

**协议类型**: 二进制（MySQL Protocol）

**常见实现**: MySQL, MariaDB, Percona Server

**Banner 示例**:
```
连接后服务器主动发握手包（二进制），包含：
- 协议版本号 (1 byte)
- 服务器版本字符串 (null-terminated)
- 连接 ID (4 bytes)
- auth-plugin-data (8 bytes)
- 能力标志 (2 bytes)
- 字符集 (1 byte)
- 服务器状态 (2 bytes)
```

**信息量**: ⭐⭐⭐ — 握手包直接包含精确版本号（如 "5.7.35-log"、"8.0.27"、"10.5.12-MariaDB-log"）

**探测方式**: 连上即收握手包，无需发任何数据。

**探测价值**: 极高。版本号精确到小版本，MariaDB 和 MySQL 的版本格式不同（MariaDB 版号含 "MariaDB" 字符串）。

**建议**: 实现（banner-only 版本，只解析版本字符串，不做完整认证）。

---

## 9. PostgreSQL (5432)

**协议类型**: 二进制（PostgreSQL Protocol）

**常见实现**: PostgreSQL, Amazon Aurora, Greenplum

**Banner 示例**:
```
连接后服务器发 StartupMessage 响应，二进制格式：
- 长度 (4 bytes)
- 协议版本 (4 bytes, e.g. 196608 = 3.0)
- 参数键值对：server_version, server_encoding, etc.
```

**信息量**: ⭐⭐⭐ — `server_version` 参数直接暴露精确版本（如 "14.5"、"13.8"）

**探测方式**: 连上后服务器自动发参数列表（AuthenticationRequest 前）。

**探测价值**: 高。版本号精确，广泛部署。

**建议**: 实现（banner-only 版本）。

---

## 10. MS-SQL (1433)

**协议类型**: 二进制 (TDS)

**常见实现**: Microsoft SQL Server, Azure SQL

**Banner 示例**:
```
连接后服务器发 TDS 应答包，包含 SQL Server 版本信息。
```

**信息量**: ⭐⭐ — 有版本号但解析复杂（TDS 协议需解析多层嵌套）。

**探测价值**: 中。SQL Server 在 Windows 服务器上部署广泛，但 TDS 协议解析复杂度高。

**建议**: 优先级低。可做简易 banner read 尝试读 TCP 流的前几个字节，不做完整 TDS 解析。

---

## 11. Oracle (1521)

**协议类型**: 二进制 (TNS)

**常见实现**: Oracle Database, Oracle XE

**Banner 示例**:
```
连接后服务器发 TNS 包，包含 Oracle 版本和主机信息。
```

**信息量**: ⭐⭐ — 有版本信息但需要 TNS 协议解析。

**探测价值**: 低。Oracle 在互联网上暴露面小（多为内网），TNS 解析复杂。

**建议**: 不实现。

---

## 12. MongoDB (27017)

**协议类型**: 二进制 (BSON)

**常见实现**: MongoDB, Percona Server for MongoDB

**Banner 示例**:
```
连接后服务器主动发 ismaster 响应（二进制 BSON），包含：
- "ok" : 1
- "ismaster" : true
- "maxBsonObjectSize" : 16777216
- "maxMessageSizeBytes" : 48000000
- "maxWriteBatchSize" : 100000
- "minWireVersion" : 0
- "maxWireVersion" : 17
- "version" : "5.0.14"
```

**信息量**: ⭐⭐⭐ — `version` 字段直接暴露精确版本

**探测方式**: 连上后 MongoDB 默认发 `ismaster` 响应，无需认证。

**探测价值**: 高。版本号精确，且 MongoDB 4.x/5.x/6.x/7.x 的特征差异明显。

**建议**: 实现（banner-only 版本，读取 ismaster 响应提取 version 字段）。

---

## 13. Redis (6379/6380)

**协议类型**: 纯文本 (RESP)

**常见实现**: Redis, Valkey (fork), KeyDB

**Banner 示例**:
```
连接后无主动 banner。需要发 PING → +PONG
发 INFO server → 返回含 redis_version 的文本块
```

**信息量**: ⭐⭐⭐ — `INFO server` 响应精确到小版本号

**探测价值**: 极高。Valkey 和 Redis 分叉后的版本格式不同。

**已实现**: ✅ (redis_protocol.cpp)

---

## 14. Firebird (3050)

**协议类型**: 二进制

**常见实现**: Firebird SQL

**Banner 示例**:
```
连接后服务器发协议版本号 + 服务器版本字符串。
WireCrypt: 二进制，但第一个包包含版本字段。
```

**信息量**: ⭐⭐ — 有版本信息但解析复杂。常用版本较老（2.x, 3.x）。

**探测价值**: 低。Firebird 部署面窄，收益低。

**建议**: 不实现。

---

## 15. CouchDB (5984)

**协议类型**: HTTP REST

**常见实现**: Apache CouchDB, Couchbase

**Banner 示例**:
```
HTTP/1.1 200 OK
Server: CouchDB/3.2.2
```

**信息量**: ⭐⭐⭐ — HTTP `Server` 头暴露精确版本

**探测方式**: HTTP GET / 即可

**探测价值**: 高。CouchDB 的 `Server` 头格式为 `CouchDB/X.Y.Z`。

**建议**: 可以利用现有的 `HttpProtocol`，只需配置端口和路径。不单独实现。

---

## 总结

### 值得实现（信息量 ⭐⭐⭐）

| 协议 | 端口 | 实现难度 | 理由 |
|------|:----:|:--------:|------|
| Redis | 6379/6380 | ⭐ 简单 | ✅ 已实现 |
| RTSP | 554 | ⭐ 简单 | 发 OPTIONS 即可 |
| SIP | 5060 | ⭐ 简单 | 发 OPTIONS 即可 |
| MySQL | 3306 | ⭐⭐ 中等 | 只解析版本字符串（banner-only） |
| PostgreSQL | 5432 | ⭐⭐ 中等 | 只解析版本参数（banner-only） |
| MongoDB | 27017 | ⭐⭐ 中等 | 只读取 ismaster 响应 |
| CouchDB | 5984 | ⭐ 简单 | 复用 HttpProtocol |

### 暂时不实现（信息量 ≤ ⭐⭐）

| 协议 | 理由 |
|------|------|
| Radmin | 无文本 banner，二进制解析复杂，暴露面小 |
| LDAP | 无 banner，需交互才能获取信息 |
| CVS | 基本被 Git 取代，无 banner |
| MS-SQL | TDS 解析复杂 |
| Oracle | 部署面窄（多为内网），TNS 解析复杂 |
| Firebird | 部署面窄 |

### 建议实施顺序

1. **RTSP + SIP**（各 ~1 小时，模式同 HTTP OPTIONS）
2. **MySQL**（~2 小时，只解析握手包版本字符串）
3. **PostgreSQL**（~2 小时，只解析参数列表）
4. **MongoDB**（~3 小时，需要 BSON 解析）
5. **CouchDB**（~30 分钟，配置 HttpProtocol 新端口）
