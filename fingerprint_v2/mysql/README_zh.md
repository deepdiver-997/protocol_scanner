# MySQL 指纹库说明

本目录包含基于 `MYSQL` 扫描结果构建的 MySQL / MySQL-compatible 指纹库。

## 文件说明

- `mysql_fingerprints.json`：核心指纹规则库。
- `fingerprint_schema.json`：规则库格式说明。
- `tools/match_mysql_fingerprints.py`：对单条 scanner `protocols[]` 结果做匹配。
- `tools/online_mysql_reprobe.py`：授权后随机抽样公网目标，重连读取 MySQL 初始握手并在线匹配。
- `reports/validation_report.md`：全量样本与 10% 真实 IP 留出集测试结果。
- `reports/online_reprobe_20260625.md`：2026-06-25 在线重探测摘要。
- `reports/observed_versions.csv`：高频版本字符串统计。

原始扫描文件、原始 IP 列表不提交。

## 当前样本

- 全量记录：422199 条
- 端口：3306
- 协议：MYSQL
- 10% 真实 IP 留出集：42220 条记录

## 当前能力

- MySQL protocol v10 handshake 识别
- 版本字符串提取
- 主版本号提取
- MariaDB / Percona Server / TiDB / 未标记 MySQL-compatible 实现识别
- Ubuntu、Debian、Azure、CloudLinux LVE 等版本后缀线索识别
- `-log` 运行线索识别
- auth plugin 和 capability flags 元数据记录

## 测试结果

全量样本：

- 协议识别：100.0%
- 实现识别：422198 / 422199
- 版本提取：100.0%

10% 留出集：

- 协议识别：100.0%
- 实现识别：100.0%
- 版本提取：100.0%

在线重探测：

- 抽样方式：从 10% 随机 IP 样本池中限制 500 个 IP:port 作为 pilot
- 主动行为：仅连接并读取 MySQL 服务端初始握手，不发送登录包
- 有响应目标：482 / 500
- 响应目标协议匹配：100.0%
- 响应目标实现识别：100.0%
- 响应目标版本提取：100.0%

注意：当前 scanner 的 `auth_plugin` 字段在很多记录中疑似被截断，例如 `_password`，因此只作为低置信度元数据，不作为强产品指纹。
