# PGSQL 指纹库说明

本目录包含基于 `PGSQL` 扫描结果构建的 PostgreSQL wire protocol 指纹库。

## 文件说明

- `pgsql_fingerprints.json`：核心指纹规则库。
- `fingerprint_schema.json`：规则库格式说明。
- `tools/match_pgsql_fingerprints.py`：对单条 scanner `protocols[]` 结果做匹配。
- `reports/validation_report.md`：全量样本与 10% 真实 IP 留出集测试结果。
- `reports/observed_errors.csv`：高频 SQLSTATE 和错误消息统计。

原始扫描文件、原始 IP 列表不提交。

## 当前样本

- 全量记录：2053 条
- 端口：5432
- 协议：PGSQL
- 10% 真实 IP 留出集：205 条记录

## 当前能力

- PostgreSQL protocol v3 scanner 上下文识别
- PostgreSQL ErrorResponse / Authentication 响应识别
- SQLSTATE 提取
- 错误消息提取
- Amazon Redshift、CrateDB、租户/SNI 代理等实现线索识别
- bad packet header、invalid startup packet、TLS required、认证失败、服务暂停/不可用等错误类别识别

## 测试结果

全量样本：

- 协议识别：100.0%
- SQLSTATE 提取：85.68%
- 实现线索识别：25.86%

10% 留出集：

- 协议识别：100.0%
- SQLSTATE 提取：88.78%
- 实现线索识别：30.24%

注意：这批 PGSQL 结果主要是 PostgreSQL wire ErrorResponse / Authentication 响应，基本不暴露服务器版本，因此版本提取不是当前库的目标。
