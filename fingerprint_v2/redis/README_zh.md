# Redis 指纹库说明

本目录是 Redis / Redis-compatible 服务的指纹库成果，不包含原始扫描目标 IP
列表，也不包含在线复测的原始明细。

## 文件说明

- `redis_fingerprints.json`：核心指纹库，程序可直接读取。
- `fingerprint_schema.json`：指纹库格式约束。
- `tools/match_redis_fingerprints.py`：对单条已采集 banner 做离线匹配。
- `tools/online_redis_reprobe.py`：授权范围内的在线随机复测脚本。
- `reports/validation_report.md`：全量样本上的规则覆盖率。
- `reports/holdout_eval_10pct.md`：按真实 IP 抽 10% 留出集的离线评估。
- `reports/live_reprobe_20260623_232520.md`：一次授权在线随机 10% 复测摘要。
- `reports/observed_fields.csv`：Redis INFO 字段出现频率。
- `reports/normalized_templates.jsonl`：标准化后的高频模板。

## 指纹库能力

当前规则库包含 24 条规则，可以做：

- Redis 协议兼容服务识别
- Redis / Valkey / Dragonfly / Memurai 实现识别
- 版本字段提取
- standalone / cluster 模式识别
- INFO 响应深度识别
- Redis Stack、容器化路径、Linux 包安装路径等部署线索识别
- Linux、epoll、systemd 等运行环境线索识别

## 当前评估结果

全量已采集样本：

- 记录数：7338
- 协议识别覆盖率：100%

10% 真实 IP 留出集：

- 测试 IP 数：529
- 测试记录数：707
- 协议匹配：100.0%
- 强协议证据：99.86%
- 实现识别：99.86%
- 版本提取：99.86%
- 模式提取：99.72%

一次授权在线 10% 随机复测：

- 抽样 IP 数：529
- 抽样 IP:port 数：711
- 有响应目标数：327
- 有响应目标上的协议匹配率：100.0%
- 有响应目标上的实现识别率：96.64%
- 有响应目标上的版本提取率：96.64%
- 有响应目标上的模式提取率：96.33%

在线复测中大量目标连接失败，这反映的是目标下线、端口关闭、过滤或超时等可达性变化，
不应直接算作指纹库误匹配。
