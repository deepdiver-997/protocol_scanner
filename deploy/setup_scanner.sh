#!/usr/bin/env bash
# Protocol Scanner 部署脚本
# 用法: sudo ./setup_scanner.sh
# 功能: 创建 /opt/scanner/ 目录结构，安装 systemd 服务模板，编译并部署

set -euo pipefail

INSTALL_DIR="/opt/scanner"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"

echo "========================================="
echo "Protocol Scanner 部署"
echo "========================================="

# ---- 1. 创建目录结构 ----
echo "[1/5] 创建目录结构 ..."
mkdir -p "$INSTALL_DIR"/{bin,config,input,output,logs}
echo "  $INSTALL_DIR/"
echo "  ├── bin/       # 可执行文件"
echo "  ├── config/    # 配置文件"
echo "  ├── input/     # 扫描目标列表"
echo "  ├── output/    # 扫描结果（按协议分目录）"
echo "  └── logs/      # 日志"

# ---- 2. 编译 ----
echo "[2/5] 编译（不使用 c-ares）..."
cd "$PROJECT_DIR"
mkdir -p "$BUILD_DIR"
cmake -S . -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=InfoRelease \
    -DUSE_CARES=OFF \
    -DENABLE_LOGGING=ON

cmake --build "$BUILD_DIR" --target scanner -- -j"$(nproc)"

cp "$BUILD_DIR/scanner" "$INSTALL_DIR/bin/scanner"
chmod +x "$INSTALL_DIR/bin/scanner"
echo "  编译完成: $INSTALL_DIR/bin/scanner"

# ---- 3. 复制配置文件 ----
echo "[3/5] 部署配置文件 ..."
cp "$PROJECT_DIR/config/scanner_config_prod.json" "$INSTALL_DIR/config/scanner_config.json"
cp "$PROJECT_DIR/config/vendors.json" "$INSTALL_DIR/config/vendors.json"
echo "  配置已复制到 $INSTALL_DIR/config/"

# ---- 4. 创建启动脚本 ----
echo "[4/5] 创建启动脚本 ..."
cat > "$INSTALL_DIR/bin/run_scan.sh" << 'RUNNER'
#!/usr/bin/env bash
# 单协议扫描启动器，被 systemd 模板服务调用
# Usage: run_scan.sh <PROTOCOL> [input_file]

set -euo pipefail

PROTOCOL="${1:?Usage: $0 <PROTOCOL> [input_file]}"
INPUT_FILE="${2:-${SCANNER_INPUT:-/opt/scanner/input/targets.txt}}"
CONFIG_FILE="${SCANNER_CONFIG:-/opt/scanner/config/scanner_config.json}"

OUTPUT_DIR="/opt/scanner/output/${PROTOCOL}"

cd /opt/scanner
mkdir -p "$OUTPUT_DIR" logs

exec /opt/scanner/bin/scanner \
    --config "$CONFIG_FILE" \
    --domains "$INPUT_FILE" \
    --protocols "$PROTOCOL" \
    --output "$OUTPUT_DIR" \
    --scan \
    ${EXTRA_ARGS:-}
RUNNER
chmod +x "$INSTALL_DIR/bin/run_scan.sh"
echo "  启动脚本: $INSTALL_DIR/bin/run_scan.sh"

# ---- 5. 安装 systemd 服务 ----
echo "[5/5] 安装 systemd 服务模板 ..."
# 安装 cgroup slice
cat > /etc/systemd/system/scanner.slice << 'SLICE'
[Unit]
Description=Protocol Scanner resource slice
Before=slices.target

[Slice]
MemoryMax=5.5G
MemoryHigh=5G
CPUQuota=400%
TasksMax=60
SLICE

cat > /etc/systemd/system/scanner@.service << 'UNIT'
[Unit]
Description=Protocol Scanner - %i scan
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/scanner
Environment=SCANNER_CONFIG=/opt/scanner/config/scanner_config.json
Environment=SCANNER_INPUT=/opt/scanner/input/targets.txt
ExecStart=/opt/scanner/bin/run_scan.sh %i

# === cgroup 层级隔离 ===
Slice=scanner.slice

# === 重启策略 ===
Restart=on-failure
RestartSec=60
TimeoutStopSec=60
LimitNOFILE=65535

# 重启风暴保护：120s 内最多重启 3 次，超出则停止
StartLimitBurst=3
StartLimitIntervalSec=120

# === 内存硬限制 ===
MemoryMax=5G
MemoryHigh=4.5G

# === CPU 限制：6 核留 2 核 ===
CPUQuota=400%

# === 线程上限 ===
TasksMax=50

# === IO 限制：防磁盘打满 ===
IOWriteBandwidthMax=/opt 50M
IOReadBandwidthMax=/opt 200M

# === 日志 ===
# stdout/stderr 进 journal（自动轮转），scanner 自身日志走配置文件中的 logrotate
StandardOutput=journal
StandardError=journal
SyslogIdentifier=scanner-%i

[Install]
WantedBy=multi-user.target
UNIT

# 安装磁盘守卫：每 5 分钟检查一次，超过 100GB 就停掉所有 scanner
cat > /etc/systemd/system/scanner-disk-guard.service << 'GUARD'
[Unit]
Description=Scanner disk guard — stops scanners if /opt/scanner exceeds 100GB

[Service]
Type=oneshot
ExecStart=/bin/bash -c '\
  THRESHOLD_MB=102400; \
  USED=$$(du -sm /opt/scanner 2>/dev/null | cut -f1); \
  if [ "$$USED" -gt "$$THRESHOLD_MB" ]; then \
    echo "FATAL: /opt/scanner using $${USED}MB > $${THRESHOLD_MB}MB, stopping all scanners"; \
    systemctl stop "scanner@*.service" 2>/dev/null; \
  fi'
GUARD

cat > /etc/systemd/system/scanner-disk-guard.timer << 'TIMER'
[Unit]
Description=Run scanner disk guard every 5 minutes

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now scanner-disk-guard.timer
echo "  已安装: /etc/systemd/system/scanner.slice"
echo "  已安装: /etc/systemd/system/scanner@.service"
echo "  已安装: scanner-disk-guard.timer (100GB 上限，每 5 分钟检查)"

echo ""
echo "========================================="
echo "部署完成!"
echo "========================================="
echo ""
echo "目录结构:"
echo "  程序:     $INSTALL_DIR/bin/scanner"
echo "  配置:     $INSTALL_DIR/config/scanner_config.json"
echo "  厂商库:   $INSTALL_DIR/config/vendors.json"
echo "  输入目标: $INSTALL_DIR/input/targets.txt (请放入扫描目标!)"
echo "  输出结果: $INSTALL_DIR/output/<PROTOCOL>/"
echo "  日志:     $INSTALL_DIR/logs/"
echo ""
echo "使用方法:"
echo "  # 准备扫描目标"
echo "  vim /opt/scanner/input/targets.txt"
echo ""
echo "  # 启动单个协议扫描"
echo "  systemctl start scanner@SMTP"
echo "  systemctl start scanner@HTTP"
echo "  systemctl start scanner@SSH"
echo ""
echo "  # 查看状态"
echo "  systemctl status scanner@SMTP"
echo ""
echo "  # 开机自启"
echo "  systemctl enable scanner@SMTP"
echo ""
echo "  # 查看日志"
echo "  journalctl -u scanner@SMTP -f"
echo "  tail -f /opt/scanner/logs/scanner-SMTP.log"
echo ""
echo "  # 可用协议: SMTP POP3 IMAP HTTP FTP SSH TELNET REDIS RTSP SIP MYSQL"
