#!/bin/bash
#
# deploy_optimized_scanner.sh
# 部署优化后的 scanner 到服务器

set -e  # 遇到错误立即退出

# 配置
SERVER="usa"
REMOTE_DIR="/opt/protocol_scanner"
LOCAL_BUILD="./build/scanner"
LOCAL_CONFIG="./config/scanner_config_2gb_optimized.json"
LOCAL_MONITOR="./monitor_scanner_memory.sh"

echo "========================================"
echo "  Deploy Optimized Scanner"
echo "========================================"
echo "Server: $SERVER"
echo "Remote dir: $REMOTE_DIR"
echo ""

# 检查本地文件是否存在
if [ ! -f "$LOCAL_BUILD" ]; then
    echo "❌ Error: $LOCAL_BUILD not found"
    echo "Run 'cmake --build build --target scanner' first"
    exit 1
fi

if [ ! -f "$LOCAL_CONFIG" ]; then
    echo "⚠️  Warning: $LOCAL_CONFIG not found, skipping config update"
    LOCAL_CONFIG=""
fi

if [ ! -f "$LOCAL_MONITOR" ]; then
    echo "⚠️  Warning: $LOCAL_MONITOR not found, skipping monitor script"
    LOCAL_MONITOR=""
fi

# 步骤1: 备份旧版本
echo "[1/5] Backing up old scanner..."
ssh "$SERVER" "cp $REMOTE_DIR/scanner $REMOTE_DIR/scanner.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true"
echo "✅ Backup complete"

# 步骤2: 上传新版本
echo ""
echo "[2/5] Uploading new scanner binary..."
scp "$LOCAL_BUILD" "$SERVER:$REMOTE_DIR/scanner.new"
echo "✅ Upload complete"

# 步骤3: 上传配置文件（如果存在）
if [ -n "$LOCAL_CONFIG" ]; then
    echo ""
    echo "[3/5] Uploading optimized config..."
    scp "$LOCAL_CONFIG" "$SERVER:$REMOTE_DIR/config/scanner_config.json.new"
    echo "✅ Config upload complete"
else
    echo ""
    echo "[3/5] Skipping config upload"
fi

# 步骤4: 上传监控脚本（如果存在）
if [ -n "$LOCAL_MONITOR" ]; then
    echo ""
    echo "[4/5] Uploading memory monitor..."
    scp "$LOCAL_MONITOR" "$SERVER:$REMOTE_DIR/"
    ssh "$SERVER" "chmod +x $REMOTE_DIR/monitor_scanner_memory.sh"
    echo "✅ Monitor script upload complete"
else
    echo ""
    echo "[4/5] Skipping monitor script upload"
fi

# 步骤5: 重启服务
echo ""
echo "[5/5] Restarting scanner service..."
ssh "$SERVER" << 'ENDSSH'
cd /opt/protocol_scanner

# 停止服务
echo "Stopping service..."
systemctl stop protocol-scanner || true
sleep 2

# 替换二进制
echo "Replacing binary..."
mv scanner.new scanner
chmod +x scanner

# 替换配置（如果存在）
if [ -f config/scanner_config.json.new ]; then
    cp config/scanner_config.json config/scanner_config.json.backup.$(date +%Y%m%d_%H%M%S)
    mv config/scanner_config.json.new config/scanner_config.json
    echo "✅ Config replaced"
fi

# 启动服务
echo "Starting service..."
systemctl start protocol-scanner
sleep 2

# 检查状态
if systemctl is-active --quiet protocol-scanner; then
    echo "✅ Service is running"
    systemctl status protocol-scanner --no-pager -l | head -15
else
    echo "❌ Service failed to start"
    journalctl -u protocol-scanner -n 50 --no-pager
    exit 1
fi
ENDSSH

echo ""
echo "========================================"
echo "  ✅ Deployment Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Monitor logs:    ssh $SERVER 'tail -f $REMOTE_DIR/logs/scanner.log'"
echo "2. Check memory:    ssh $SERVER '$REMOTE_DIR/monitor_scanner_memory.sh'"
echo "3. View stats:      ssh $SERVER 'grep -E \"\\[Memory\\]|\\[BufferPool\\]\" $REMOTE_DIR/logs/scanner.log'"
echo ""
echo "Look for:"
echo "  - [Memory] sessions_total=X sessions_pending=Y"
echo "  - [BufferPool] size=3000 available=X hit_rate=Y%"
echo ""
