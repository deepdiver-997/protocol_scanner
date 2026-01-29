#!/bin/bash

# 服务器性能对比测试脚本
# 在 Linux 服务器上运行以验证优化效果

set -e

PROJECT_DIR="${1:-.}"
DURATION="${2:-120}"  # 默认 120 秒

if [ ! -f "$PROJECT_DIR/build/scanner" ]; then
    echo "错误：找不到 scanner 可执行文件"
    echo "请确保已在 $PROJECT_DIR 目录下编译"
    exit 1
fi

SCANNER="$PROJECT_DIR/build/scanner"
CONFIG="$PROJECT_DIR/config/scanner_config_2gb_optimized.json"
IP_FILE="$PROJECT_DIR/JP_ip.txt"

if [ ! -f "$CONFIG" ]; then
    CONFIG="$PROJECT_DIR/config/scanner_config.json"
fi

if [ ! -f "$IP_FILE" ]; then
    echo "警告：找不到 IP 文件 $IP_FILE，尝试使用 US_ip.txt"
    IP_FILE="$PROJECT_DIR/US_ip.txt"
fi

if [ ! -f "$IP_FILE" ]; then
    echo "错误：找不到 IP 列表文件"
    exit 1
fi

echo "=========================================="
echo "性能测试 - Socket 缓冲区优化"
echo "=========================================="
echo ""
echo "配置："
echo "  - Scanner: $SCANNER"
echo "  - Config:  $CONFIG"
echo "  - IP File: $IP_FILE"
echo "  - Duration: ${DURATION}s"
echo ""

# 检查 perf 是否可用
if command -v perf &> /dev/null; then
    echo "运行 perf stat 性能分析..."
    echo ""
    
    perf stat \
        -e "cycles,instructions,cache-references,cache-misses,branch-instructions,branch-misses,context-switches,page-faults" \
        -e "syscalls:sys_enter_read,syscalls:sys_enter_write,syscalls:sys_enter_epoll_ctl,syscalls:sys_enter_epoll_wait" \
        timeout "$DURATION" "$SCANNER" \
            -d "$IP_FILE" \
            -c "$CONFIG" \
            --scan 2>&1 | tee "perf_result_$(date +%s).log"
else
    echo "警告：perf 不可用，使用 time 命令..."
    echo ""
    time timeout "$DURATION" "$SCANNER" \
        -d "$IP_FILE" \
        -c "$CONFIG" \
        --scan
fi

echo ""
echo "=========================================="
echo "测试完成"
echo "=========================================="
echo ""
echo "关键指标："
echo "  [1] context-switches: 应该 < 2M（每秒 < 16K）"
echo "  [2] cache-misses: 应该 < 10%"
echo "  [3] syscalls:sys_enter_epoll_ctl: 应该相对较小"
echo ""
