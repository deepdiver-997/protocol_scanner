#!/bin/bash

# 性能对比测试脚本
# 测试优化前后的性能差异

set -e

PROJECT_DIR="/Users/zhuhongrui/Desktop/code/c++/protocol-scanner"
cd "$PROJECT_DIR"

SCANNER="./build/scanner"
TEST_IP_FILE="JP_ip.txt"
CONFIG="config/scanner_config_2gb_optimized.json"
TIME_LIMIT="120s"  # 2分钟测试

echo "=========================================="
echo "性能对比测试 - Socket 缓冲区优化"
echo "=========================================="
echo ""
echo "测试配置："
echo "  - Scanner: $SCANNER"
echo "  - IP文件: $TEST_IP_FILE (样本前 1000 行)"
echo "  - 配置: $CONFIG"
echo "  - 时间限制: $TIME_LIMIT"
echo ""

# 创建测试样本（前 1000 行）
TEST_SAMPLE="test_sample_1000.txt"
if [ ! -f "$TEST_SAMPLE" ]; then
    echo "创建测试样本..."
    head -1000 "$TEST_IP_FILE" > "$TEST_SAMPLE"
fi

echo "运行性能测试..."
echo "  命令: $SCANNER -d $TEST_SAMPLE -c $CONFIG --scan --time-limit $TIME_LIMIT"
echo ""

# 运行 perf stat 获取性能指标
perf stat -e "cycles,instructions,cache-misses,branch-misses,context-switches,page-faults,syscalls:sys_enter_read,syscalls:sys_enter_write,syscalls:sys_enter_epoll_ctl" \
  timeout "$TIME_LIMIT" "$SCANNER" -d "$TEST_SAMPLE" -c "$CONFIG" --scan 2>&1 | tee perf_test_output.log

echo ""
echo "=========================================="
echo "测试完成"
echo "=========================================="
echo "详细结果已保存至: perf_test_output.log"
echo ""
echo "关键指标："
echo "  - 如果 cache-misses 减少 > 10%，说明缓冲区优化有效"
echo "  - 如果 context-switches 减少 > 15%，说明系统调用减少"
echo "  - 如果 syscalls:sys_enter_epoll_ctl 减少 > 20%，说明 epoll 修改减少"
