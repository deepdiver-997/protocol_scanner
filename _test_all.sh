#!/bin/bash
# Protocol Scanner 全面测试脚本
# 用法: bash _test_all.sh
# 确保先编译: cmake -B build-fix && cmake --build build-fix -j

SCANNER="./build-fix/scanner"
TIMEOUT=15000
THREADS=4

echo "============================================"
echo " Protocol Scanner — 全面测试"
echo "============================================"

# 1. 快速测试 (所有协议)
echo ""
echo "=== 1/5: 快测模式 (所有协议) ==="
$SCANNER --domains _test_quick.txt --scan \
  --enable-ssh --enable-http --enable-ftp \
  --timeout $TIMEOUT --threads $THREADS \
  --format text 2>&1 | tail -40

echo ""
echo "=== 2/5: SSH 单独测试 + 版本提取 ==="
$SCANNER --domains _test_quick.txt --scan \
  --enable-ssh \
  --timeout $TIMEOUT --threads $THREADS \
  --format json 2>&1 | grep -A5 '"protocol":"SSH"' || echo "(check full output)"

echo ""
echo "=== 3/5: HTTP 单独测试 + Server头 ==="
$SCANNER --domains _test_quick.txt --scan \
  --enable-http \
  --timeout $TIMEOUT --threads $THREADS \
  --format json 2>&1 | grep -A5 '"protocol":"HTTP"' || echo "(check full output)"

echo ""
echo "=== 4/5: FTP 单独测试 + FEAT ==="
$SCANNER --domains _test_quick.txt --scan \
  --enable-ftp \
  --timeout $TIMEOUT --threads $THREADS \
  --format json 2>&1 | grep -A5 '"protocol":"FTP"' || echo "(check full output)"

echo ""
echo "=== 5/5: 结果文件 ==="
echo "输出目录: ./result/"
ls -la ./result/*.txt ./result/*.json 2>/dev/null
echo ""
echo "=== 完成 ==="
