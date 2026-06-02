#!/bin/bash
# SSH 版本提取专项测试
# 测试 SSH parse_capabilities 是否正常工作
# 用法: bash _test_ssh.sh

SCANNER="./build-fix/scanner"
echo "=== SSH 版本提取测试 ==="
echo ""

# 用 JSON 格式输出，提取 SSH 相关字段
$SCANNER --domains _test_quick.txt --scan \
  --enable-ssh \
  --timeout 15000 --threads 4 \
  --format json 2>&1 | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        data = json.loads(line)
    except:
        continue
    protocols = data.get('protocols', data if isinstance(data, list) else [])
    if isinstance(data, dict):
        protocols = data.get('protocols', [])
    for p in (protocols if isinstance(protocols, list) else [protocols]):
        if p.get('protocol') == 'SSH' and p.get('accessible'):
            a = p.get('attrs', {})
            print(f'Host: {p.get(\"host\", \"?\")}')
            print(f'Banner: {a.get(\"banner\", \"N/A\")}')
            print(f'Version string: {a.get(\"ssh\", {}).get(\"version_string\", \"N/A\")}')
            print(f'Software: {a.get(\"ssh\", {}).get(\"software\", \"N/A\")}')
            print(f'Version: {a.get(\"ssh\", {}).get(\"version\", \"N/A\")}')
            print(f'Protocol ver: {a.get(\"ssh\", {}).get(\"protocol_version\", \"N/A\")}')
            print(f'Vendor: {a.get(\"vendor\", \"N/A\")}')
            print(f'Truncated: {a.get(\"banner_truncated\", False)}')
            print()
" 2>/dev/null || echo "Python parse skipped, check raw output"
