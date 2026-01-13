#!/bin/bash

# 获取指定国家的所有 IP 地址段
# 使用 ipdeny.com 数据库

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 显示使用说明
usage() {
    cat << EOF
Usage: $0 <country_code> [output_file]

获取指定国家的所有 IP 地址段

参数:
    country_code    国家代码（ISO 3166-1 alpha-2，如 CN, US, JP）
    output_file     输出文件名（可选，默认为 {country_code}_ip.txt）

示例:
    $0 CN                    # 获取中国 IP，输出到 CN_ip.txt
    $0 US us_ips.txt         # 获取美国 IP，输出到 us_ips.txt
    $0 JP                    # 获取日本 IP，输出到 JP_ip.txt

常用国家代码:
    CN - 中国    US - 美国    JP - 日本
    KR - 韩国    GB - 英国    DE - 德国
    FR - 法国    RU - 俄罗斯  IN - 印度
    BR - 巴西    CA - 加拿大  AU - 澳大利亚
    IT - 意大利  ES - 西班牙  NL - 荷兰
    SG - 新加坡  HK - 香港    TW - 台湾

数据来源: https://www.ipdeny.com/ipblocks/
EOF
    exit 1
}

# 检查参数
if [ $# -lt 1 ]; then
    usage
fi

COUNTRY_CODE=$(echo "$1" | tr '[:lower:]' '[:upper:]')
OUTPUT_FILE="${2:-${COUNTRY_CODE}_ip.txt}"

# 验证国家代码格式（应该是两个字母）
if [[ ! "$COUNTRY_CODE" =~ ^[A-Z]{2}$ ]]; then
    echo -e "${RED}错误: 国家代码必须是两个字母（ISO 3166-1 alpha-2）${NC}"
    echo "例如: CN, US, JP"
    exit 1
fi

echo -e "${GREEN}正在获取 $COUNTRY_CODE 的 IP 地址段...${NC}"

# 转换为小写（兼容旧版 bash）
COUNTRY_LOWER=$(echo "$COUNTRY_CODE" | tr '[:upper:]' '[:lower:]')

# ipdeny.com 提供的 IPv4 地址段 URL
IPV4_URL="https://www.ipdeny.com/ipblocks/data/aggregated/${COUNTRY_LOWER}-aggregated.zone"

# 尝试下载 IPv4 地址段
echo -e "${YELLOW}下载数据中...${NC}"
if curl -f -L -o "$OUTPUT_FILE" "$IPV4_URL" 2>/dev/null; then
    LINE_COUNT=$(wc -l < "$OUTPUT_FILE")
    echo -e "${GREEN}✓ 成功！${NC}"
    echo -e "获取到 ${GREEN}$LINE_COUNT${NC} 个 IP 地址段"
    echo -e "已保存到: ${GREEN}$OUTPUT_FILE${NC}"
    
    # 显示前几行示例
    echo -e "\n${YELLOW}前 5 个地址段:${NC}"
    head -5 "$OUTPUT_FILE"
    
    if [ $LINE_COUNT -gt 5 ]; then
        echo "..."
    fi
else
    echo -e "${RED}✗ 下载失败${NC}"
    echo -e "${YELLOW}可能的原因:${NC}"
    echo "  1. 国家代码不正确（必须是 ISO 3166-1 alpha-2 格式）"
    echo "  2. 网络连接问题"
    echo "  3. ipdeny.com 服务暂时不可用"
    echo ""
    echo -e "${YELLOW}常用国家代码示例:${NC}"
    echo "  CN (中国), US (美国), JP (日本), KR (韩国)"
    echo "  完整列表: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2"
    exit 1
fi

# 可选：同时获取 IPv6 地址段
read -p "是否同时获取 IPv6 地址段？(y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    IPV6_URL="https://www.ipdeny.com/ipv6/ipaddresses/aggregated/${COUNTRY_LOWER}-aggregated.zone"
    IPV6_OUTPUT="${OUTPUT_FILE%.txt}_ipv6.txt"
    
    echo -e "${YELLOW}下载 IPv6 数据中...${NC}"
    if curl -f -L -o "$IPV6_OUTPUT" "$IPV6_URL" 2>/dev/null; then
        IPV6_COUNT=$(wc -l < "$IPV6_OUTPUT")
        echo -e "${GREEN}✓ IPv6 成功！${NC}"
        echo -e "获取到 ${GREEN}$IPV6_COUNT${NC} 个 IPv6 地址段"
        echo -e "已保存到: ${GREEN}$IPV6_OUTPUT${NC}"
    else
        echo -e "${YELLOW}⚠ IPv6 数据不可用${NC}"
    fi
fi

echo -e "\n${GREEN}完成！${NC}"
