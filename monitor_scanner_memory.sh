#!/bin/bash
# 
# monitor_scanner_memory.sh
# 实时监控 scanner 进程的内存占用情况
# 使用方法: ./monitor_scanner_memory.sh

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
LOG_FILE="memory_monitor.log"
INTERVAL=5  # 监控间隔(秒)
ALERT_RSS_MB=1500  # RSS超过此值时告警(MB)
ALERT_AVAILABLE_MB=100  # 系统可用内存低于此值时告警(MB)

echo "========================================"
echo "  Scanner Memory Monitor"
echo "========================================"
echo "Interval: ${INTERVAL}s"
echo "Alert RSS: ${ALERT_RSS_MB} MB"
echo "Alert Available: ${ALERT_AVAILABLE_MB} MB"
echo "Log file: ${LOG_FILE}"
echo "========================================"
echo ""

# 创建日志文件
echo "=== Scanner Memory Monitor Started at $(date) ===" > "$LOG_FILE"

while true; do
    # 查找 scanner 进程
    pid=$(pgrep -f "scanner" | head -1)
    
    if [ -z "$pid" ]; then
        echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Scanner process not found"
        sleep "$INTERVAL"
        continue
    fi
    
    # 获取进程内存信息
    if [ -f "/proc/$pid/status" ]; then
        vm_rss=$(grep "^VmRSS:" /proc/$pid/status | awk '{print $2}')
        vm_size=$(grep "^VmSize:" /proc/$pid/status | awk '{print $2}')
        vm_swap=$(grep "^VmSwap:" /proc/$pid/status | awk '{print $2}')
        threads=$(grep "^Threads:" /proc/$pid/status | awk '{print $2}')
        
        # 转换为MB
        vm_rss_mb=$((vm_rss / 1024))
        vm_size_mb=$((vm_size / 1024))
        vm_swap_mb=$((vm_swap / 1024))
    else
        echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Cannot read /proc/$pid/status"
        sleep "$INTERVAL"
        continue
    fi
    
    # 获取系统内存信息
    mem_total=$(grep "^MemTotal:" /proc/meminfo | awk '{print $2}')
    mem_available=$(grep "^MemAvailable:" /proc/meminfo | awk '{print $2}')
    swap_total=$(grep "^SwapTotal:" /proc/meminfo | awk '{print $2}')
    swap_free=$(grep "^SwapFree:" /proc/meminfo | awk '{print $2}')
    
    mem_total_mb=$((mem_total / 1024))
    mem_available_mb=$((mem_available / 1024))
    swap_total_mb=$((swap_total / 1024))
    swap_free_mb=$((swap_free / 1024))
    swap_used_mb=$((swap_total_mb - swap_free_mb))
    
    # 计算百分比
    mem_percent=$((vm_rss * 100 / mem_total))
    
    # 构建输出
    timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    
    # 颜色输出(根据告警阈值)
    if [ "$vm_rss_mb" -gt "$ALERT_RSS_MB" ]; then
        rss_color=$RED
        rss_alert="[!ALERT!]"
    elif [ "$vm_rss_mb" -gt $((ALERT_RSS_MB * 80 / 100)) ]; then
        rss_color=$YELLOW
        rss_alert="[WARNING]"
    else
        rss_color=$GREEN
        rss_alert=""
    fi
    
    if [ "$mem_available_mb" -lt "$ALERT_AVAILABLE_MB" ]; then
        avail_color=$RED
        avail_alert="[!ALERT!]"
    elif [ "$mem_available_mb" -lt $((ALERT_AVAILABLE_MB * 150 / 100)) ]; then
        avail_color=$YELLOW
        avail_alert="[WARNING]"
    else
        avail_color=$GREEN
        avail_alert=""
    fi
    
    # 屏幕输出
    echo -e "${BLUE}[$timestamp]${NC} PID=$pid Threads=$threads"
    echo -e "  ${rss_color}RSS: ${vm_rss_mb} MB${NC} ${rss_alert} (${mem_percent}% of system)"
    echo -e "  VmSize: ${vm_size_mb} MB"
    echo -e "  ${YELLOW}Swap: ${vm_swap_mb} MB${NC}"
    echo -e "  ${avail_color}System Available: ${mem_available_mb} MB${NC} ${avail_alert} / ${mem_total_mb} MB"
    echo -e "  System Swap Used: ${swap_used_mb} MB / ${swap_total_mb} MB"
    echo ""
    
    # 写入日志
    {
        echo "$timestamp,PID=$pid,RSS=${vm_rss_mb}MB,VmSize=${vm_size_mb}MB,VmSwap=${vm_swap_mb}MB,Threads=$threads,SysAvail=${mem_available_mb}MB,SysSwap=${swap_used_mb}MB"
    } >> "$LOG_FILE"
    
    sleep "$INTERVAL"
done
