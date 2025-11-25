#!/bin/bash

# SSH代理转发 - 快速启动脚本
# 用途：方便地启动、停止、重启代理服务

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_FILE="$SCRIPT_DIR/代理转发.py"
LOG_FILE="$SCRIPT_DIR/ssh_proxy.log"
PID_FILE="/tmp/ssh_proxy.pid"

# 函数：打印带颜色的输出
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# 函数：检查依赖
check_dependencies() {
    print_info "检查依赖..."
    
    # 检查Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python3未安装"
        exit 1
    fi
    print_status "Python3 $(python3 --version | cut -d' ' -f2)"
    
    # 检查paramiko
    if ! python3 -c "import paramiko" 2>/dev/null; then
        print_warning "paramiko未安装，尝试安装..."
        pip3 install paramiko || {
            print_error "无法安装paramiko"
            exit 1
        }
    fi
    print_status "paramiko已安装"
}

# 函数：检查配置
check_config() {
    print_info "检查配置..."
    
    if [ ! -f "$PROXY_FILE" ]; then
        print_error "代理文件不存在：$PROXY_FILE"
        exit 1
    fi
    print_status "代理文件存在"
    
    # 检查关键配置
    if ! grep -q "LISTEN_PORT" "$PROXY_FILE"; then
        print_error "配置文件缺少 LISTEN_PORT"
        exit 1
    fi
    
    if ! grep -q "AUTHORIZED_CLIENT_KEYS" "$PROXY_FILE"; then
        print_error "配置文件缺少 AUTHORIZED_CLIENT_KEYS"
        exit 1
    fi
    
    print_status "配置检查通过"
}

# 函数：启动服务
start_service() {
    print_info "启动SSH代理服务..."
    
    if [ -f "$PID_FILE" ]; then
        local old_pid=$(cat "$PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            print_warning "服务已在运行 (PID: $old_pid)"
            return 0
        fi
    fi
    
    # 后台启动服务
    nohup python3 "$PROXY_FILE" > "$LOG_FILE" 2>&1 &
    local pid=$!
    echo $pid > "$PID_FILE"
    
    # 等待服务启动
    sleep 2
    
    if kill -0 "$pid" 2>/dev/null; then
        print_status "SSH代理服务已启动 (PID: $pid)"
        print_info "日志文件：$LOG_FILE"
    else
        print_error "服务启动失败"
        echo "--- 错误信息 ---"
        tail -20 "$LOG_FILE"
        exit 1
    fi
}

# 函数：停止服务
stop_service() {
    print_info "停止SSH代理服务..."
    
    if [ ! -f "$PID_FILE" ]; then
        print_warning "PID文件不存在，没有运行中的服务"
        return 0
    fi
    
    local pid=$(cat "$PID_FILE")
    
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        print_status "服务已停止 (PID: $pid)"
        rm -f "$PID_FILE"
    else
        print_warning "服务未运行"
        rm -f "$PID_FILE"
    fi
}

# 函数：查看状态
status_service() {
    print_info "SSH代理服务状态"
    
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_status "服务运行中 (PID: $pid)"
            
            # 获取端口信息
            local port=$(grep "LISTEN_PORT" "$PROXY_FILE" | grep "=" | head -1 | awk '{print $NF}')
            print_info "监听端口：$port"
            
            # 查看进程占用
            if command -v lsof &> /dev/null; then
                print_info "进程详情："
                lsof -p "$pid" | head -20
            fi
            
            return 0
        fi
    fi
    
    print_warning "服务未运行"
}

# 函数：查看日志
show_logs() {
    print_info "显示最后100行日志..."
    
    if [ -f "$LOG_FILE" ]; then
        tail -100 "$LOG_FILE"
    else
        print_warning "日志文件不存在"
    fi
}

# 函数：实时查看日志
tail_logs() {
    print_info "实时查看日志 (Ctrl+C 停止)..."
    
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        print_warning "日志文件不存在"
    fi
}

# 函数：查看配置
show_config() {
    print_info "代理配置信息："
    
    echo ""
    grep -E "LISTEN|REAL_SSH|AUTHORIZED" "$PROXY_FILE" | grep "=" | head -10
    echo ""
}

# 函数：生成密钥
generate_keys() {
    print_info "生成测试RSA密钥对..."
    
    if command -v python3 &> /dev/null; then
        python3 -c "
import sys
sys.path.insert(0, '.')
from test_ssh_proxy import SSHProxyTester
tester = SSHProxyTester()
tester.generate_test_keys()
" || print_error "密钥生成失败"
    else
        print_error "需要Python3"
    fi
}

# 函数：重启服务
restart_service() {
    print_info "重启SSH代理服务..."
    stop_service
    sleep 1
    start_service
}

# 函数：打印帮助
show_help() {
    cat << EOF
${BLUE}SSH代理转发 - 快速启动脚本${NC}

用法：
    $0 [命令]

命令：
    start           启动服务
    stop            停止服务
    restart         重启服务
    status          查看状态
    logs            查看日志（最后100行）
    tail            实时查看日志 (Ctrl+C 停止)
    config          查看配置信息
    genkeys         生成测试密钥对
    help            显示本帮助信息

示例：
    $0 start        # 启动服务
    $0 status       # 查看状态
    $0 logs         # 查看最近的日志
    $0 tail         # 实时监控日志

特色功能：
    • 自动检查依赖（Python3、paramiko）
    • 验证配置文件有效性
    • PID管理防止重复启动
    • 日志输出到文件
    • 快速诊断工具

EOF
}

# 主程序
main() {
    local command="${1:-help}"
    
    case "$command" in
        start)
            check_dependencies
            check_config
            start_service
            ;;
        stop)
            stop_service
            ;;
        restart)
            check_dependencies
            check_config
            restart_service
            ;;
        status)
            status_service
            ;;
        logs)
            show_logs
            ;;
        tail)
            tail_logs
            ;;
        config)
            show_config
            ;;
        genkeys)
            check_dependencies
            generate_keys
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "未知命令：$command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# 执行主程序
main "$@"
