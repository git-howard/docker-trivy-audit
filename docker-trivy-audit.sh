#!/usr/bin/env bash
# ==============================================================================
# 脚本名称: docker-trivy-audit.sh
# 功能描述: 利用现有的 aquasec/trivy Docker 镜像，对本地或远程 Linux 主机上的
#           Docker 容器与镜像进行全量安全性评估（操作系统/语言依赖漏洞、凭证密钥泄露），
#           远程评估时依然使用本地的 Trivy，并在本地完成下载评估与临时镜像清理。
# ==============================================================================

set -uo pipefail

# 终端输出颜色与样式
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# 默认基础配置
DEFAULT_MIRROR_TRIVY_IMAGE="docker.m.daocloud.io/aquasec/trivy:latest"
DEFAULT_OFFICIAL_TRIVY_IMAGE="aquasec/trivy:latest"
TRIVY_IMAGE="${TRIVY_IMAGE:-$DEFAULT_MIRROR_TRIVY_IMAGE}"
DB_REPOSITORY="ghcr.io/aquasecurity/trivy-db:2"
SEVERITY="CRITICAL,HIGH,MEDIUM,LOW"
SCANNERS="vuln,secret"
SCAN_SCOPE="running"   # running: 仅正在运行的容器镜像 (默认); all: 宿主机所有本地镜像
OUTPUT_BASE_DIR="./trivy-audit-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TASK_START_SEC=$(date +%s)
TASK_START_DATETIME=$(date +"%Y-%m-%d %H:%M:%S")
SUCCESS_COUNT=0
FAIL_COUNT=0
CACHE_DIR="${HOME}/.cache/trivy"
TIMEOUT="15m"
SKIP_DB_UPDATE=false
UPDATE_JAVA_DB=false
JAVA_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-java-db:1"
FORCE_INTERACTIVE=false
NON_INTERACTIVE=false
if [[ ! -t 0 ]]; then
    NON_INTERACTIVE=true
fi
DEBUG=false

# 远程评估 SSH 配置参数
REMOTE_HOST=""
SSH_PORT="22"
SSH_USER="root"
SSH_PASSWORD=""
SSH_KEY=""
CLEANUP_REMOTE=true
REMOTE_DOCKER_CONFIG=""
SYNC_REMOTE_DOCKER_AUTH=true
ACTIVE_DOCKER_CONFIG=""
REMOTE_DOCKER_REGISTRIES=()
REMOTE_USE_SUDO=false
REMOTE_SUDO_TYPE=""
SUDO_PASSWORD=""
IMAGE_TRANSFER_MODE="copy"  # copy: 远程计算机直接复制; pull: Docker 镜像源拉取

# 代理环境变量数组
PROXY_FLAGS=()

# 打印日志函数
log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "\n${BOLD}${CYAN}==>${NC} ${BOLD}$*${NC}"; }

# 显示帮助信息
show_help() {
    cat << 'EOF'
用法:
  ./docker-trivy-audit.sh [选项]

通用评估选项:
  -s, --scope <running|all>      扫描范围:
                                   running: 仅扫描当前正在运行的容器所用的镜像 (默认)
                                   all: 扫描所有本地 Docker 镜像
  -l, --severity <LEVELS>        严重程度过滤，逗号分隔 (默认: CRITICAL,HIGH,MEDIUM,LOW)
                                 可选值: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
      --scanners <SCANNERS>      启用的扫描器模块 (默认: vuln,secret)
                                 可选: vuln (组件漏洞 - 速度极快)
                                       vuln,secret (同时扫描漏洞和敏感硬编码)
  -o, --output-dir <DIR>         报告输出根目录 (默认: ./trivy-audit-reports)
  -t, --trivy-image <IMAGE>      指定使用的 Trivy Docker 镜像 (默认: docker.m.daocloud.io/aquasec/trivy:latest)
                                 支持第三方加速源 (如: docker.m.daocloud.io/aquasec/trivy:latest)
      --mirror                   快速切换为国内第三方加速源 (docker.m.daocloud.io/aquasec/trivy:latest)
      --official                 切换为 Docker Hub 官方源 (aquasec/trivy:latest)
  -c, --cache-dir <DIR>          漏洞数据库本地缓存目录 (默认: ~/.cache/trivy)
      --db-repository <REPO>     自定义漏洞数据库 OCI 仓库地址 (默认: ghcr.io/aquasecurity/trivy-db:2)
      --skip-db-update           跳过漏洞数据库更新 (适用于离线/内网隔离环境)
      --update-java-db           连网下载/更新 Java jar 依赖数据库 (默认: 跳过)
      --java-db-repository <REPO> 自定义 Java 依赖数据库仓库 (默认: ghcr.io/aquasecurity/trivy-java-db:1)
  -y, --non-interactive          以非交互模式直接执行 (跳过启动配置向导问询)
      --cleanup                  远程评估完成后自动清理本地拉取的临时镜像 (默认: true)
      --no-cleanup               远程评估完成后保留本地拉取的临时镜像
      --timeout <DURATION>       单个镜像扫描超时上限 (默认: 15m)
  -d, --debug                    开启调试模式，打印详细 Docker 执行日志
  -h, --help                     显示此帮助信息

远程主机评估选项 (SSH 架构: 本地 Trivy 引擎 + 远程流式拉取评估 + 自动清除临时镜像):
  -H, --host <HOST>              远程 Linux 目标主机 IP 或域名 (指定此项即启用远程模式)
  -P, --remote-port <PORT>       远程 SSH 端口 (默认: 22)
  -u, --user <USERNAME>          远程 SSH 登录用户名 (默认: root)
  -p, --password <PASSWORD>      远程 SSH 登录密码 (可选；若不提供且无私钥，将交互式安全输入)
  -k, --key <KEY_FILE>           远程 SSH 私钥文件路径 (可选)
      --sudo-password <PASSWORD> 远程 sudo 提权密码 (默认复用 SSH 登录密码)
      --remote-docker-config <P> 指定远程 Docker 配置文件路径 (默认自动探测 ~/.docker/config.json 或 /root/.docker/config.json)
      --no-sync-docker-auth      禁用远程 Docker 源认证凭据自动同步至本地
      --image-transfer-mode <MODE> 远程评估镜像获取方式:
                                   copy: 直接从远程计算机复制镜像到本地 (SSH 流式传输，不经 Docker 源，默认)
                                   pull: 本地通过网络从 Docker 镜像源直接拉取 (docker pull)
      --copy-remote-image        快捷选择: 直接从远程计算机复制镜像到本地 (默认)
      --pull-from-registry       快捷选择: 从 Docker 镜像源直接拉取镜像

示例:
  1. 启动交互式向导运行 (默认推荐):
     ./docker-trivy-audit.sh

  2. 极速模式 (仅扫描运行中容器组件漏洞，跳过密钥扫描):
     ./docker-trivy-audit.sh -s running --scanners vuln

  3. 离线/内网非交互评估 (使用本地缓存，跳过每次联网检测 DB 与问询):
     ./docker-trivy-audit.sh -y --skip-db-update

  4. 远程主机评估 (指定参数直接运行):
     ./docker-trivy-audit.sh -H 192.168.1.100 -u root -p 'MySecretPass'

EOF
    exit 0
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--scope)
                SCAN_SCOPE="$2"
                shift 2
                ;;
            -l|--severity)
                SEVERITY="$2"
                shift 2
                ;;
            --scanners)
                SCANNERS="$2"
                shift 2
                ;;
            -o|--output-dir)
                OUTPUT_BASE_DIR="$2"
                shift 2
                ;;
            -t|--trivy-image)
                TRIVY_IMAGE="$2"
                shift 2
                ;;
            --mirror|--use-mirror|--cn-mirror)
                TRIVY_IMAGE="$DEFAULT_MIRROR_TRIVY_IMAGE"
                shift
                ;;
            --official)
                TRIVY_IMAGE="$DEFAULT_OFFICIAL_TRIVY_IMAGE"
                shift
                ;;
            -c|--cache-dir)
                CACHE_DIR="$2"
                shift 2
                ;;
            --db-repository)
                DB_REPOSITORY="$2"
                shift 2
                ;;
            --skip-db-update)
                SKIP_DB_UPDATE=true
                shift
                ;;
            --update-java-db)
                UPDATE_JAVA_DB=true
                shift
                ;;
            --skip-java-db-update)
                UPDATE_JAVA_DB=false
                shift
                ;;
            --java-db-repository)
                JAVA_DB_REPOSITORY="$2"
                shift 2
                ;;
            -y|--non-interactive|--batch)
                NON_INTERACTIVE=true
                shift
                ;;
            -i|--interactive)
                FORCE_INTERACTIVE=true
                NON_INTERACTIVE=false
                shift
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -d|--debug)
                DEBUG=true
                shift
                ;;
            -H|--host|--remote-host)
                REMOTE_HOST="$2"
                shift 2
                ;;
            -P|--remote-port)
                SSH_PORT="$2"
                shift 2
                ;;
            -u|--user)
                SSH_USER="$2"
                shift 2
                ;;
            -p|--password)
                SSH_PASSWORD="$2"
                shift 2
                ;;
            -k|--key|--identity-file)
                SSH_KEY="$2"
                shift 2
                ;;
            --sudo-password)
                SUDO_PASSWORD="$2"
                shift 2
                ;;
            --remote-docker-config)
                REMOTE_DOCKER_CONFIG="$2"
                shift 2
                ;;
            --no-sync-docker-auth)
                SYNC_REMOTE_DOCKER_AUTH=false
                shift
                ;;
            --image-transfer-mode)
                IMAGE_TRANSFER_MODE="$2"
                shift 2
                ;;
            --copy-remote-image)
                IMAGE_TRANSFER_MODE="copy"
                shift
                ;;
            --pull-from-registry)
                IMAGE_TRANSFER_MODE="pull"
                shift
                ;;
            --cleanup)
                CLEANUP_REMOTE=true
                shift
                ;;
            --no-cleanup)
                CLEANUP_REMOTE=false
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                ;;
        esac
    done

    IMAGE_TRANSFER_MODE=$(echo "$IMAGE_TRANSFER_MODE" | tr '[:upper:]' '[:lower:]')
    if [[ "$IMAGE_TRANSFER_MODE" != "copy" && "$IMAGE_TRANSFER_MODE" != "pull" ]]; then
        IMAGE_TRANSFER_MODE="copy"
    fi

    if [[ "$SCAN_SCOPE" != "all" && "$SCAN_SCOPE" != "running" ]]; then
        log_error "无效的扫描范围: $SCAN_SCOPE (只能为 all 或 running)"
        exit 1
    fi
}

# 检测并注入终端代理配置
detect_proxy() {
    PROXY_FLAGS=()
    local p_http="${HTTP_PROXY:-${http_proxy:-}}"
    local p_https="${HTTPS_PROXY:-${https_proxy:-}}"
    local p_no="${NO_PROXY:-${no_proxy:-}}"

    if [[ -n "$p_http" ]]; then
        PROXY_FLAGS+=("-e" "HTTP_PROXY=${p_http}" "-e" "http_proxy=${p_http}")
    fi
    if [[ -n "$p_https" ]]; then
        PROXY_FLAGS+=("-e" "HTTPS_PROXY=${p_https}" "-e" "https_proxy=${p_https}")
    fi
    if [[ -n "$p_no" ]]; then
        PROXY_FLAGS+=("-e" "NO_PROXY=${p_no}" "-e" "no_proxy=${p_no}")
    fi

    if [[ ${#PROXY_FLAGS[@]} -gt 0 ]]; then
        log_info "检测到终端网络代理环境变量，已自动透传给 Trivy 容器。"
    fi
}

# ==============================================================================
# 远程 SSH 执行工具函数组
# ==============================================================================

# 执行远程 SSH 文本命令
execute_ssh() {
    local cmd="$1"
    local pty_flag="${2:-false}"
    local tty_opt=""
    if [[ "$pty_flag" == true ]]; then
        tty_opt="-t"
    fi

    local ssh_opts=(-o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "LogLevel=ERROR" -o "ConnectTimeout=15" -p "$SSH_PORT")

    if [[ -n "$SSH_KEY" ]]; then
        ssh "${ssh_opts[@]}" $tty_opt -i "$SSH_KEY" "${SSH_USER}@${REMOTE_HOST}" "$cmd"
    elif [[ -n "$SSH_PASSWORD" ]]; then
        if command -v sshpass >/dev/null 2>&1; then
            export SSHPASS="$SSH_PASSWORD"
            sshpass -e ssh "${ssh_opts[@]}" $tty_opt "${SSH_USER}@${REMOTE_HOST}" "$cmd"
        elif command -v expect >/dev/null 2>&1; then
            expect -c "
                set timeout 600
                spawn ssh ${ssh_opts[*]} $tty_opt ${SSH_USER}@${REMOTE_HOST} \"$cmd\"
                expect {
                    \"*yes/no*\" { send \"yes\r\"; exp_continue }
                    \"*password:*\" { send \"$SSH_PASSWORD\r\"; exp_continue }
                    \"*Password:*\" { send \"$SSH_PASSWORD\r\"; exp_continue }
                    eof
                }
                catch wait result
                exit [lindex \$result 3]
            "
        else
            log_error "使用密码连接远程主机需要本地安装 'sshpass' (推荐) 或 'expect' 工具。"
            echo -e "  安装建议:"
            echo -e "  - Ubuntu/Debian:  ${CYAN}sudo apt-get install -y sshpass${NC}"
            echo -e "  - CentOS/RHEL:    ${CYAN}sudo yum install -y sshpass${NC}"
            echo -e "  - Alpine Linux:   ${CYAN}apk add sshpass${NC}"
            echo -e "  - macOS:          ${CYAN}brew install hudochenkov/sshpass/sshpass${NC}"
            exit 1
        fi
    else
        ssh "${ssh_opts[@]}" $tty_opt "${SSH_USER}@${REMOTE_HOST}" "$cmd"
    fi
}

# 流式传输远程二进制数据 (专用于 docker save 导入本地 docker load，严禁加 -t)
execute_ssh_stream() {
    local cmd="$1"
    local ssh_opts=(-o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "LogLevel=ERROR" -o "ConnectTimeout=15" -p "$SSH_PORT")

    if [[ -n "$SSH_KEY" ]]; then
        ssh "${ssh_opts[@]}" -i "$SSH_KEY" "${SSH_USER}@${REMOTE_HOST}" "$cmd"
    elif [[ -n "$SSH_PASSWORD" ]]; then
        if command -v sshpass >/dev/null 2>&1; then
            export SSHPASS="$SSH_PASSWORD"
            sshpass -e ssh "${ssh_opts[@]}" "${SSH_USER}@${REMOTE_HOST}" "$cmd"
        else
            log_error "需要安装 'sshpass' 工具以支持远程二进制镜像数据流传输。"
            exit 1
        fi
    else
        ssh "${ssh_opts[@]}" "${SSH_USER}@${REMOTE_HOST}" "$cmd"
    fi
}

# 验证远程 SSH 连接并深入分析报错原因
verify_ssh_connection() {
    log_info "正在验证远程主机 SSH 连通性与凭据 (${SSH_USER}@${REMOTE_HOST}:${SSH_PORT})..."

    # 预检本地 SSH 工具链
    if [[ -n "$SSH_PASSWORD" ]] && ! command -v sshpass >/dev/null 2>&1 && ! command -v expect >/dev/null 2>&1; then
        log_error "使用密码连接远程主机需要本地安装 'sshpass' (推荐) 或 'expect' 工具。"
        echo -e "  安装建议:"
        echo -e "  - Ubuntu/Debian:  ${CYAN}sudo apt-get install -y sshpass${NC}"
        echo -e "  - CentOS/RHEL:    ${CYAN}sudo yum install -y sshpass${NC}"
        echo -e "  - Alpine Linux:   ${CYAN}apk add sshpass${NC}"
        echo -e "  - macOS:          ${CYAN}brew install hudochenkov/sshpass/sshpass${NC}"
        return 1
    fi

    if [[ -n "$SSH_KEY" && ! -f "$SSH_KEY" ]]; then
        log_error "指定的 SSH 私钥文件不存在: ${SSH_KEY}"
        return 1
    fi

    local err_log="${OUTPUT_DIR}/ssh_conn_error.log"
    local out_log="${OUTPUT_DIR}/ssh_conn_out.log"
    : > "$err_log"
    : > "$out_log"

    local exit_code=0
    # 执行连通性测试命令，捕获输出与错误日志
    execute_ssh "echo SSH_CONNECT_OK" false >"$out_log" 2>"$err_log" || exit_code=$?

    local ssh_out=""
    local ssh_err=""
    [[ -f "$out_log" ]] && ssh_out=$(<"$out_log" tr -d '\r')
    [[ -f "$err_log" ]] && ssh_err=$(<"$err_log" tr -d '\r')
    rm -f "$out_log" 2>/dev/null || true

    if [[ $exit_code -ne 0 || "$ssh_out" != *"SSH_CONNECT_OK"* ]]; then
        log_error "远程 SSH 登录失败 (退出状态码: ${exit_code})"
        echo -e "\n${BOLD}${YELLOW}【远程登录错误原因诊断】:${NC}"

        local combined_info="${ssh_err} ${ssh_out}"

        if [[ "$combined_info" == *"Permission denied"* || "$combined_info" == *"Authentication failed"* || $exit_code -eq 5 ]]; then
            echo -e "  └─ ${RED}原因: 身份认证失败 (用户名、密码或 SSH 私钥错误)${NC}"
            echo -e "     建议排查:"
            echo -e "     1. 请检查远程主机用户名 [${BOLD}${SSH_USER}${NC}] 与登录密码是否正确。"
            echo -e "     2. 若使用 SSH 密钥登录，请确认私钥 [${SSH_KEY:-默认密钥}] 正确无误且远程已写入 authorized_keys。"
            echo -e "     3. 确认远程 SSH 服务是否禁用了密码登录 (PasswordAuthentication no)。"
        elif [[ "$combined_info" == *"Connection refused"* || "$combined_info" == *"connection refused"* ]]; then
            echo -e "  └─ ${RED}原因: 网络连接被拒绝 (Connection refused)${NC}"
            echo -e "     建议排查:"
            echo -e "     1. 远程主机 [${BOLD}${REMOTE_HOST}${NC}] 的 SSH 端口 [${BOLD}${SSH_PORT}${NC}] 未开放或填写错误。"
            echo -e "     2. 目标主机的 SSH 服务 (sshd) 可能未启动，可在目标机执行: sudo systemctl status ssh"
        elif [[ "$combined_info" == *"Connection timed out"* || "$combined_info" == *"Operation timed out"* || "$combined_info" == *"timed out"* ]]; then
            echo -e "  └─ ${RED}原因: 网络连接超时 (Connection timed out)${NC}"
            echo -e "     建议排查:"
            echo -e "     1. 无法在 15 秒内连通目标主机 [${BOLD}${REMOTE_HOST}:${SSH_PORT}${NC}]。"
            echo -e "     2. 请检查网络路由、VPN 隧道状态，或目标机防火墙 (ufw / firewalld / iptables) 是否放行端口 ${SSH_PORT}。"
        elif [[ "$combined_info" == *"No route to host"* || "$combined_info" == *"Network is unreachable"* ]]; then
            echo -e "  └─ ${RED}原因: 网络路由不可达 (No route to host / Network unreachable)${NC}"
            echo -e "     建议排查: 本机与目标 IP [${BOLD}${REMOTE_HOST}${NC}] 之间无网络路由，请检查网段配置或网关连接。"
        elif [[ "$combined_info" == *"Could not resolve hostname"* || "$combined_info" == *"Name or service not known"* ]]; then
            echo -e "  └─ ${RED}原因: 无法解析主机名 (Could not resolve hostname)${NC}"
            echo -e "     建议排查: 无法解析主机域名 [${BOLD}${REMOTE_HOST}${NC}]，请检查主机名拼写或本地 DNS / /etc/hosts 配置。"
        elif [[ "$combined_info" == *"Host key verification failed"* ]]; then
            echo -e "  └─ ${RED}原因: 主机指纹冲突校验失败 (Host key verification failed)${NC}"
            echo -e "     建议排查: 目标主机公钥变更。可执行: ssh-keygen -R ${REMOTE_HOST} 清除旧已知指纹。"
        elif [[ "$combined_info" == *"Too many authentication failures"* ]]; then
            echo -e "  └─ ${RED}原因: 认证尝试次数过多 (Too many authentication failures)${NC}"
            echo -e "     建议排查: 远程 SSH 服务限制了失败重试次数，请稍后再试或重启目标主机 SSH 服务。"
        elif [[ "$combined_info" == *"sshpass: command not found"* || "$combined_info" == *"Failed to run command"* ]]; then
            echo -e "  └─ ${RED}原因: 本地缺少 sshpass 工具或命令执行异常${NC}"
        elif [[ -n "$ssh_err" ]]; then
            echo -e "  └─ ${RED}原因: 远程 SSH 连接报错${NC}"
            echo -e "     ${ssh_err}"
        else
            echo -e "  └─ ${RED}原因: 未收到远程主机握手响应 (空回显，退出码: ${exit_code})${NC}"
        fi

        if [[ -n "$ssh_err" ]]; then
            echo -e "\n${YELLOW}【SSH 终端原始错误日志】:${NC}"
            echo "$ssh_err" | sed 's/^/    /'
        fi
        echo ""
        return 1
    fi

    rm -f "$err_log" 2>/dev/null || true
    log_success "SSH 认证成功，与远程主机 [${BOLD}${SSH_USER}@${REMOTE_HOST}:${SSH_PORT}${NC}] 成功建立会话。"
    return 0
}

# 生成远程 Docker 执行提权包装函数 (仅在权限不够且成功验证 sudo 提权时生效)
get_remote_docker_wrapper() {
    if [[ "$REMOTE_USE_SUDO" == true ]]; then
        local sudo_pwd="${SUDO_PASSWORD:-${SSH_PASSWORD:-}}"
        if [[ "$REMOTE_SUDO_TYPE" == "password" && -n "$sudo_pwd" ]]; then
            local esc_pass="${sudo_pwd//\'/\'\\\'\'}"
            printf "docker() { printf '%%s\\n' '%s' | sudo -S -p '' docker \"\$@\"; }; " "$esc_pass"
        else
            printf 'docker() { sudo -n docker "$@"; }; '
        fi
    fi
}

# 验证远程 Docker 守护进程与运行权限 (支持使用登录凭据提权，仅在权限不够时提升权限)
check_remote_docker_service() {
    local docker_err_log="${OUTPUT_DIR}/remote_docker_check.err"
    : > "$docker_err_log"

    # 1. 检查远程主机是否安装 docker
    if ! execute_ssh "command -v docker" false >/dev/null 2>"$docker_err_log"; then
        log_error "远程主机未检测到 docker 命令！"
        echo -e "${YELLOW}提示: 请确认目标主机 [${REMOTE_HOST}] 已正确安装 Docker 引擎。${NC}"
        if [[ -s "$docker_err_log" ]]; then
            echo -e "${YELLOW}错误输出:${NC}"
            cat "$docker_err_log" | sed 's/^/    /'
        fi
        rm -f "$docker_err_log" 2>/dev/null || true
        return 1
    fi

    # 2. 首先测试当前用户是否可直接访问 Docker 守护进程 (不提升权限)
    # 注意: 部分 Docker 客户端版本 (如 Docker 20.10) 将 "Got permission denied" 等核心错误输出在 STDOUT，
    # 而 STDERR 仅输出 "errors pretty printing info"，因此必须将 STDOUT 与 STDERR 一并捕获 (>log 2>&1)
    if execute_ssh "docker info" false >"$docker_err_log" 2>&1; then
        REMOTE_USE_SUDO=false
        REMOTE_SUDO_TYPE=""
        rm -f "$docker_err_log" 2>/dev/null || true
        log_success "远程 Docker 守护进程运行正常 (用户 [${SSH_USER}] 具备直接访问权限)。"
        return 0
    fi

    # 3. 若直接访问失败，捕获错误信息并仅在权限不够时尝试凭据提权 (sudo)
    local d_err=""
    [[ -f "$docker_err_log" ]] && d_err=$(<"$docker_err_log" tr -d '\r')
    rm -f "$docker_err_log" 2>/dev/null || true

    local sudo_err=""
    local sudo_err_log="${OUTPUT_DIR}/remote_sudo_check.err"
    : > "$sudo_err_log"

    # 若为权限问题 (包含 permission denied、Got permission denied、socket 访问受限或 errors pretty printing info)，自动尝试使用登录凭据或免密 sudo 提升权限
    if [[ "$d_err" == *"permission denied"* || "$d_err" == *"Got permission denied"* || "$d_err" == *"errors pretty printing info"* || "$d_err" == *"/var/run/docker.sock"* ]]; then
        log_warn "用户 [${SSH_USER}] 没有直接访问 Docker Socket 的权限，正在尝试提升权限..."

        # 检查远程是否安装了 sudo
        if execute_ssh "command -v sudo" false >/dev/null 2>&1; then
            # 3.1 优先测试免密 sudo
            if execute_ssh "sudo -n docker info" false >"$sudo_err_log" 2>&1; then
                REMOTE_USE_SUDO=true
                REMOTE_SUDO_TYPE="nopasswd"
                rm -f "$sudo_err_log" 2>/dev/null || true
                log_success "检测到远程免密 sudo 可用，已自动提升 Docker 执行权限！"
                return 0
            fi

            # 3.2 准备提权密码 (优先使用 SUDO_PASSWORD，其次使用 SSH_PASSWORD)
            local sudo_pwd="${SUDO_PASSWORD:-${SSH_PASSWORD:-}}"
            if [[ -z "$sudo_pwd" && -t 0 && "$NON_INTERACTIVE" != true ]]; then
                echo -e "  └─ ${YELLOW}检测到当前未提供密码，请输入用户 [${SSH_USER}] 的 sudo 提权密码${NC}"
                read -s -r -p "     sudo 密码: " sudo_pwd || sudo_pwd=""
                echo ""
                [[ -n "$sudo_pwd" ]] && SUDO_PASSWORD="$sudo_pwd"
            fi

            # 3.3 使用密码通过 sudo -S 提权 (注意：使用单个 %s，避免 %%s 被当做字面量)
            if [[ -n "$sudo_pwd" ]]; then
                local esc_pass="${sudo_pwd//\'/\'\\\'\'}"
                local sudo_test_cmd="printf '%s\n' '${esc_pass}' | sudo -S -p '' docker info"
                if execute_ssh "$sudo_test_cmd" false >"$sudo_err_log" 2>&1; then
                    REMOTE_USE_SUDO=true
                    REMOTE_SUDO_TYPE="password"
                    rm -f "$sudo_err_log" 2>/dev/null || true
                    log_success "已使用登录凭据成功通过 sudo 提升远程 Docker 执行权限！"
                    return 0
                fi
            fi
        else
            sudo_err="远程主机未安装 sudo 命令"
        fi
    fi

    [[ -f "$sudo_err_log" ]] && sudo_err=$(<"$sudo_err_log" tr -d '\r')
    rm -f "$sudo_err_log" 2>/dev/null || true

    # 4. 若无法自动提权，输出结构化诊断与建议
    log_error "无法与远程 Docker 守护进程通信！(普通权限不足且 sudo 自动提权失败)"
    echo -e "\n${BOLD}${YELLOW}【Docker 服务异常原因诊断】:${NC}"
    if [[ "$d_err" == *"permission denied"* || "$d_err" == *"Got permission denied"* || "$d_err" == *"errors pretty printing info"* || "$d_err" == *"/var/run/docker.sock"* ]]; then
        echo -e "  └─ ${RED}原因: 用户 [${SSH_USER}] 没有访问 Docker Socket 权限，且尝试 sudo 自动提权失败${NC}"
        if [[ "$sudo_err" == *"not in the sudoers file"* ]]; then
            echo -e "     提权失败分析: 用户 [${SSH_USER}] 不在 sudoers 授权名单中。"
        elif [[ "$sudo_err" == *"incorrect password"* || "$sudo_err" == *"authentication failure"* || "$sudo_err" == *"Password:"* || "$sudo_err" == *"Sorry, try again"* ]]; then
            echo -e "     提权失败分析: sudo 密码认证失败，请确认输入的登录密码是否与远程 sudo 密码一致。"
        elif [[ "$sudo_err" == *"a terminal is required"* ]]; then
            echo -e "     提权失败分析: 远程 sudo 限制必须在终端 (requiretty) 中运行。"
        elif [[ -z "${SUDO_PASSWORD:-${SSH_PASSWORD:-}}" ]]; then
            echo -e "     提权失败分析: 未提供 sudo/SSH 密码，且远程主机未配置免密 sudo。"
        fi
        echo -e "     建议修复方案:"
        echo -e "     1. 在远程主机执行以下命令将该用户加入 docker 用户组并重新登录:"
        echo -e "        ${CYAN}sudo usermod -aG docker ${SSH_USER}${NC}"
        echo -e "     2. 或为用户 [${SSH_USER}] 在 /etc/sudoers 中配置 sudo 权限，或直接使用 ${CYAN}root${NC} 账号进行评估。"
    elif [[ "$d_err" == *"Is the docker daemon running"* || "$d_err" == *"Cannot connect to the Docker daemon"* ]]; then
        echo -e "  └─ ${RED}原因: 远程 Docker 守护进程 (dockerd) 未启动${NC}"
        echo -e "     建议修复: 在远程主机执行以下命令启动 Docker 服务:"
        echo -e "       ${CYAN}sudo systemctl start docker${NC}"
    else
        echo -e "  └─ ${RED}原因: 远程 Docker 运行环境异常${NC}"
    fi

    if [[ -n "$d_err" ]]; then
        echo -e "\n${YELLOW}【Docker 终端原始错误日志】:${NC}"
        echo "$d_err" | sed 's/^/    /'
    fi
    if [[ -n "$sudo_err" ]]; then
        echo -e "\n${YELLOW}【sudo 提权原始报错信息】:${NC}"
        echo "$sudo_err" | sed 's/^/    /'
    fi
    echo ""
    return 1
}

# 获取本地 Docker 配置文件路径 (跨平台支持 Linux/WSL/macOS/Windows Git Bash)
get_local_docker_config_path() {
    if [[ -n "${DOCKER_CONFIG:-}" ]]; then
        echo "${DOCKER_CONFIG}/config.json"
        return
    fi
    # 检查 Windows 用户主目录 (Git Bash / MSYS 环境)
    if [[ -n "${USERPROFILE:-}" ]]; then
        local win_cfg
        if command -v cygpath >/dev/null 2>&1; then
            win_cfg="$(cygpath -u "$USERPROFILE")/.docker/config.json"
        else
            win_cfg="${USERPROFILE//\\//}/.docker/config.json"
        fi
        if [[ -f "$win_cfg" || -d "$(dirname "$win_cfg")" ]]; then
            echo "$win_cfg"
            return
        fi
    fi
    # 默认 Linux / WSL / macOS 路径
    echo "${HOME}/.docker/config.json"
}

# 从 Docker config.json 提取所有认证仓库域名
extract_registries_from_docker_config() {
    local cfg_file="$1"
    [[ ! -f "$cfg_file" ]] && return 0

    # 1. 尝试使用 python3 / python
    if command -v python3 >/dev/null 2>&1 && python3 -c "import sys, json" >/dev/null 2>&1; then
        python3 -c '
import sys, json
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
    for k in d.get("auths", {}).keys():
        if k:
            print(k)
except Exception:
    pass
' "$cfg_file" 2>/dev/null && return 0
    elif command -v python >/dev/null 2>&1 && python -c "import sys, json" >/dev/null 2>&1; then
        python -c '
import sys, json
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
    for k in d.get("auths", {}).keys():
        if k:
            print(k)
except Exception:
    pass
' "$cfg_file" 2>/dev/null && return 0
    fi

    # 2. 尝试使用 PowerShell (Windows)
    if command -v powershell.exe >/dev/null 2>&1; then
        powershell.exe -NoProfile -Command "
            try {
                \$c = Get-Content -LiteralPath '$cfg_file' -Raw -Encoding UTF8 | ConvertFrom-Json
                if (\$c.auths) {
                    \$c.auths.psobject.properties | ForEach-Object { \$_.Name }
                }
            } catch {}
        " 2>/dev/null && return 0
    fi

    # 3. 纯 awk 兜底解析
    awk '
        /"auths"[[:space:]]*:[[:space:]]*\{/ { in_auths=1; next }
        in_auths && /^[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*\{/ {
            line = $0
            sub(/^[[:space:]]*"/, "", line)
            sub(/".*/, "", line)
            if (line != "") print line
        }
        in_auths && /^[[:space:]]*\}/ { in_auths=0 }
    ' "$cfg_file" 2>/dev/null
}

# 安全合并本地与远程 Docker 凭证 (保留本地原有配置，增量注入远程 auths)
merge_docker_configs() {
    local local_file="$1"
    local remote_file="$2"
    local out_file="$3"

    if [[ ! -f "$local_file" ]]; then
        cp -f "$remote_file" "$out_file"
        return $?
    fi

    # 1. 优先使用 Python3 / Python
    if command -v python3 >/dev/null 2>&1 && python3 -c "import sys, json" >/dev/null 2>&1; then
        python3 -c '
import sys, json
loc_f, rem_f, out_f = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(loc_f, "r", encoding="utf-8") as f:
        loc = json.load(f)
except Exception:
    loc = {}
try:
    with open(rem_f, "r", encoding="utf-8") as f:
        rem = json.load(f)
except Exception:
    rem = {}
if "auths" not in loc or not isinstance(loc["auths"], dict):
    loc["auths"] = {}
rem_auths = rem.get("auths", {})
if isinstance(rem_auths, dict):
    for k, v in rem_auths.items():
        loc["auths"][k] = v
with open(out_f, "w", encoding="utf-8") as f:
    json.dump(loc, f, indent=2, ensure_ascii=False)
' "$local_file" "$remote_file" "$out_file" 2>/dev/null && return 0
    elif command -v python >/dev/null 2>&1 && python -c "import sys, json" >/dev/null 2>&1; then
        python -c '
import sys, json
loc_f, rem_f, out_f = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(loc_f, "r", encoding="utf-8") as f:
        loc = json.load(f)
except Exception:
    loc = {}
try:
    with open(rem_f, "r", encoding="utf-8") as f:
        rem = json.load(f)
except Exception:
    rem = {}
if "auths" not in loc or not isinstance(loc["auths"], dict):
    loc["auths"] = {}
rem_auths = rem.get("auths", {})
if isinstance(rem_auths, dict):
    for k, v in rem_auths.items():
        loc["auths"][k] = v
with open(out_f, "w", encoding="utf-8") as f:
    json.dump(loc, f, indent=2, ensure_ascii=False)
' "$local_file" "$remote_file" "$out_file" 2>/dev/null && return 0
    fi

    # 2. 尝试使用 PowerShell (Windows)
    if command -v powershell.exe >/dev/null 2>&1; then
        powershell.exe -NoProfile -Command "
            try {
                \$loc = if (Test-Path -LiteralPath '$local_file') { Get-Content -LiteralPath '$local_file' -Raw -Encoding UTF8 | ConvertFrom-Json } else { [PSCustomObject]@{} }
                \$rem = if (Test-Path -LiteralPath '$remote_file') { Get-Content -LiteralPath '$remote_file' -Raw -Encoding UTF8 | ConvertFrom-Json } else { [PSCustomObject]@{} }
                if (-not \$loc.PSObject.Properties['auths']) {
                    \$loc | Add-Member -MemberType NoteProperty -Name 'auths' -Value ([PSCustomObject]@{}) -Force
                }
                if (\$rem.PSObject.Properties['auths']) {
                    \$rem.auths.PSObject.Properties | ForEach-Object {
                        \$loc.auths | Add-Member -MemberType NoteProperty -Name \$_.Name -Value \$_.Value -Force
                    }
                }
                \$loc | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath '$out_file' -Encoding UTF8
                exit 0
            } catch {
                exit 1
            }
        " 2>/dev/null && return 0
    fi

    # 3. 兜底策略：若无脚本环境，直接将远程凭据作为配置输出
    cp -f "$remote_file" "$out_file" 2>/dev/null
    return 0
}

# 获取远程 Docker 源认证凭据并复制/合并至本地使用
sync_remote_docker_auth() {
    if [[ "$SYNC_REMOTE_DOCKER_AUTH" != true ]]; then
        log_info "跳过远程 Docker 镜像源认证凭证同步 (--no-sync-docker-auth)。"
        return 0
    fi

    log_step "获取远程 Docker 镜像源认证凭证并同步至本地"
    log_info "正在探测远程主机 Docker 认证配置文件 (~/.docker/config.json / /root/.docker/config.json) ..."

    local remote_probe_script='
        cfgs=()
        [ -n "'"$REMOTE_DOCKER_CONFIG"'" ] && cfgs+=("'"$REMOTE_DOCKER_CONFIG"'")
        cfgs+=("$HOME/.docker/config.json" "/root/.docker/config.json" "/etc/docker/daemon.json")

        for p in "${cfgs[@]}"; do
            if [ -f "$p" ] && grep -q "\"auths\"" "$p" 2>/dev/null; then
                echo "FOUND_SOURCE:$p"
                cat "$p"
                exit 0
            fi
        done

        if command -v sudo >/dev/null 2>&1; then
            if sudo -n [ -f /root/.docker/config.json ] 2>/dev/null && sudo -n grep -q "\"auths\"" /root/.docker/config.json 2>/dev/null; then
                echo "FOUND_SOURCE:/root/.docker/config.json"
                sudo -n cat /root/.docker/config.json 2>/dev/null
                exit 0
            fi
        fi

        find_res=$(find "$HOME" /etc/docker -maxdepth 4 -name "config.json" -type f -exec grep -l "\"auths\"" {} + 2>/dev/null | head -n 1)
        if [ -n "$find_res" ] && [ -f "$find_res" ]; then
            echo "FOUND_SOURCE:$find_res"
            cat "$find_res"
            exit 0
        fi

        exit 1
    '

    local remote_raw=""
    remote_raw=$(execute_ssh "$remote_probe_script" false 2>/dev/null | tr -d '\r')

    # 若普通探测未找到且提供了 SSH 密码，尝试使用 sudo 密码探测 /root/.docker/config.json
    if [[ -z "$remote_raw" && -n "$SSH_PASSWORD" ]]; then
        local sudo_cmd="echo '$SSH_PASSWORD' | sudo -S sh -c 'if [ -f /root/.docker/config.json ] && grep -q \"\\\"auths\\\"\" /root/.docker/config.json 2>/dev/null; then echo \"FOUND_SOURCE:/root/.docker/config.json\"; cat /root/.docker/config.json; fi' 2>/dev/null"
        remote_raw=$(execute_ssh "$sudo_cmd" false 2>/dev/null | tr -d '\r')
    fi

    if [[ -z "$remote_raw" || "$remote_raw" != *"FOUND_SOURCE:"* ]]; then
        log_info "远程主机未检测到 Docker 源认证凭据 (未发现包含 auths 的 config.json)。"
        log_info "提示: 若远程评估涉及需要登录的私有镜像仓库，请确保在远程主机执行过 'docker login <私有仓库>'。"
        return 0
    fi

    local source_path
    source_path=$(echo "$remote_raw" | grep -m 1 "^FOUND_SOURCE:" | sed 's/^FOUND_SOURCE://')
    local remote_json
    remote_json=$(echo "$remote_raw" | sed '/^FOUND_SOURCE:/d')

    if [[ -z "$remote_json" || "$remote_json" != *"auths"* ]]; then
        log_warn "从远程获取到的 Docker 配置文件 [${source_path}] 不包含有效的 auths 字段，跳过同步。"
        return 0
    fi

    # 1. 保存远程原始配置副本到任务报告目录
    local remote_save_file="${OUTPUT_DIR}/remote_docker_config.json"
    echo "$remote_json" > "$remote_save_file"
    ACTIVE_DOCKER_CONFIG="$remote_save_file"

    # 2. 提取识别到的所有私有仓库域名
    REMOTE_DOCKER_REGISTRIES=()
    local reg_lines
    reg_lines=$(extract_registries_from_docker_config "$remote_save_file")
    while IFS= read -r reg; do
        [[ -n "$reg" ]] && REMOTE_DOCKER_REGISTRIES+=("$reg")
    done <<< "$reg_lines"

    log_success "成功从远程主机 [${BOLD}${source_path}${NC}] 获取 Docker 源认证凭据！"
    if [[ ${#REMOTE_DOCKER_REGISTRIES[@]} -gt 0 ]]; then
        echo -e "  ${GREEN}├─${NC} 已获取以下 ${BOLD}${#REMOTE_DOCKER_REGISTRIES[@]}${NC} 个私有仓库认证信息:"
        for (( i=0; i<${#REMOTE_DOCKER_REGISTRIES[@]}; i++ )); do
            local prefix="├─"
            [[ $i -eq $((${#REMOTE_DOCKER_REGISTRIES[@]} - 1)) ]] && prefix="└─"
            echo -e "  ${GREEN}${prefix}${NC} ${CYAN}${REMOTE_DOCKER_REGISTRIES[i]}${NC}"
        done
    fi

    # 3. 复制/合并到本地 Docker 客户端配置，供本地 docker pull / docker build 与 Trivy 容器使用
    local local_cfg
    local_cfg=$(get_local_docker_config_path)

    if [[ -f "$local_cfg" ]]; then
        local bak_file="${local_cfg}.bak.$(date +%Y%m%d_%H%M%S)"
        cp -f "$local_cfg" "$bak_file" 2>/dev/null || true
        log_info "本地已存在 Docker 配置，已自动备份至: ${bak_file}"

        local merged_file="${OUTPUT_DIR}/merged_docker_config.json"
        if merge_docker_configs "$local_cfg" "$remote_save_file" "$merged_file"; then
            cp -f "$merged_file" "$local_cfg" 2>/dev/null || true
            ACTIVE_DOCKER_CONFIG="$local_cfg"
            log_success "已将远程 Docker 凭据合并至本地 Docker 配置文件: ${BOLD}${local_cfg}${NC}"
        else
            log_warn "合并本地配置失败，将优先使用远程专属配置进行评估: ${remote_save_file}"
        fi
    else
        mkdir -p "$(dirname "$local_cfg")" 2>/dev/null || true
        if cp -f "$remote_save_file" "$local_cfg" 2>/dev/null; then
            ACTIVE_DOCKER_CONFIG="$local_cfg"
            log_success "已将远程 Docker 凭据复制至本地 Docker 客户端: ${BOLD}${local_cfg}${NC}"
        else
            log_info "使用任务输出目录中的远程凭据配置: ${remote_save_file}"
        fi
    fi
    echo -e "  ${GREEN}└─${NC} 本地 Docker 引擎与 Trivy 扫描容器已自动挂载并注入远程私有源认证凭据。\n"
}

# ==============================================================================
# 本地与通用评估函数组
# ==============================================================================

# 本地环境预检
check_prerequisites() {
    log_step "本地环境依赖预检"

    # 1. 检查 docker CLI
    if ! command -v docker >/dev/null 2>&1; then
        log_error "未找到 docker 命令，请确认本地机器已安装 Docker。"
        exit 1
    fi

    # 2. 检查 docker 服务状态与通信权限
    if ! docker info >/dev/null 2>&1; then
        log_error "无法与本地 Docker 守护进程通信，请检查 dockerd 是否启动或当前用户是否有 docker 权限。"
        exit 1
    fi
    log_info "本地 Docker 守护进程运行正常。"

    # 3. 检查 /var/run/docker.sock
    if [[ ! -S /var/run/docker.sock ]]; then
        log_error "未找到本地 Docker 套接字: /var/run/docker.sock"
        exit 1
    fi

    # 4. 检查指定的 Trivy 镜像是否存在 (支持官方与第三方加速源，如 docker.m.daocloud.io/aquasec/trivy:latest)
    local has_trivy_image=false
    if docker image inspect "$TRIVY_IMAGE" >/dev/null 2>&1; then
        has_trivy_image=true
        log_info "本地已存在 Trivy 镜像: ${TRIVY_IMAGE}"
    elif [[ "$TRIVY_IMAGE" == "$DEFAULT_OFFICIAL_TRIVY_IMAGE" ]] && docker image inspect "$DEFAULT_MIRROR_TRIVY_IMAGE" >/dev/null 2>&1; then
        TRIVY_IMAGE="$DEFAULT_MIRROR_TRIVY_IMAGE"
        has_trivy_image=true
        log_info "检测到本地已存在第三方加速镜像: ${TRIVY_IMAGE}，自动采用。"
    elif [[ "$TRIVY_IMAGE" == "$DEFAULT_MIRROR_TRIVY_IMAGE" ]] && docker image inspect "$DEFAULT_OFFICIAL_TRIVY_IMAGE" >/dev/null 2>&1; then
        TRIVY_IMAGE="$DEFAULT_OFFICIAL_TRIVY_IMAGE"
        has_trivy_image=true
        log_info "检测到本地已存在官方镜像: ${TRIVY_IMAGE}，自动采用。"
    fi

    if [[ "$has_trivy_image" != true ]]; then
        log_warn "本地未找到镜像 [${TRIVY_IMAGE}]，正在拉取..."
        if docker pull "$TRIVY_IMAGE"; then
            log_success "成功拉取 Trivy 镜像: ${TRIVY_IMAGE}"
        else
            log_warn "拉取镜像 [${TRIVY_IMAGE}] 失败。"
            if [[ "$TRIVY_IMAGE" != "$DEFAULT_MIRROR_TRIVY_IMAGE" ]]; then
                log_info "尝试自动切换至第三方加速源 [${DEFAULT_MIRROR_TRIVY_IMAGE}] 继续拉取..."
                if docker pull "$DEFAULT_MIRROR_TRIVY_IMAGE"; then
                    TRIVY_IMAGE="$DEFAULT_MIRROR_TRIVY_IMAGE"
                    log_success "成功从第三方加速源拉取 Trivy 镜像: ${TRIVY_IMAGE}"
                else
                    log_error "拉取 Trivy 镜像失败，请检查网络连接或提前手动拉取: docker pull $TRIVY_IMAGE"
                    exit 1
                fi
            else
                log_error "拉取 Trivy 镜像失败，请检查网络连接或提前手动拉取: docker pull $TRIVY_IMAGE"
                exit 1
            fi
        fi
    fi

    # 5. 转换路径为绝对路径 (Docker -v 挂载必须使用绝对路径)
    mkdir -p "${OUTPUT_BASE_DIR}"
    local abs_output_base
    abs_output_base=$(cd "${OUTPUT_BASE_DIR}" && pwd)

    if [[ -n "$REMOTE_HOST" ]]; then
        OUTPUT_DIR="${abs_output_base}/remote_${REMOTE_HOST}_${TIMESTAMP}"
    else
        OUTPUT_DIR="${abs_output_base}/scan_${TIMESTAMP}"
    fi

    mkdir -p "${OUTPUT_DIR}/raw_json"
    mkdir -p "${OUTPUT_DIR}/raw_txt"

    mkdir -p "${CACHE_DIR}"
    CACHE_DIR=$(cd "${CACHE_DIR}" && pwd)

    # 规范化缓存目录结构：建立软链接确保无论是挂载到 /root/.cache 还是 /root/.cache/trivy 均可准确定位
    if [[ -d "${CACHE_DIR}/db" && ! -e "${CACHE_DIR}/trivy" ]]; then
        (cd "${CACHE_DIR}" && ln -snf . trivy 2>/dev/null || true)
    elif [[ -d "${CACHE_DIR}/trivy/db" && ! -d "${CACHE_DIR}/db" ]]; then
        (cd "${CACHE_DIR}" && ln -snf trivy/db db 2>/dev/null && ln -snf trivy/java-db java-db 2>/dev/null || true)
    fi

    detect_proxy

    log_info "报告生成绝对路径: ${OUTPUT_DIR}"
    log_info "漏洞库缓存路径:   ${CACHE_DIR}"
}

# 获取本地 Trivy 主漏洞数据库版本日期
get_db_date() {
    local c_dir="${CACHE_DIR/#\~/$HOME}"
    local meta_candidates=(
        "${c_dir}/db/metadata.json"
        "${c_dir}/trivy/db/metadata.json"
    )
    local db_candidates=(
        "${c_dir}/db/trivy.db"
        "${c_dir}/trivy/db/trivy.db"
    )

    for meta_file in "${meta_candidates[@]}"; do
        if [[ -f "$meta_file" && -s "$meta_file" ]]; then
            local dt=""
            if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
                dt=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
    print(d.get("UpdatedAt") or d.get("DownloadedAt") or "")
except Exception:
    pass
' "$meta_file" 2>/dev/null || true)
            elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
                dt=$(python -c '
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
    print(d.get("UpdatedAt") or d.get("DownloadedAt") or "")
except Exception:
    pass
' "$meta_file" 2>/dev/null || true)
            fi
            if [[ -z "$dt" ]]; then
                dt=$(grep -oE '"(UpdatedAt|DownloadedAt)"[[:space:]]*:[[:space:]]*"[^"]+"' "$meta_file" 2>/dev/null | head -n 1 | cut -d'"' -f4 || true)
            fi
            if [[ -n "$dt" ]]; then
                dt=$(echo "$dt" | sed -E 's/T/ /; s/\.[0-9]+Z$/ UTC/; s/Z$/ UTC/')
                echo "$dt"
                return
            fi
        fi
    done

    for db_file in "${db_candidates[@]}"; do
        if [[ -f "$db_file" ]]; then
            local file_time=""
            if date -r "$db_file" +"%Y-%m-%d %H:%M:%S" >/dev/null 2>&1; then
                file_time=$(date -r "$db_file" +"%Y-%m-%d %H:%M:%S")
            elif stat -c "%y" "$db_file" >/dev/null 2>&1; then
                file_time=$(stat -c "%y" "$db_file" | cut -d'.' -f1)
            fi
            if [[ -n "$file_time" ]]; then
                echo "$file_time"
                return
            fi
        fi
    done

    echo "本地未安装 (首次使用)"
}

# 获取本地 Trivy Java (jar) 依赖数据库版本日期
get_java_db_date() {
    local c_dir="${CACHE_DIR/#\~/$HOME}"
    local meta_candidates=(
        "${c_dir}/java-db/metadata.json"
        "${c_dir}/trivy/java-db/metadata.json"
    )
    local db_candidates=(
        "${c_dir}/java-db/trivy-java.db"
        "${c_dir}/trivy/java-db/trivy-java.db"
    )

    for meta_file in "${meta_candidates[@]}"; do
        if [[ -f "$meta_file" && -s "$meta_file" ]]; then
            local dt=""
            if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
                dt=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
    print(d.get("UpdatedAt") or d.get("DownloadedAt") or "")
except Exception:
    pass
' "$meta_file" 2>/dev/null || true)
            elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
                dt=$(python -c '
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
    print(d.get("UpdatedAt") or d.get("DownloadedAt") or "")
except Exception:
    pass
' "$meta_file" 2>/dev/null || true)
            fi
            if [[ -z "$dt" ]]; then
                dt=$(grep -oE '"(UpdatedAt|DownloadedAt)"[[:space:]]*:[[:space:]]*"[^"]+"' "$meta_file" 2>/dev/null | head -n 1 | cut -d'"' -f4 || true)
            fi
            if [[ -n "$dt" ]]; then
                dt=$(echo "$dt" | sed -E 's/T/ /; s/\.[0-9]+Z$/ UTC/; s/Z$/ UTC/')
                echo "$dt"
                return
            fi
        fi
    done

    for db_file in "${db_candidates[@]}"; do
        if [[ -f "$db_file" ]]; then
            local file_time=""
            if date -r "$db_file" +"%Y-%m-%d %H:%M:%S" >/dev/null 2>&1; then
                file_time=$(date -r "$db_file" +"%Y-%m-%d %H:%M:%S")
            elif stat -c "%y" "$db_file" >/dev/null 2>&1; then
                file_time=$(stat -c "%y" "$db_file" | cut -d'.' -f1)
            fi
            if [[ -n "$file_time" ]]; then
                echo "$file_time"
                return
            fi
        fi
    done

    echo "本地未安装 (首次使用)"
}

# 交互式启动配置向导
prompt_interactive_wizard() {
    echo -e "${BOLD}${CYAN}──────────────────────────────────────────────────────────${NC}"
    echo -e "${BOLD}${CYAN}           📋 任务配置向导 (直接按回车使用默认值)          ${NC}"
    echo -e "${BOLD}${CYAN}──────────────────────────────────────────────────────────${NC}"

    # 引擎镜像来源选择 (支持 Docker Hub 官方或第三方加速源)
    echo -e "${BOLD}[引擎] Trivy 镜像来源配置 (支持官方源或第三方加速源)${NC}"
    echo -e "      1) 国内加速源: docker.m.daocloud.io/aquasec/trivy:latest (推荐国内网络，速度极快)"
    echo -e "      2) Docker Hub 官方源: aquasec/trivy:latest"
    echo -e "      3) 自定义第三方镜像源"
    local def_tsrc="1"
    [[ "$TRIVY_IMAGE" == "$DEFAULT_OFFICIAL_TRIVY_IMAGE" ]] && def_tsrc="2"
    [[ "$TRIVY_IMAGE" != "$DEFAULT_MIRROR_TRIVY_IMAGE" && "$TRIVY_IMAGE" != "$DEFAULT_OFFICIAL_TRIVY_IMAGE" ]] && def_tsrc="3"

    read -r -p "      请选择 [1: 国内加速 / 2: 官方 / 3: 自定义] (默认: ${def_tsrc}): " ans_tsrc || ans_tsrc=""
    ans_tsrc="${ans_tsrc:-$def_tsrc}"
    if [[ "$ans_tsrc" == "2" || "$ans_tsrc" == "official" ]]; then
        TRIVY_IMAGE="$DEFAULT_OFFICIAL_TRIVY_IMAGE"
        echo -e "      ${BLUE}✔ 已选择: 官方源 [${TRIVY_IMAGE}]${NC}"
    elif [[ "$ans_tsrc" == "3" || "$ans_tsrc" == "custom" ]]; then
        local prompt_custom="      -> 请输入第三方 Trivy 镜像地址"
        [[ -n "$TRIVY_IMAGE" ]] && prompt_custom="${prompt_custom} [当前: ${TRIVY_IMAGE}]"
        read -r -p "${prompt_custom}: " custom_img || custom_img=""
        custom_img=$(echo "$custom_img" | xargs)
        [[ -n "$custom_img" ]] && TRIVY_IMAGE="$custom_img"
        echo -e "      ${PURPLE}✔ 已配置第三方镜像: [${TRIVY_IMAGE}]${NC}"
    else
        TRIVY_IMAGE="$DEFAULT_MIRROR_TRIVY_IMAGE"
        echo -e "      ${GREEN}✔ 已选择: 国内第三方加速源 [${TRIVY_IMAGE}]${NC}"
    fi

    # 1. 更新主漏洞数据库
    local cur_db_date
    cur_db_date=$(get_db_date)
    echo -e "${BOLD}[1/5] 更新主漏洞数据库 (Trivy CVE 漏洞库)${NC}"
    echo -e "      当前版本日期: ${YELLOW}${cur_db_date}${NC}"
    read -r -p "      是否连网更新主漏洞数据库？[y/N] (默认: N): " ans_db || ans_db=""
    ans_db=$(echo "${ans_db:-N}" | tr '[:lower:]' '[:upper:]')
    if [[ "$ans_db" == "Y" || "$ans_db" == "YES" ]]; then
        SKIP_DB_UPDATE=false
        echo -e "      ${GREEN}✔ 已选择: 更新主漏洞数据库${NC}"
    else
        SKIP_DB_UPDATE=true
        echo -e "      ${BLUE}✔ 已选择: 跳过数据库更新 (使用本地缓存)${NC}"
    fi

    # 2. 更新 Java jar DB
    local cur_java_date
    cur_java_date=$(get_java_db_date)
    echo -e "\n${BOLD}[2/5] 更新 Java jar 依赖数据库 (trivy-java-db)${NC}"
    echo -e "      当前版本日期: ${YELLOW}${cur_java_date}${NC}"
    read -r -p "      是否连网更新 Java jar DB？[y/N] (默认: N): " ans_java || ans_java=""
    ans_java=$(echo "${ans_java:-N}" | tr '[:lower:]' '[:upper:]')
    if [[ "$ans_java" == "Y" || "$ans_java" == "YES" ]]; then
        UPDATE_JAVA_DB=true
        echo -e "      ${GREEN}✔ 已选择: 更新 Java jar DB${NC}"
    else
        UPDATE_JAVA_DB=false
        echo -e "      ${BLUE}✔ 已选择: 跳过 Java jar DB 更新${NC}"
    fi

    # 3. 本地 / 远程
    echo -e "\n${BOLD}[3/5] 评估目标环境 (本地宿主机 / 远程主机)${NC}"
    echo -e "      1) 本地宿主机评估"
    echo -e "      2) 远程主机评估 (SSH 架构: 本地引擎 + 远程流式拉取)"
    local def_mode="1"
    [[ -n "$REMOTE_HOST" ]] && def_mode="2"
    read -r -p "      请选择 [1: 本地 / 2: 远程] (默认: ${def_mode}): " ans_mode || ans_mode=""
    ans_mode="${ans_mode:-$def_mode}"

    if [[ "$ans_mode" == "2" || "$ans_mode" == "remote" ]]; then
        echo -e "      ${PURPLE}✔ 已选择: 远程主机评估模式${NC}"
        while true; do
            local prompt_h="      -> 请输入远程主机 IP 或域名"
            [[ -n "$REMOTE_HOST" ]] && prompt_h="${prompt_h} [当前: ${REMOTE_HOST}]"
            read -r -p "${prompt_h}: " input_h || input_h=""
            input_h=$(echo "$input_h" | xargs)
            if [[ -n "$input_h" ]]; then
                REMOTE_HOST="$input_h"
                break
            elif [[ -n "$REMOTE_HOST" ]]; then
                break
            else
                echo -e "         ${RED}远程主机地址不能为空，请重新输入！${NC}"
            fi
        done

        read -r -p "      -> 请输入远程 SSH 端口 [默认: ${SSH_PORT:-22}]: " input_p || input_p=""
        input_p=$(echo "$input_p" | xargs)
        [[ -n "$input_p" ]] && SSH_PORT="$input_p"

        read -r -p "      -> 请输入远程 SSH 用户名 [默认: ${SSH_USER:-root}]: " input_u || input_u=""
        input_u=$(echo "$input_u" | xargs)
        [[ -n "$input_u" ]] && SSH_USER="$input_u"

        if [[ -z "$SSH_PASSWORD" && -z "$SSH_KEY" ]]; then
            read -s -r -p "      -> 请输入远程 SSH 登录密码 (隐蔽输入): " input_pass || input_pass=""
            echo ""
            SSH_PASSWORD="$input_pass"
        else
            echo -e "      -> SSH 凭证已配置 (跳过输入密码)"
        fi

        # 远程评估镜像获取方式选择
        echo -e "\n      ${BOLD}[镜像获取] 选择远程镜像拉取到本地的方式:${NC}"
        echo -e "        1) 远程计算机复制镜像 (直接从远程计算机复制到本地，不消耗 Docker 源网络下载 - 默认)"
        echo -e "        2) Docker 源下载镜像 (本地通过网络从 Docker 镜像源直接 pull 下载)"
        local def_trans="1"
        [[ "$IMAGE_TRANSFER_MODE" == "pull" ]] && def_trans="2"
        read -r -p "        请选择 [1: 远程计算机复制 / 2: Docker 源下载] (默认: ${def_trans}): " ans_trans || ans_trans=""
        ans_trans="${ans_trans:-$def_trans}"
        if [[ "$ans_trans" == "2" || "$ans_trans" == "pull" || "$ans_trans" == "registry" ]]; then
            IMAGE_TRANSFER_MODE="pull"
            echo -e "        ${BLUE}✔ 已选择: Docker 源下载镜像 (docker pull)${NC}"
        else
            IMAGE_TRANSFER_MODE="copy"
            echo -e "        ${GREEN}✔ 已选择: 远程计算机复制镜像 (直接从远程计算机复制到本地，不经 Docker 源)${NC}"
        fi
    else
        REMOTE_HOST=""
        echo -e "      ${GREEN}✔ 已选择: 本地宿主机评估模式${NC}"
    fi

    # 4. 仅运行镜像 / 全部镜像
    echo -e "\n${BOLD}[4/5] 镜像扫描范围${NC}"
    echo -e "      1) 仅正在运行的容器镜像 (默认: 聚焦活跃业务容器，速度极快)"
    echo -e "      2) 宿主机全部本地镜像 (全量排查)"
    local def_scope="1"
    [[ "$SCAN_SCOPE" == "all" ]] && def_scope="2"
    read -r -p "      请选择 [1: 仅运行 / 2: 全部] (默认: ${def_scope}): " ans_scope || ans_scope=""
    ans_scope="${ans_scope:-$def_scope}"

    if [[ "$ans_scope" == "2" || "$ans_scope" == "all" ]]; then
        SCAN_SCOPE="all"
        echo -e "      ${BLUE}✔ 已选择: 扫描全部镜像${NC}"
    else
        SCAN_SCOPE="running"
        echo -e "      ${GREEN}✔ 已选择: 仅扫描运行中容器镜像${NC}"
    fi

    # 5. 如是远程，运行后是否清理镜像
    if [[ -n "$REMOTE_HOST" ]]; then
        echo -e "\n${BOLD}[5/5] 远程评估临时镜像清理配置${NC}"
        local def_clean="Y"
        [[ "$CLEANUP_REMOTE" == false ]] && def_clean="N"
        read -r -p "      扫描完成后是否自动清理本地临时拉取的镜像？[Y/n] (默认: ${def_clean}): " ans_clean || ans_clean=""
        ans_clean=$(echo "${ans_clean:-$def_clean}" | tr '[:lower:]' '[:upper:]')
        if [[ "$ans_clean" == "N" || "$ans_clean" == "NO" ]]; then
            CLEANUP_REMOTE=false
            echo -e "      ${YELLOW}✔ 已选择: 保留本地临时镜像 (不自动清理)${NC}"
        else
            CLEANUP_REMOTE=true
            echo -e "      ${GREEN}✔ 已选择: 自动清理本地临时镜像 (保障磁盘空间)${NC}"
        fi
    fi

    echo -e "${BOLD}${CYAN}──────────────────────────────────────────────────────────${NC}\n"
}

# 独立检测并初始化 Trivy 漏洞数据库
init_trivy_db() {
    log_step "检查与准备本地 Trivy 主漏洞数据库"

    local db_file="${CACHE_DIR}/db/trivy.db"
    [[ ! -f "$db_file" ]] && db_file="${CACHE_DIR}/trivy/db/trivy.db"
    local has_local_db=false
    if [[ -f "$db_file" && -s "$db_file" ]]; then
        has_local_db=true
    fi

    # 如果显式指定了 --skip-db-update
    if [[ "$SKIP_DB_UPDATE" == true ]]; then
        if [[ "$has_local_db" == true ]]; then
            log_info "已配置跳过主漏洞库更新，使用本地缓存数据库。"
            return 0
        else
            log_warn "您选择了跳过主漏洞库更新，但本地缓存目录中未找到漏洞数据库: ${db_file}"
            if [[ "$NON_INTERACTIVE" != true && -t 0 ]]; then
                read -r -p "本地无数据库，是否立即连网下载全量漏洞库？[Y/n]: " need_dl || need_dl="Y"
                need_dl=$(echo "${need_dl:-Y}" | tr '[:lower:]' '[:upper:]')
                if [[ "$need_dl" != "Y" && "$need_dl" != "YES" ]]; then
                    log_error "无可用漏洞数据库，无法继续执行安全性评估。"
                    exit 1
                fi
            else
                log_error "本地无漏洞数据库且开启了非交互跳过更新模式，无法继续评估。"
                exit 1
            fi
        fi
    fi

    # 如果本地已经有数据库，尝试连网更新，但设置短超时
    if [[ "$has_local_db" == true ]]; then
        log_info "检测到本地已有历史漏洞数据库，正在连接 [${DB_REPOSITORY}] 检查更新..."
    else
        log_info "本地未发现漏洞数据库。首次运行需下载全量数据库 (约 60~80MB)，正在连接 [${DB_REPOSITORY}] ..."
        log_info "若在国内网络直连 ghcr.io 较慢，请耐心等待或配置代理..."
    fi

    local update_cmd=(
        docker run --rm
        "${PROXY_FLAGS[@]}"
        -v "${CACHE_DIR}:/root/.cache/trivy"
        "$TRIVY_IMAGE"
        "--cache-dir" "/root/.cache/trivy"
        image
        "--db-repository" "$DB_REPOSITORY"
        "--download-db-only"
        "--timeout" "3m"
    )

    if "${update_cmd[@]}"; then
        log_success "Trivy 主漏洞数据库准备就绪！"
    else
        local err_code=$?
        if [[ "$has_local_db" == true ]]; then
            echo ""
            log_warn "连接官方源 [${DB_REPOSITORY}] 更新失败 (可能受网络或墙影响)。"
            log_warn "检测到本地已有历史缓存数据库，自动降级为【离线模式】继续执行扫描！"
            SKIP_DB_UPDATE=true
        else
            echo ""
            log_error "下载漏洞数据库失败！(错误码: ${err_code})"
            echo -e "\n${YELLOW}【常见原因与解决方案】:${NC}"
            echo -e "  1. ${BOLD}国内网络直连 ghcr.io (GitHub) 超时/被拦截${NC}"
            echo -e "     - ${CYAN}方案 A (终端配置代理):${NC}"
            echo -e "       export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890"
            echo -e "       ./docker-trivy-audit.sh"
            echo -e "     - ${CYAN}方案 B (使用国内加速仓库):${NC}"
            echo -e "       ./docker-trivy-audit.sh --db-repository ghcr.nju.edu.cn/aquasecurity/trivy-db:2"
            echo -e "     - ${CYAN}方案 C (离线导入):${NC}"
            echo -e "       在能联网的机器下载好缓存后解压到 ${CACHE_DIR}，随后加 --skip-db-update 运行。\n"
            exit $err_code
        fi
    fi
}

# 独立检测并初始化/更新 Trivy Java 依赖数据库 (jar DB)
init_java_db() {
    log_step "检查与准备本地 Trivy Java (jar) 依赖数据库"

    local java_db_file="${CACHE_DIR}/java-db/trivy-java.db"
    [[ ! -f "$java_db_file" ]] && java_db_file="${CACHE_DIR}/trivy/java-db/trivy-java.db"
    local has_java_db=false
    if [[ -f "$java_db_file" && -s "$java_db_file" ]]; then
        has_java_db=true
    fi

    if [[ "$UPDATE_JAVA_DB" != true ]]; then
        if [[ "$has_java_db" == true ]]; then
            log_info "跳过 Java DB 网络更新，使用本地缓存数据库。"
        else
            log_info "未启用 Java DB 更新，跳过 Java 依赖库下载。"
        fi
        return 0
    fi

    log_info "正在连接 [${JAVA_DB_REPOSITORY}] 下载/更新 Java 依赖数据库 (约数十MB)..."
    log_info "若在国内直连 ghcr.io 较慢，请耐心等待或配置代理..."

    local update_java_cmd=(
        docker run --rm
        "${PROXY_FLAGS[@]}"
        -v "${CACHE_DIR}:/root/.cache/trivy"
        "$TRIVY_IMAGE"
        "--cache-dir" "/root/.cache/trivy"
        image
        "--java-db-repository" "$JAVA_DB_REPOSITORY"
        "--download-java-db-only"
        "--timeout" "5m"
    )

    if "${update_java_cmd[@]}"; then
        log_success "Trivy Java (jar) 依赖数据库更新成功！"
    else
        local err_code=$?
        if [[ "$has_java_db" == true ]]; then
            echo ""
            log_warn "连接官方源 [${JAVA_DB_REPOSITORY}] 更新 Java 数据库失败。"
            log_warn "检测到本地已有历史缓存数据库，继续使用本地历史版本。"
        else
            echo ""
            log_warn "下载 Java 数据库失败 (错误码: ${err_code})，将跳过 jar 深度索引比对。"
        fi
    fi
}

# 本地发现待扫描镜像并关联容器信息 (自动处理 <none> 悬空和未打标签镜像)
get_target_images() {
    log_step "发现待扫描的目标 Docker 镜像"
    TARGET_IMAGES=()

    if [[ "$SCAN_SCOPE" == "running" ]]; then
        log_info "扫描策略: 仅扫描运行中容器所引用的镜像"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if [[ "$line" == *":<none>"* || "$line" == "<none>"* ]]; then
                local cid
                cid=$(docker ps --filter "ancestor=$line" --format '{{.ID}}' 2>/dev/null | head -n 1)
                if [[ -n "$cid" ]]; then
                    local real_id
                    real_id=$(docker inspect --format '{{.Image}}' "$cid" 2>/dev/null | sed 's/^sha256://' | cut -c1-12)
                    [[ -n "$real_id" ]] && line="$real_id"
                fi
            fi
            TARGET_IMAGES+=("$line")
        done < <(docker ps --format '{{.Image}}' | sort -u)
    else
        log_info "扫描策略: 扫描宿主机上的全部本地镜像"
        while IFS=$'\t' read -r repo tag id; do
            [[ -z "$id" ]] && continue
            if [[ "$repo" == "<none>" || "$tag" == "<none>" ]]; then
                TARGET_IMAGES+=("$id")
            else
                TARGET_IMAGES+=("${repo}:${tag}")
            fi
        done < <(docker images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}' | sort -u)
    fi

    local unique_images=()
    while IFS= read -r item; do
        [[ -n "$item" ]] && unique_images+=("$item")
    done < <(printf '%s\n' "${TARGET_IMAGES[@]}" | sort -u)
    TARGET_IMAGES=("${unique_images[@]}")

    local total_count=${#TARGET_IMAGES[@]}
    if [[ $total_count -eq 0 ]]; then
        log_warn "未发现任何 Docker 镜像，扫描提前结束。"
        exit 0
    fi

    log_success "共获取到 ${BOLD}${total_count}${NC} 个评估目标镜像。"
}

# 辅助函数: 获取可读展示名
get_display_name() {
    local target="$1"
    if [[ -f "${OUTPUT_DIR}/display_map.tsv" ]]; then
        local mapped
        mapped=$(grep -F -m 1 "$target	" "${OUTPUT_DIR}/display_map.tsv" 2>/dev/null | cut -f2 || true)
        if [[ -n "$mapped" ]]; then
            echo "$mapped"
            return
        fi
    fi

    if [[ "$target" =~ ^[a-f0-9]{12}$ ]]; then
        local repo
        repo=$(docker images --format '{{if and (eq .ID "'"$target"'") (ne .Repository "<none>")}}{{.Repository}}{{end}}' 2>/dev/null | head -n 1)
        if [[ -n "$repo" ]]; then
            echo "${repo}:${target}"
            return
        fi
    fi
    echo "$target"
}

# 安全清理文件名
sanitize_filename() {
    local raw="$1"
    echo "$raw" | sed -e 's/[^a-zA-Z0-9._-]/_/g'
}

# 查询镜像关联的运行中容器名
get_associated_containers() {
    local img="$1"
    if [[ -f "${OUTPUT_DIR}/container_map.tsv" ]]; then
        local found
        found=$(grep -F -m 1 "$img	" "${OUTPUT_DIR}/container_map.tsv" 2>/dev/null | cut -f2 || true)
        if [[ -n "$found" ]]; then
            echo "$found"
            return
        fi
    fi

    local containers
    containers=$(docker ps --filter "ancestor=$img" --format '{{.Names}}' 2>/dev/null | paste -sd ", " -)
    if [[ -z "$containers" ]]; then
        echo "-"
    else
        echo "$containers"
    fi
}

# 辅助函数: 格式化容器名称展示
format_container_names() {
    local count=$#
    if [[ $count -eq 0 ]]; then
        echo "-"
        return
    fi
    if [[ $count -le 5 ]]; then
        local res="$1"
        shift
        while [[ $# -gt 0 ]]; do
            res="${res}, $1"
            shift
        done
        echo "$res"
    else
        echo "$1, $2, $3, $4, $5 等共 ${count} 个容器"
    fi
}

# 解析 JSON 提取漏洞与密钥数量
extract_counts() {
    local json_path="$1"

    if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
        python3 -c '
import json, sys

crit, high, med, low, sec = 0, 0, 0, 0, 0
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    results = data.get("Results", [])
    for res in results:
        for v in res.get("Vulnerabilities") or []:
            s = v.get("Severity", "").upper()
            if s == "CRITICAL": crit += 1
            elif s == "HIGH": high += 1
            elif s == "MEDIUM": med += 1
            elif s == "LOW": low += 1
        sec += len(res.get("Secrets") or [])
except Exception:
    pass
print(f"{crit} {high} {med} {low} {sec}")
' "$json_path"
    elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
        python -c '
import json, sys

crit, high, med, low, sec = 0, 0, 0, 0, 0
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    results = data.get("Results", [])
    for res in results:
        for v in res.get("Vulnerabilities") or []:
            s = v.get("Severity", "").upper()
            if s == "CRITICAL": crit += 1
            elif s == "HIGH": high += 1
            elif s == "MEDIUM": med += 1
            elif s == "LOW": low += 1
        sec += len(res.get("Secrets") or [])
except Exception:
    pass
print(f"{crit} {high} {med} {low} {sec}")
' "$json_path"
    elif command -v jq >/dev/null 2>&1; then
        local crit high med low sec
        crit=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$json_path" 2>/dev/null || echo 0)
        high=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$json_path" 2>/dev/null || echo 0)
        med=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$json_path" 2>/dev/null || echo 0)
        low=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$json_path" 2>/dev/null || echo 0)
        sec=$(jq '[.Results[]?.Secrets[]?] | length' "$json_path" 2>/dev/null || echo 0)
        echo "${crit:-0} ${high:-0} ${med:-0} ${low:-0} ${sec:-0}"
    else
        local crit high med low sec
        crit=$(grep -o -E '"Severity"[[:space:]]*:[[:space:]]*"CRITICAL"' "$json_path" | wc -l)
        high=$(grep -o -E '"Severity"[[:space:]]*:[[:space:]]*"HIGH"' "$json_path" | wc -l)
        med=$(grep -o -E '"Severity"[[:space:]]*:[[:space:]]*"MEDIUM"' "$json_path" | wc -l)
        low=$(grep -o -E '"Severity"[[:space:]]*:[[:space:]]*"LOW"' "$json_path" | wc -l)
        sec=$(grep -o -E '"Class"[[:space:]]*:[[:space:]]*"secret"|"RuleID"' "$json_path" | wc -l)
        echo "$crit $high $med $low $sec"
    fi
}

# 执行单一镜像的本地 Trivy 容器扫描 (关键优化: 本地引擎、离线数据库比对、禁止向公网发起请求)
scan_image() {
    local target="$1"
    local index="$2"
    local total="$3"

    local scan_ref="$target"
    local display_name
    display_name=$(get_display_name "$target")

    # 兼容防御：如果传入的目标字符串意外包含 :<none>
    if [[ "$target" == *":<none>"* || "$target" == "<none>"* ]]; then
        local repo_name="${target%%:<none>*}"
        local found_id=""
        if [[ "$repo_name" != "<none>" && -n "$repo_name" ]]; then
            found_id=$(docker images --filter "reference=$repo_name" --format '{{if eq .Tag "<none>"}}{{.ID}}{{end}}' 2>/dev/null | head -n 1)
        fi
        if [[ -z "$found_id" ]]; then
            found_id=$(docker images -q --filter "reference=$target" 2>/dev/null | head -n 1)
        fi
        if [[ -n "$found_id" ]]; then
            scan_ref="$found_id"
            display_name="${repo_name}:${found_id}"
        fi
    fi

    local safe_name
    safe_name=$(sanitize_filename "$target")

    local json_file="${OUTPUT_DIR}/raw_json/${safe_name}.json"
    local txt_file="${OUTPUT_DIR}/raw_txt/${safe_name}.txt"
    local scan_log="${OUTPUT_DIR}/raw_txt/${safe_name}_scan.log"

    local running_containers
    running_containers=$(get_associated_containers "$target")
    if [[ "$running_containers" == "-" && "$target" != "$scan_ref" ]]; then
        running_containers=$(get_associated_containers "$scan_ref")
    fi

    if [[ -z "$REMOTE_HOST" ]]; then
        echo -e "\n${BOLD}[$index/$total]${NC} 正在评估: ${PURPLE}${display_name}${NC}"
        if [[ "$running_containers" != "-" ]]; then
            echo -e "  ├─ 关联活跃容器: ${CYAN}${running_containers}${NC}"
        fi
    fi

    # 核心防卡死参数:
    # 1. --image-src docker: 强制仅读取本地 Docker 引擎已导入的镜像，绝不向私有仓库发网路请求
    # 2. --skip-db-update: 使用本地准备好的主漏洞库
    # 3. --skip-java-db-update: 禁止尝试下载 700MB Java 数据库，避免被阻断的 Google 源超时 7 分钟
    # 4. --offline-scan: 禁止向 Maven/PyPI 等外部仓库请求元数据
    local trivy_flags=(
        image
        "--image-src" "docker"
        "--scanners" "$SCANNERS"
        "--severity" "$SEVERITY"
        "--timeout" "$TIMEOUT"
        "--skip-db-update"
        "--skip-java-db-update"
        "--offline-scan"
    )

    # 构造 Docker 镜像源认证挂载选项 (若存在已同步凭证或本地凭证)
    local auth_mount=()
    local docker_cfg_for_mount=""
    if [[ -n "$ACTIVE_DOCKER_CONFIG" && -f "$ACTIVE_DOCKER_CONFIG" ]]; then
        docker_cfg_for_mount="$ACTIVE_DOCKER_CONFIG"
    elif [[ -f "${OUTPUT_DIR}/remote_docker_config.json" ]]; then
        docker_cfg_for_mount="${OUTPUT_DIR}/remote_docker_config.json"
    else
        local local_cfg
        local_cfg=$(get_local_docker_config_path)
        if [[ -f "$local_cfg" ]]; then
            docker_cfg_for_mount="$local_cfg"
        fi
    fi

    if [[ -n "$docker_cfg_for_mount" && -f "$docker_cfg_for_mount" ]]; then
        auth_mount=(-v "${docker_cfg_for_mount}:/root/.docker/config.json:ro")
    fi

    # 1. 运行 Trivy Docker 容器，输出 JSON 结构化数据
    local docker_run_cmd=(
        docker run --rm
        "${PROXY_FLAGS[@]}"
        "${auth_mount[@]}"
        -v /var/run/docker.sock:/var/run/docker.sock
        -v "${CACHE_DIR}:/root/.cache/trivy"
        -v "${OUTPUT_DIR}:/reports"
        "$TRIVY_IMAGE"
        "--cache-dir" "/root/.cache/trivy"
        "${trivy_flags[@]}"
        "--format" "json"
        "--output" "/reports/raw_json/${safe_name}.json"
        "$scan_ref"
    )

    local exit_code=0
    local elapsed=0

    if [[ "$DEBUG" == true ]]; then
        echo ""
        "${docker_run_cmd[@]}"
        exit_code=$?
    else
        "${docker_run_cmd[@]}" > "$scan_log" 2>&1 &
        local pid=$!
        local spin=('|' '/' '-' '\')
        local i=0

        while kill -0 "$pid" 2>/dev/null; do
            local phase="分层解包中"
            if [[ -f "$scan_log" ]]; then
                local last_line
                last_line=$(grep -E '\[vuln\]|\[secret\]|extracting' "$scan_log" 2>/dev/null | tail -n 1 || true)
                if [[ "$last_line" =~ secret ]]; then
                    phase="深度扫描敏感凭据"
                elif [[ "$last_line" =~ vuln|Detecting|Number ]]; then
                    phase="CVE特征匹配比对"
                fi
            fi
            printf "\r  ├─ 正在解包镜像分层与比对 (%s) [%ds] %s " "$phase" "$elapsed" "${spin[i%4]}"
            sleep 1
            ((i++))
            ((elapsed++))
        done
        wait "$pid" || true
        exit_code=$?
    fi

    if [[ $exit_code -ne 0 || ! -s "$json_file" ]]; then
        # 防御机制: 若因上一容器退出时释放缓存锁瞬时延迟导致 lock timeout，自动静默重试一次
        if [[ -f "$scan_log" ]] && grep -q "Failed to acquire cache or database lock" "$scan_log" 2>/dev/null; then
            printf "\r  ├─ 正在解包镜像分层与比对 (检测到缓存锁争用，2秒后自动重试)...                     \n"
            sleep 2
            "${docker_run_cmd[@]}" > "$scan_log" 2>&1
            exit_code=$?
            if [[ $exit_code -eq 0 && -s "$json_file" ]]; then
                printf "  ├─ 正在解包镜像分层与比对... ${GREEN}[完成]${NC} (重试成功)                   \n"
            fi
        fi
    fi

    if [[ $exit_code -ne 0 || ! -s "$json_file" ]]; then
        printf "\r  ├─ 正在解包镜像分层与比对... ${RED}[失败]${NC} (耗时: %ds)                   \n" "$elapsed"
        log_error "扫描异常: ${display_name}"
        if [[ -f "$scan_log" ]]; then
            echo -e "${YELLOW}错误日志尾部信息:${NC}"
            tail -n 6 "$scan_log" | sed 's/^/    /'
        fi
        return 1
    fi

    printf "\r  ├─ 正在解包镜像分层与比对... ${GREEN}[完成]${NC} (耗时: %ds)                   \n" "$elapsed"
    rm -f "$scan_log" 2>/dev/null || true

    # 2. 生成一份纯文本易读表格报告
    docker run --rm \
        "${PROXY_FLAGS[@]}" \
        "${auth_mount[@]}" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "${CACHE_DIR}:/root/.cache/trivy" \
        -v "${OUTPUT_DIR}:/reports" \
        "$TRIVY_IMAGE" \
        "--cache-dir" "/root/.cache/trivy" \
        "${trivy_flags[@]}" \
        "--format" "table" \
        "--output" "/reports/raw_txt/${safe_name}.txt" \
        "$scan_ref" >/dev/null 2>&1 || true

    # 提取风险统计
    local counts
    counts=$(extract_counts "$json_file")
    local crit high med low sec
    crit=$(echo "$counts" | awk '{print $1}')
    high=$(echo "$counts" | awk '{print $2}')
    med=$(echo "$counts" | awk '{print $3}')
    low=$(echo "$counts" | awk '{print $4}')
    sec=$(echo "$counts" | awk '{print $5}')

    echo -e "  └─ 风险统计: ${RED}CRITICAL: ${crit}${NC} | ${YELLOW}HIGH: ${high}${NC} | ${BLUE}MEDIUM: ${med}${NC} | LOW: ${low} | ${PURPLE}SECRETS: ${sec}${NC}"
    return 0
}

# 批量执行本地扫描任务
run_batch_scan() {
    log_step "启动批量安全性评估"

    local total=${#TARGET_IMAGES[@]}
    local current=0
    SUCCESS_COUNT=0
    FAIL_COUNT=0

    for img in "${TARGET_IMAGES[@]}"; do
        ((current++))
        if scan_image "$img" "$current" "$total"; then
            ((SUCCESS_COUNT++))
        else
            ((FAIL_COUNT++))
        fi
    done

    log_step "扫描阶段完成"
    log_info "评估成功: ${SUCCESS_COUNT}/${total}，失败: ${FAIL_COUNT}"
}

# ==============================================================================
# 远程主机评估新架构主流程 (本地 Trivy + 远程流式拉取 + 自动清除临时镜像)
# ==============================================================================
run_remote_audit() {
    log_step "准备远程评估任务: ${BOLD}${SSH_USER}@${REMOTE_HOST}:${SSH_PORT}${NC}"
    if [[ "$IMAGE_TRANSFER_MODE" == "pull" ]]; then
        log_info "镜像获取模式: Docker 镜像源直接下载 (docker pull)"
    else
        log_info "镜像获取模式: 远程计算机直接复制镜像 (SSH 流式传输，不经 Docker 源)"
    fi
    log_info "评估架构: 本地 Trivy 引擎 + 评估完成自动清除临时镜像 (远程主机零污染)"

    # 1. 密码交互式安全补齐
    if [[ -z "$SSH_PASSWORD" && -z "$SSH_KEY" ]]; then
        read -s -p "请输入远程主机 [${SSH_USER}@${REMOTE_HOST}] 的 SSH 登录密码: " SSH_PASSWORD
        echo ""
        if [[ -z "$SSH_PASSWORD" ]]; then
            log_error "未提供 SSH 密码或私钥，无法连接远程主机。"
            exit 1
        fi
    fi

    # 2. 验证远程主机 SSH 连通性与 Docker 守护进程 (带详细错误原因诊断)
    log_step "验证远程主机连通性与 Docker 环境"
    if ! verify_ssh_connection; then
        exit 1
    fi

    log_info "检查远程主机 Docker 服务状态与运行权限..."
    if ! check_remote_docker_service; then
        exit 1
    fi

    # 3. 探测远程 Docker 源认证凭据并同步至本地
    sync_remote_docker_auth

    # 4. 获取远程主机目标镜像清单与其关联容器 (单个 SSH 会话全量获取)
    log_step "发现远程主机上的 Docker 镜像与关联容器"
    local remote_inventory_script
    if [[ "$SCAN_SCOPE" == "running" ]]; then
        log_info "扫描策略: 仅扫描远程主机上正在运行容器所引用的镜像"
        remote_inventory_script='
            docker ps --format "{{.Image}}" | sort -u | while IFS= read -r img; do
                [ -z "$img" ] && continue
                target="$img"
                display="$img"
                cid=$(docker ps --filter "ancestor=$img" --format "{{.ID}}" 2>/dev/null | head -n 1)
                img_id=""
                if [ -n "$cid" ]; then
                    img_id=$(docker inspect --format "{{.Image}}" "$cid" 2>/dev/null | sed "s/^sha256://" | cut -c1-12)
                fi
                case "$img" in
                    *":<none>"*|"<none>"*)
                        if [ -n "$img_id" ]; then
                            target="$img_id"
                            display="${img%%:<none>*}:${img_id}"
                        fi
                        ;;
                esac
                [ -z "$img_id" ] && img_id="$target"
                c=$(docker ps --filter "ancestor=$img" --format "{{.Names}}" 2>/dev/null | paste -sd ", " -)
                [ -z "$c" ] && c="-"
                printf "%s\t%s\t%s\t%s\n" "$target" "$display" "$img_id" "$c"
            done
        '
    else
        log_info "扫描策略: 扫描远程主机上的全部本地镜像"
        remote_inventory_script='
            TAB=$(printf "\t")
            docker images --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}" | sort -u | while IFS="$TAB" read -r r t id; do
                [ -z "$id" ] && continue
                target="${r}:${t}"
                display="${r}:${t}"
                if [ "$r" = "<none>" ] || [ "$t" = "<none>" ]; then
                    target="$id"
                    if [ "$r" != "<none>" ]; then
                        display="${r}:${id}"
                    else
                        display="$id"
                    fi
                fi
                c=$(docker ps --filter "ancestor=$target" --format "{{.Names}}" 2>/dev/null | paste -sd ", " -)
                [ -z "$c" ] && c="-"
                printf "%s\t%s\t%s\t%s\n" "$target" "$display" "$id" "$c"
            done
        '
    fi

    # 建立本地映射表
    local map_file="${OUTPUT_DIR}/container_map.tsv"
    local disp_file="${OUTPUT_DIR}/display_map.tsv"
    : > "$map_file"
    : > "$disp_file"

    local targets=()
    local displays=()
    local image_ids=()
    local containers_list=()

    while IFS=$'\t' read -r t_ref t_disp t_id t_cnt; do
        [[ -z "$t_ref" ]] && continue
        targets+=("$t_ref")
        displays+=("$t_disp")
        image_ids+=("$t_id")
        containers_list+=("$t_cnt")

        printf "%s\t%s\n" "${t_disp}" "${t_cnt}" >> "$map_file"
        printf "%s\t%s\n" "${t_ref}" "${t_cnt}" >> "$map_file"
        printf "%s\t%s\n" "${t_ref}" "${t_disp}" >> "$disp_file"
        if [[ -n "$t_id" && "$t_id" != "$t_ref" ]]; then
            printf "%s\t%s\n" "${t_id}" "${t_cnt}" >> "$map_file"
            printf "%s\t%s\n" "${t_id}" "${t_disp}" >> "$disp_file"
        fi
    done < <(execute_ssh "$(get_remote_docker_wrapper)$remote_inventory_script" false | tr -d '\r')

    local total=${#targets[@]}
    if [[ $total -eq 0 ]]; then
        log_warn "未在远程主机发现任何匹配的 Docker 镜像，评估结束。"
        exit 0
    fi
    log_success "共获取到远程主机 ${BOLD}${total}${NC} 个评估目标镜像。"

    # 5. 循环流式拉取 -> 本地 Trivy 评估 -> 立即清除临时镜像
    if [[ "$IMAGE_TRANSFER_MODE" == "pull" ]]; then
        log_step "启动本地从 Docker 源拉取目标镜像、本地安全评估与清理"
    else
        log_step "启动远程计算机镜像直接复制、本地安全评估与清理"
    fi
    TARGET_IMAGES=()
    SUCCESS_COUNT=0
    FAIL_COUNT=0

    for (( idx=0; idx<total; idx++ )); do
        local current=$((idx + 1))
        local t_target="${targets[idx]}"
        local t_display="${displays[idx]}"
        local t_id="${image_ids[idx]}"
        local t_container="${containers_list[idx]}"

        TARGET_IMAGES+=("$t_target")

        echo -e "\n${BOLD}[$current/$total]${NC} 目标: ${PURPLE}${t_display}${NC}"
        if [[ "$t_container" != "-" ]]; then
            echo -e "  ├─ 远程活跃容器: ${CYAN}${t_container}${NC}"
        fi

        # 检查本地在拉取前是否已经存在该镜像
        local was_local=false
        if docker image inspect "$t_target" >/dev/null 2>&1; then
            was_local=true
        elif [[ -n "$t_id" ]] && docker image inspect "$t_id" >/dev/null 2>&1; then
            was_local=true
        fi

        local t_start=$(date +%s)
        local pull_success=false
        local r_docker_wrap
        r_docker_wrap=$(get_remote_docker_wrapper)

        if [[ "$IMAGE_TRANSFER_MODE" == "copy" ]]; then
            # 模式 1: 远程计算机复制镜像 (直接从远程计算机复制到本地，绝不从 Docker 源拉取)
            echo -n -e "  ├─ 正在从远程计算机直接复制镜像到本地 (SSH 流式传输)... "
            local err_tmp="${OUTPUT_DIR}/stream_err_${idx}.log"
            if execute_ssh_stream "${r_docker_wrap}docker save '$t_target'" 2>"$err_tmp" | docker load >/dev/null 2>&1; then
                pull_success=true
            elif [[ -n "$t_id" && "$t_id" != "$t_target" ]]; then
                # 如果使用目标引用导出失败，尝试用镜像 ID 导出
                if execute_ssh_stream "${r_docker_wrap}docker save '$t_id'" 2>"$err_tmp" | docker load >/dev/null 2>&1; then
                    pull_success=true
                fi
            fi

            if [[ "$pull_success" == true ]]; then
                rm -f "$err_tmp" >/dev/null 2>&1 || true
                local t_cost=$(( $(date +%s) - t_start ))
                echo -e "${GREEN}[完成]${NC} (传输耗时: ${t_cost}s)"
            else
                echo -e "${RED}[失败]${NC}"
                local err_detail=""
                if [[ -s "$err_tmp" ]]; then
                    err_detail=$(head -n 2 "$err_tmp" | tr -d '\r')
                fi
                rm -f "$err_tmp" >/dev/null 2>&1 || true
                if [[ -n "$err_detail" ]]; then
                    log_error "从远程计算机复制镜像失败 (原因: ${err_detail})"
                else
                    log_error "从远程计算机直接复制镜像失败: $t_target (当前为远程复制模式，未从 Docker 源拉取)"
                fi
                ((FAIL_COUNT++))
                continue
            fi
        else
            # 模式 2: Docker 源下载镜像 (本地通过网络从 Docker 镜像源直接 pull 下载)
            echo -n -e "  ├─ 正在从 Docker 镜像源直接下载镜像到本地 (docker pull)... "
            if [[ "$t_target" =~ ^[0-9a-f]{12}$ ]] || [[ "$t_target" == *"<none>"* ]]; then
                echo -e "${RED}[失败]${NC}"
                log_error "目标镜像为本地未标记镜像 ID ($t_target)，Docker 源不存在此镜像，无法通过 pull 下载；建议使用远程计算机复制镜像模式"
                ((FAIL_COUNT++))
                continue
            fi

            local pull_err_tmp="${OUTPUT_DIR}/pull_err_${idx}.log"
            if docker pull "$t_target" >/dev/null 2>"$pull_err_tmp"; then
                pull_success=true
            fi

            if [[ "$pull_success" == true ]]; then
                rm -f "$pull_err_tmp" >/dev/null 2>&1 || true
                local t_cost=$(( $(date +%s) - t_start ))
                echo -e "${GREEN}[完成]${NC} (拉取耗时: ${t_cost}s)"
            else
                echo -e "${RED}[失败]${NC}"
                local pull_err_detail=""
                if [[ -s "$pull_err_tmp" ]]; then
                    pull_err_detail=$(head -n 2 "$pull_err_tmp" | tr -d '\r')
                fi
                rm -f "$pull_err_tmp" >/dev/null 2>&1 || true
                if [[ -n "$pull_err_detail" ]]; then
                    log_error "从 Docker 镜像源拉取镜像失败 (原因: ${pull_err_detail})"
                else
                    log_error "从 Docker 镜像源拉取镜像失败: $t_target"
                fi
                ((FAIL_COUNT++))
                continue
            fi
        fi

        # 调用本地已有的高性能 scan_image 评估该镜像
        if scan_image "$t_target" "$current" "$total"; then
            ((SUCCESS_COUNT++))
        else
            ((FAIL_COUNT++))
        fi

        # 清除本地临时镜像（若扫描前本地原本不存在此镜像且启用了清理配置）
        if [[ "$was_local" == false && "$CLEANUP_REMOTE" == true ]]; then
            echo -n -e "  ├─ 正在清理本地临时镜像... "
            docker rmi -f "$t_target" >/dev/null 2>&1 || true
            if [[ -n "$t_id" && "$t_id" != "$t_target" ]]; then
                docker rmi -f "$t_id" >/dev/null 2>&1 || true
            fi
            echo -e "${GREEN}[已清除]${NC}"
        elif [[ "$was_local" == false && "$CLEANUP_REMOTE" == false ]]; then
            echo -e "  ├─ 依用户配置保留本地拉取的临时镜像。"
        else
            echo -e "  ├─ 镜像扫描前已存在于本地，保留本地副本。"
        fi
    done

    # 6. 生成本地 Markdown 与 HTML 汇总报告及任务简报
    log_step "生成评估汇总报告与任务简报"
    generate_markdown_report
    generate_html_report
    generate_task_brief
}

# ==============================================================================
# 报告生成函数组
# ==============================================================================

# 生成 Markdown 综合报告
generate_markdown_report() {
    local md_file="${OUTPUT_DIR}/summary.md"
    log_info "正在生成 Markdown 报告: ${md_file}"

    local host_label="$(hostname)"
    if [[ -n "$REMOTE_HOST" ]]; then
        host_label="远程主机 ${REMOTE_HOST}"
    fi

    local auth_desc="本地默认凭证"
    if [[ ${#REMOTE_DOCKER_REGISTRIES[@]} -gt 0 ]]; then
        auth_desc="已同步远程私有仓库认证 (共 ${#REMOTE_DOCKER_REGISTRIES[@]} 个源: $(IFS=, ; echo "${REMOTE_DOCKER_REGISTRIES[*]}"))"
    fi

    local perm_desc="普通用户权限直接执行 (无需提权)"
    if [[ "$REMOTE_USE_SUDO" == true ]]; then
        if [[ "$REMOTE_SUDO_TYPE" == "password" ]]; then
            perm_desc="自动提升权限 (凭据 sudo 提权)"
        else
            perm_desc="自动提升权限 (免密 sudo 提权)"
        fi
    fi

    local transfer_desc="本地镜像直接评估"
    if [[ -n "$REMOTE_HOST" ]]; then
        if [[ "$IMAGE_TRANSFER_MODE" == "pull" ]]; then
            transfer_desc="Docker 镜像源直接拉取 (docker pull)"
        else
            transfer_desc="远程计算机复制镜像 (SSH 流式传输，不经 Docker 源)"
        fi
    fi

    cat << EOF > "$md_file"
# 🛡️ Docker 容器与镜像安全评估综合报告

- **评估时间**: $(date +"%Y-%m-%d %H:%M:%S")
- **目标主机**: ${host_label}
- **扫描器镜像**: \`${TRIVY_IMAGE}\`
- **扫描范围**: \`${SCAN_SCOPE}\` (评估总数: ${#TARGET_IMAGES[@]})
- **严重等级过滤**: \`${SEVERITY}\`
- **启用扫描模块**: \`${SCANNERS}\`
- **执行权限**: \`${perm_desc}\`
- **镜像源认证**: \`${auth_desc}\`
- **镜像获取方式**: \`${transfer_desc}\`
- **任务简报**: [📄 任务简报 (task_brief.txt)](task_brief.txt) | [📝 任务简报 (task_brief.md)](task_brief.md) | [🖥️ 可视化大屏 (index.html)](index.html)

---

## 📊 镜像风险与关联容器评估总览

| 目标镜像 | 关联活跃容器 | 严重 (CRITICAL) | 高危 (HIGH) | 中危 (MEDIUM) | 低危 (LOW) | 凭证泄露 (SECRETS) | 综合评级 | 详细报告 |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
EOF

    local total_crit=0
    local total_high=0
    local total_med=0
    local total_low=0
    local total_sec=0

    for img in "${TARGET_IMAGES[@]}"; do
        local safe_name
        safe_name=$(sanitize_filename "$img")
        local display_name
        display_name=$(get_display_name "$img")

        local json_file="${OUTPUT_DIR}/raw_json/${safe_name}.json"
        local txt_rel="raw_txt/${safe_name}.txt"
        local containers
        containers=$(get_associated_containers "$img")

        if [[ -f "$json_file" && -s "$json_file" ]]; then
            local counts
            counts=$(extract_counts "$json_file")
            local crit high med low sec
            crit=$(echo "$counts" | awk '{print $1}')
            high=$(echo "$counts" | awk '{print $2}')
            med=$(echo "$counts" | awk '{print $3}')
            low=$(echo "$counts" | awk '{print $4}')
            sec=$(echo "$counts" | awk '{print $5}')

            total_crit=$((total_crit + crit))
            total_high=$((total_high + high))
            total_med=$((total_med + med))
            total_low=$((total_low + low))
            total_sec=$((total_sec + sec))

            local badge="🟢 安全"
            if (( crit > 0 )); then
                badge="🔴 严重风险"
            elif (( high > 0 )); then
                badge="🟠 高度风险"
            elif (( sec > 0 )); then
                badge="🟣 凭证暴露"
            elif (( med > 0 )); then
                badge="🟡 中度风险"
            fi

            echo "| \`$display_name\` | \`$containers\` | **$crit** | $high | $med | $low | $sec | $badge | [查看文本]($txt_rel) |" >> "$md_file"
        else
            echo "| \`$display_name\` | \`$containers\` | - | - | - | - | - | ⚪ 扫描失败 | - |" >> "$md_file"
        fi
    done

    cat << EOF >> "$md_file"

### 📈 全局漏洞统计汇总
- **严重漏洞 (CRITICAL)**: **${total_crit}**
- **高危漏洞 (HIGH)**: **${total_high}**
- **中危漏洞 (MEDIUM)**: ${total_med}
- **低危漏洞 (LOW)**: ${total_low}
- **敏感信息泄露 (SECRETS)**: **${total_sec}**

---
*本报告由 \`docker-trivy-audit.sh\` 自动化生成*
EOF
}

# 生成单文件自包含 HTML 可视化仪表盘
generate_html_report() {
    local html_file="${OUTPUT_DIR}/index.html"
    local json_summary_file="${OUTPUT_DIR}/summary_data.js"
    log_info "正在生成可视化 HTML 仪表盘: ${html_file}"

    local host_label="$(hostname)"
    if [[ -n "$REMOTE_HOST" ]]; then
        host_label="远程主机: ${REMOTE_HOST}"
    fi

    echo "const scanResults = [" > "$json_summary_file"

    for img in "${TARGET_IMAGES[@]}"; do
        local safe_name
        safe_name=$(sanitize_filename "$img")
        local display_name
        display_name=$(get_display_name "$img")

        local json_file="${OUTPUT_DIR}/raw_json/${safe_name}.json"
        local txt_rel="raw_txt/${safe_name}.txt"
        local containers
        containers=$(get_associated_containers "$img")

        if [[ -f "$json_file" && -s "$json_file" ]]; then
            local counts
            counts=$(extract_counts "$json_file")
            local crit high med low sec
            crit=$(echo "$counts" | awk '{print $1}')
            high=$(echo "$counts" | awk '{print $2}')
            med=$(echo "$counts" | awk '{print $3}')
            low=$(echo "$counts" | awk '{print $4}')
            sec=$(echo "$counts" | awk '{print $5}')

            cat << EOF >> "$json_summary_file"
  {
    image: "$display_name",
    containers: "$containers",
    safeName: "$safe_name",
    critical: $crit,
    high: $high,
    medium: $med,
    low: $low,
    secrets: $sec,
    status: "success",
    txtReport: "$txt_rel"
  },
EOF
        else
            cat << EOF >> "$json_summary_file"
  {
    image: "$display_name",
    containers: "$containers",
    safeName: "$safe_name",
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    secrets: 0,
    status: "failed",
    txtReport: ""
  },
EOF
        fi
    done
    echo "];" >> "$json_summary_file"

    cat << EOF > "$html_file"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Docker 容器安全评估大屏 - Trivy</title>
    <style>
        :root {
            --bg: #0b1120;
            --surface: #1e293b;
            --surface-hover: #2e3e56;
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --border: #334155;
            --crit: #ef4444;
            --high: #f97316;
            --med: #eab308;
            --low: #38bdf8;
            --sec: #c084fc;
            --success: #34d399;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            padding: 24px;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        header {
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
        h1 {
            font-size: 1.65rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
            background: linear-gradient(135deg, #60a5fa, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .meta-info {
            font-size: 0.85rem;
            color: var(--text-sub);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: var(--surface);
            border-radius: 12px;
            padding: 18px;
            border: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        }
        .stat-card .label {
            font-size: 0.8rem;
            color: var(--text-sub);
            font-weight: 600;
            text-transform: uppercase;
        }
        .stat-card .value {
            font-size: 2.2rem;
            font-weight: 800;
            margin-top: 6px;
        }
        .stat-card.crit .value { color: var(--crit); }
        .stat-card.high .value { color: var(--high); }
        .stat-card.med .value { color: var(--med); }
        .stat-card.sec .value { color: var(--sec); }
        .stat-card.total .value { color: #60a5fa; }

        .toolbar {
            background: var(--surface);
            border-radius: 10px;
            padding: 12px 18px;
            display: flex;
            gap: 12px;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            border: 1px solid var(--border);
        }
        .toolbar input {
            background: #0f172a;
            border: 1px solid var(--border);
            color: #fff;
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 0.9rem;
            flex: 1;
            min-width: 260px;
            outline: none;
        }
        .toolbar input:focus {
            border-color: #38bdf8;
        }
        .btn-filter {
            background: #0f172a;
            border: 1px solid var(--border);
            color: var(--text-sub);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-filter.active, .btn-filter:hover {
            background: #334155;
            color: #fff;
            border-color: #64748b;
        }

        .table-wrapper {
            background: var(--surface);
            border-radius: 12px;
            overflow-x: auto;
            border: 1px solid var(--border);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }
        thead {
            background: #0f172a;
            border-bottom: 2px solid var(--border);
        }
        th, td {
            padding: 12px 16px;
        }
        th {
            font-weight: 600;
            color: var(--text-sub);
            font-size: 0.78rem;
            text-transform: uppercase;
        }
        tbody tr {
            border-bottom: 1px solid var(--border);
            transition: background 0.15s;
        }
        tbody tr:hover {
            background: var(--surface-hover);
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.75rem;
        }
        .badge-crit { background: rgba(239, 68, 68, 0.2); color: var(--crit); border: 1px solid rgba(239, 68, 68, 0.4); }
        .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.4); }
        .badge-med { background: rgba(234, 179, 8, 0.2); color: var(--med); border: 1px solid rgba(234, 179, 8, 0.4); }
        .badge-sec { background: rgba(192, 132, 252, 0.2); color: var(--sec); border: 1px solid rgba(192, 132, 252, 0.4); }
        .badge-safe { background: rgba(52, 211, 153, 0.2); color: var(--success); border: 1px solid rgba(52, 211, 153, 0.4); }
        .tag-container {
            font-family: monospace;
            font-size: 0.8rem;
            color: #38bdf8;
            background: rgba(56, 189, 248, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
        }
        .btn-view {
            color: #38bdf8;
            text-decoration: none;
            font-weight: 500;
            padding: 4px 10px;
            border-radius: 4px;
            background: rgba(56, 189, 248, 0.1);
            transition: background 0.2s;
            font-size: 0.82rem;
        }
        .btn-view:hover {
            background: rgba(56, 189, 248, 0.25);
        }
        footer {
            margin-top: 24px;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-sub);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ Docker 容器与镜像安全评估仪表盘</h1>
                <div class="meta-info" id="meta-text">目标主机: ${host_label} | 评估引擎: Aquasec Trivy</div>
            </div>
        </header>

        <!-- 统计指标 -->
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="label">扫描镜像总数</div>
                <div class="value" id="stat-total">0</div>
            </div>
            <div class="stat-card crit">
                <div class="label">严重漏洞 (CRITICAL)</div>
                <div class="value" id="stat-crit">0</div>
            </div>
            <div class="stat-card high">
                <div class="label">高危漏洞 (HIGH)</div>
                <div class="value" id="stat-high">0</div>
            </div>
            <div class="stat-card med">
                <div class="label">中危漏洞 (MEDIUM)</div>
                <div class="value" id="stat-med">0</div>
            </div>
            <div class="stat-card sec">
                <div class="label">凭证泄露 (SECRETS)</div>
                <div class="value" id="stat-sec">0</div>
            </div>
        </div>

        <!-- 过滤与搜索 -->
        <div class="toolbar">
            <input type="text" id="searchInput" placeholder="🔍 快速搜索镜像名或容器名..." oninput="renderTable()">
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
                <button class="btn-filter active" onclick="setFilter('all', this)">全部</button>
                <button class="btn-filter" onclick="setFilter('crit', this)">仅 CRITICAL</button>
                <button class="btn-filter" onclick="setFilter('risk', this)">有风险</button>
                <button class="btn-filter" onclick="setFilter('running', this)">仅运行中容器</button>
                <button class="btn-filter" onclick="setFilter('clean', this)">安全无风险</button>
                <a class="btn-filter" href="task_brief.txt" target="_blank" style="text-decoration:none; display:inline-flex; align-items:center;">📋 查看任务简报</a>
            </div>
        </div>

        <!-- 结果表格 -->
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>目标镜像</th>
                        <th>关联活跃容器</th>
                        <th>严重 (CRITICAL)</th>
                        <th>高危 (HIGH)</th>
                        <th>中危 (MEDIUM)</th>
                        <th>低危 (LOW)</th>
                        <th>敏感泄露 (SECRETS)</th>
                        <th>风险评级</th>
                        <th>详细报告</th>
                    </tr>
                </thead>
                <tbody id="tableBody"></tbody>
            </table>
        </div>

        <footer>
            由自动化评估脚本 <code>docker-trivy-audit.sh</code> 基于 Aqua Security Trivy 驱动生成
        </footer>
    </div>

    <script src="summary_data.js"></script>
    <script>
        let currentFilter = 'all';

        function setFilter(filter, btn) {
            currentFilter = filter;
            document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderTable();
        }

        function calculateStats() {
            let total = scanResults.length;
            let crit = 0, high = 0, med = 0, sec = 0;

            scanResults.forEach(item => {
                crit += item.critical;
                high += item.high;
                med += item.medium;
                sec += item.secrets;
            });

            document.getElementById('stat-total').innerText = total;
            document.getElementById('stat-crit').innerText = crit;
            document.getElementById('stat-high').innerText = high;
            document.getElementById('stat-med').innerText = med;
            document.getElementById('stat-sec').innerText = sec;
        }

        function renderTable() {
            const query = document.getElementById('searchInput').value.toLowerCase().trim();
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';

            const filtered = scanResults.filter(item => {
                const matchQuery = !query ||
                                   item.image.toLowerCase().includes(query) ||
                                   item.containers.toLowerCase().includes(query);
                if (!matchQuery) return false;

                if (currentFilter === 'crit') return item.critical > 0;
                if (currentFilter === 'risk') return (item.critical + item.high + item.medium + item.secrets) > 0;
                if (currentFilter === 'running') return item.containers !== '-';
                if (currentFilter === 'clean') return (item.critical + item.high + item.medium + item.secrets) === 0 && item.status === 'success';
                return true;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = \`<tr><td colspan="9" style="text-align: center; color: var(--text-sub); padding: 30px;">未发现匹配的记录</td></tr>\`;
                return;
            }

            filtered.forEach(item => {
                let ratingBadge = \`<span class="badge badge-safe">安全</span>\`;
                if (item.status === 'failed') {
                    ratingBadge = \`<span class="badge" style="background:#475569; color:#cbd5e1;">扫描失败</span>\`;
                } else if (item.critical > 0) {
                    ratingBadge = \`<span class="badge badge-crit">极度严重</span>\`;
                } else if (item.high > 0) {
                    ratingBadge = \`<span class="badge badge-high">高危风险</span>\`;
                } else if (item.secrets > 0) {
                    ratingBadge = \`<span class="badge badge-sec">凭据泄露</span>\`;
                } else if (item.medium > 0) {
                    ratingBadge = \`<span class="badge badge-med">中度风险</span>\`;
                }

                const containerDisplay = item.containers !== '-'
                    ? \`<span class="tag-container">\${item.containers}</span>\`
                    : '<span style="color:var(--text-sub);">-</span>';

                const tr = document.createElement('tr');
                tr.innerHTML = \`
                    <td><strong>\${item.image}</strong></td>
                    <td>\${containerDisplay}</td>
                    <td>\${item.critical > 0 ? \`<span class="badge badge-crit">\${item.critical}</span>\` : '0'}</td>
                    <td>\${item.high > 0 ? \`<span class="badge badge-high">\${item.high}</span>\` : '0'}</td>
                    <td>\${item.medium > 0 ? \`<span class="badge badge-med">\${item.medium}</span>\` : '0'}</td>
                    <td>\${item.low}</td>
                    <td>\${item.secrets > 0 ? \`<span class="badge badge-sec">\${item.secrets}</span>\` : '0'}</td>
                    <td>\${ratingBadge}</td>
                    <td>
                        \${item.txtReport ? \`<a class="btn-view" href="\${item.txtReport}" target="_blank">查看详情</a>\` : '-'}
                    </td>
                \`;
                tbody.appendChild(tr);
            });
        }

        window.onload = function() {
            calculateStats();
            renderTable();
        };
    </script>
</body>
</html>
EOF

    log_success "可视化 HTML 仪表盘已生成至: ${html_file}"
}

# 生成整个任务的快速简报 (包含纯文本 task_brief.txt 与 Markdown task_brief.md，并兼顾 brief.txt)
generate_task_brief() {
    local brief_txt="${OUTPUT_DIR}/task_brief.txt"
    local brief_md="${OUTPUT_DIR}/task_brief.md"
    local brief_compat="${OUTPUT_DIR}/brief.txt"

    log_info "正在生成任务简报: ${brief_txt} 与 ${brief_md}"

    local task_end_sec=$(date +%s)
    local task_end_datetime=$(date +"%Y-%m-%d %H:%M:%S")
    local duration_sec=$(( task_end_sec - TASK_START_SEC ))
    if (( duration_sec < 0 )); then
        duration_sec=0
    fi

    local duration_str
    local dur_min=$(( duration_sec / 60 ))
    local dur_sec=$(( duration_sec % 60 ))
    if (( dur_min > 0 )); then
        duration_str="${dur_min}分${dur_sec}秒"
    else
        duration_str="${dur_sec}秒"
    fi

    local host_label="$(hostname 2>/dev/null || echo 'localhost')"
    local target_type="本地宿主机"
    if [[ -n "$REMOTE_HOST" ]]; then
        host_label="${SSH_USER}@${REMOTE_HOST}:${SSH_PORT}"
        target_type="远程 Linux 主机"
    fi

    local total_targets=${#TARGET_IMAGES[@]}
    local total_crit=0
    local total_high=0
    local total_med=0
    local total_low=0
    local total_sec=0

    local img_crit_count=0
    local img_high_count=0
    local img_med_count=0
    local img_low_count=0
    local img_sec_count=0
    local img_clean_count=0
    local img_failed_count=0

    local raw_risk_entries=()
    local all_active_containers=()
    local affected_active_containers=()

    for img in "${TARGET_IMAGES[@]}"; do
        local safe_name
        safe_name=$(sanitize_filename "$img")
        local display_name
        display_name=$(get_display_name "$img")

        local json_file="${OUTPUT_DIR}/raw_json/${safe_name}.json"
        local containers
        containers=$(get_associated_containers "$img")

        if [[ "$containers" != "-" && -n "$containers" ]]; then
            local prev_ifs="$IFS"
            IFS=','
            for c_raw in $containers; do
                local c_trim
                c_trim=$(echo "$c_raw" | xargs)
                if [[ -n "$c_trim" ]]; then
                    all_active_containers+=("$c_trim")
                fi
            done
            IFS="$prev_ifs"
        fi

        if [[ -f "$json_file" && -s "$json_file" ]]; then
            local counts
            counts=$(extract_counts "$json_file")
            local crit high med low sec
            read -r crit high med low sec <<< "$counts"
            crit=${crit:-0}
            high=${high:-0}
            med=${med:-0}
            low=${low:-0}
            sec=${sec:-0}

            total_crit=$((total_crit + crit))
            total_high=$((total_high + high))
            total_med=$((total_med + med))
            total_low=$((total_low + low))
            total_sec=$((total_sec + sec))

            local badge="安全无风险"
            if (( crit > 0 )); then
                img_crit_count=$(( img_crit_count + 1 ))
                badge="严重风险"
            elif (( high > 0 )); then
                img_high_count=$(( img_high_count + 1 ))
                badge="高度风险"
            elif (( sec > 0 )); then
                badge="凭证暴露"
            elif (( med > 0 )); then
                img_med_count=$(( img_med_count + 1 ))
                badge="中度风险"
            elif (( low > 0 )); then
                img_low_count=$(( img_low_count + 1 ))
                badge="低度风险"
            else
                img_clean_count=$(( img_clean_count + 1 ))
                badge="安全无风险"
            fi

            if (( sec > 0 )); then
                img_sec_count=$(( img_sec_count + 1 ))
            fi

            if (( crit > 0 || sec > 0 || high > 0 || med > 0 )); then
                raw_risk_entries+=("$(printf "%05d\t%05d\t%05d\t%05d\t%05d\t%s\t%s\t%s" "$crit" "$sec" "$high" "$med" "$low" "$display_name" "$containers" "$badge")")
                if [[ "$containers" != "-" && -n "$containers" ]]; then
                    local prev_ifs="$IFS"
                    IFS=','
                    for c_raw in $containers; do
                        local c_trim
                        c_trim=$(echo "$c_raw" | xargs)
                        if [[ -n "$c_trim" ]]; then
                            affected_active_containers+=("$c_trim")
                        fi
                    done
                    IFS="$prev_ifs"
                fi
            fi
        else
            img_failed_count=$(( img_failed_count + 1 ))
        fi
    done

    # 容器名称去重
    local unique_active_containers=()
    if [[ ${#all_active_containers[@]} -gt 0 ]]; then
        while IFS= read -r c_name; do
            [[ -n "$c_name" ]] && unique_active_containers+=("$c_name")
        done < <(printf '%s\n' "${all_active_containers[@]}" | sort -u)
    fi

    local unique_affected_containers=()
    if [[ ${#affected_active_containers[@]} -gt 0 ]]; then
        while IFS= read -r c_name; do
            [[ -n "$c_name" ]] && unique_affected_containers+=("$c_name")
        done < <(printf '%s\n' "${affected_active_containers[@]}" | sort -u)
    fi

    local active_cnt_str
    active_cnt_str=$(format_container_names "${unique_active_containers[@]}")
    local affected_cnt_str
    affected_cnt_str=$(format_container_names "${unique_affected_containers[@]}")

    # 风险排序
    local sorted_risk_entries=()
    if [[ ${#raw_risk_entries[@]} -gt 0 ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && sorted_risk_entries+=("$line")
        done < <(printf '%s\n' "${raw_risk_entries[@]}" | sort -r)
    fi

    # 判定总体风险等级
    local verdict_title=""
    local verdict_desc=""
    if (( total_crit > 0 || total_sec > 0 )); then
        verdict_title="🚨 严重安全告警 (CRITICAL RISK)"
        if (( total_sec > 0 && total_crit > 0 )); then
            verdict_desc="检测到 ${total_crit} 个严重 CVE 漏洞且存在 ${total_sec} 处敏感硬编码凭据泄露，系统面临被勒索、提权或横向渗透的严重威胁，需立即阻断并紧急修复！"
        elif (( total_crit > 0 )); then
            verdict_desc="检测到 ${total_crit} 个严重级别 (CRITICAL) 漏洞，攻击者可据此实施远程代码执行或获取宿主机特权，必须作为最高优先级修复！"
        else
            verdict_desc="检测到 ${total_sec} 处敏感密钥/密码/API Token 泄露，存在凭据滥用与未授权访问风险，请立即吊销暴露的密钥！"
        fi
    elif (( total_high > 0 )); then
        verdict_title="⚠️ 高度风险警告 (HIGH RISK)"
        verdict_desc="检测到 ${total_high} 个高危漏洞 (HIGH)，系统可能被拒绝服务、提权或越权访问，建议限期排查受影响的依赖组件并升级。"
    elif (( total_med > 0 )); then
        verdict_title="🟡 中度安全风险 (MEDIUM RISK)"
        verdict_desc="未发现严重与高危漏洞，存在 ${total_med} 个中度风险项，整体安全态势基本可控，可随业务版本日常迭代优化更新。"
    elif (( total_low > 0 )); then
        verdict_title="🔵 低度安全风险 (LOW RISK)"
        verdict_desc="仅发现少量低危漏洞，整体处于安全基准线内，定期关注官方补丁即可。"
    else
        verdict_title="🟢 安全基线优秀 (HEALTHY / CLEAN)"
        verdict_desc="未在评估的目标镜像中检出符合条件的 CVE 漏洞或硬编码凭据泄露，系统安全基线优秀！"
    fi

    local success_rate="100%"
    if (( total_targets > 0 )); then
        success_rate="$(( (total_targets - img_failed_count) * 100 / total_targets ))%"
    fi

    local crit_tag=""
    (( total_crit > 0 )) && crit_tag="<-- [🚨 需紧急修复]"
    local high_tag=""
    (( total_high > 0 )) && high_tag="<-- [⚠️ 需限期修复]"
    local sec_tag=""
    (( total_sec > 0 )) && sec_tag="<-- [🟣 存在密钥暴露，立即吊销]"

    local auth_desc="本地默认凭证"
    if [[ ${#REMOTE_DOCKER_REGISTRIES[@]} -gt 0 ]]; then
        auth_desc="已同步远程私有仓库认证 (共 ${#REMOTE_DOCKER_REGISTRIES[@]} 个源: $(IFS=, ; echo "${REMOTE_DOCKER_REGISTRIES[*]}"))"
    fi

    local perm_desc="普通用户权限直接执行 (无需提权)"
    if [[ "$REMOTE_USE_SUDO" == true ]]; then
        if [[ "$REMOTE_SUDO_TYPE" == "password" ]]; then
            perm_desc="自动提升权限 (凭据 sudo 提权)"
        else
            perm_desc="自动提升权限 (免密 sudo 提权)"
        fi
    fi

    local transfer_desc="本地宿主机镜像直接评估"
    if [[ -n "$REMOTE_HOST" ]]; then
        if [[ "$IMAGE_TRANSFER_MODE" == "pull" ]]; then
            transfer_desc="Docker 镜像源直接拉取 (docker pull)"
        else
            transfer_desc="远程计算机复制镜像 (SSH 流式传输，不经 Docker 源)"
        fi
    fi

    # 1. 写入纯文本简报 task_brief.txt
    cat << EOF > "$brief_txt"
================================================================================
                      🛡️  DOCKER 容器安全评估任务简报
================================================================================

【任务概况】
  * 任务标识:     ${TIMESTAMP}
  * 目标类型:     ${target_type}
  * 目标主机:     ${host_label}
  * 评估引擎:     ${TRIVY_IMAGE} (本地离线比对)
  * 扫描范围:     ${SCAN_SCOPE} (共 ${total_targets} 个目标镜像)
  * 检测模块:     ${SCANNERS}
  * 过滤等级:     ${SEVERITY}
  * 执行权限:     ${perm_desc}
  * 镜像源认证:   ${auth_desc}
  * 镜像获取方式: ${transfer_desc}
  * 执行周期:     ${TASK_START_DATETIME} ~ ${task_end_datetime} (总耗时: ${duration_str})

【资产与扫描执行】
  * 评估目标总数: ${total_targets} 个
  * 扫描成功数量: $(( total_targets - img_failed_count )) 个 (成功率: ${success_rate})
  * 扫描失败数量: ${img_failed_count} 个
  * 活跃业务容器: 共 ${#unique_active_containers[@]} 个在线运行 (${active_cnt_str})
  * 风险影响容器: 共 ${#unique_affected_containers[@]} 个受风险波及 (${affected_cnt_str})

【安全态势与风险定级】
  * 综合安全评级: [ ${verdict_title} ]
  * 态势简评结论: ${verdict_desc}
  * 漏洞统计汇总:
    ├─ 严重漏洞 (CRITICAL): ${total_crit} 项  ${crit_tag}
    ├─ 高危漏洞 (HIGH):     ${total_high} 项  ${high_tag}
    ├─ 中危漏洞 (MEDIUM):   ${total_med} 项
    ├─ 低危漏洞 (LOW):      ${total_low} 项
    └─ 凭据泄露 (SECRETS):  ${total_sec} 项  ${sec_tag}
  * 镜像风险分布:
    ├─ 严重风险镜像: ${img_crit_count} 个 (含 CRITICAL)
    ├─ 高度风险镜像: ${img_high_count} 个 (含 HIGH，无 CRITICAL)
    ├─ 凭据泄露镜像: ${img_sec_count} 个 (含 SECRETS)
    ├─ 中度风险镜像: ${img_med_count} 个 (含 MEDIUM)
    ├─ 低度风险镜像: ${img_low_count} 个 (仅含 LOW)
    ├─ 安全合规镜像: ${img_clean_count} 个 (无任何风险项)
    └─ 评估失败镜像: ${img_failed_count} 个

【重点关注风险资产 (TOP 风险目标)】
EOF

    local top_risk_count=0
    local max_top_risks=10

    if [[ ${#sorted_risk_entries[@]} -eq 0 ]]; then
        echo "  ✔ 未发现包含严重漏洞、高危漏洞或敏感凭据泄露的风险镜像，系统基线安全。" >> "$brief_txt"
    else
        for entry in "${sorted_risk_entries[@]}"; do
            top_risk_count=$(( top_risk_count + 1 ))
            if (( top_risk_count > max_top_risks )); then
                echo -e "\n  ... (其余 $(( ${#sorted_risk_entries[@]} - max_top_risks )) 个风险目标请查阅 summary.md 与 index.html)" >> "$brief_txt"
                break
            fi

            local r_crit r_sec r_high r_med r_low r_name r_cnt r_badge
            IFS=$'\t' read -r r_crit r_sec r_high r_med r_low r_name r_cnt r_badge <<< "$entry"
            r_crit=$((10#$r_crit))
            r_sec=$((10#$r_sec))
            r_high=$((10#$r_high))
            r_med=$((10#$r_med))
            r_low=$((10#$r_low))

            local priority_label="[P2 高危]"
            local advice="存在高危依赖漏洞，建议限期排查组件版本并完成修复。"
            if (( r_crit > 0 || r_sec > 0 )); then
                if [[ "$r_cnt" != "-" && -n "$r_cnt" ]]; then
                    priority_label="[🚨 P0 紧急]"
                    advice="关联在线业务容器且含严重漏洞/密钥暴露，应立即排查密钥并更新基础镜像！"
                else
                    priority_label="[🔴 P1 严重]"
                    advice="含有严重漏洞或敏感凭据暴露，建议立即重建镜像并更新依赖。"
                fi
            elif (( r_high > 0 )); then
                if [[ "$r_cnt" != "-" && -n "$r_cnt" ]]; then
                    priority_label="[⚠️ P1 高危]"
                    advice="在线容器存在高危漏洞，建议在下一个维护窗口优先升级修复。"
                fi
            elif (( r_med > 0 )); then
                priority_label="[🟡 P3 中危]"
                advice="存在中度风险项，建议纳入常规迭代维护与更新。"
            fi

            local cnt_label="无活跃容器关联"
            if [[ "$r_cnt" != "-" && -n "$r_cnt" ]]; then
                cnt_label="${r_cnt} (正在运行)"
            fi

            cat << EOF >> "$brief_txt"
  ${top_risk_count}. ${priority_label} ${r_name}
     ├─ 关联活跃容器: ${cnt_label}
     ├─ 漏洞发现统计: CRITICAL: ${r_crit} | HIGH: ${r_high} | MEDIUM: ${r_med} | LOW: ${r_low} | SECRETS: ${r_sec}
     └─ 处置行动建议: ${advice}
EOF
        done
    fi

    cat << 'EOF' >> "$brief_txt"

【整改与处置建议】
  1. 凭据吊销轮换: 针对检出的敏感硬编码凭据 (SECRETS)，应立即在对应服务商或平台吊销并重新生成密码/Token，从 Dockerfile 历史构建层彻底清除。
  2. 优先修正在线容器: 优先对关联运行中业务容器的镜像实施修复与验证，消除生产环境被直接攻击的安全隐患。
  3. 基础镜像更新: 升级基础镜像至官方最新补丁版 (如 Alpine / Debian-slim 最新版)，精简镜像并减少攻击面。
  4. 依赖升级与代码加固: 升级受影响的应用程序第三方依赖包 (Node.js/Python/Java/Go 等) 至修复版本。
  5. 质量红线卡点: 建议在 CI/CD 流水线中引入基于 Trivy 的安全门禁，阻断高危漏洞与密钥泄露镜像发布上线。

【交付物索引】
  * 任务简报 (纯文本):  task_brief.txt (或 brief.txt)
  * 任务简报 (Markdown): task_brief.md
  * 交互式 HTML 仪表盘:  index.html
  * Markdown 汇总详报:   summary.md
  * 原始文本扫描报告:    raw_txt/
  * 原始结构化 JSON:     raw_json/
================================================================================
EOF

    # 2. 写入 Markdown 版简报 task_brief.md
    cat << EOF > "$brief_md"
# 🛡️ Docker 容器安全评估任务简报

> **任务标识**: \`${TIMESTAMP}\`  
> **目标主机**: ${host_label} (\`${target_type}\`)  
> **执行时间**: ${TASK_START_DATETIME} ~ ${task_end_datetime} (总耗时: **${duration_str}**)  
> **扫描引擎**: \`${TRIVY_IMAGE}\` | **扫描范围**: \`${SCAN_SCOPE}\` | **检测模块**: \`${SCANNERS}\`  
> **执行权限**: \`${perm_desc}\`  
> **镜像源认证**: \`${auth_desc}\`  
> **镜像获取方式**: \`${transfer_desc}\`  
> **报告索引**: [📄 纯文本简报 (task_brief.txt)](task_brief.txt) | [🖥️ Web 可视化仪表盘 (index.html)](index.html) | [📊 综合汇总详报 (summary.md)](summary.md)

---

## 🚦 综合安全态势与风险定级

| 综合安全评级 | 严重 (CRITICAL) | 高危 (HIGH) | 中危 (MEDIUM) | 低危 (LOW) | 凭证泄露 (SECRETS) | 涉及活跃容器 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **${verdict_title}** | **${total_crit}** | ${total_high} | ${total_med} | ${total_low} | **${total_sec}** | ${#unique_affected_containers[@]} 个 |

> **态势判定**: ${verdict_desc}

---

## 📈 资产与执行统计

- **目标镜像总数**: **${total_targets}** 个 (成功: **$(( total_targets - img_failed_count ))**, 失败: **${img_failed_count}**, 成功率: **${success_rate}**)
- **在线业务容器**: **${#unique_active_containers[@]}** 个正在运行 (\`${active_cnt_str}\`)
- **受风险波及容器**: **${#unique_affected_containers[@]}** 个活跃容器位于风险镜像中 (\`${affected_cnt_str}\`)
- **镜像风险层级分布**:
  - 🔴 **严重风险镜像**: **${img_crit_count}** 个
  - 🟠 **高度风险镜像**: **${img_high_count}** 个
  - 🟣 **凭证泄露镜像**: **${img_sec_count}** 个
  - 🟡 **中度风险镜像**: **${img_med_count}** 个
  - 🟢 **安全合规镜像**: **${img_clean_count}** 个

---

## 🎯 重点关注风险资产 (Top 风险目标)

EOF

    if [[ ${#sorted_risk_entries[@]} -eq 0 ]]; then
        echo "> ✔ **安全基线良好**：未发现包含严重漏洞、高危漏洞或敏感凭据泄露的风险镜像资产。" >> "$brief_md"
    else
        cat << 'EOF' >> "$brief_md"
| 优先级 | 目标镜像 | 关联活跃容器 | CRITICAL | HIGH | MEDIUM | SECRETS | 处置建议 |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
EOF
        local md_risk_count=0
        for entry in "${sorted_risk_entries[@]}"; do
            md_risk_count=$(( md_risk_count + 1 ))
            if (( md_risk_count > max_top_risks )); then
                break
            fi

            local r_crit r_sec r_high r_med r_low r_name r_cnt r_badge
            IFS=$'\t' read -r r_crit r_sec r_high r_med r_low r_name r_cnt r_badge <<< "$entry"
            r_crit=$((10#$r_crit))
            r_sec=$((10#$r_sec))
            r_high=$((10#$r_high))
            r_med=$((10#$r_med))
            r_low=$((10#$r_low))

            local prio_md="**P2 高危**"
            local advice_md="存在高危依赖漏洞，建议限期排查组件版本并完成修复"
            if (( r_crit > 0 || r_sec > 0 )); then
                if [[ "$r_cnt" != "-" && -n "$r_cnt" ]]; then
                    prio_md="**🚨 P0 紧急**"
                    advice_md="关联在线业务容器且含严重漏洞/密钥暴露，应立即排查密钥并更新基础镜像"
                else
                    prio_md="**🔴 P1 严重**"
                    advice_md="含有严重漏洞或敏感凭据暴露，建议立即重建镜像并更新依赖"
                fi
            elif (( r_high > 0 )); then
                if [[ "$r_cnt" != "-" && -n "$r_cnt" ]]; then
                    prio_md="**⚠️ P1 高危**"
                    advice_md="在线容器存在高危漏洞，建议在下一个维护窗口优先升级修复"
                fi
            elif (( r_med > 0 )); then
                prio_md="**🟡 P3 中危**"
                advice_md="存在中度风险项，建议纳入常规迭代维护与更新"
            fi

            local cnt_md="-"
            if [[ "$r_cnt" != "-" && -n "$r_cnt" ]]; then
                cnt_md="\`$r_cnt\` *(运行中)*"
            fi

            echo "| ${prio_md} | \`$r_name\` | ${cnt_md} | **$r_crit** | $r_high | $r_med | **$r_sec** | ${advice_md} |" >> "$brief_md"
        done

        if (( ${#sorted_risk_entries[@]} > max_top_risks )); then
            echo "" >> "$brief_md"
            echo "*(注: 简报仅列出前 ${max_top_risks} 项最高优先级资产，全部目标请查阅 [summary.md](summary.md) 与 [index.html](index.html))*" >> "$brief_md"
        fi
    fi

    cat << 'EOF' >> "$brief_md"

---

## 💡 处置与整改建议

1. **敏感凭据立即吊销与轮换**: 针对检出的硬编码密码、Token 或私钥，立即在业务平台作废并轮换，禁止在 Dockerfile 构建历史中残留敏感凭据。
2. **优先修复在线业务容器**: 针对正在运行的活跃业务容器，优先在测试环境验证升级并重新部署，避免生产环境被利用提权或横向渗透。
3. **升级基础镜像与依赖版本**: 采用官方最新的安全补丁版本重构 Dockerfile，并同步升级第三方语言依赖组件。
4. **CI/CD 安全门禁准入**: 在流水线中引入镜像扫描质量红线，实现漏洞与密钥泄露自动化卡点阻断。

---

## 📁 报告产物导航

- [📄 纯文本任务简报 (task_brief.txt)](task_brief.txt)
- [📝 Markdown 任务简报 (task_brief.md)](task_brief.md)
- [🖥️ 交互式 HTML 仪表盘 (index.html)](index.html)
- [📊 结构化 Markdown 详报 (summary.md)](summary.md)
- [📁 原始细粒度日志与数据 (raw_txt/ 与 raw_json/)](raw_txt/)
EOF

    # 3. 复制兼容 brief.txt
    cp -f "$brief_txt" "$brief_compat" 2>/dev/null || true

    # 终端输出简报摘要卡片
    echo -e "\n${BOLD}${PURPLE}======================================================================${NC}"
    echo -e "${BOLD}${CYAN}                     🛡️  安全评估任务简报                       ${NC}"
    echo -e "${BOLD}${PURPLE}======================================================================${NC}"
    echo -e "  * 目标主机:     ${BOLD}${host_label}${NC}"
    echo -e "  * 任务耗时:     ${BOLD}${duration_str}${NC} (${TASK_START_DATETIME} ~ ${task_end_datetime})"
    echo -e "  * 评估目标:     共 ${BOLD}${total_targets}${NC} 个镜像 (成功: ${GREEN}$(( total_targets - img_failed_count ))${NC}, 失败: ${RED}${img_failed_count}${NC})"
    echo -e "  * 活跃业务容器: 共 ${BOLD}${#unique_active_containers[@]}${NC} 个正在运行 (受影响: ${RED}${#unique_affected_containers[@]}${NC} 个)"
    echo -e "  * 综合安全评级: ${BOLD}${verdict_title}${NC}"
    echo -e "  * 漏洞统计汇总: ${RED}CRITICAL: ${total_crit}${NC} | ${YELLOW}HIGH: ${total_high}${NC} | ${BLUE}MEDIUM: ${total_med}${NC} | LOW: ${total_low} | ${PURPLE}SECRETS: ${total_sec}${NC}"
    echo -e "${BOLD}${PURPLE}======================================================================${NC}"
    log_success "任务简报与全量报告已成功生成至: ${OUTPUT_DIR}"
    echo -e "  ├── 📋 任务简报 (纯文本):   ${BOLD}${CYAN}${OUTPUT_DIR}/task_brief.txt${NC}"
    echo -e "  ├── 📝 任务简报 (Markdown): ${BOLD}${CYAN}${OUTPUT_DIR}/task_brief.md${NC}"
    echo -e "  ├── 🌟 交互式仪表盘:        ${BOLD}${CYAN}${OUTPUT_DIR}/index.html${NC}"
    echo -e "  ├── 📊 Markdown 综合报告:   ${BOLD}${CYAN}${OUTPUT_DIR}/summary.md${NC}"
    echo -e "  └── 📁 详细扫描日志:        ${OUTPUT_DIR}/raw_txt/ 与 raw_json/\n"
}

# 脚本主入口
main() {
    echo -e "${BOLD}${PURPLE}"
    echo "=========================================================="
    echo "       Docker 容器安全评估工具 (基于 aquasec/trivy)       "
    echo "=========================================================="
    echo -e "${NC}"

    parse_args "$@"

    # 启动配置向导：终端可交互且未显式指定非交互模式时，或显式传入 -i/--interactive 时进入
    if [[ "$FORCE_INTERACTIVE" == true ]] || [[ "$NON_INTERACTIVE" != true && -t 0 ]]; then
        prompt_interactive_wizard
    fi

    # 本地环境预检与输出目录准备
    check_prerequisites

    # 准备主漏洞数据库与 Java jar 数据库
    init_trivy_db
    init_java_db

    if [[ -n "$REMOTE_HOST" ]]; then
        # 远程主机评估模式 (使用本地 Trivy + 远程流式拉取 + 自动清理临时镜像)
        run_remote_audit
    else
        # 本地主机评估模式
        get_target_images
        run_batch_scan
        log_step "生成评估汇总报告与任务简报"
        generate_markdown_report
        generate_html_report
        generate_task_brief
    fi

    echo -e "\n${BOLD}${GREEN}✔ 全部评估任务已圆满完成！${NC}\n"
}

main "$@"
