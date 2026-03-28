#!/bin/bash

# ============================================================
#  VPN Node Firewall Setup Script
#  Использование: bash node-setup.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

EXTRA_PROTO=()

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC}   $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERR]${NC}  $1"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $1${NC}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════${NC}\n"; }

ask() {
    local prompt="$1"
    local default="$2"
    local result
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e ${YELLOW})${prompt} [${default}]: $(echo -e ${NC})" result
        echo "${result:-$default}"
    else
        read -rp "$(echo -e ${YELLOW})${prompt}: $(echo -e ${NC})" result
        echo "$result"
    fi
}

ask_yn() {
    local prompt="$1"
    local default="${2:-y}"
    local result
    read -rp "$(echo -e ${YELLOW})${prompt} [y/n] (${default}): $(echo -e ${NC})" result
    result="${result:-$default}"
    [[ "${result,,}" == "y" ]]
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -ra parts <<< "$ip"
        for part in "${parts[@]}"; do
            [[ "$part" -gt 255 ]] && return 1
        done
        return 0
    fi
    return 1
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 ]] && [[ "$1" -le 65535 ]]
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Скрипт должен запускаться от root. Используйте: sudo bash node-setup.sh"
        exit 1
    fi
}

# ── Сбор данных ──────────────────────────────────────────────

collect_config() {
    header "Настройка ноды — сбор параметров"

    while true; do
        ADMIN_IP=$(ask "Ваш управляющий IP (с которого будет доступ)")
        if validate_ip "$ADMIN_IP"; then
            break
        else
            error "Некорректный IP. Попробуйте ещё раз."
        fi
    done

    while true; do
        SSH_PORT=$(ask "Новый порт SSH (рекомендуется 49152–65535)" "51822")
        if validate_port "$SSH_PORT"; then
            break
        else
            error "Некорректный порт."
        fi
    done

    EXTRA_PORTS=()
    EXTRA_IPS=()

    header "Дополнительные порты"
    info "Добавьте порты которые нужно открыть (например 443, 2083)."

    while true; do
        if ask_yn "Добавить порт?"; then
            while true; do
                port=$(ask "Порт")
                if validate_port "$port"; then
                    break
                else
                    error "Некорректный порт."
                fi
            done

            ip_for_port=$(ask "Разрешённый IP для порта $port (Enter = любой IP)")
            if [[ -n "$ip_for_port" ]] && ! validate_ip "$ip_for_port"; then
                error "Некорректный IP — порт будет открыт для всех."
                ip_for_port=""
            fi

            proto=$(ask "Протокол: tcp / udp / both" "both")

            EXTRA_PORTS+=("$port")
            EXTRA_IPS+=("$ip_for_port")
            EXTRA_PROTO+=("$proto")

            success "Порт $port добавлен (IP: ${ip_for_port:-любой}, протокол: $proto)"
        else
            break
        fi
    done

    header "Port Knocking для SSH"
    if ask_yn "Включить port knocking для SSH?"; then
        USE_KNOCK=true
        KNOCK_SEQ=$(ask "Последовательность портов через пробел" "7000 8000 9000")
    else
        USE_KNOCK=false
    fi

    if ask_yn "Установить и настроить Fail2Ban?" "y"; then
        USE_FAIL2BAN=true
    else
        USE_FAIL2BAN=false
    fi

    header "Итоговая конфигурация"
    echo -e "  Управляющий IP : ${GREEN}$ADMIN_IP${NC}"
    echo -e "  SSH порт       : ${GREEN}$SSH_PORT${NC}"
    for i in "${!EXTRA_PORTS[@]}"; do
        echo -e "  Порт           : ${GREEN}${EXTRA_PORTS[$i]}${NC} | IP: ${EXTRA_IPS[$i]:-любой} | ${EXTRA_PROTO[$i]}"
    done
    echo -e "  Port Knocking  : ${GREEN}$USE_KNOCK${NC}"
    [[ "$USE_KNOCK" == true ]] && echo -e "  Knock sequence : ${GREEN}$KNOCK_SEQ${NC}"
    echo -e "  Fail2Ban       : ${GREEN}$USE_FAIL2BAN${NC}"
    echo ""

    if ! ask_yn "Всё верно? Применить настройки?"; then
        warn "Отменено пользователем."
        exit 0
    fi
}

# ── SSH ──────────────────────────────────────────────────────

setup_ssh() {
    header "Настройка SSH"

    SSH_SERVICE=$(systemctl list-units --type=service 2>/dev/null | grep -oE 'ssh(d)?\.service' | head -1)
    SSH_SERVICE=${SSH_SERVICE:-ssh}

    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    success "Бэкап: /etc/ssh/sshd_config.bak"

    sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config

    declare -A SSH_OPTS=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="no"
        ["PubkeyAuthentication"]="yes"
        ["MaxAuthTries"]="3"
        ["LoginGraceTime"]="20"
        ["X11Forwarding"]="no"
        ["AllowAgentForwarding"]="no"
        ["AllowTcpForwarding"]="no"
        ["Banner"]="none"
    )

    for key in "${!SSH_OPTS[@]}"; do
        val="${SSH_OPTS[$key]}"
        if grep -qE "^#?${key}" /etc/ssh/sshd_config; then
            sed -i "s/^#\?${key}.*/${key} ${val}/" /etc/ssh/sshd_config
        else
            echo "${key} ${val}" >> /etc/ssh/sshd_config
        fi
    done

    sed -i '/AllowUsers youruser/d' /etc/ssh/sshd_config

    systemctl restart "$SSH_SERVICE" 2>/dev/null && success "SSH перезапущен на порту $SSH_PORT" \
        || error "Ошибка перезапуска SSH. Проверьте: sshd -t"
}

# ── Фаервол (nftables) ───────────────────────────────────────

setup_firewall() {
    header "Настройка nftables"

    apt-get install -y nftables > /dev/null 2>&1

    # Автооткат на 2 минуты
    if command -v at &>/dev/null; then
        echo "nft flush ruleset" | at now + 2 minutes 2>/dev/null
        ROLLBACK_JOB=$(atq 2>/dev/null | tail -1 | awk '{print $1}')
        warn "Автооткат запланирован на 2 мин. Если всё ок — скрипт отменит сам."
    fi

    # Собираем правила для дополнительных портов
    EXTRA_RULES=""
    for i in "${!EXTRA_PORTS[@]}"; do
        port="${EXTRA_PORTS[$i]}"
        ip="${EXTRA_IPS[$i]}"
        proto="${EXTRA_PROTO[$i]}"

        add_rule() {
            local p="$1"
            if [[ -n "$ip" ]]; then
                EXTRA_RULES+="        ip saddr $ip $p dport $port accept\n"
            else
                EXTRA_RULES+="        $p dport $port accept\n"
            fi
        }

        case "$proto" in
            tcp)  add_rule "tcp" ;;
            udp)  add_rule "udp" ;;
            *)    add_rule "tcp"; add_rule "udp" ;;
        esac
    done

    if [[ "$USE_KNOCK" == true ]]; then
        SSH_RULE="# SSH открывается через port knocking (knockd)"
    else
        SSH_RULE="ip saddr $ADMIN_IP tcp dport $SSH_PORT accept"
    fi

    cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset

define ADMIN_IP = $ADMIN_IP

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept

        # SSH
        $SSH_RULE

$(echo -e "$EXTRA_RULES")
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

    nft -f /etc/nftables.conf && success "Правила nftables применены" \
        || { error "Ошибка применения правил nftables!"; return 1; }

    systemctl enable nftables > /dev/null 2>&1
    success "nftables включён в автозагрузку"

    if [[ -n "$ROLLBACK_JOB" ]]; then
        atrm "$ROLLBACK_JOB" 2>/dev/null && success "Автооткат отменён — правила стабильны"
    fi
}

# ── sysctl hardening ─────────────────────────────────────────

setup_sysctl() {
    header "Сетевой hardening (sysctl)"

    cp /etc/sysctl.conf /etc/sysctl.conf.bak

    cat >> /etc/sysctl.conf << 'EOF'

# === VPN Node Hardening ===
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.ip_default_ttl = 128
EOF

    sysctl -p > /dev/null 2>&1 && success "sysctl применён" \
        || warn "Некоторые параметры sysctl не применились"
}

# ── Port Knocking ────────────────────────────────────────────

setup_knockd() {
    header "Настройка Port Knocking"

    apt-get install -y knockd > /dev/null 2>&1

    read -ra KNOCK_PORTS <<< "$KNOCK_SEQ"
    OPEN_SEQ=$(IFS=','; echo "${KNOCK_PORTS[*]}")
    CLOSE_PORTS=()
    for (( i=${#KNOCK_PORTS[@]}-1; i>=0; i-- )); do
        CLOSE_PORTS+=("${KNOCK_PORTS[$i]}")
    done
    CLOSE_SEQ=$(IFS=','; echo "${CLOSE_PORTS[*]}")

    cat > /etc/knockd.conf << EOF
[options]
    UseSyslog

[openSSH]
    sequence    = $OPEN_SEQ
    seq_timeout = 5
    command     = /sbin/nft add rule inet filter input ip saddr %IP% tcp dport $SSH_PORT accept
    tcpflags    = syn

[closeSSH]
    sequence    = $CLOSE_SEQ
    seq_timeout = 5
    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport $SSH_PORT -j ACCEPT
    tcpflags    = syn
EOF

    IFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    if [[ -f /etc/default/knockd ]]; then
        sed -i "s/^START_KNOCKD=.*/START_KNOCKD=1/" /etc/default/knockd
        sed -i "s|^KNOCKD_OPTS=.*|KNOCKD_OPTS=\"-i $IFACE\"|" /etc/default/knockd
    fi

    systemctl enable knockd --now 2>/dev/null && success "knockd запущен" \
        || warn "knockd не запустился, проверьте: systemctl status knockd"

    echo ""
    info "Для подключения с Windows — knock.ps1:"
    echo -e "  ${CYAN}knock <IP> ${KNOCK_PORTS[*]} && ssh -p $SSH_PORT user@<IP>${NC}"
}

# ── Fail2Ban ─────────────────────────────────────────────────

setup_fail2ban() {
    header "Настройка Fail2Ban"

    apt-get install -y fail2ban > /dev/null 2>&1

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port    = $SSH_PORT
EOF

    systemctl enable fail2ban --now 2>/dev/null && success "Fail2Ban запущен" \
        || warn "Fail2Ban не запустился"
}

# ── Итог ─────────────────────────────────────────────────────

print_summary() {
    header "Готово!"

    echo -e "  ${GREEN}✔${NC} SSH порт       : $SSH_PORT"
    echo -e "  ${GREEN}✔${NC} Управляющий IP : $ADMIN_IP"
    for i in "${!EXTRA_PORTS[@]}"; do
        echo -e "  ${GREEN}✔${NC} Открытый порт : ${EXTRA_PORTS[$i]} | IP: ${EXTRA_IPS[$i]:-любой} | ${EXTRA_PROTO[$i]}"
    done
    [[ "$USE_KNOCK" == true ]] && echo -e "  ${GREEN}✔${NC} Port knocking  : $KNOCK_SEQ"
    [[ "$USE_FAIL2BAN" == true ]] && echo -e "  ${GREEN}✔${NC} Fail2Ban       : активен"
    echo ""
    warn "Бэкапы сохранены: /etc/ssh/sshd_config.bak | /etc/sysctl.conf.bak"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────

main() {
    check_root
    collect_config
    setup_ssh
    setup_firewall
    setup_sysctl
    [[ "$USE_KNOCK" == true ]]    && setup_knockd
    [[ "$USE_FAIL2BAN" == true ]] && setup_fail2ban
    print_summary
}

main
