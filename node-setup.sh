#!/bin/bash

# ============================================================
#  VPN Node Firewall Setup Script (Tailscale edition)
#  v2.4 — подкоманды: setup / add-port / list / install
#
#  Использование:
#    sudo bash node-setup.sh            — полная первичная настройка
#    sudo bash node-setup.sh install    — установить как 'vpnctl'
#    vpnctl add-port                    — быстро добавить порт
#    vpnctl list                        — список открытых портов
#    vpnctl help                        — справка
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

EXTRA_PROTO=()
EXTRA_PORTS=()
EXTRA_IPS=()
USE_FAIL2BAN=false
SSH_PUBKEY=""
INSTALL_DOCKER=false
INSTALL_REMNAWAVE=false

NFTABLES_CONF="/etc/nftables.conf"
VPNCTL_BIN="/usr/local/bin/vpnctl"

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC}   $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERR]${NC}  $1"; }
header()  {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════${NC}\n"
}

ask() {
    local prompt="$1" default="$2" result
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${YELLOW}")${prompt} [${default}]: $(echo -e "${NC}")" result
        echo "${result:-$default}"
    else
        read -rp "$(echo -e "${YELLOW}")${prompt}: $(echo -e "${NC}")" result
        echo "$result"
    fi
}

ask_yn() {
    local prompt="$1" default="${2:-y}" result
    read -rp "$(echo -e "${YELLOW}")${prompt} [y/n] (${default}): $(echo -e "${NC}")" result
    result="${result:-$default}"
    [[ "${result,,}" == "y" ]]
}

validate_ip() {
    local ip="$1"
    # Принимаем одиночный IP и CIDR (например 10.0.0.0/8)
    local addr="${ip%%/*}"
    [[ "$addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -ra parts <<< "$addr"
    for part in "${parts[@]}"; do
        [[ "$part" -gt 255 ]] && return 1
    done
    return 0
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 ]] && [[ "$1" -le 65535 ]]
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Нужны права root. Используйте: sudo $0 ${1:-}"
        exit 1
    fi
}

# ════════════════════════════════════════════════════════════
#  ПОДКОМАНДА: install
#  Копирует скрипт в /usr/local/bin/vpnctl
# ════════════════════════════════════════════════════════════

cmd_install() {
    check_root

    SCRIPT_SRC="$(realpath "$0")"

    if [[ "$SCRIPT_SRC" != "$VPNCTL_BIN" ]]; then
        cp "$SCRIPT_SRC" "$VPNCTL_BIN"
        chmod +x "$VPNCTL_BIN"
        success "Установлено: $VPNCTL_BIN"
    else
        success "Уже установлено: $VPNCTL_BIN"
    fi

    echo ""
    echo -e "${BOLD}Доступные команды:${NC}"
    echo -e "  ${GREEN}vpnctl${NC}              — полная первичная настройка"
    echo -e "  ${GREEN}vpnctl add-port${NC}     — быстро добавить порт/IP в фаервол"
    echo -e "  ${GREEN}vpnctl list${NC}         — показать открытые порты"
    echo -e "  ${GREEN}vpnctl help${NC}         — справка"
    echo ""
}

# ════════════════════════════════════════════════════════════
#  ПОДКОМАНДА: list
#  Показывает текущие правила nftables
# ════════════════════════════════════════════════════════════

cmd_list() {
    check_root
    header "Открытые порты"

    if ! command -v nft &>/dev/null; then
        error "nftables не установлен"
        exit 1
    fi

    echo -e "${BOLD}Live-правила (inet filter · input):${NC}"
    echo ""
    nft list chain inet filter input 2>/dev/null \
        | grep -E 'dport|saddr|iif|policy' \
        | sed \
            -e 's/^[[:space:]]*/  /' \
            -e "s/accept/${GREEN}accept${NC}/g" \
            -e "s/\bdrop\b/${RED}drop${NC}/g" \
            -e "s/\btcp\b/${CYAN}tcp${NC}/g" \
            -e "s/\budp\b/${CYAN}udp${NC}/g" \
        || warn "Правила не найдены или nftables не запущен"

    echo ""

    if [[ -f "$NFTABLES_CONF" ]]; then
        echo -e "${BOLD}Персистентные правила ($NFTABLES_CONF):${NC}"
        echo ""
        grep -E '^\s+(tcp|udp|ip saddr).*(dport|accept)' "$NFTABLES_CONF" \
            | grep -v '#.*SSH\|#.*ssh' \
            | sed 's/^[[:space:]]*/  /' \
            || info "Дополнительных портов не найдено"
        echo ""
    fi
}

# ════════════════════════════════════════════════════════════
#  ПОДКОМАНДА: add-port
#  Добавляет порт в live-nftables и персистентный конфиг
# ════════════════════════════════════════════════════════════

cmd_add_port() {
    check_root
    header "Добавить порт"

    if ! command -v nft &>/dev/null; then
        error "nftables не установлен. Сначала выполните полную настройку."
        exit 1
    fi

    if [[ ! -f "$NFTABLES_CONF" ]]; then
        error "Конфиг $NFTABLES_CONF не найден. Сначала выполните полную настройку."
        exit 1
    fi

    # ── Сбор параметров ──────────────────────────────────────
    while true; do
        PORT=$(ask "Порт")
        validate_port "$PORT" && break
        error "Некорректный порт (1–65535)."
    done

    SRC_IP=$(ask "Источник: IP, CIDR или Enter = любой")
    if [[ -n "$SRC_IP" ]] && ! validate_ip "$SRC_IP"; then
        warn "Некорректный IP/CIDR — порт будет открыт для всех."
        SRC_IP=""
    fi

    PROTO=$(ask "Протокол" "both")
    case "$PROTO" in
        tcp|udp|both) ;;
        *) warn "Неизвестный протокол, используем both"; PROTO="both" ;;
    esac

    COMMENT=$(ask "Комментарий (необязательно)")

    # ── Формируем правила ────────────────────────────────────
    make_rule() {
        local p="$1"
        if [[ -n "$SRC_IP" ]]; then
            echo "ip saddr $SRC_IP $p dport $PORT accept"
        else
            echo "$p dport $PORT accept"
        fi
    }

    declare -a RULES=()
    case "$PROTO" in
        tcp)  RULES+=("$(make_rule tcp)") ;;
        udp)  RULES+=("$(make_rule udp)") ;;
        both) RULES+=("$(make_rule tcp)" "$(make_rule udp)") ;;
    esac

    # ── Превью ───────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}Будут добавлены правила:${NC}"
    for r in "${RULES[@]}"; do
        echo -e "  ${GREEN}+${NC} $r"
    done
    echo ""
    ask_yn "Применить?" "y" || { warn "Отменено."; return 0; }

    # ── Live-применение ──────────────────────────────────────
    APPLIED=0
    for rule in "${RULES[@]}"; do
        if nft add rule inet filter input $rule 2>/dev/null; then
            success "Live: $rule"
            APPLIED=$((APPLIED + 1))
        else
            error "Live-применение не удалось: $rule"
        fi
    done

    # ── Запись в конфиг ──────────────────────────────────────
    # Резервная копия
    cp "$NFTABLES_CONF" "${NFTABLES_CONF}.bak.$(date +%s)"

    # Формируем блок строк для вставки
    BLOCK=""
    [[ -n "$COMMENT" ]] && BLOCK+="        # ${COMMENT}\n"
    for rule in "${RULES[@]}"; do
        BLOCK+="        ${rule}\n"
    done

    # Вставляем перед первым 'drop' в таблице inet (не ip6)
    python3 - "$NFTABLES_CONF" "$BLOCK" << 'PYEOF'
import sys, re

path  = sys.argv[1]
block = sys.argv[2]   # уже содержит \n как escape-последовательности

with open(path) as f:
    content = f.read()

inet_pos = content.find('table inet')
if inet_pos == -1:
    sys.exit("ERR: table inet не найдена")

drop_m = re.search(r'^        drop$', content[inet_pos:], re.MULTILINE)
if not drop_m:
    sys.exit("ERR: drop не найден в inet filter")

ins = inet_pos + drop_m.start()
# Раскрываем escape \n в реальные переносы строк
block_real = block.replace('\\n', '\n')
new = content[:ins] + block_real + content[ins:]

with open(path, 'w') as f:
    f.write(new)
PYEOF

    if [[ $? -eq 0 ]]; then
        success "Конфиг обновлён: $NFTABLES_CONF"
    else
        error "Не удалось обновить конфиг автоматически."
        warn "Добавьте вручную в $NFTABLES_CONF перед строкой 'drop':"
        for rule in "${RULES[@]}"; do
            echo "        $rule"
        done
        return 1
    fi

    # ── Итог ─────────────────────────────────────────────────
    echo ""
    if [[ $APPLIED -gt 0 ]]; then
        success "Порт $PORT ($PROTO${SRC_IP:+ ← $SRC_IP}) активен и сохранён."
    else
        warn "Записано в конфиг, но live-применение не удалось."
        warn "Перезапустите: systemctl restart nftables"
    fi
    info "Просмотр: vpnctl list"
    echo ""
}

# ════════════════════════════════════════════════════════════
#  ПОДКОМАНДА: help
# ════════════════════════════════════════════════════════════

cmd_help() {
    echo ""
    echo -e "${BOLD}${CYAN}vpnctl — управление VPN нодой${NC}"
    echo ""
    echo -e "  ${GREEN}vpnctl${NC}              Полная первичная настройка сервера"
    echo -e "  ${GREEN}vpnctl install${NC}      Установить как системную команду vpnctl"
    echo -e "  ${GREEN}vpnctl add-port${NC}     Быстро добавить порт + IP в фаервол"
    echo -e "  ${GREEN}vpnctl list${NC}         Показать активные правила фаервола"
    echo -e "  ${GREEN}vpnctl help${NC}         Эта справка"
    echo ""
    echo -e "  ${CYAN}Алиасы:${NC} add = add-port, ls = list"
    echo ""
}

# ════════════════════════════════════════════════════════════
#  ПОЛНАЯ ПЕРВИЧНАЯ НАСТРОЙКА
# ════════════════════════════════════════════════════════════

setup_tailscale() {
    header "Настройка Tailscale"

    if ! command -v tailscale &>/dev/null; then
        info "Tailscale не найден — устанавливаем..."
        curl -fsSL https://tailscale.com/install.sh | sh
        command -v tailscale &>/dev/null \
            || { error "Не удалось установить Tailscale."; exit 1; }
        success "Tailscale установлен"
    else
        success "Tailscale уже установлен"
    fi

    systemctl is-active --quiet tailscaled 2>/dev/null \
        || systemctl enable tailscaled --now 2>/dev/null

    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null)

    if [[ -z "$TAILSCALE_IP" ]]; then
        info "Нода не авторизована — запускаем авторизацию..."
        tailscale up --shields-up
        for i in {1..15}; do
            TAILSCALE_IP=$(tailscale ip -4 2>/dev/null)
            [[ -n "$TAILSCALE_IP" ]] && break
            sleep 2
        done
    else
        tailscale set --shields-up 2>/dev/null || true
    fi

    [[ -n "$TAILSCALE_IP" ]] \
        || { error "Не удалось получить Tailscale IP."; exit 1; }

    success "Tailscale IP: $TAILSCALE_IP"
}

collect_config() {
    header "Настройка ноды — сбор параметров"

    while true; do
        ADMIN_IP=$(ask "Tailscale IP вашего управляющего компьютера (Windows)")
        validate_ip "$ADMIN_IP" && break
        error "Некорректный IP."
    done

    while true; do
        SSH_PORT=$(ask "Новый порт SSH (рекомендуется 49152–65535)" "51822")
        validate_port "$SSH_PORT" && break
        error "Некорректный порт."
    done

    header "Дополнительные порты"

    while true; do
        ask_yn "Добавить порт?" || break

        while true; do
            port=$(ask "Порт")
            validate_port "$port" && break
            error "Некорректный порт."
        done

        ip_for_port=$(ask "Разрешённый IP (Enter = любой)")
        if [[ -n "$ip_for_port" ]] && ! validate_ip "$ip_for_port"; then
            error "Некорректный IP — порт будет открыт для всех."
            ip_for_port=""
        fi

        proto=$(ask "Протокол: tcp / udp / both" "both")
        EXTRA_PORTS+=("$port")
        EXTRA_IPS+=("$ip_for_port")
        EXTRA_PROTO+=("$proto")
        success "Порт $port (IP: ${ip_for_port:-любой}, $proto)"
    done

    ask_yn "Установить Fail2Ban?" "y" && USE_FAIL2BAN=true
    ask_yn "Установить Docker?"   "y" && INSTALL_DOCKER=true
    [[ "$INSTALL_DOCKER" == true ]] \
        && ask_yn "Установить Remnawave Node?" "y" && INSTALL_REMNAWAVE=true

    header "SSH ключ для доступа"
    info "Скрипт отключит вход по паролю — нужен ваш публичный SSH ключ."
    info "Termius → Settings → Keychain → Copy Public Key"
    info "Или: cat ~/.ssh/id_ed25519.pub"
    echo ""

    while true; do
        read -rp "$(echo -e "${YELLOW}")Вставьте публичный ключ: $(echo -e "${NC}")" SSH_PUBKEY
        if [[ "$SSH_PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ssh-ecdsa|ecdsa-sha2-nistp256)[[:space:]]+[A-Za-z0-9+/=]+ ]]; then
            success "Ключ принят"
            break
        fi
        error "Неверный формат."
        ask_yn "Попробовать снова?" || { warn "Ключ не добавлен!"; SSH_PUBKEY=""; break; }
    done

    header "Итог"
    echo -e "  Tailscale IP ноды    : ${GREEN}$TAILSCALE_IP${NC}"
    echo -e "  Управляющий IP       : ${GREEN}$ADMIN_IP${NC}"
    echo -e "  SSH порт             : ${GREEN}$SSH_PORT${NC}"
    for i in "${!EXTRA_PORTS[@]}"; do
        echo -e "  Порт                 : ${GREEN}${EXTRA_PORTS[$i]}${NC} | IP: ${EXTRA_IPS[$i]:-любой} | ${EXTRA_PROTO[$i]}"
    done
    echo -e "  Fail2Ban / Docker    : ${GREEN}$USE_FAIL2BAN${NC} / ${GREEN}$INSTALL_DOCKER${NC}"
    [[ -n "$SSH_PUBKEY" ]] \
        && echo -e "  SSH ключ             : ${GREEN}${SSH_PUBKEY:0:40}...${NC}" \
        || echo -e "  SSH ключ             : ${RED}НЕ ДОБАВЛЕН${NC}"
    echo ""

    ask_yn "Применить настройки?" "y" || { warn "Отменено."; exit 0; }
}

setup_ssh() {
    header "Настройка SSH"

    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        systemctl stop ssh.socket 2>/dev/null
        systemctl disable ssh.socket 2>/dev/null
        success "ssh.socket отключён"
    fi

    systemctl enable ssh.service 2>/dev/null
    SSH_SERVICE=$(systemctl list-units --type=service 2>/dev/null | grep -oE 'ssh(d)?\.service' | head -1)
    SSH_SERVICE=${SSH_SERVICE:-ssh}

    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    sshd_set() {
        local key="$1" val="$2"
        sed -i "/^[[:space:]]*#\?[[:space:]]*${key}[[:space:]]/d" /etc/ssh/sshd_config
        echo "${key} ${val}" >> /etc/ssh/sshd_config
    }

    sshd_set "Port"                   "$SSH_PORT"
    sshd_set "PermitRootLogin"        "yes"
    sshd_set "PasswordAuthentication" "no"
    sshd_set "PubkeyAuthentication"   "yes"
    sshd_set "MaxAuthTries"           "3"
    sshd_set "LoginGraceTime"         "20"
    sshd_set "X11Forwarding"          "no"
    sshd_set "AllowAgentForwarding"   "no"
    sshd_set "AllowTcpForwarding"     "no"
    sshd_set "Banner"                 "none"
    sshd_set "ClientAliveInterval"    "300"
    sshd_set "ClientAliveCountMax"    "2"

    sshd -T 2>/dev/null | grep -qi "debianbanner" && sshd_set "DebianBanner" "no"

    WANT_KEX="curve25519-sha256,curve25519-sha256@libssh.org"
    WANT_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"
    WANT_MACS="hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"

    TEST_CONF=$(mktemp)
    printf "Port 22\nKexAlgorithms %s\nCiphers %s\nMACs %s\n" \
        "$WANT_KEX" "$WANT_CIPHERS" "$WANT_MACS" > "$TEST_CONF"

    if sshd -t -f "$TEST_CONF" 2>/dev/null; then
        sshd_set "KexAlgorithms" "$WANT_KEX"
        sshd_set "Ciphers"       "$WANT_CIPHERS"
        sshd_set "MACs"          "$WANT_MACS"
        success "Криптоалгоритмы применены"
    else
        for pair in "KexAlgorithms $WANT_KEX" "Ciphers $WANT_CIPHERS" "MACs $WANT_MACS"; do
            TF=$(mktemp); echo "$pair" > "$TF"
            sshd -t -f "$TF" 2>/dev/null && sshd_set ${pair% *} "${pair#* }"
            rm -f "$TF"
        done
    fi
    rm -f "$TEST_CONF"

    SSHD_CHECK=$(sshd -t 2>&1)
    if [[ $? -ne 0 ]]; then
        error "Ошибка конфига sshd — восстанавливаем бэкап:"
        echo "$SSHD_CHECK" | while IFS= read -r line; do error "  $line"; done
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        systemctl restart "$SSH_SERVICE" 2>/dev/null
        exit 1
    fi

    systemctl restart "$SSH_SERVICE" 2>/dev/null \
        && success "SSH перезапущен на порту $SSH_PORT" \
        || { error "Ошибка перезапуска SSH"; exit 1; }

    sleep 2
    ss -tlnp | grep -q ":$SSH_PORT" \
        && success "SSH слушает на порту $SSH_PORT" \
        || warn "Проверьте: ss -tlnp | grep ssh"
}

setup_authorized_keys() {
    header "SSH ключ"
    [[ -z "$SSH_PUBKEY" ]] && { warn "Ключ не указан — пропускаем."; return; }

    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    grep -qF "$SSH_PUBKEY" /root/.ssh/authorized_keys 2>/dev/null \
        && warn "Ключ уже есть" \
        || { echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; success "Ключ добавлен в /root/.ssh/authorized_keys"; }

    TARGET_USER="${SUDO_USER:-}"
    if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
        TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
        if [[ -n "$TARGET_HOME" ]]; then
            mkdir -p "$TARGET_HOME/.ssh" && chmod 700 "$TARGET_HOME/.ssh"
            grep -qF "$SSH_PUBKEY" "$TARGET_HOME/.ssh/authorized_keys" 2>/dev/null \
                || { echo "$SSH_PUBKEY" >> "$TARGET_HOME/.ssh/authorized_keys"; chmod 600 "$TARGET_HOME/.ssh/authorized_keys"; chown -R "$TARGET_USER:$TARGET_USER" "$TARGET_HOME/.ssh"; success "Ключ добавлен в $TARGET_HOME/.ssh/authorized_keys"; }
        fi
    fi
}

setup_firewall() {
    header "Настройка nftables"
    apt-get install -y nftables > /dev/null 2>&1

    if command -v at &>/dev/null; then
        echo "nft flush ruleset" | at now + 2 minutes 2>/dev/null
        ROLLBACK_JOB=$(atq 2>/dev/null | tail -1 | awk '{print $1}')
    fi

    EXTRA_RULES=""
    for i in "${!EXTRA_PORTS[@]}"; do
        port="${EXTRA_PORTS[$i]}"
        ip="${EXTRA_IPS[$i]}"
        proto="${EXTRA_PROTO[$i]}"
        add_rule() {
            [[ -n "$ip" ]] \
                && EXTRA_RULES+="        ip saddr $ip $1 dport $port accept\n" \
                || EXTRA_RULES+="        $1 dport $port accept\n"
        }
        case "$proto" in
            tcp)  add_rule "tcp" ;;
            udp)  add_rule "udp" ;;
            *)    add_rule "tcp"; add_rule "udp" ;;
        esac
    done

    cat > "$NFTABLES_CONF" << EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept
        ct state invalid drop

        # ICMP: блокируем ping и диагностику
        ip protocol icmp icmp type { echo-request, echo-reply, timestamp-request, timestamp-reply, address-mask-request, address-mask-reply } drop
        ip protocol icmp accept

        # Tailscale — полный доступ внутри mesh
        iif "tailscale0" accept

        # SSH только с управляющего Tailscale IP + rate limit
        ip saddr $ADMIN_IP tcp dport $SSH_PORT ct state new limit rate 5/minute accept
        ip saddr $ADMIN_IP tcp dport $SSH_PORT drop

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

# IPv6: полная блокировка
table ip6 filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
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

    nft -f "$NFTABLES_CONF" \
        && success "Правила nftables применены" \
        || { error "Ошибка nftables!"; return 1; }

    systemctl enable nftables > /dev/null 2>&1
    [[ -n "${ROLLBACK_JOB:-}" ]] && atrm "$ROLLBACK_JOB" 2>/dev/null && success "Автооткат отменён"
}

setup_sysctl() {
    header "Сетевой hardening (sysctl)"
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    sed -i '/# === VPN Node Hardening ===/,/^$/d' /etc/sysctl.conf

    cat >> /etc/sysctl.conf << 'EOF'

# === VPN Node Hardening ===
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv4.ip_default_ttl = 128
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
net.core.somaxconn = 1024
EOF

    sysctl -p > /dev/null 2>&1 && success "sysctl применён" || warn "Часть параметров не применилась"
}

setup_fail2ban() {
    header "Fail2Ban"
    apt-get install -y fail2ban > /dev/null 2>&1

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = 86400
findtime = 300
maxretry = 3
banaction = nftables-drop
banaction_allports = nftables-allports

[sshd]
enabled  = true
port     = $SSH_PORT
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = 3
EOF

    systemctl enable fail2ban --now 2>/dev/null \
        && success "Fail2Ban запущен" \
        || warn "Fail2Ban не запустился — проверьте логи"
}

setup_docker() {
    header "Docker"
    command -v docker &>/dev/null \
        && { success "Docker уже установлен"; return; }

    curl -fsSL https://get.docker.com | sh > /dev/null 2>&1
    command -v docker &>/dev/null \
        || { error "Не удалось установить Docker"; return 1; }

    systemctl enable docker --now 2>/dev/null
    success "Docker установлен ($(docker --version))"
    docker compose version &>/dev/null \
        && success "Docker Compose: $(docker compose version)" \
        || warn "Docker Compose не найден"
}

setup_remnawave() {
    header "Remnawave Node"
    REMNA_DIR="/opt/remnanode"
    mkdir -p "$REMNA_DIR"
    cd "$REMNA_DIR" || { error "Не удалось перейти в $REMNA_DIR"; return 1; }

    echo -e "\n${YELLOW}Remnawave → Nodes → '+' → Copy docker-compose.yml → вставьте в nano${NC}\n"
    read -rp "$(echo -e "${YELLOW}")Нажмите Enter чтобы открыть nano...$(echo -e "${NC}")"
    nano docker-compose.yml

    [[ -f "docker-compose.yml" ]] \
        || { error "docker-compose.yml не найден"; return 1; }

    docker compose up -d && docker compose logs -f -t
    success "Remnawave Node запущен"
}

setup_stealth_extras() {
    header "Stealth"
    NEW_HOSTNAME="srv-$(head -c4 /dev/urandom | xxd -p)"
    hostnamectl set-hostname "$NEW_HOSTNAME" 2>/dev/null && success "Hostname → $NEW_HOSTNAME"
    truncate -s 0 /etc/motd 2>/dev/null
    echo "" > /etc/issue 2>/dev/null
    echo "" > /etc/issue.net 2>/dev/null
    for svc in avahi-daemon cups bluetooth ModemManager; do
        systemctl is-active --quiet "$svc" 2>/dev/null \
            && systemctl disable --now "$svc" 2>/dev/null \
            && info "Отключён: $svc"
    done
    success "Stealth-режим применён"
}

print_summary() {
    header "Готово!"

    echo -e "  ${GREEN}✔${NC} Tailscale IP  : $TAILSCALE_IP"
    echo -e "  ${GREEN}✔${NC} SSH порт      : $SSH_PORT"
    for i in "${!EXTRA_PORTS[@]}"; do
        echo -e "  ${GREEN}✔${NC} Порт          : ${EXTRA_PORTS[$i]} | IP: ${EXTRA_IPS[$i]:-любой} | ${EXTRA_PROTO[$i]}"
    done
    [[ "$USE_FAIL2BAN"     == true ]] && echo -e "  ${GREEN}✔${NC} Fail2Ban      : активен"
    [[ "$INSTALL_DOCKER"   == true ]] && echo -e "  ${GREEN}✔${NC} Docker        : установлен"
    [[ "$INSTALL_REMNAWAVE" == true ]] && echo -e "  ${GREEN}✔${NC} Remnawave     : запущен"
    [[ -n "$SSH_PUBKEY" ]] \
        && echo -e "  ${GREEN}✔${NC} SSH ключ      : добавлен" \
        || echo -e "  ${RED}✘${NC} SSH ключ      : НЕ ДОБАВЛЕН"

    echo ""
    echo -e "  ${CYAN}Stealth:${NC} ping↓  IPv6↓  timestamps↓  TTL=128  баннер скрыт"
    echo -e "  ${CYAN}Подключение:${NC} ${GREEN}$TAILSCALE_IP${NC} : ${GREEN}$SSH_PORT${NC}"
    echo ""
    warn "Бэкапы: /etc/ssh/sshd_config.bak | /etc/sysctl.conf.bak"
    warn "Проверьте SSH до закрытия сессии!"
    echo ""

    if [[ ! -f "$VPNCTL_BIN" ]]; then
        echo -e "${CYAN}[СОВЕТ]${NC} Установите удобную команду:"
        echo -e "  ${GREEN}sudo vpnctl install${NC}"
        echo -e "  Затем: ${GREEN}vpnctl add-port${NC}  /  ${GREEN}vpnctl list${NC}"
        echo ""
    fi
}

main_setup() {
    check_root
    setup_tailscale
    collect_config
    setup_ssh
    setup_authorized_keys
    setup_firewall
    setup_sysctl
    setup_stealth_extras
    [[ "$USE_FAIL2BAN"     == true ]] && setup_fail2ban
    [[ "$INSTALL_DOCKER"   == true ]] && setup_docker
    [[ "$INSTALL_REMNAWAVE"== true ]] && setup_remnawave
    print_summary
}

# ════════════════════════════════════════════════════════════
#  РОУТИНГ КОМАНД
# ════════════════════════════════════════════════════════════

case "${1:-}" in
    add-port|add)   cmd_add_port ;;
    list|ls)        cmd_list     ;;
    install)        cmd_install  ;;
    help|--help|-h) cmd_help     ;;
    "")             main_setup   ;;
    *)
        error "Неизвестная команда: $1"
        cmd_help
        exit 1
        ;;
esac
