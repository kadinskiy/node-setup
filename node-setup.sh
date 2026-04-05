#!/bin/bash

# ============================================================
#  VPN Node Firewall Setup Script (Tailscale edition)
#  v2.6.1 — подкоманды: setup / add-port / remove-port / list / install
#
#  Использование:
#    sudo bash node-setup.sh             — полная первичная настройка
#    sudo bash node-setup.sh add-port    — быстро добавить порт/IP в фаервол
#    sudo bash node-setup.sh remove-port — удалить правило порта/IP из фаервола
#    sudo bash node-setup.sh install     — обновить / переустановить vpnctl
#    vpnctl add-port                     — быстро добавить порт/IP в фаервол
#    vpnctl remove-port                  — удалить правило порта/IP из фаервола
#    vpnctl list                         — список открытых портов
#    vpnctl help                         — справка
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
    local prompt="$1" default="${2:-}" result
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${YELLOW}")${prompt} [${default}]: $(echo -e "${NC}")" result
        echo "${result:-$default}"
    else
        read -rp "$(echo -e "${YELLOW}")${prompt}: $(echo -e "${NC}")" result
        echo "$result"
    fi
}

# FIX: ask_yn теперь всегда завершается с кодом 0 на уровне вызова,
# чтобы set -e не убивал скрипт при ответе "n"
ask_yn() {
    local prompt="$1" default="${2:-y}" result
    read -rp "$(echo -e "${YELLOW}")${prompt} [y/n] (${default}): $(echo -e "${NC}")" result
    result="${result:-$default}"
    [[ "${result,,}" == "y" ]]
}

validate_ip() {
    local ip="$1"
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

ensure_prereqs_for_port_cmds() {
    if ! command -v nft &>/dev/null; then
        error "nftables не установлен. Сначала выполните полную настройку."
        exit 1
    fi

    if [[ ! -f "$NFTABLES_CONF" ]]; then
        error "Конфиг $NFTABLES_CONF не найден. Сначала выполните полную настройку."
        exit 1
    fi
}

ensure_self_installed() {
    check_root

    local script_src
    script_src="$(realpath "$0")"

    if [[ "$script_src" != "$VPNCTL_BIN" ]]; then
        cp "$script_src" "$VPNCTL_BIN"
        chmod +x "$VPNCTL_BIN"
        success "Команда vpnctl установлена: $VPNCTL_BIN"
    else
        success "Команда vpnctl уже доступна: $VPNCTL_BIN"
    fi
}

backup_nft_conf() {
    cp "$NFTABLES_CONF" "${NFTABLES_CONF}.bak.$(date +%s)"
}

normalize_nft_conf() {
    [[ -f "$NFTABLES_CONF" ]] || return 0

    python3 - "$NFTABLES_CONF" << 'PYEOF'
from pathlib import Path
import re
import sys

p = Path(sys.argv[1])
s = p.read_text(encoding='utf-8')
orig = s

# Чиним старую поломку вида: accept        drop
s = re.sub(r'(\baccept)\s+drop\b', r'\1\n        drop', s)
# На всякий случай: udp/tcp accept сразу перед закрывающей скобкой цепочки
s = re.sub(r'(\baccept)(\s*)(\n\s*\})', r'\1\n\3', s)

if s != orig:
    p.write_text(s, encoding='utf-8')
PYEOF
}

validate_nft_conf() {
    normalize_nft_conf
    nft -c -f "$NFTABLES_CONF" >/dev/null 2>&1
}

wait_for_apt() {
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
        info "apt занят (${waited}с), ждём освобождения блокировки..."
        sleep 2
        waited=$((waited + 2))
        if [[ $waited -ge 180 ]]; then
            warn "apt занят слишком долго. Проверьте: ps aux | egrep "apt|dpkg""
            return 1
        fi
    done
    return 0
}

apt_install_pkg() {
    local pkg="$1"
    wait_for_apt || return 1
    info "Устанавливаем пакет: $pkg"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
}

get_drop_handle() {
    nft -a list chain inet filter input 2>/dev/null \
        | grep -E '^[[:space:]]*drop([[:space:]]|$)' \
        | sed -n 's/.*# handle \([0-9][0-9]*\)$/\1/p' \
        | head -1
}

insert_live_rule_before_drop() {
    local rule="$1"
    local drop_handle
    drop_handle="$(get_drop_handle || true)"

    if [[ -n "$drop_handle" ]]; then
        nft insert rule inet filter input position "$drop_handle" $rule
    else
        nft add rule inet filter input $rule
    fi
}

get_rule_handles() {
    local rule="$1"
    nft -a list chain inet filter input 2>/dev/null \
        | grep -F -- "$rule" \
        | sed -n 's/.*# handle \([0-9][0-9]*\)$/\1/p'
}

live_rule_exists() {
    local rule="$1"
    nft list chain inet filter input 2>/dev/null | grep -Fq -- "$rule"
}

conf_rule_exists() {
    local rule="$1"
    grep -Fq -- "$rule" "$NFTABLES_CONF"
}

conf_insert_block_before_drop() {
    local block="$1"

    python3 - "$NFTABLES_CONF" "$block" << 'PYEOF'
import re
import sys

path = sys.argv[1]
block = sys.argv[2].replace('\\n', '\n')

with open(path, encoding='utf-8') as f:
    content = f.read()

pattern = re.compile(
    r'(table inet filter\s*\{.*?chain input\s*\{.*?)(^\s*drop\s*$)',
    re.DOTALL | re.MULTILINE,
)
match = pattern.search(content)
if not match:
    sys.exit('ERR: не найден terminal drop в table inet filter / chain input')

new_content = content[:match.start(2)] + block + content[match.start(2):]
with open(path, 'w', encoding='utf-8') as f:
    f.write(new_content)
PYEOF
}

conf_remove_rules_exact() {
    local joined="$1"

    python3 - "$NFTABLES_CONF" "$joined" << 'PYEOF'
import sys

path = sys.argv[1]
rules = {line for line in sys.argv[2].split('\\n') if line.strip()}

with open(path, encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    stripped = lines[i].strip()

    if stripped in rules:
        j = i
        while j < len(lines) and lines[j].strip() in rules:
            j += 1
        if new_lines and new_lines[-1].lstrip().startswith('#'):
            new_lines.pop()
        i = j
        continue

    new_lines.append(lines[i])
    i += 1

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
PYEOF
}

make_rule_for_values() {
    local src_ip="$1" proto="$2" port="$3"
    if [[ -n "$src_ip" ]]; then
        echo "ip saddr $src_ip $proto dport $port accept"
    else
        echo "$proto dport $port accept"
    fi
}

build_rules_for_values() {
    local src_ip="$1" proto="$2" port="$3"
    local -n out_ref=$4

    out_ref=()
    case "$proto" in
        tcp)  out_ref+=("$(make_rule_for_values "$src_ip" tcp "$port")") ;;
        udp)  out_ref+=("$(make_rule_for_values "$src_ip" udp "$port")") ;;
        both) out_ref+=("$(make_rule_for_values "$src_ip" tcp "$port")" "$(make_rule_for_values "$src_ip" udp "$port")") ;;
        *)    return 1 ;;
    esac
}

prompt_port_ip_proto() {
    local -n port_ref="$1" ip_ref="$2" proto_ref="$3"
    local tmp_port tmp_src_ip tmp_proto

    while true; do
        tmp_port=$(ask "Порт")
        if validate_port "$tmp_port"; then break; fi
        error "Некорректный порт (1–65535)."
    done

    tmp_src_ip=$(ask "Источник: IP, CIDR или Enter = любой")
    if [[ -n "$tmp_src_ip" ]] && ! validate_ip "$tmp_src_ip"; then
        warn "Некорректный IP/CIDR — будет использован режим 'любой'."
        tmp_src_ip=""
    fi

    tmp_proto=$(ask "Протокол" "both")
    case "$tmp_proto" in
        tcp|udp|both) ;;
        *) warn "Неизвестный протокол, используем both"; tmp_proto="both" ;;
    esac

    port_ref="$tmp_port"
    ip_ref="$tmp_src_ip"
    proto_ref="$tmp_proto"
}

# ════════════════════════════════════════════════════════════
#  ПОДКОМАНДА: install
# ════════════════════════════════════════════════════════════

cmd_install() {
    ensure_self_installed

    echo ""
    echo -e "${BOLD}Доступные команды:${NC}"
    echo -e "  ${GREEN}vpnctl${NC}               — полная первичная настройка"
    echo -e "  ${GREEN}vpnctl add-port${NC}      — быстро добавить порт/IP в фаервол"
    echo -e "  ${GREEN}vpnctl remove-port${NC}   — удалить правило порта/IP"
    echo -e "  ${GREEN}vpnctl list${NC}          — показать открытые порты"
    echo -e "  ${GREEN}vpnctl help${NC}          — справка"
    echo ""
}

# ════════════════════════════════════════════════════════════
#  ПОДКОМАНДА: list
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
# ════════════════════════════════════════════════════════════

cmd_add_port() {
    check_root
    ensure_prereqs_for_port_cmds
    header "Добавить порт"

    local port src_ip proto comment
    local -a rules=() missing_rules=()

    prompt_port_ip_proto port src_ip proto
    comment=$(ask "Комментарий (необязательно)")

    build_rules_for_values "$src_ip" "$proto" "$port" rules

    echo ""
    echo -e "${BOLD}Будут добавлены правила:${NC}"
    for r in "${rules[@]}"; do
        echo -e "  ${GREEN}+${NC} $r"
    done
    echo ""

    if ! ask_yn "Применить?" "y"; then
        warn "Отменено."
        return 0
    fi

    local applied=0
    for rule in "${rules[@]}"; do
        if live_rule_exists "$rule"; then
            warn "Live-правило уже существует: $rule"
        else
            if insert_live_rule_before_drop "$rule" 2>/dev/null; then
                success "Live: $rule"
                applied=$((applied + 1))
            else
                error "Live-применение не удалось: $rule"
            fi
        fi

        if conf_rule_exists "$rule"; then
            warn "В конфиге уже есть: $rule"
        else
            missing_rules+=("$rule")
        fi
    done

    if [[ ${#missing_rules[@]} -gt 0 ]]; then
        backup_nft_conf

        local block=""
        if [[ -n "$comment" ]]; then
            block+="        # ${comment}\n"
        fi
        for rule in "${missing_rules[@]}"; do
            block+="        ${rule}\n"
        done

        if conf_insert_block_before_drop "$block" && validate_nft_conf; then
            success "Конфиг обновлён: $NFTABLES_CONF"
        else
            error "Не удалось обновить конфиг автоматически. Восстанавливаю бэкап."
            local latest_bak
            latest_bak=$(ls -1t "${NFTABLES_CONF}.bak."* 2>/dev/null | head -1 || true)
            [[ -n "$latest_bak" ]] && cp "$latest_bak" "$NFTABLES_CONF"
            return 1
        fi
    else
        info "В конфиге новые строки не требовались"
    fi

    echo ""
    success "Порт $port ($proto${src_ip:+ ← $src_ip}) обработан."
    info "Просмотр: vpnctl list"
    echo ""
}

# ════════════════════════════════════════════════════════════
#  ПОДКОМАНДА: remove-port
# ════════════════════════════════════════════════════════════

cmd_remove_port() {
    check_root
    ensure_prereqs_for_port_cmds
    header "Удалить порт"

    local port src_ip proto
    local -a rules=()
    prompt_port_ip_proto port src_ip proto
    build_rules_for_values "$src_ip" "$proto" "$port" rules

    echo ""
    echo -e "${BOLD}Будут удалены правила:${NC}"
    for r in "${rules[@]}"; do
        echo -e "  ${RED}-${NC} $r"
    done
    echo ""

    if ! ask_yn "Удалить?" "y"; then
        warn "Отменено."
        return 0
    fi

    local removed_live=0 removed_conf=0

    for rule in "${rules[@]}"; do
        mapfile -t handles < <(get_rule_handles "$rule" || true)
        if [[ ${#handles[@]} -eq 0 ]]; then
            warn "Live-правило не найдено: $rule"
        else
            for h in "${handles[@]}"; do
                if nft delete rule inet filter input handle "$h" 2>/dev/null; then
                    success "Live удалён: $rule (handle $h)"
                    removed_live=$((removed_live + 1))
                else
                    warn "Не удалось удалить live-правило: $rule (handle $h)"
                fi
            done
        fi
    done

    backup_nft_conf
    conf_remove_rules_exact "$(printf '%s\n' "${rules[@]}")"
    if validate_nft_conf; then
        success "Конфиг обновлён: $NFTABLES_CONF"
        removed_conf=1
    else
        error "После удаления конфиг стал некорректным. Восстанавливаю бэкап."
        local latest_bak
        latest_bak=$(ls -1t "${NFTABLES_CONF}.bak."* 2>/dev/null | head -1 || true)
        [[ -n "$latest_bak" ]] && cp "$latest_bak" "$NFTABLES_CONF"
        return 1
    fi

    echo ""
    if [[ $removed_live -eq 0 ]]; then
        warn "Live-правила не были удалены. Если строки были только в конфиге — примените: systemctl restart nftables"
    fi
    if [[ $removed_conf -eq 1 ]]; then
        success "Порт $port ($proto${src_ip:+ ← $src_ip}) удалён из конфигурации"
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
    echo -e "  ${GREEN}vpnctl${NC}               Полная первичная настройка сервера"
    echo -e "  ${GREEN}vpnctl install${NC}       Обновить / переустановить системную команду vpnctl"
    echo -e "  ${GREEN}vpnctl add-port${NC}      Быстро добавить порт + IP в фаервол"
    echo -e "  ${GREEN}vpnctl remove-port${NC}   Удалить правило порта + IP из фаервола"
    echo -e "  ${GREEN}vpnctl list${NC}          Показать активные правила фаервола"
    echo -e "  ${GREEN}vpnctl help${NC}          Эта справка"
    echo ""
    echo -e "  ${CYAN}Алиасы:${NC} add = add-port, del/rm/remove = remove-port, ls = list"
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
        if ! command -v tailscale &>/dev/null; then
            error "Не удалось установить Tailscale."
            exit 1
        fi
        success "Tailscale установлен"
    else
        success "Tailscale уже установлен"
    fi

    if ! systemctl is-active --quiet tailscaled 2>/dev/null; then
        systemctl enable tailscaled --now 2>/dev/null || true
    fi

    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || true)

    if [[ -z "$TAILSCALE_IP" ]]; then
        info "Нода не авторизована — запускаем авторизацию..."
        tailscale up
        for i in {1..15}; do
            TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || true)
            if [[ -n "$TAILSCALE_IP" ]]; then break; fi
            sleep 2
        done
    fi
    # shields-up НЕ используем — он блокирует входящий SSH через Tailscale
    tailscale set --shields-up=false 2>/dev/null || true

    if [[ -z "$TAILSCALE_IP" ]]; then
        error "Не удалось получить Tailscale IP."
        exit 1
    fi

    success "Tailscale IP: $TAILSCALE_IP"
}

collect_config() {
    header "Настройка ноды — сбор параметров"

    while true; do
        ADMIN_IP=$(ask "Tailscale IP вашего управляющего компьютера (Windows)")
        if validate_ip "$ADMIN_IP"; then break; fi
        error "Некорректный IP."
    done

    while true; do
        SSH_PORT=$(ask "Новый порт SSH (рекомендуется 49152–65535)" "51822")
        if validate_port "$SSH_PORT"; then break; fi
        error "Некорректный порт."
    done

    header "Дополнительные порты"

    while true; do
        if ! ask_yn "Добавить порт?"; then break; fi

        while true; do
            port=$(ask "Порт")
            if validate_port "$port"; then break; fi
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

    if ask_yn "Установить Fail2Ban?" "y"; then
        USE_FAIL2BAN=true
    fi

    if ask_yn "Установить Docker?" "y"; then
        INSTALL_DOCKER=true
    fi

    if [[ "$INSTALL_DOCKER" == true ]]; then
        if ask_yn "Установить Remnawave Node?" "y"; then
            INSTALL_REMNAWAVE=true
        fi
    fi

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
        if ! ask_yn "Попробовать снова?"; then
            warn "Ключ не добавлен!"
            SSH_PUBKEY=""
            break
        fi
    done

    header "Итог"
    echo -e "  Tailscale IP ноды    : ${GREEN}$TAILSCALE_IP${NC}"
    echo -e "  Управляющий IP       : ${GREEN}$ADMIN_IP${NC}"
    echo -e "  SSH порт             : ${GREEN}$SSH_PORT${NC}"
    for i in "${!EXTRA_PORTS[@]}"; do
        echo -e "  Порт                 : ${GREEN}${EXTRA_PORTS[$i]}${NC} | IP: ${EXTRA_IPS[$i]:-любой} | ${EXTRA_PROTO[$i]}"
    done
    echo -e "  Fail2Ban / Docker    : ${GREEN}$USE_FAIL2BAN${NC} / ${GREEN}$INSTALL_DOCKER${NC}"
    if [[ -n "$SSH_PUBKEY" ]]; then
        echo -e "  SSH ключ             : ${GREEN}${SSH_PUBKEY:0:40}...${NC}"
    else
        echo -e "  SSH ключ             : ${RED}НЕ ДОБАВЛЕН${NC}"
    fi
    echo ""

    if ! ask_yn "Применить настройки?" "y"; then
        warn "Отменено."
        exit 0
    fi
}

setup_ssh() {
    header "Настройка SSH"

    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        systemctl stop ssh.socket 2>/dev/null || true
        systemctl disable ssh.socket 2>/dev/null || true
        success "ssh.socket отключён"
    fi

    systemctl enable ssh.service 2>/dev/null || true
    SSH_SERVICE=$(systemctl list-units --type=service 2>/dev/null | grep -oE 'ssh(d)?\.service' | head -1 || true)
    SSH_SERVICE=${SSH_SERVICE:-ssh}

    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    mkdir -p /run/sshd

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

    if sshd -T 2>/dev/null | grep -qi "debianbanner"; then
        sshd_set "DebianBanner" "no"
    fi

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
            TF=$(mktemp)
            echo "$pair" > "$TF"
            if sshd -t -f "$TF" 2>/dev/null; then
                sshd_set ${pair% *} "${pair#* }"
            fi
            rm -f "$TF"
        done
    fi
    rm -f "$TEST_CONF"

    SSHD_CHECK=$(sshd -t 2>&1) || true
    if ! sshd -t 2>/dev/null; then
        error "Ошибка конфига sshd — восстанавливаем бэкап:"
        echo "$SSHD_CHECK" | while IFS= read -r line; do error "  $line"; done
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        systemctl restart "$SSH_SERVICE" 2>/dev/null || true
        exit 1
    fi

    if systemctl restart "$SSH_SERVICE" 2>/dev/null; then
        success "SSH перезапущен на порту $SSH_PORT"
    else
        error "Ошибка перезапуска SSH"
        exit 1
    fi

    sleep 2
    if ss -tlnp | grep -q ":$SSH_PORT"; then
        success "SSH слушает на порту $SSH_PORT"
    else
        warn "Проверьте: ss -tlnp | grep ssh"
    fi
}

setup_authorized_keys() {
    header "SSH ключ"
    if [[ -z "$SSH_PUBKEY" ]]; then
        warn "Ключ не указан — пропускаем."
        return
    fi

    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    if grep -qF "$SSH_PUBKEY" /root/.ssh/authorized_keys 2>/dev/null; then
        warn "Ключ уже есть"
    else
        echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        success "Ключ добавлен в /root/.ssh/authorized_keys"
    fi

    TARGET_USER="${SUDO_USER:-}"
    if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
        TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6 || true)
        if [[ -n "$TARGET_HOME" ]]; then
            mkdir -p "$TARGET_HOME/.ssh" && chmod 700 "$TARGET_HOME/.ssh"
            if ! grep -qF "$SSH_PUBKEY" "$TARGET_HOME/.ssh/authorized_keys" 2>/dev/null; then
                echo "$SSH_PUBKEY" >> "$TARGET_HOME/.ssh/authorized_keys"
                chmod 600 "$TARGET_HOME/.ssh/authorized_keys"
                chown -R "$TARGET_USER:$TARGET_USER" "$TARGET_HOME/.ssh"
                success "Ключ добавлен в $TARGET_HOME/.ssh/authorized_keys"
            fi
        fi
    fi
}

setup_firewall() {
    header "Настройка nftables"

    if ! command -v nft &>/dev/null; then
        apt_install_pkg nftables || { error "Не удалось установить nftables"; return 1; }
    else
        success "nftables уже установлен"
    fi

    ROLLBACK_JOB=""
    if command -v at &>/dev/null; then
        info "Ставим временный автооткат правил на 2 минуты"
        echo "nft flush ruleset" | at now + 2 minutes 2>/dev/null || true
        ROLLBACK_JOB=$(atq 2>/dev/null | tail -1 | awk '{print $1}' || true)
    fi

    EXTRA_RULES=""
    for i in "${!EXTRA_PORTS[@]}"; do
        port="${EXTRA_PORTS[$i]}"
        ip="${EXTRA_IPS[$i]}"
        proto="${EXTRA_PROTO[$i]}"
        add_rule() {
            if [[ -n "$ip" ]]; then
                EXTRA_RULES+="        ip saddr $ip $1 dport $port accept\n"
            else
                EXTRA_RULES+="        $1 dport $port accept\n"
            fi
        }
        case "$proto" in
            tcp)  add_rule "tcp" ;;
            udp)  add_rule "udp" ;;
            *)    add_rule "tcp"; add_rule "udp" ;;
        esac
    done

    {
        printf '%s
' '#!/usr/sbin/nft -f'
        printf '%s
' 'flush ruleset'
        printf '
'
        printf '%s
' 'table inet filter {'
        printf '%s
' '    chain input {'
        printf '%s
' '        type filter hook input priority 0; policy drop;'
        printf '
'
        printf '%s
' '        iif "lo" accept'
        printf '%s
' '        ct state established,related accept'
        printf '%s
' '        ct state invalid drop'
        printf '
'
        printf '%s
' '        # ICMP: блокируем ping и диагностику'
        printf '%s
' '        ip protocol icmp icmp type { echo-request, echo-reply, timestamp-request, timestamp-reply, address-mask-request, address-mask-reply } drop'
        printf '%s
' '        ip protocol icmp accept'
        printf '
'
        printf '%s
' '        # Tailscale — полный доступ внутри mesh'
        printf '%s
' '        iif "tailscale0" accept'
        printf '
'
        printf '%s
' '        # SSH только с управляющего Tailscale IP + rate limit'
        printf '%s
' "        ip saddr $ADMIN_IP tcp dport $SSH_PORT ct state new limit rate 5/minute accept"
        printf '%s
' "        ip saddr $ADMIN_IP tcp dport $SSH_PORT drop"
        printf '
'
        if [[ -n "$EXTRA_RULES" ]]; then
            printf '%b' "$EXTRA_RULES"
        fi
        printf '%s
' '        drop'
        printf '%s
' '    }'
        printf '
'
        printf '%s
' '    chain forward {'
        printf '%s
' '        type filter hook forward priority 0; policy drop;'
        printf '%s
' '    }'
        printf '
'
        printf '%s
' '    chain output {'
        printf '%s
' '        type filter hook output priority 0; policy accept;'
        printf '%s
' '    }'
        printf '%s
' '}'
        printf '
'
        printf '%s
' '# IPv6: полная блокировка'
        printf '%s
' 'table ip6 filter {'
        printf '%s
' '    chain input {'
        printf '%s
' '        type filter hook input priority 0; policy drop;'
        printf '%s
' '        iif "lo" accept'
        printf '%s
' '        ct state established,related accept'
        printf '%s
' '        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept'
        printf '%s
' '        drop'
        printf '%s
' '    }'
        printf '%s
' '    chain forward {'
        printf '%s
' '        type filter hook forward priority 0; policy drop;'
        printf '%s
' '    }'
        printf '%s
' '    chain output {'
        printf '%s
' '        type filter hook output priority 0; policy accept;'
        printf '%s
' '    }'
        printf '%s
' '}'
    } > "$NFTABLES_CONF"

    normalize_nft_conf
    info "Проверяем синтаксис $NFTABLES_CONF"
    if ! validate_nft_conf; then
        error "Синтаксическая ошибка в $NFTABLES_CONF"
        nft -c -f "$NFTABLES_CONF"
        return 1
    fi

    info "Применяем правила nftables"
    if nft -f "$NFTABLES_CONF"; then
        success "Правила nftables применены"
    else
        error "Ошибка применения nftables!"
        return 1
    fi

    systemctl enable nftables > /dev/null 2>&1 || true

    if [[ -n "$ROLLBACK_JOB" ]]; then
        atrm "$ROLLBACK_JOB" 2>/dev/null || true
        success "Автооткат отменён"
    fi
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
# BBR — улучшение пропускной способности для VPN-клиентов
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

    sysctl -p > /dev/null 2>&1 && success "sysctl применён" || warn "Часть параметров не применилась"
}

setup_fail2ban() {
    header "Fail2Ban"
    apt_install_pkg fail2ban || { error "Не удалось установить Fail2Ban"; return 1; }

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

    if systemctl enable fail2ban --now 2>/dev/null; then
        success "Fail2Ban запущен"
    else
        warn "Fail2Ban не запустился — проверьте логи"
    fi
}

setup_docker() {
    header "Docker"
    if command -v docker &>/dev/null; then
        success "Docker уже установлен ($(docker --version 2>/dev/null || true))"
    else
        info "Ждём освобождения apt-блокировки..."
        local waited=0
        while fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock &>/dev/null 2>&1; do
            sleep 2
            waited=$((waited + 2))
            if [[ $waited -ge 120 ]]; then
                warn "apt занят больше 2 минут — снимаем блокировку принудительно"
                rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock
                dpkg --configure -a 2>/dev/null || true
                break
            fi
            info "apt занят (${waited}с)..."
        done

        info "Устанавливаем Docker..."
        set +e
        curl -fsSL https://get.docker.com | sh
        DOCKER_INSTALL_RC=$?
        set -e

        if [[ $DOCKER_INSTALL_RC -ne 0 ]]; then
            warn "Установщик Docker завершился с кодом $DOCKER_INSTALL_RC"
        fi

        if ! command -v docker &>/dev/null; then
            error "Docker не найден после установки — пропускаем."
            warn "Установите вручную: https://docs.docker.com/engine/install/"
            INSTALL_REMNAWAVE=false
            return 0
        fi

        systemctl enable docker --now 2>/dev/null || true
        success "Docker установлен ($(docker --version 2>/dev/null || true))"
    fi

    if docker compose version &>/dev/null 2>&1; then
        success "Docker Compose: $(docker compose version 2>/dev/null || true)"
    else
        warn "Docker Compose не найден"
    fi
}

setup_remnawave() {
    header "Remnawave Node"
    REMNA_DIR="/opt/remnanode"
    mkdir -p "$REMNA_DIR"
    cd "$REMNA_DIR" || { error "Не удалось перейти в $REMNA_DIR"; return 1; }

    echo -e "\n${YELLOW}Remnawave → Nodes → '+' → Copy docker-compose.yml → вставьте в nano${NC}\n"
    read -rp "$(echo -e "${YELLOW}")Нажмите Enter чтобы открыть nano...$(echo -e "${NC}")"
    nano docker-compose.yml

    if [[ ! -f "docker-compose.yml" ]]; then
        error "docker-compose.yml не найден"
        return 1
    fi

    docker compose up -d && docker compose logs -f -t
    success "Remnawave Node запущен"
}

setup_stealth_extras() {
    header "Stealth"
    NEW_HOSTNAME="srv-$(head -c4 /dev/urandom | xxd -p)"
    hostnamectl set-hostname "$NEW_HOSTNAME" 2>/dev/null && success "Hostname → $NEW_HOSTNAME" || true
    truncate -s 0 /etc/motd 2>/dev/null || true
    echo "" > /etc/issue 2>/dev/null || true
    echo "" > /etc/issue.net 2>/dev/null || true
    for svc in avahi-daemon cups bluetooth ModemManager; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl disable --now "$svc" 2>/dev/null || true
            info "Отключён: $svc"
        fi
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

    if [[ "$USE_FAIL2BAN" == true ]]; then
        echo -e "  ${GREEN}✔${NC} Fail2Ban      : активен"
    fi
    if [[ "$INSTALL_DOCKER" == true ]]; then
        echo -e "  ${GREEN}✔${NC} Docker        : установлен"
    fi
    if [[ "$INSTALL_REMNAWAVE" == true ]]; then
        echo -e "  ${GREEN}✔${NC} Remnawave     : запущен"
    fi
    if [[ -n "$SSH_PUBKEY" ]]; then
        echo -e "  ${GREEN}✔${NC} SSH ключ      : добавлен"
    else
        echo -e "  ${RED}✘${NC} SSH ключ      : НЕ ДОБАВЛЕН"
    fi

    echo ""
    echo -e "  ${GREEN}✔${NC} vpnctl        : доступен как $VPNCTL_BIN"
    echo -e "  ${CYAN}Stealth:${NC} ping↓  IPv6↓  timestamps↓  TTL=128  баннер скрыт"
    echo -e "  ${CYAN}Подключение:${NC} ${GREEN}$TAILSCALE_IP${NC} : ${GREEN}$SSH_PORT${NC}"
    echo ""
    warn "Бэкапы: /etc/ssh/sshd_config.bak | /etc/sysctl.conf.bak | ${NFTABLES_CONF}.bak.*"
    warn "Проверьте SSH до закрытия сессии!"
    echo ""
    info "Команды: vpnctl add-port / vpnctl remove-port / vpnctl list"
    echo ""
}

main_setup() {
    check_root
    ensure_self_installed
    setup_tailscale
    collect_config
    setup_ssh
    setup_authorized_keys
    setup_firewall
    setup_sysctl
    setup_stealth_extras

    if [[ "$USE_FAIL2BAN" == true ]]; then
        setup_fail2ban
    fi
    if [[ "$INSTALL_DOCKER" == true ]]; then
        setup_docker
    fi
    if [[ "$INSTALL_REMNAWAVE" == true ]]; then
        setup_remnawave
    fi

    print_summary
}

# ════════════════════════════════════════════════════════════
#  РОУТИНГ КОМАНД
# ════════════════════════════════════════════════════════════

case "${1:-}" in
    add-port|add)                cmd_add_port ;;
    remove-port|remove|rm|del)   cmd_remove_port ;;
    list|ls)                     cmd_list ;;
    install)                     cmd_install ;;
    help|--help|-h)              cmd_help ;;
    "")                          main_setup ;;
    *)
        error "Неизвестная команда: $1"
        cmd_help
        exit 1
        ;;
esac
