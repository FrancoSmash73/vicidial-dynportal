#!/bin/bash
# =============================================================================
# ViciDial Server Security Hardening Script v3-lite
# =============================================================================
# Configures fail2ban, firewalld hardening, and service checks.
# NO geo-blocking — lighter on the system, simpler to maintain.
#
# Protection stack:
#   - Firewalld: strict port control, SIP locked to trunk IPs only
#   - Fail2ban:  auto-ban on brute-force (Asterisk, SSH, Apache, MariaDB)
#   - SQLite WAL mode: prevents Asterisk DB lock contention
#
# Usage:
#   ./vicidial-server-security-setup-lite.sh [OPTIONS]
#
# Options:
#   --sip-allow-ip <IP>      Allow SIP traffic (5060/5061) only from this IP/CIDR.
#                             Can be specified multiple times.
#   --whitelist-ip <IP>       Add trusted IP to fail2ban ignoreip (never banned).
#                             Can be specified multiple times.
#   --with-dynportal          Enable integration with vicidial-dynportal.
#   --non-interactive         Skip prompts (for automated deployments).
#   -h, --help                Show this help message.
#
# Examples:
#   ./vicidial-server-security-setup-lite.sh --sip-allow-ip 203.0.113.10
#   ./vicidial-server-security-setup-lite.sh --sip-allow-ip 203.0.113.10 --with-dynportal
# =============================================================================

set -euo pipefail

# --- Color helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()     { echo -e "${RED}[FAIL]${NC} $*"; }
section() { echo -e "\n${BLUE}====== $* ======${NC}"; }

# --- Parse arguments ---
SIP_ALLOW_IPS=()
WHITELIST_IPS=()
NON_INTERACTIVE=false
WITH_DYNPORTAL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sip-allow-ip)
            [[ -z "${2:-}" ]] && { err "--sip-allow-ip requires an IP/CIDR argument"; exit 1; }
            SIP_ALLOW_IPS+=("$2"); shift 2 ;;
        --whitelist-ip)
            [[ -z "${2:-}" ]] && { err "--whitelist-ip requires an IP/CIDR argument"; exit 1; }
            WHITELIST_IPS+=("$2"); shift 2 ;;
        --with-dynportal)
            WITH_DYNPORTAL=true; shift ;;
        --non-interactive)
            NON_INTERACTIVE=true; shift ;;
        -h|--help)
            head -n 30 "$0" | tail -n +2 | sed 's/^# \?//'; exit 0 ;;
        *)
            err "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
fi

# --- SIP IP prompt ---
if [[ ${#SIP_ALLOW_IPS[@]} -eq 0 ]]; then
    if [[ "$NON_INTERACTIVE" == true ]]; then
        err "No --sip-allow-ip provided and --non-interactive is set."
        exit 1
    fi
    echo ""
    warn "No --sip-allow-ip addresses provided."
    warn "Leaving SIP ports (5060/5061) open to the internet is EXTREMELY DANGEROUS."
    echo ""
    echo "Enter IP addresses/CIDRs to allow SIP access (one per line)."
    echo "Press Enter on an empty line when done."
    echo ""
    while true; do
        read -rp "SIP allow IP (blank to finish): " ip
        [[ -z "$ip" ]] && break
        SIP_ALLOW_IPS+=("$ip")
    done
    if [[ ${#SIP_ALLOW_IPS[@]} -eq 0 ]]; then
        err "No SIP IPs provided. Cannot continue."
        exit 1
    fi
fi

# --- Dynportal pre-checks ---
if [[ "$WITH_DYNPORTAL" == true ]]; then
    DYNPORTAL_MISSING=()
    [[ ! -f /var/www/html/dynportal/valid8.php ]]        && DYNPORTAL_MISSING+=("portal PHP files")
    [[ ! -x /usr/bin/VB-firewall ]]                      && DYNPORTAL_MISSING+=("VB-firewall script")
    [[ ! -f /etc/firewalld/ipsets/dynamiclist.xml ]]     && DYNPORTAL_MISSING+=("dynamiclist ipset definition")
    [[ ! -f /etc/firewalld/services/asterisk.xml ]]      && DYNPORTAL_MISSING+=("asterisk.xml service definition")
    if [[ ${#DYNPORTAL_MISSING[@]} -gt 0 ]]; then
        warn "--with-dynportal specified but some components are not installed:"
        for item in "${DYNPORTAL_MISSING[@]}"; do warn "  - $item"; done
        warn "Run the dynportal install.sh first, then re-run this script."
        warn "Continuing without dynportal integration..."
        WITH_DYNPORTAL=false
    fi
fi

echo ""
section "ViciDial Server Security Hardening v3-lite (No Geo-Block)"
info "SIP allowed IPs (static trunks): ${SIP_ALLOW_IPS[*]}"
[[ ${#WHITELIST_IPS[@]} -gt 0 ]] && info "Fail2ban whitelisted IPs: ${WHITELIST_IPS[*]}"
[[ "$WITH_DYNPORTAL" == true ]] && info "Dynportal integration: ENABLED" || info "Dynportal integration: disabled"
echo ""

# =============================================================================
# 0. SQLite WAL Mode (Asterisk DB lock contention fix)
# =============================================================================
section "0. Asterisk SQLite WAL Mode"

ASTERISK_DB="/var/lib/asterisk/astdb.sqlite3"

if ! command -v sqlite3 &>/dev/null; then
    info "Installing sqlite3..."
    dnf install -y sqlite &>/dev/null && ok "sqlite3 installed." || warn "Could not install sqlite3 – WAL mode step skipped."
fi

if [[ -f "$ASTERISK_DB" ]] && command -v sqlite3 &>/dev/null; then
    current_mode=$(sqlite3 "$ASTERISK_DB" "PRAGMA journal_mode;" 2>/dev/null || echo "unknown")
    if [[ "$current_mode" == "wal" ]]; then
        ok "Asterisk SQLite DB already in WAL mode."
    else
        # Asterisk must be stopped to safely set WAL mode
        ASTERISK_WAS_RUNNING=false
        if systemctl is-active --quiet asterisk; then
            ASTERISK_WAS_RUNNING=true
            info "Stopping Asterisk to set WAL mode..."
            systemctl stop asterisk
        fi

        sqlite3 "$ASTERISK_DB" "PRAGMA journal_mode=WAL;" &>/dev/null && \
            ok "Asterisk SQLite DB set to WAL mode (eliminates DB lock errors)." || \
            warn "Could not set WAL mode."

        if [[ "$ASTERISK_WAS_RUNNING" == true ]]; then
            info "Restarting Asterisk..."
            systemctl start asterisk
            sleep 3
            systemctl is-active --quiet asterisk && \
                ok "Asterisk restarted successfully." || \
                err "Asterisk failed to restart! Check: systemctl status asterisk"
        fi
    fi
else
    warn "Asterisk DB not found at $ASTERISK_DB – skipping WAL mode."
fi

# =============================================================================
# 1. Install Dependencies
# =============================================================================
section "1. Installing Dependencies"

for pkg in conntrack-tools fail2ban; do
    if ! rpm -q "$pkg" &>/dev/null; then
        info "Installing ${pkg}..."
        dnf install -y "$pkg" && ok "${pkg} installed." || err "Failed to install ${pkg}."
    else
        ok "${pkg} already installed."
    fi
done

systemctl enable fail2ban &>/dev/null
ok "fail2ban enabled on boot."

# =============================================================================
# 2. Fail2ban Configuration
# =============================================================================
section "2. Configuring Fail2ban"

IGNOREIP="127.0.0.1/8 ::1"
for ip in "${WHITELIST_IPS[@]}"; do IGNOREIP="$IGNOREIP $ip"; done

# Default banaction
cat > /etc/fail2ban/jail.d/00-firewalld.local <<'EOF'
[DEFAULT]
banaction = iptables-allports
banaction_allports = iptables-allports
EOF
ok "Default banaction set to iptables-allports."

# iptables action with conntrack flush (kills existing connections on ban)
cat > /etc/fail2ban/action.d/iptables.local <<EOF
[Definition]
actionban   = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
              conntrack -D -s <ip> 2>/dev/null || true
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
EOF
ok "iptables action with conntrack flush configured."

# Asterisk jail
cat > /etc/fail2ban/jail.d/asterisk.local <<EOF
[asterisk]
enabled    = true
filter     = asterisk
port       = 5060,5061
action     = iptables-allports[name=ASTERISK, protocol=all]
logpath    = /var/log/asterisk/messages*
maxretry   = 5
bantime    = 86400
findtime   = 600
ignoreip   = ${IGNOREIP}
EOF
ok "Asterisk jail configured (5 attempts = 24h ban)."

# Apache jail
cat > /etc/fail2ban/jail.d/apache.local <<EOF
[apache-auth]
enabled    = true
filter     = apache-auth
port       = http,https
action     = iptables-allports[name=APACHE, protocol=all]
logpath    = /var/log/httpd/error_log
maxretry   = 5
bantime    = 3600
findtime   = 600
ignoreip   = ${IGNOREIP}
EOF
ok "Apache jail configured (5 attempts = 1h ban)."

# MariaDB jail
if [[ ! -f /var/log/mariadb/mariadb.log ]]; then
    warn "MariaDB auth log not found – mysqld-auth jail will be inactive."
    warn "  Enable logging: add 'log_error = /var/log/mariadb/mariadb.log' under [mysqld] in /etc/my.cnf"
    warn "  Then: systemctl restart mariadb"
fi
cat > /etc/fail2ban/jail.d/mysqld-auth.local <<EOF
[mysqld-auth]
enabled    = true
filter     = mysqld-auth
port       = 3306
action     = iptables-allports[name=MYSQL, protocol=all]
logpath    = /var/log/mariadb/mariadb.log
maxretry   = 5
bantime    = 3600
findtime   = 600
ignoreip   = 127.0.0.1/8 ::1 ${WHITELIST_IPS[*]:-}
EOF
ok "MariaDB jail configured (5 attempts = 1h ban)."

# SSH jail
SSH_PORT=$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
SSH_PORT="${SSH_PORT:-22}"
cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled    = true
filter     = sshd
port       = ${SSH_PORT}
action     = iptables-allports[name=SSH, protocol=all]
logpath    = /var/log/secure
maxretry   = 5
bantime    = 3600
findtime   = 600
ignoreip   = ${IGNOREIP}
EOF
ok "SSH jail configured (port ${SSH_PORT}, 5 attempts = 1h ban)."

# Dynportal jail (optional)
if [[ "$WITH_DYNPORTAL" == true ]]; then
    cat > /etc/fail2ban/jail.d/dynportal.local <<EOF
[dynportal]
enabled    = true
filter     = apache-auth
port       = 446
action     = iptables-allports[name=DYNPORTAL, protocol=all]
logpath    = /var/log/httpd/error_log
maxretry   = 5
bantime    = 86400
findtime   = 300
ignoreip   = ${IGNOREIP}
EOF
    ok "Dynportal jail configured (5 attempts = 24h ban on port 446)."
fi

# =============================================================================
# 3. Firewalld Hardening
# =============================================================================
section "3. Configuring Firewalld"

systemctl enable firewalld &>/dev/null
systemctl start firewalld &>/dev/null
ok "Firewalld enabled and running."

firewall-cmd --set-default-zone=public &>/dev/null
ok "Default zone set to public."

# Allow HTTP/HTTPS
for svc in http https; do
    firewall-cmd --permanent --zone=public --add-service="$svc" &>/dev/null 2>&1 || true
done
ok "HTTP/HTTPS services allowed."

# SSH port
if [[ "$SSH_PORT" != "22" ]]; then
    firewall-cmd --permanent --zone=public --remove-service=ssh &>/dev/null 2>&1 || true
    firewall-cmd --permanent --zone=public --add-port="${SSH_PORT}/tcp" &>/dev/null 2>&1 || true
    ok "SSH on non-standard port ${SSH_PORT} opened."
else
    firewall-cmd --permanent --zone=public --add-service=ssh &>/dev/null 2>&1 || true
    ok "SSH on port 22 opened."
fi

# Port strategy: dynportal vs standard
if [[ "$WITH_DYNPORTAL" == true ]]; then
    info "Dynportal mode: restricting agent-facing ports to dynamiclist ipset..."

    for port in "9000-35000/udp" "8089/tcp"; do
        firewall-cmd --permanent --zone=public --remove-port="$port" &>/dev/null 2>&1 || true
    done

    if ! firewall-cmd --get-ipsets 2>/dev/null | grep -qw "dynamiclist"; then
        firewall-cmd --permanent --new-ipset="dynamiclist" --type=hash:ip &>/dev/null 2>/dev/null || true
        firewall-cmd --reload &>/dev/null
    fi
    ok "dynamiclist ipset present."

    # Clean old dynportal rich rules
    existing_rules=$(firewall-cmd --permanent --zone=public --list-rich-rules 2>/dev/null || true)
    while IFS= read -r rule; do
        [[ "$rule" == *'ipset="dynamiclist"'* ]] && \
            firewall-cmd --permanent --zone=public --remove-rich-rule="$rule" &>/dev/null 2>&1 || true
    done <<< "$existing_rules"

    for svc in asterisk rtp; do
        firewall-cmd --permanent --zone=public \
            --add-rich-rule="rule family=\"ipv4\" source ipset=\"dynamiclist\" service name=\"${svc}\" accept" \
            &>/dev/null 2>&1 || true
    done
    firewall-cmd --permanent --zone=public \
        --add-rich-rule='rule family="ipv4" source ipset="dynamiclist" port port="1951" protocol="tcp" accept' \
        &>/dev/null 2>&1 || true
    ok "dynamiclist ipset → asterisk, RTP, port 1951 rules added."

    if [[ -f /etc/firewalld/services/viciportal-ssl.xml ]]; then
        firewall-cmd --permanent --zone=public \
            --add-rich-rule='rule family="ipv4" service name="viciportal-ssl" accept' \
            &>/dev/null 2>&1 || true
    else
        firewall-cmd --permanent --zone=public --add-port="446/tcp" &>/dev/null 2>&1 || true
    fi
    ok "Portal port 446 open (agent self-service entry point)."

else
    # Standard mode - open ports globally
    firewall-cmd --permanent --zone=public --add-port="9000-35000/udp" &>/dev/null 2>&1 || true
    firewall-cmd --permanent --zone=public --add-port="8089/tcp"        &>/dev/null 2>&1 || true
    if [[ "$SSH_PORT" != "1951" ]]; then
        firewall-cmd --permanent --zone=public --add-port="1951/tcp" &>/dev/null 2>&1 || true
    fi
    ok "Ports opened: 9000-35000/udp (RTP), 8089/tcp (WebPhone), 1951/tcp (ViciDial)."
fi

# Remove cockpit
if firewall-cmd --zone=public --query-service=cockpit &>/dev/null 2>&1; then
    firewall-cmd --permanent --zone=public --remove-service=cockpit &>/dev/null
    ok "Removed cockpit service."
fi

# Lock down SIP ports — remove any global access
for port in 5060/tcp 5060/udp 5061/tcp 5061/udp; do
    firewall-cmd --permanent --zone=public --remove-port="$port" &>/dev/null 2>&1 || true
done
for svc in sip sips; do
    firewall-cmd --permanent --zone=public --remove-service="$svc" &>/dev/null 2>&1 || true
done
ok "Global SIP port access removed."

# SIP whitelist — only allow specified trunk IPs
info "Whitelisting SIP trunk IPs for ports 5060/5061..."
existing_rules=$(firewall-cmd --permanent --zone=public --list-rich-rules 2>/dev/null || true)
while IFS= read -r rule; do
    if [[ "$rule" == *'port="5060"'* ]] || [[ "$rule" == *'port="5061"'* ]]; then
        [[ "$rule" != *"ipset="* ]] && \
            firewall-cmd --permanent --zone=public --remove-rich-rule="$rule" &>/dev/null 2>&1 || true
    fi
done <<< "$existing_rules"

for ip in "${SIP_ALLOW_IPS[@]}"; do
    if [[ "$ip" == *:* ]]; then family="ipv6"; else family="ipv4"; fi
    for port in 5060 5061; do
        for proto in tcp udp; do
            firewall-cmd --permanent --zone=public \
                --add-rich-rule="rule family=\"${family}\" source address=\"${ip}\" port port=\"${port}\" protocol=\"${proto}\" accept" \
                &>/dev/null 2>&1 || true
        done
    done
    ok "SIP access granted to trunk: $ip"
done

firewall-cmd --reload &>/dev/null
ok "Firewalld rules reloaded."

# =============================================================================
# 4. Asterisk SIP Hardening Checks
# =============================================================================
section "4. Asterisk SIP Hardening Checks"

SIP_CONF="/etc/asterisk/sip.conf"
if [[ -f "$SIP_CONF" ]]; then
    if grep -qE '^\s*alwaysauthreject\s*=\s*yes' "$SIP_CONF"; then
        ok "alwaysauthreject=yes is set (prevents username enumeration)."
    else
        warn "alwaysauthreject=yes NOT set in $SIP_CONF"
        warn "  Add under [general]: alwaysauthreject=yes"
        warn "  Then run: asterisk -rx 'sip reload'"
    fi
    if grep -qE '^\s*allowguest\s*=\s*no' "$SIP_CONF"; then
        ok "allowguest=no is set (blocks unauthorized calls)."
    else
        warn "allowguest=no NOT set in $SIP_CONF"
        warn "  Add under [general]: allowguest=no"
        warn "  Then run: asterisk -rx 'sip reload'"
    fi
else
    warn "sip.conf not found at $SIP_CONF – skipping SIP hardening checks."
fi

# =============================================================================
# 5. SSH Hardening Check
# =============================================================================
section "5. SSH Hardening Check"

SSHD_CONF="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONF" ]]; then
    grep -qE '^\s*PasswordAuthentication\s+no' "$SSHD_CONF" && \
        ok "PasswordAuthentication no is set (key-based auth only)." || \
        warn "PasswordAuthentication is NOT 'no' – password login is a brute-force risk."
    grep -qE '^\s*PermitRootLogin\s+(no|prohibit-password)' "$SSHD_CONF" && \
        ok "PermitRootLogin is restricted." || \
        warn "PermitRootLogin not restricted – consider 'prohibit-password' or 'no'."
else
    warn "sshd_config not found – skipping SSH hardening checks."
fi

# =============================================================================
# 6. MariaDB Hardening Check
# =============================================================================
section "6. MariaDB Hardening Check"

MYCNF="/etc/my.cnf"
found_bind=false
if [[ -f "$MYCNF" ]] && grep -qE '^\s*bind-address\s*=\s*127\.0\.0\.1' "$MYCNF"; then
    ok "MariaDB bind-address = 127.0.0.1 found in $MYCNF."; found_bind=true
fi
if [[ "$found_bind" == false && -d /etc/my.cnf.d ]]; then
    for f in /etc/my.cnf.d/*.cnf; do
        [[ -f "$f" ]] || continue
        if grep -qE '^\s*bind-address\s*=\s*127\.0\.0\.1' "$f"; then
            ok "MariaDB bind-address = 127.0.0.1 found in $f."; found_bind=true; break
        fi
    done
fi
[[ "$found_bind" == false ]] && \
    warn "Could not verify MariaDB bind-address = 127.0.0.1 – add to /etc/my.cnf under [mysqld]."

# =============================================================================
# 7. Restart & Verify
# =============================================================================
section "7. Restarting Services & Verification"

info "Restarting fail2ban..."
systemctl restart fail2ban
ok "fail2ban restarted."
sleep 2

info "Fail2ban jail status:"
echo ""
fail2ban-client status 2>/dev/null || warn "Could not query fail2ban status."
echo ""

JAILS=(asterisk apache-auth mysqld-auth sshd)
[[ "$WITH_DYNPORTAL" == true ]] && JAILS+=(dynportal)

for jail in "${JAILS[@]}"; do
    status_output=$(fail2ban-client status "$jail" 2>/dev/null) && {
        echo -e "${GREEN}--- $jail ---${NC}"
        echo "$status_output" | grep -E "Currently|Total|File list"
        echo ""
    } || warn "Jail '$jail' not running – check config."
done

info "Firewalld active rules:"
echo ""
firewall-cmd --list-all 2>/dev/null || warn "Could not query firewalld."
echo ""

info "Fail2ban iptables chains:"
iptables -L INPUT -n 2>/dev/null | grep -E "f2b-|Chain" || warn "No f2b chains found yet."
echo ""

# =============================================================================
# Summary
# =============================================================================
section "Security Hardening Summary"
echo ""
echo -e "${GREEN}Protections Active:${NC}"
echo "  [0] SQLite WAL mode            - Asterisk DB lock contention eliminated"
echo "  [1] Fail2ban + conntrack flush - Bans kill established connections instantly"
echo "  [2] Asterisk jail              - 5 attempts = 24h ban"
echo "  [3] SSH jail                   - 5 attempts = 1h ban (port ${SSH_PORT})"
echo "  [4] Apache jail                - 5 attempts = 1h ban"
echo "  [5] MariaDB jail               - 5 attempts = 1h ban"
echo "  [6] Firewalld hardened         - Strict port control, unnecessary services removed"
echo "  [7] SIP ports locked           - 5060/5061 accessible ONLY from whitelisted trunk IPs"

if [[ "$WITH_DYNPORTAL" == true ]]; then
    echo "  [8] Dynportal integrated       - Agent ports restricted to dynamiclist ipset"
    echo "  [9] Dynportal jail (port 446)  - 5 attempts = 24h ban"
fi

echo ""
echo -e "${GREEN}SIP Allowed Trunk IPs:${NC}"
for ip in "${SIP_ALLOW_IPS[@]}"; do echo "  - $ip"; done

if [[ ${#WHITELIST_IPS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${GREEN}Fail2ban Whitelisted IPs (never banned):${NC}"
    for ip in "${WHITELIST_IPS[@]}"; do echo "  - $ip"; done
fi

echo ""
echo -e "${BLUE}Useful verification commands:${NC}"
echo "  fail2ban-client status                    # All active jails"
echo "  fail2ban-client status asterisk           # Asterisk jail detail"
echo "  firewall-cmd --list-all                   # Current firewall rules"
echo "  firewall-cmd --list-rich-rules            # SIP whitelist rules"
echo "  iptables -L INPUT -n                      # Verify f2b chains"
echo "  sqlite3 /var/lib/asterisk/astdb.sqlite3 'PRAGMA journal_mode;'  # Verify WAL"
if [[ "$WITH_DYNPORTAL" == true ]]; then
    echo "  firewall-cmd --ipset=dynamiclist --get-entries  # Whitelisted agent IPs"
    echo "  VB-firewall --white --dynamic                   # Manually sync agent IPs"
fi
echo ""
ok "ViciDial server security hardening v3-lite complete."
