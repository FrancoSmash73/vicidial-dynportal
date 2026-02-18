#!/bin/bash
# =============================================================================
# ViciDial Server Security Hardening Script
# =============================================================================
# Configures fail2ban, firewalld, and service hardening for ViciDial servers.
# Designed to be idempotent — safe to run multiple times.
#
# Usage:
#   ./vicidial-server-security-setup.sh [OPTIONS]
#
# Options:
#   --sip-allow-ip <IP>      Allow SIP traffic (5060/5061) only from this IP/CIDR.
#                             Can be specified multiple times. Use for SIP trunk
#                             providers and static office IPs.
#   --whitelist-ip <IP>       Add trusted IP to fail2ban ignoreip (never banned).
#                             Can be specified multiple times.
#   --with-dynportal          Enable integration with vicidial-dynportal. Agents
#                             self-whitelist via the portal; RTP/WebPhone/agent
#                             ports are restricted to the dynamiclist ipset instead
#                             of being open to all. Port 446 is opened for the
#                             portal itself.
#   --non-interactive         Skip prompts (for automated deployments).
#                             Will error if --sip-allow-ip not provided.
#   -h, --help                Show this help message.
#
# Examples:
#   # Basic — static SIP trunk IPs only:
#   ./vicidial-server-security-setup.sh --sip-allow-ip 203.0.113.10
#
#   # With dynportal — agents self-whitelist, trunks are static:
#   ./vicidial-server-security-setup.sh --sip-allow-ip 203.0.113.10 --with-dynportal
# =============================================================================

set -euo pipefail

# --- Color helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
            SIP_ALLOW_IPS+=("$2")
            shift 2
            ;;
        --whitelist-ip)
            [[ -z "${2:-}" ]] && { err "--whitelist-ip requires an IP/CIDR argument"; exit 1; }
            WHITELIST_IPS+=("$2")
            shift 2
            ;;
        --with-dynportal)
            WITH_DYNPORTAL=true
            shift
            ;;
        --non-interactive)
            NON_INTERACTIVE=true
            shift
            ;;
        -h|--help)
            head -n 33 "$0" | tail -n +2 | sed 's/^# \?//'
            exit 0
            ;;
        *)
            err "Unknown option: $1"
            exit 1
            ;;
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
        err "SIP ports MUST be restricted. Provide at least one --sip-allow-ip."
        exit 1
    fi
    echo ""
    warn "No --sip-allow-ip addresses provided."
    warn "Leaving SIP ports (5060/5061) open to the internet is EXTREMELY DANGEROUS."
    warn "SIP brute-force attacks are the #1 threat to ViciDial servers."
    echo ""
    echo "Enter IP addresses/CIDRs to allow SIP access (one per line)."
    echo "These should be your SIP trunk providers and static office IPs."
    if [[ "$WITH_DYNPORTAL" == true ]]; then
        echo "(Remote agents will self-whitelist via the dynportal — no need to list them here.)"
    fi
    echo "Press Enter on an empty line when done."
    echo ""
    while true; do
        read -rp "SIP allow IP (blank to finish): " ip
        [[ -z "$ip" ]] && break
        SIP_ALLOW_IPS+=("$ip")
    done
    if [[ ${#SIP_ALLOW_IPS[@]} -eq 0 ]]; then
        err "No SIP IPs provided. Cannot continue with SIP ports open to the world."
        err "Re-run with: $0 --sip-allow-ip <YOUR_SIP_PROVIDER_IP>"
        exit 1
    fi
fi

# --- Dynportal pre-checks ---
if [[ "$WITH_DYNPORTAL" == true ]]; then
    DYNPORTAL_MISSING=()
    [[ ! -f /var/www/html/dynportal/valid8.php ]] && DYNPORTAL_MISSING+=("portal PHP files")
    [[ ! -x /usr/bin/VB-firewall ]] && DYNPORTAL_MISSING+=("VB-firewall script")
    [[ ! -f /etc/firewalld/ipsets/dynamiclist.xml ]] && DYNPORTAL_MISSING+=("dynamiclist ipset definition")
    [[ ! -f /etc/firewalld/services/asterisk.xml ]] && DYNPORTAL_MISSING+=("asterisk.xml service definition")
    if [[ ${#DYNPORTAL_MISSING[@]} -gt 0 ]]; then
        warn "--with-dynportal specified but some components are not installed:"
        for item in "${DYNPORTAL_MISSING[@]}"; do
            warn "  - $item"
        done
        warn "Run the dynportal install.sh first, then re-run this script."
        warn "Continuing without dynportal integration..."
        WITH_DYNPORTAL=false
    fi
fi

echo ""
section "ViciDial Server Security Hardening"
info "SIP allowed IPs (static trunks): ${SIP_ALLOW_IPS[*]}"
[[ ${#WHITELIST_IPS[@]} -gt 0 ]] && info "Fail2ban whitelisted IPs: ${WHITELIST_IPS[*]}"
if [[ "$WITH_DYNPORTAL" == true ]]; then
    info "Dynportal integration: ENABLED"
    info "  - RTP/WebPhone/agent ports restricted to dynamiclist ipset"
    info "  - Portal port 446 open for agent self-service"
    info "  - Agents self-whitelist via portal -> VB-firewall syncs to ipset"
else
    info "Dynportal integration: disabled (use --with-dynportal to enable)"
fi
echo ""

# =============================================================================
# 1. Install Dependencies
# =============================================================================
section "1. Installing Dependencies"

if ! rpm -q conntrack-tools &>/dev/null; then
    info "Installing conntrack-tools..."
    dnf install -y conntrack-tools && ok "conntrack-tools installed." || err "Failed to install conntrack-tools."
else
    ok "conntrack-tools already installed."
fi

if ! rpm -q fail2ban &>/dev/null; then
    info "Installing fail2ban..."
    dnf install -y fail2ban && ok "fail2ban installed." || err "Failed to install fail2ban."
else
    ok "fail2ban already installed."
fi

systemctl enable fail2ban &>/dev/null
ok "fail2ban enabled on boot."

# =============================================================================
# 2. Fail2ban Configuration
# =============================================================================
section "2. Configuring Fail2ban"

# --- Build ignoreip list ---
IGNOREIP="127.0.0.1/8 ::1"
for ip in "${WHITELIST_IPS[@]}"; do
    IGNOREIP="$IGNOREIP $ip"
done

# --- 2a. Override default banaction to use iptables (not firewalld rich rules) ---
info "Setting default banaction to iptables-allports..."
cat > /etc/fail2ban/jail.d/00-firewalld.local <<'EOF'
# Override fail2ban-firewalld package defaults.
# Use iptables actions instead of firewalld rich rules for reliable banning.
[DEFAULT]
banaction = iptables-allports
banaction_allports = iptables-allports
EOF
ok "Default banaction set to iptables-allports."

# --- 2b. Custom iptables action with conntrack flush ---
info "Writing custom iptables action with conntrack flush..."
cat > /etc/fail2ban/action.d/iptables.local <<EOF
[Definition]

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            conntrack -D -s <ip> 2>/dev/null || true

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
EOF
ok "iptables.local action with conntrack flush configured."

# --- 2c. Asterisk jails ---
info "Writing Asterisk jail config..."
cat > /etc/fail2ban/jail.d/asterisk.local <<EOF
[asterisk]
enabled = true
port = 5060,5061
action = iptables-allports[name=ASTERISK-ast, protocol=all]
logpath = /var/log/asterisk/messages*
maxretry = 5
bantime = 86400
findtime = 600
ignoreip = ${IGNOREIP}

[asterisk-iptables]
enabled = true
filter = asterisk
action = iptables-allports[name=ASTERISK, protocol=all]
logpath = /var/log/asterisk/messages*
maxretry = 5
bantime = 86400
findtime = 600
ignoreip = ${IGNOREIP}
EOF
ok "Asterisk jails configured (24h ban, wildcard logpath)."

# --- 2d. Apache jail ---
info "Writing Apache jail config..."
cat > /etc/fail2ban/jail.d/apache.local <<EOF
[apache-auth]
enabled = true
port = http,https
logpath = /var/log/httpd/error_log
maxretry = 5
bantime = 3600
findtime = 600
ignoreip = ${IGNOREIP}
EOF
ok "Apache jail configured (1h ban)."

# --- 2e. MariaDB jail ---
info "Writing MariaDB jail config..."
cat > /etc/fail2ban/jail.d/mysqld-auth.local <<EOF
[mysqld-auth]
enabled = true
port = 3306
logpath = /var/log/mariadb/mariadb.log
maxretry = 5
bantime = 3600
findtime = 600
ignoreip = 127.0.0.1/8 ::1 ${WHITELIST_IPS[*]:-}
EOF
ok "MariaDB jail configured (1h ban, localhost ignored)."

# --- 2f. SSH jail ---
# Detect actual SSH port from sshd config
SSH_PORT=$(ss -tlnp | grep sshd | grep -oP ':\K[0-9]+' | head -1)
SSH_PORT="${SSH_PORT:-22}"
info "Writing SSH jail config (detected SSH on port ${SSH_PORT})..."
cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
logpath = /var/log/secure
maxretry = 5
bantime = 3600
findtime = 600
ignoreip = ${IGNOREIP}
EOF
ok "SSH jail configured (1h ban, port ${SSH_PORT})."

# =============================================================================
# 3. Firewalld Hardening
# =============================================================================
section "3. Configuring Firewalld"

systemctl enable firewalld &>/dev/null
systemctl start firewalld &>/dev/null
ok "Firewalld enabled and running."

# Set default zone
firewall-cmd --set-default-zone=public &>/dev/null
ok "Default zone set to public."

# Add required services (http, https only — SSH handled separately below)
for svc in http https; do
    firewall-cmd --permanent --zone=public --add-service="$svc" &>/dev/null 2>&1 || true
done

# SSH: open the actual listening port, remove default port 22 service if SSH moved
if [[ "$SSH_PORT" != "22" ]]; then
    firewall-cmd --permanent --zone=public --remove-service=ssh &>/dev/null 2>&1 || true
    firewall-cmd --permanent --zone=public --add-port="${SSH_PORT}/tcp" &>/dev/null 2>&1 || true
    ok "Services allowed: http, https. SSH on port ${SSH_PORT} (non-standard)."
else
    firewall-cmd --permanent --zone=public --add-service=ssh &>/dev/null 2>&1 || true
    ok "Services allowed: ssh, http, https."
fi

# --- Dynportal vs static port strategy ---
if [[ "$WITH_DYNPORTAL" == true ]]; then
    # =========================================================================
    # DYNPORTAL MODE: RTP, WebPhone, agent screen restricted to dynamiclist
    # =========================================================================
    info "Dynportal mode: restricting agent-facing ports to dynamiclist ipset..."

    # Remove globally-opened ports that dynportal manages via ipset
    for port in "9000-35000/udp" "8089/tcp"; do
        firewall-cmd --permanent --zone=public --remove-port="$port" &>/dev/null 2>&1 || true
    done
    # Only remove 1951/tcp from global access if SSH is NOT on that port
    if [[ "$SSH_PORT" != "1951" ]]; then
        firewall-cmd --permanent --zone=public --remove-port="1951/tcp" &>/dev/null 2>&1 || true
    else
        warn "Port 1951 is shared by SSH and ViciDial agent screen — keeping global access for SSH."
    fi
    ok "Removed global access for RTP/WebPhone ports (dynportal manages these)."

    # Ensure the dynamiclist ipset exists at runtime
    if ! firewall-cmd --get-ipsets 2>/dev/null | grep -qw "dynamiclist"; then
        info "Creating dynamiclist ipset in firewalld..."
        firewall-cmd --permanent --new-ipset="dynamiclist" --type=hash:ip 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null
    fi
    ok "dynamiclist ipset present."

    # Ensure dynportal service definitions are loaded
    # (The dynportal install.sh copies these, we just verify)
    for svc_file in asterisk rtp; do
        if [[ -f "/etc/firewalld/services/${svc_file}.xml" ]]; then
            ok "Firewalld service definition: ${svc_file}.xml present."
        else
            warn "Missing /etc/firewalld/services/${svc_file}.xml — dynportal install may be incomplete."
        fi
    done

    # Clean up any old dynportal rich rules before re-adding (idempotent)
    existing_rules=$(firewall-cmd --permanent --zone=public --list-rich-rules 2>/dev/null || true)
    while IFS= read -r rule; do
        if [[ "$rule" == *'ipset="dynamiclist"'* ]]; then
            firewall-cmd --permanent --zone=public --remove-rich-rule="$rule" &>/dev/null 2>&1 || true
        fi
    done <<< "$existing_rules"

    # Rich rules: dynamiclist ipset -> asterisk service (SIP/IAX2/8088/8089)
    firewall-cmd --permanent --zone=public \
        --add-rich-rule='rule family="ipv4" source ipset="dynamiclist" service name="asterisk" accept' \
        &>/dev/null 2>&1 || true
    ok "dynamiclist -> asterisk service (SIP/IAX2/WebPhone for agents)."

    # Rich rules: dynamiclist ipset -> rtp service (9000-35000/udp)
    firewall-cmd --permanent --zone=public \
        --add-rich-rule='rule family="ipv4" source ipset="dynamiclist" service name="rtp" accept' \
        &>/dev/null 2>&1 || true
    ok "dynamiclist -> RTP service (media streams for agents)."

    # Rich rules: dynamiclist ipset -> agent screen port 1951
    firewall-cmd --permanent --zone=public \
        --add-rich-rule='rule family="ipv4" source ipset="dynamiclist" port port="1951" protocol="tcp" accept' \
        &>/dev/null 2>&1 || true
    ok "dynamiclist -> port 1951 (ViciDial agent screen)."

    # Open portal port 446 to everyone (agents must reach it BEFORE being whitelisted)
    if [[ -f /etc/firewalld/services/viciportal-ssl.xml ]]; then
        firewall-cmd --permanent --zone=public \
            --add-rich-rule='rule family="ipv4" service name="viciportal-ssl" accept' \
            &>/dev/null 2>&1 || true
        ok "Portal port 446 open to all (agent self-service entry point)."
    else
        # Fallback: open port directly if service definition missing
        firewall-cmd --permanent --zone=public --add-port="446/tcp" &>/dev/null 2>&1 || true
        ok "Portal port 446 open to all (direct port rule, service XML missing)."
    fi

else
    # =========================================================================
    # STANDARD MODE: ports open globally (no dynportal)
    # =========================================================================
    declare -A REQUIRED_PORTS=(
        ["9000-35000/udp"]="RTP media"
        ["8089/tcp"]="WebPhone WSS"
    )
    # Only open 1951 for agent screen if SSH isn't already on that port
    if [[ "$SSH_PORT" != "1951" ]]; then
        REQUIRED_PORTS["1951/tcp"]="ViciDial agent screen"
    fi
    for port in "${!REQUIRED_PORTS[@]}"; do
        firewall-cmd --permanent --zone=public --add-port="$port" &>/dev/null 2>&1 || true
    done
    ok "Ports opened: 9000-35000/udp (RTP), 8089/tcp (WebPhone)$([[ "$SSH_PORT" != "1951" ]] && echo ", 1951/tcp (ViciDial)")."
fi

# Remove cockpit if present
if firewall-cmd --zone=public --query-service=cockpit &>/dev/null 2>&1; then
    firewall-cmd --permanent --zone=public --remove-service=cockpit &>/dev/null
    ok "Removed cockpit service (unnecessary attack surface)."
fi

# Remove SIP ports from general access if they were previously opened
for port in 5060/tcp 5060/udp 5061/tcp 5061/udp; do
    firewall-cmd --permanent --zone=public --remove-port="$port" &>/dev/null 2>&1 || true
done
for svc in sip sips; do
    firewall-cmd --permanent --zone=public --remove-service="$svc" &>/dev/null 2>&1 || true
done
ok "Removed any global SIP port access."

# --- 3b. SIP IP whitelisting via rich rules (static trunk IPs) ---
info "Configuring SIP access for static trunk IPs..."

# Remove any existing per-IP SIP rich rules first (idempotent cleanup)
existing_rules=$(firewall-cmd --permanent --zone=public --list-rich-rules 2>/dev/null || true)
while IFS= read -r rule; do
    # Match per-IP SIP rules but NOT ipset-based rules (dynportal's)
    if [[ "$rule" == *"port=\"5060\""* ]] || [[ "$rule" == *"port=\"5061\""* ]]; then
        if [[ "$rule" != *"ipset="* ]]; then
            firewall-cmd --permanent --zone=public --remove-rich-rule="$rule" &>/dev/null 2>&1 || true
        fi
    fi
done <<< "$existing_rules"

# Add rich rules for each static SIP trunk IP
for ip in "${SIP_ALLOW_IPS[@]}"; do
    for port in 5060 5061; do
        for proto in tcp udp; do
            firewall-cmd --permanent --zone=public \
                --add-rich-rule="rule family=\"ipv4\" source address=\"${ip}\" port port=\"${port}\" protocol=\"${proto}\" accept" \
                &>/dev/null 2>&1 || true
        done
    done
    ok "SIP access granted to: $ip (static trunk)"
done

# Reload firewalld to apply all changes
firewall-cmd --reload &>/dev/null
ok "Firewalld rules reloaded."

# =============================================================================
# 4. Asterisk SIP Hardening Checks
# =============================================================================
section "4. Asterisk SIP Hardening Checks"

SIP_CONF="/etc/asterisk/sip.conf"
if [[ -f "$SIP_CONF" ]]; then
    # Check alwaysauthreject
    if grep -qE '^\s*alwaysauthreject\s*=\s*yes' "$SIP_CONF"; then
        ok "alwaysauthreject=yes is set (prevents username enumeration)."
    else
        warn "alwaysauthreject=yes is NOT set in $SIP_CONF"
        warn "  This allows attackers to enumerate valid SIP usernames."
        warn "  Add 'alwaysauthreject=yes' under [general] in sip.conf."
    fi

    # Check allowguest
    if grep -qE '^\s*allowguest\s*=\s*no' "$SIP_CONF"; then
        ok "allowguest=no is set (blocks unauthorized calls)."
    else
        warn "allowguest=no is NOT set in $SIP_CONF"
        warn "  This may allow unauthenticated SIP calls."
        warn "  Add 'allowguest=no' under [general] in sip.conf."
    fi
else
    warn "Asterisk sip.conf not found at $SIP_CONF — skipping SIP hardening checks."
fi

# =============================================================================
# 5. MariaDB Hardening Check
# =============================================================================
section "5. MariaDB Hardening Check"

MYCNF="/etc/my.cnf"
if [[ -f "$MYCNF" ]]; then
    if grep -qE '^\s*bind-address\s*=\s*127\.0\.0\.1' "$MYCNF"; then
        ok "MariaDB bind-address is 127.0.0.1 (local only)."
    else
        warn "MariaDB bind-address is NOT set to 127.0.0.1 in $MYCNF"
        warn "  The database may be accessible from the network."
        warn "  Add 'bind-address = 127.0.0.1' under [mysqld] in $MYCNF."
    fi
else
    # Check alternative locations
    MYCNF_D="/etc/my.cnf.d/"
    found_bind=false
    if [[ -d "$MYCNF_D" ]]; then
        for f in "$MYCNF_D"/*.cnf; do
            [[ -f "$f" ]] || continue
            if grep -qE '^\s*bind-address\s*=\s*127\.0\.0\.1' "$f"; then
                ok "MariaDB bind-address is 127.0.0.1 (found in $f)."
                found_bind=true
                break
            fi
        done
    fi
    if [[ "$found_bind" == false ]]; then
        warn "Could not verify MariaDB bind-address. Check /etc/my.cnf or /etc/my.cnf.d/ manually."
    fi
fi

# =============================================================================
# 6. Restart & Verify
# =============================================================================
section "6. Restarting Services & Verification"

info "Restarting fail2ban..."
systemctl restart fail2ban
ok "fail2ban restarted."

# Brief pause for jails to initialize
sleep 2

# Show jail status
info "Fail2ban jail status:"
echo ""
fail2ban-client status 2>/dev/null || warn "Could not query fail2ban status."
echo ""

# Show individual jail details
for jail in asterisk asterisk-iptables apache-auth mysqld-auth sshd; do
    status_output=$(fail2ban-client status "$jail" 2>/dev/null) && {
        echo -e "${GREEN}--- $jail ---${NC}"
        echo "$status_output" | grep -E "Currently|Total|File list"
        echo ""
    } || warn "Jail '$jail' not running."
done

# Show firewall summary
info "Firewalld active rules:"
echo ""
firewall-cmd --list-all 2>/dev/null || warn "Could not query firewalld."
echo ""

# Show iptables f2b chains
info "Fail2ban iptables chains:"
iptables -L INPUT -n 2>/dev/null | grep -E "f2b-|Chain" || warn "No f2b chains found in iptables."
echo ""

# =============================================================================
# Summary Report
# =============================================================================
section "Security Hardening Summary"
echo ""
echo -e "${GREEN}Protections Active:${NC}"
echo "  [1] Fail2ban conntrack flush   - Bans immediately kill established connections"
echo "  [2] Asterisk jails (x2)        - 24h ban, wildcard logpath for rotated logs"
echo "  [3] SSH jail                   - 5 failures = 1h ban"
echo "  [4] Apache jail                - 5 failures = 1h ban"
echo "  [5] MariaDB jail               - 5 failures = 1h ban, localhost ignored"
echo "  [6] Firewalld hardened         - Only ssh/http/https + required ports open"
echo "  [7] SIP port restricted        - Only allowed IPs can reach 5060/5061"

if [[ "$WITH_DYNPORTAL" == true ]]; then
    echo "  [8] Dynportal integrated       - RTP/WebPhone/agent ports restricted to ipset"
    echo "  [9] Portal port 446 open       - Agent self-service whitelisting entry point"
    echo ""
    echo -e "${GREEN}How agent access works:${NC}"
    echo "  1. Agent visits https://<server>:446 (open to all)"
    echo "  2. Authenticates with ViciDial credentials"
    echo "  3. IP added to ViciWhite DB list"
    echo "  4. VB-firewall cron syncs IP to dynamiclist ipset (within 60s)"
    echo "  5. Firewalld rich rules grant SIP/RTP/WebPhone/agent access"
fi

echo ""
echo -e "${GREEN}SIP Allowed IPs (static trunks):${NC}"
for ip in "${SIP_ALLOW_IPS[@]}"; do
    echo "  - $ip"
done
if [[ "$WITH_DYNPORTAL" == true ]]; then
    echo ""
    echo -e "${GREEN}Dynamic Agent IPs:${NC}"
    echo "  Managed by dynportal -> VB-firewall -> dynamiclist ipset"
    IPSET_COUNT=$(firewall-cmd --ipset=dynamiclist --get-entries 2>/dev/null | wc -w || echo "0")
    echo "  Currently whitelisted: ${IPSET_COUNT} IPs"
fi
if [[ ${#WHITELIST_IPS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${GREEN}Fail2ban Whitelisted IPs (never banned):${NC}"
    for ip in "${WHITELIST_IPS[@]}"; do
        echo "  - $ip"
    done
fi
echo ""
echo -e "${BLUE}Verification commands:${NC}"
echo "  fail2ban-client status                    # List all active jails"
echo "  fail2ban-client status asterisk            # Check asterisk jail details"
echo "  firewall-cmd --list-all                    # Show firewall rules"
echo "  iptables -L INPUT -n                       # Verify f2b chains"
echo "  conntrack -L | grep <attacker-ip>          # Check if connections flushed"
if [[ "$WITH_DYNPORTAL" == true ]]; then
    echo "  firewall-cmd --ipset=dynamiclist --get-entries  # Show whitelisted agent IPs"
    echo "  VB-firewall --white --dynamic             # Manually sync agent IPs now"
fi
echo ""
ok "ViciDial server security hardening complete."
