#!/bin/bash
###############################################################################
# Dynamic Portal Installer
# Deploys the agent IP self-service whitelisting portal for ViciDial.
#
# Prerequisites:
#   - ViciDial installed with /etc/astguiclient.conf configured
#   - Apache (httpd) with mod_ssl
#   - Let's Encrypt certs at /etc/letsencrypt/live/<domain>/
#   - firewalld active
#   - ipset installed
#   - MySQL/MariaDB with vicidial_ip_lists and vicidial_ip_list_entries tables
#
# Usage:
#   sudo ./install.sh --domain <your.domain.com>
###############################################################################

set -euo pipefail

DOMAIN=""
CERT_DIR=""
CARRIER_IP=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
    echo "Usage: $0 --domain <your.domain.com> [--carrier-ip <ip>]"
    echo "  --carrier-ip   Permanently whitelist a SIP carrier IP (e.g. 88.151.128.22)"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)     DOMAIN="$2";     shift 2 ;;
        --carrier-ip) CARRIER_IP="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ -n "$DOMAIN" ]] || die "Missing required --domain argument. Run with --help for usage."

# Validate carrier IP if provided
if [[ -n "$CARRIER_IP" ]]; then
    if ! [[ "$CARRIER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        die "Invalid --carrier-ip address: $CARRIER_IP"
    fi
fi
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

[[ $EUID -eq 0 ]] || die "Run as root"
[[ -f /etc/astguiclient.conf ]] || die "/etc/astguiclient.conf not found"
[[ -d "$CERT_DIR" ]] || die "SSL certs not found at $CERT_DIR"

echo "=== Installing Dynamic Portal for ${DOMAIN} ==="

# 1. PHP portal files
echo "Installing PHP portal..."
mkdir -p /var/www/html/dynportal/inc
cp "${SCRIPT_DIR}/dynportal/valid8.php" /var/www/html/dynportal/
cp "${SCRIPT_DIR}/dynportal/inc/dbconnect.inc.php" /var/www/html/dynportal/inc/
cp "${SCRIPT_DIR}/dynportal/inc/defaults.inc.php" /var/www/html/dynportal/inc/

# Update redirect URLs in defaults.inc.php to match domain
sed -i "s|https://[^/]*/agc/|https://${DOMAIN}/agc/|g" /var/www/html/dynportal/inc/defaults.inc.php
sed -i "s|https://[^/]*/vicidial/|https://${DOMAIN}/vicidial/|g" /var/www/html/dynportal/inc/defaults.inc.php
chown -R apache:apache /var/www/html/dynportal

# 2. Firewall definitions
echo "Installing firewall service definitions..."
cp "${SCRIPT_DIR}/firewalld/services/viciportal-ssl.xml" /etc/firewalld/services/
cp "${SCRIPT_DIR}/firewalld/services/asterisk.xml" /etc/firewalld/services/
cp "${SCRIPT_DIR}/firewalld/services/rtp.xml" /etc/firewalld/services/
mkdir -p /etc/firewalld/ipsets
cp "${SCRIPT_DIR}/firewalld/ipsets/dynamiclist.xml" /etc/firewalld/ipsets/

# 3. Apache vhost (generate from domain, not hardcoded)
echo "Installing Apache vhost..."
cat > /etc/httpd/conf.d/dynportal-ssl.conf <<VHOST
Listen 446 https

<VirtualHost _default_:446>
    ServerName ${DOMAIN}:446
    DocumentRoot /var/www/html/dynportal

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/${DOMAIN}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${DOMAIN}/privkey.pem

    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder on

    <Directory /var/www/html/dynportal>
        AllowOverride None
        Require all granted

        DirectoryIndex valid8.php
    </Directory>

    # Block access to inc/ directory
    <Directory /var/www/html/dynportal/inc>
        Require all denied
    </Directory>

    ErrorLog logs/dynportal_ssl_error_log
    TransferLog logs/dynportal_ssl_access_log
    LogLevel warn
</VirtualHost>
VHOST

# 4. SELinux port
echo "Allowing port 446 in SELinux..."
semanage port -a -t http_port_t -p tcp 446 2>/dev/null || \
semanage port -m -t http_port_t -p tcp 446 2>/dev/null || true

# 5. VB-firewall script
echo "Installing VB-firewall..."
cp "${SCRIPT_DIR}/bin/VB-firewall" /usr/bin/VB-firewall
chmod +x /usr/bin/VB-firewall

# 6. Database setup
echo "Creating ViciWhite IP list in database..."
CONF="/etc/astguiclient.conf"
# Read and strip leading/trailing whitespace from each value
get_conf() { grep "^${1} " "$CONF" 2>/dev/null | sed "s/^${1} => //;s/[[:space:]]*$//"; }
DB_HOST=$(get_conf VARDB_server)
DB_NAME=$(get_conf VARDB_database)
DB_USER=$(get_conf VARDB_user)
DB_PASS=$(get_conf VARDB_pass)
DB_PORT=$(get_conf VARDB_port)

mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e \
  "INSERT IGNORE INTO vicidial_ip_lists (ip_list_id, ip_list_name, active, user_group) VALUES ('ViciWhite', 'Dynamic Agent Whitelist', 'Y', '---ALL---');" 2>/dev/null

# 7. Firewall rules (permanent + reload)
echo "Applying firewall rules..."
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" service name="viciportal-ssl" accept' 2>/dev/null || true
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source ipset="dynamiclist" service name="asterisk" accept' 2>/dev/null || true
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source ipset="dynamiclist" service name="rtp" accept' 2>/dev/null || true

# Permanently whitelist carrier IP for SIP trunk (if provided)
if [[ -n "$CARRIER_IP" ]]; then
    echo "Whitelisting carrier IP ${CARRIER_IP} for SIP/RTP..."
    firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"${CARRIER_IP}\" service name=\"asterisk\" accept" 2>/dev/null || true
    firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"${CARRIER_IP}\" service name=\"rtp\" accept" 2>/dev/null || true
fi

firewall-cmd --reload

# 8. Restart Apache
echo "Restarting Apache..."
if httpd -t 2>&1 | grep -q "Syntax OK"; then
    systemctl restart httpd
    echo "Apache restarted"
else
    echo "WARNING: Apache config syntax issue - check with: httpd -t"
fi

# 9. Cron jobs
echo "Adding cron jobs..."
if ! crontab -l 2>/dev/null | grep -q "VB-firewall"; then
    (crontab -l 2>/dev/null; echo ""; echo "### VB-firewall: sync ViciWhite dynamic IPs to ipset"; echo "* * * * * /usr/bin/VB-firewall --white --dynamic --quiet"; echo "@reboot /usr/bin/VB-firewall --white --dynamic --quiet") | crontab -
    echo "Cron job added"
else
    echo "VB-firewall cron already exists"
fi

# 10. Initial sync
echo "Running initial VB-firewall sync..."
/usr/bin/VB-firewall --white --dynamic

echo ""
echo "=== Installation complete ==="
echo "Portal URL: https://${DOMAIN}:446/valid8.php"
echo "Cron: VB-firewall runs every minute to sync IPs"
[[ -n "$CARRIER_IP" ]] && echo "Carrier IP ${CARRIER_IP} permanently whitelisted for SIP/RTP"
