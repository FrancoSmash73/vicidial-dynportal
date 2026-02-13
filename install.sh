#!/bin/bash
###############################################################################
# Dynamic Portal Installer
# Deploys the agent IP self-service whitelisting portal for ViciDial.
#
# Prerequisites:
#   - ViciDial installed with /etc/astguiclient.conf configured
#   - Apache (httpd) with mod_ssl
#   - Let's Encrypt certs at /etc/letsencrypt/live/<hostname>/
#   - firewalld active
#   - ipset installed
#   - MySQL/MariaDB with vicidial_ip_lists and vicidial_ip_list_entries tables
#
# Usage:
#   sudo ./install.sh
###############################################################################

set -euo pipefail

HOSTNAME="callbakz.ddns.net"
CERT_DIR="/etc/letsencrypt/live/${HOSTNAME}"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root"
[[ -f /etc/astguiclient.conf ]] || die "/etc/astguiclient.conf not found"
[[ -d "$CERT_DIR" ]] || die "SSL certs not found at $CERT_DIR"

echo "=== Installing Dynamic Portal ==="

# 1. PHP portal files
echo "Installing PHP portal..."
mkdir -p /var/www/html/dynportal/inc
cp dynportal/valid8.php /var/www/html/dynportal/
cp dynportal/inc/dbconnect.inc.php /var/www/html/dynportal/inc/
cp dynportal/inc/defaults.inc.php /var/www/html/dynportal/inc/
chown -R apache:apache /var/www/html/dynportal

# 2. Firewall definitions
echo "Installing firewall service definitions..."
cp firewalld/services/viciportal-ssl.xml /etc/firewalld/services/
cp firewalld/services/asterisk.xml /etc/firewalld/services/
cp firewalld/services/rtp.xml /etc/firewalld/services/
mkdir -p /etc/firewalld/ipsets
cp firewalld/ipsets/dynamiclist.xml /etc/firewalld/ipsets/

# 3. Apache vhost
echo "Installing Apache vhost..."
cp httpd/dynportal-ssl.conf /etc/httpd/conf.d/

# 4. SELinux port
echo "Allowing port 446 in SELinux..."
semanage port -a -t http_port_t -p tcp 446 2>/dev/null || \
semanage port -m -t http_port_t -p tcp 446 2>/dev/null || true

# 5. VB-firewall script
echo "Installing VB-firewall..."
cp bin/VB-firewall /usr/bin/VB-firewall
chmod +x /usr/bin/VB-firewall

# 6. Database setup
echo "Creating ViciWhite IP list in database..."
CONF="/etc/astguiclient.conf"
DB_HOST=$(grep "^VARDB_server " "$CONF" | sed "s/^VARDB_server => //")
DB_NAME=$(grep "^VARDB_database " "$CONF" | sed "s/^VARDB_database => //")
DB_USER=$(grep "^VARDB_user " "$CONF" | sed "s/^VARDB_user => //")
DB_PASS=$(grep "^VARDB_pass " "$CONF" | sed "s/^VARDB_pass => //")
DB_PORT=$(grep "^VARDB_port " "$CONF" | sed "s/^VARDB_port => //")

mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e \
  "INSERT IGNORE INTO vicidial_ip_lists (ip_list_id, ip_list_name, active, user_group) VALUES ('ViciWhite', 'Dynamic Agent Whitelist', 'Y', '---ALL---');" 2>/dev/null

# 7. Firewall rules
echo "Applying firewall rules..."
firewall-cmd --reload
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" service name="viciportal-ssl" accept' 2>/dev/null || true
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source ipset="dynamiclist" service name="asterisk" accept' 2>/dev/null || true
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source ipset="dynamiclist" service name="rtp" accept' 2>/dev/null || true
firewall-cmd --runtime-to-permanent

# 8. Restart Apache
echo "Restarting Apache..."
httpd -t 2>&1 && systemctl restart httpd

# 9. Cron jobs
echo "Adding cron jobs..."
if ! crontab -l 2>/dev/null | grep -q "VB-firewall"; then
    (crontab -l 2>/dev/null; echo ""; echo "### VB-firewall: sync ViciWhite dynamic IPs to ipset"; echo "* * * * * /usr/bin/VB-firewall --white --dynamic --quiet"; echo "@reboot /usr/bin/VB-firewall --white --dynamic --quiet") | crontab -
fi

# 10. Initial sync
echo "Running initial VB-firewall sync..."
/usr/bin/VB-firewall --white --dynamic

echo ""
echo "=== Installation complete ==="
echo "Portal URL: https://${HOSTNAME}:446/valid8.php"
echo "Cron: VB-firewall runs every minute to sync IPs"
