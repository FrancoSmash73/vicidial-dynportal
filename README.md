# 🌐 ViciDial Dynamic Portal

**Agent IP Self-Service Whitelisting for ViciDial Call Centers**

[![PHP](https://img.shields.io/badge/PHP-66%25-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![Shell](https://img.shields.io/badge/Shell-34%25-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Platform](https://img.shields.io/badge/platform-Rocky%20Linux%2010-red?logo=redhat)](https://rockylinux.org/)

---

## 📖 Overview

**ViciDial Dynamic Portal** is a self-service web application that lets remote ViciDial agents whitelist their own dynamic IP addresses — without admin intervention. Agents log in with their ViciDial credentials, and their current public IP is automatically added to the `ViciWhite` list in the ViciDial database. The `VB-firewall` cron job picks it up and adds it to the `dynamiclist` firewalld ipset within 60 seconds.

Tested and running on:
- **Rocky Linux 10**
- **ViciDial 2.14b0.5**
- **Apache 2.4 + mod_ssl**
- **PHP 8.x + mysqli**
- **firewalld with `dynamiclist` ipset**

---

## ✨ How It Works

```
Agent opens portal → https://your-server:446/valid8.php
         ↓
Enters ViciDial username + password
         ↓
valid8.php authenticates against vicidial_users table
         ↓
Detects agent's current public IP
         ↓
Inserts/updates IP in vicidial_ip_list_entries (list: ViciWhite)
         ↓
VB-firewall cron (every 60s) reads ViciWhite list
and adds IPs to firewalld dynamiclist ipset
         ↓
Agent can now connect to ViciDial ✅
         ↓
Redirected → agent screen or admin panel
```

---

## 📁 File Structure

```
dynportal/
├── valid8.php              ← Portal login page & IP whitelisting logic
└── inc/
    ├── defaults.inc.php    ← Portal configuration (title, redirects, list ID)
    └── dbconnect.inc.php   ← DB connection (auto-reads /etc/astguiclient.conf)
```

> **Note:** `dbconnect.inc.php` reads DB credentials directly from `/etc/astguiclient.conf`
> on the ViciDial server — no manual credential configuration required.

---

## 🚀 Installation

### 1. Clone into web root

```bash
cd /var/www/html
git clone https://github.com/FrancoSmash73/vicidial-dynportal.git dynportal

chmod -R 755 /var/www/html/dynportal
chown -R apache:apache /var/www/html/dynportal
```

### 2. Configure the portal

Edit `/var/www/html/dynportal/inc/defaults.inc.php`:

```php
// IP list ID in vicidial_ip_list_entries
$ip_list_id = 'ViciWhite';

// Minimum ViciDial user level to use the portal (1 = all active agents)
$min_user_level = 1;

// Where to redirect after successful login
$redirect_agent = 'https://your-server/agc/vicidial.php';
$redirect_admin = 'https://your-server/vicidial/welcome.php';

// User level considered admin (gets redirected to admin panel)
$admin_level = 9;

// Portal page title
$portal_title = 'ViciDial Agent Portal';
```

No database credentials needed here — the portal reads them automatically from `/etc/astguiclient.conf`.

### 3. Apache virtual host

Create `/etc/httpd/conf.d/dynportal-ssl.conf`:

```apache
Listen 446 https

<VirtualHost _default_:446>
    ServerName your-server-hostname.com:446
    DocumentRoot /var/www/html/dynportal

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/your-domain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/your-domain.com/privkey.pem

    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder on

    <Directory /var/www/html/dynportal>
        AllowOverride None
        Require all granted
        DirectoryIndex valid8.php
    </Directory>

    # Block direct access to includes
    <Directory /var/www/html/dynportal/inc>
        Require all denied
    </Directory>

    ErrorLog  logs/dynportal_ssl_error_log
    TransferLog logs/dynportal_ssl_access_log
</VirtualHost>

# HTTP on port 81 — redirect to HTTPS:446
Listen 81

<VirtualHost _default_:81>
    ServerName your-server-hostname.com
    RewriteEngine On
    RewriteRule ^/?(.*) https://your-server-hostname.com:446/$1 [R=301,L]
</VirtualHost>
```

> **Important:** Use a valid TLS certificate (e.g. Let's Encrypt). Browsers will block the
> mic/WebRTC on mixed content — agents need HTTPS throughout.

### 4. Open firewall ports

```bash
firewall-cmd --permanent --add-port=446/tcp
firewall-cmd --permanent --add-port=81/tcp
firewall-cmd --reload
```

### 5. ViciDial IP List

In **ViciDial Admin → Admin → IP Lists**, create a list named exactly `ViciWhite`.
This is the list the portal writes to and that `VB-firewall` reads from.

### 6. Restart Apache

```bash
systemctl restart httpd
```

Portal is now live at `https://your-server:446/`

---

## 🔧 Configuration Reference

### `inc/defaults.inc.php`

| Variable         | Default                                | Description                                          |
|------------------|----------------------------------------|------------------------------------------------------|
| `$ip_list_id`    | `ViciWhite`                            | IP list ID in `vicidial_ip_list_entries`             |
| `$min_user_level`| `1`                                    | Minimum ViciDial user level allowed                  |
| `$redirect_agent`| `https://your-server/agc/vicidial.php` | Redirect URL for regular agents after login          |
| `$redirect_admin`| `https://your-server/vicidial/welcome.php` | Redirect URL for admins (user_level ≥ admin_level) |
| `$admin_level`   | `9`                                    | User level threshold for admin redirect              |
| `$portal_title`  | `ViciDial Agent Portal`                | HTML page title shown in browser                     |

---

## 🔥 Firewall Integration

The portal writes IPs into ViciDial's `vicidial_ip_list_entries` table (list: `ViciWhite`).
The `VB-firewall` script (installed by VICIdial) runs as a cron job every minute and syncs
that list into the `dynamiclist` firewalld ipset:

```bash
# Cron entry (auto-managed by VICIdial)
* * * * * /usr/share/astguiclient/VB-firewall ...
```

IPs are active within **~60 seconds** of login. When an agent re-authenticates, `entry_date`
is refreshed (audit trail). VB-firewall handles expiry of stale entries.

---

## 🐛 Troubleshooting

### "Bad Request" when accessing the portal URL

**Cause:** Browser (or redirect) sent an HTTP request to the SSL-only port 446.

**Fix:** Add an HTTP listener on port 81 that redirects to HTTPS:446 (see Apache config above).
Open port 81/tcp in firewalld.

### Portal login page not loading at all

Check that ports 81 and 446 are open:
```bash
firewall-cmd --list-ports | grep -E "81|446"
```

Check Apache is listening:
```bash
ss -tlnp | grep -E "81|446"
```

### "Invalid username or password" on valid ViciDial credentials

Verify the DB connection is working and the user exists in `vicidial_users` with `active='Y'`:
```sql
SELECT user, user_level, active FROM vicidial_users WHERE user = 'your_agent';
```

Also check `/etc/astguiclient.conf` is readable by Apache (`apache` user).

### IP whitelisted but agent still can't connect after 60 seconds

Check the IP was actually inserted:
```sql
SELECT * FROM vicidial_ip_list_entries WHERE ip_list_id = 'ViciWhite' ORDER BY entry_date DESC LIMIT 10;
```

Check the `dynamiclist` ipset:
```bash
ipset list dynamiclist | grep YOUR_AGENT_IP
```

Check VB-firewall cron is running:
```bash
grep VB-firewall /var/log/cron | tail -5
```

---

## 🛡️ Security Notes

- The portal must be served over **HTTPS only** — agents submit ViciDial credentials through it
- The `inc/` directory is blocked from direct web access via Apache `Require all denied`
- No credentials are stored by the portal — authentication goes directly against the ViciDial DB
- `dbconnect.inc.php` reads from `/etc/astguiclient.conf` — ensure Apache cannot serve that file

---

## 👤 Author

**FrancoSmash73** — [@FrancoSmash73](https://github.com/FrancoSmash73)

## 📄 License

MIT — See LICENSE file.
