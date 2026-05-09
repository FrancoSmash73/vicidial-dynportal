# 📋 ViciDial Dynamic Portal — Step-by-Step Installation Guide

> **Target OS:** CentOS 7/8 · Rocky Linux 8/9 · AlmaLinux 8/9  
> **Web Server:** Apache httpd  
> **Firewall:** `firewalld`  
> **Estimated Time:** 20–30 minutes

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Clone the Repository](#2-clone-the-repository)
3. [Run the Installer](#3-run-the-installer)
4. [Configure the Portal](#4-configure-the-portal)
5. [Configure Apache (httpd)](#5-configure-apache-httpd)
6. [Configure Firewalld](#6-configure-firewalld)
7. [Set Up SSL (HTTPS) — Recommended](#7-set-up-ssl-https--recommended)
8. [Set Up the Cron Job](#8-set-up-the-cron-job)
9. [Restart Services](#9-restart-services)
10. [Test the Portal](#10-test-the-portal)
11. [Agent Usage Instructions](#11-agent-usage-instructions)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisites

Before starting, make sure the following are in place on your ViciDial server:

```bash
# Verify Apache is installed and running
systemctl status httpd

# Verify firewalld is installed and running
systemctl status firewalld

# Verify PHP is installed (7.2+ required)
php -v

# Verify PHP mysqli module is loaded
php -m | grep mysqli
```

If any are missing, install them:

```bash
# Install Apache and PHP (Rocky/AlmaLinux 8+)
dnf install -y httpd php php-mysqli php-curl

# Install and enable firewalld
dnf install -y firewalld
systemctl enable --now firewalld

# Start and enable Apache
systemctl enable --now httpd
```

---

## 2. Clone the Repository

```bash
# Navigate to a working directory
cd /opt

# Clone the repo
git clone https://github.com/FrancoSmash73/vicidial-dynportal.git

# Enter the project directory
cd vicidial-dynportal
```

> **No git?** Install it first: `dnf install -y git`

---

## 3. Run the Installer

The included `install.sh` script handles the bulk of the setup automatically.

```bash
# Make the installer executable
chmod +x install.sh

# Run as root
sudo ./install.sh
```

The installer will:
- Copy the portal files to the web root (`/var/www/html/dynportal`)
- Deploy the Apache virtual host config from `httpd/`
- Apply `firewalld` zone and ipset configs from `firewalld/`
- Set correct file permissions on the portal files

> ⚠️ **If prompted to overwrite existing firewalld zone files (e.g. `public.xml`), type `yes`.**

---

## 4. Configure the Portal

After installation, edit the portal's configuration file to point it to your ViciDial database.

```bash
# Open the main config file
vi /var/www/html/dynportal/inc/defaults.inc.php
```

Update the following values:

```php
// --- Database Connection ---
$PORTAL_dbhost   = 'localhost';       // Your ViciDial DB host
$PORTAL_dbuser   = 'cron';           // ViciDial DB user (usually 'cron')
$PORTAL_dbpass   = 'your_password';  // ViciDial DB password
$PORTAL_dbname   = 'asterisk';       // ViciDial database name

// --- Portal Behavior ---
$PORTAL_userlevel     = 1;   // Minimum ViciDial user level allowed (1 = agents)
$PORTAL_secure        = 1;   // 1 = require HTTPS, 0 = allow HTTP
$PORTAL_casesensitive = 0;   // 1 = case-sensitive login, 0 = case-insensitive
$PORTAL_loginfails    = 5;   // Max failed login attempts before lockout
```

> 💡 Your ViciDial DB credentials can be found in `/etc/astguiclient.conf` on the ViciDial server.

---

## 5. Configure Apache (httpd)

The portal runs on a separate port from your main ViciDial interface:

| Mode  | Port |
|-------|------|
| HTTP  | 81   |
| HTTPS | 446  |

### 5a. Add the Listen Ports

```bash
vi /etc/httpd/conf/httpd.conf
```

Make sure these lines are present:

```apache
Listen 80
Listen 81
```

For HTTPS, also edit your SSL config:

```bash
vi /etc/httpd/conf.d/ssl.conf
```

Add after `Listen 443`:

```apache
Listen 446
```

### 5b. Verify the Virtual Host Config

The installer should have placed this file automatically. Verify it:

```bash
cat /etc/httpd/conf.d/dynportal.conf
```

It should look like this (HTTP version):

```apache
<VirtualHost *:81>
    ServerName your-server-hostname.com
    DocumentRoot /var/www/html/dynportal
    ErrorLog /var/log/httpd/dynportal-error.log
    CustomLog /dev/null combined

    DirectoryIndex index.html index.php

    <Files ~ "^\.ht">
        Require all denied
    </Files>
    <Files ~ "^\debug.txt">
        Require all denied
    </Files>
    <Directory "/var/www/html/dynportal/inc">
        Require all denied
    </Directory>
    <Directory "/var/www/html/dynportal">
        Options FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
```

---

## 6. Configure Firewalld

### 6a. Open the Portal Ports

```bash
# Allow the portal ports through the firewall
sudo firewall-cmd --permanent --add-port=81/tcp
sudo firewall-cmd --permanent --add-port=446/tcp

# Reload firewall to apply
sudo firewall-cmd --reload
```

### 6b. Verify Zones and IPSets

The installer copies zone and ipset configs from the `firewalld/` folder. Confirm they're in place:

```bash
# List available zones
sudo firewall-cmd --list-all-zones | grep -A5 "vicidial"

# List custom ipsets
sudo firewall-cmd --get-ipsets
```

---

## 7. Set Up SSL (HTTPS) — Recommended

Running the portal over HTTPS is **strongly recommended** since agents submit their credentials through it.

### Option A: Let's Encrypt (Certbot)

```bash
# Install certbot
dnf install -y certbot python3-certbot-apache

# Obtain a certificate for your domain
certbot --apache -d your-server-hostname.com
```

### Option B: Manual SSL Certificate

Edit the SSL virtual host config:

```bash
vi /etc/httpd/conf.d/dynportal-ssl.conf
```

Update the certificate paths:

```apache
<VirtualHost *:446>
    ServerName your-server-hostname.com
    DocumentRoot /var/www/html/dynportal

    SSLEngine on
    SSLCertificateFile     /etc/letsencrypt/live/your-domain.com/cert.pem
    SSLCACertificateFile   /etc/letsencrypt/live/your-domain.com/fullchain.pem
    SSLCertificateKeyFile  /etc/letsencrypt/live/your-domain.com/privkey.pem
</VirtualHost>
```

### Force HTTPS Redirect (Optional)

To redirect all HTTP portal traffic to HTTPS, add this to your HTTP virtual host (`*:81`):

```apache
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule (.*) https://%{SERVER_NAME}:446/$1 [R,L]
```

---

## 8. Set Up the Cron Job

The firewall script must run every minute to pick up newly whitelisted IPs from the database and apply them to `firewalld`.

```bash
sudo crontab -e
```

Add these two lines:

```cron
@reboot /usr/bin/VB-firewall --white --dynamic --quiet
* * * * * /usr/bin/VB-firewall --white --dynamic --quiet
```

> 📌 `--white` applies the static whitelist. `--dynamic` applies IPs submitted through the portal. Both should always be used together.

---

## 9. Restart Services

```bash
sudo systemctl restart httpd
sudo systemctl reload firewalld

# Verify both are running cleanly
sudo systemctl status httpd
sudo systemctl status firewalld
```

Check the Apache error log if something doesn't start:

```bash
sudo tail -f /var/log/httpd/error_log
sudo tail -f /var/log/httpd/dynportal-error.log
```

---

## 10. Test the Portal

Open a browser and navigate to:

| Protocol | URL |
|----------|-----|
| HTTP     | `http://your-server-ip:81/valid8.php` |
| HTTPS    | `https://your-server-hostname.com:446/valid8.php` |

You should see the **Dynamic Portal login page**. Enter a valid ViciDial agent username and password. On success, the agent's IP is added to the whitelist and will be applied to `firewalld` within **~60 seconds** (next cron run).

To immediately verify an IP was added:

```bash
sudo firewall-cmd --list-sources --zone=<your-dynamic-zone>
```

---

## 11. Agent Usage Instructions

Share this with your remote agents:

---

> ### 🖥️ How to Whitelist Your IP
>
> If you're working from home or your IP has changed and you can't connect to the ViciDial system:
>
> 1. Open a browser and go to: `https://your-server-hostname.com:446/valid8.php`
> 2. Enter your **ViciDial username and password**
> 3. Click **Submit / Validate**
> 4. Wait **up to 60 seconds**, then try connecting to ViciDial again
>
> ✅ Your current IP will be whitelisted automatically.  
> 🔁 If your IP changes again, simply repeat these steps.

---

## 12. Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| Portal page not loading | Port 81/446 not open | Run `firewall-cmd --add-port=81/tcp --permanent && firewall-cmd --reload` |
| "Login failed" on valid credentials | `$PORTAL_userlevel` too high | Set `$PORTAL_userlevel = 1` in `defaults.inc.php` |
| IP not being whitelisted after login | Cron job not set up | Check `crontab -l` and ensure the `VB-firewall` cron entry exists |
| SSL cert not trusted in browser | Self-signed or misconfigured cert | Use Let's Encrypt via certbot |
| Apache won't start on port 446 | `Listen 446` missing from SSL config | Add `Listen 446` to `/etc/httpd/conf.d/ssl.conf` |
| `/inc` directory accessible | VHost config missing deny rule | Add `<Directory ".../inc"> Require all denied </Directory>` |
| Portal works but ViciDial still blocked | Firewalld zone misconfigured | Verify ipsets with `firewall-cmd --get-ipsets` and check zone assignment |

---

> 💡 **Security tip:** Consider changing the portal from port 446 to a random high port (e.g. `51234`) for security through obscurity. Update `httpd.conf`, `ssl.conf`, `dynportal-ssl.conf`, and the firewall rule accordingly, then restart both services.
