# 📋 ViciDial Dynamic Portal — Installation Guide

> **Target OS:** Rocky Linux 8/9/10, CentOS 7/8, AlmaLinux 8/9  
> **Web Server:** Apache httpd 2.4+  
> **Firewall:** firewalld with `dynamiclist` ipset (standard VICIdial setup)  
> **Estimated Time:** 15 minutes

---

## Prerequisites

- VICIdial fully installed and running
- Apache (`httpd`) installed and running
- PHP 7.2+ with `mysqli` extension
- Valid TLS certificate for your server's hostname (Let's Encrypt recommended)
- `firewalld` active with the `dynamiclist` ipset (standard on VICIdial servers)
- A `ViciWhite` IP list created in ViciDial Admin → Admin → IP Lists

```bash
# Verify requirements
systemctl is-active httpd
php -m | grep mysqli
firewall-cmd --get-ipsets | grep dynamiclist
```

---

## Step 1 — Clone into web root

```bash
cd /var/www/html
git clone https://github.com/FrancoSmash73/vicidial-dynportal.git dynportal

chmod -R 755 /var/www/html/dynportal
chown -R apache:apache /var/www/html/dynportal
```

---

## Step 2 — Configure the portal

`defaults.inc.php` is excluded from git (via `.gitignore`) so it is never overwritten by future
`git pull` updates. Copy the included template and edit it for your server:

```bash
cd /var/www/html/dynportal/inc
cp defaults.inc.php.example defaults.inc.php
vi defaults.inc.php
```

Replace `YOUR_SERVER_HOSTNAME` with your server's actual hostname or domain:

```php
<?php
// IP list ID in vicidial_ip_list_entries (must match a list in ViciDial Admin)
$ip_list_id = 'ViciWhite';

// Minimum ViciDial user level to use portal (1 = all active agents)
$min_user_level = 1;

// Redirect after successful login
$redirect_agent = 'https://YOUR_SERVER_HOSTNAME/agc/vicidial.php';
$redirect_admin = 'https://YOUR_SERVER_HOSTNAME/vicidial/welcome.php';

// user_level >= this value gets the admin redirect
$admin_level = 9;

// Page title shown in browser tab
$portal_title = 'ViciDial Agent Portal';
```

> **No DB credentials needed.** `dbconnect.inc.php` auto-reads them from `/etc/astguiclient.conf`.  
> **Future `git pull` updates will never overwrite your `defaults.inc.php`.**

---

## Step 3 — Apache virtual host

Create `/etc/httpd/conf.d/dynportal-ssl.conf`:

```apache
Listen 446 https

<VirtualHost _default_:446>
    ServerName YOUR_SERVER_HOSTNAME:446
    DocumentRoot /var/www/html/dynportal

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem

    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder on

    <Directory /var/www/html/dynportal>
        AllowOverride None
        Require all granted
        DirectoryIndex valid8.php
    </Directory>

    <Directory /var/www/html/dynportal/inc>
        Require all denied
    </Directory>

    ErrorLog  logs/dynportal_ssl_error_log
    TransferLog logs/dynportal_ssl_access_log
    LogLevel warn
</VirtualHost>

# HTTP on port 81 → redirect to HTTPS:446
Listen 81

<VirtualHost _default_:81>
    ServerName YOUR_SERVER_HOSTNAME
    RewriteEngine On
    RewriteRule ^/?(.*) https://YOUR_SERVER_HOSTNAME:446/$1 [R=301,L]
</VirtualHost>
```

> Replace `YOUR_SERVER_HOSTNAME` and `YOUR_DOMAIN` throughout.

---

## Step 4 — Open firewall ports

```bash
firewall-cmd --permanent --add-port=446/tcp
firewall-cmd --permanent --add-port=81/tcp
firewall-cmd --reload

# Verify
firewall-cmd --list-ports | grep -E "81|446"
```

---

## Step 5 — Create the ViciWhite IP list in ViciDial

1. Log into ViciDial Admin
2. Go to **Admin → IP Lists**
3. Create a new list with ID: `ViciWhite`
4. Ensure the `VB-firewall` cron is configured to read this list (standard on VICIdial servers)

---

## Step 6 — Restart Apache

```bash
systemctl restart httpd
systemctl status httpd
```

---

## Step 7 — Test

Open a browser and go to:

```
https://YOUR_SERVER_HOSTNAME:446/
```

You should see the portal login page showing your public IP. Log in with any active ViciDial
agent credentials. On success:

- Your IP is inserted into `vicidial_ip_list_entries` (list: `ViciWhite`)
- Within ~60 seconds, `VB-firewall` syncs it to the `dynamiclist` firewalld ipset
- You are redirected to the ViciDial agent screen (or admin panel if user_level ≥ 9)

Verify the IP was written:
```sql
SELECT * FROM vicidial_ip_list_entries WHERE ip_list_id = 'ViciWhite' ORDER BY entry_date DESC LIMIT 5;
```

Verify it hit the firewall:
```bash
ipset list dynamiclist | grep YOUR_IP
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "Bad Request" on port 446 | Browser sent HTTP to HTTPS port — ensure port 81 redirect is in place and port 81/tcp is open in firewalld |
| Portal not loading | Verify `ss -tlnp \| grep -E "81\|446"` and that firewall ports are open |
| Login fails on valid credentials | Check `vicidial_users` has `active='Y'`; check `/etc/astguiclient.conf` is readable by `apache` user |
| IP whitelisted but agent still blocked after 60s | Check `ipset list dynamiclist`; verify VB-firewall cron is running (`grep VB-firewall /var/log/cron`) |
| `inc/` files served by Apache | Ensure `Require all denied` block is in the vhost for `/var/www/html/dynportal/inc` |
| SSL cert errors | Use a valid Let's Encrypt cert — self-signed certs are rejected by browsers for mixed-content reasons |
