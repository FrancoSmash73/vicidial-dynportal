# 🌐 ViciDial Dynamic Portal

**Agent IP Self-Service Whitelisting for ViciDial Call Centers**

[![PHP](https://img.shields.io/badge/PHP-66%25-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![Shell](https://img.shields.io/badge/Shell-34%25-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Platform](https://img.shields.io/badge/platform-CentOS%20%2F%20Rocky%20Linux-red?logo=redhat)](https://rockylinux.org/)
[![Install Guide](https://img.shields.io/badge/docs-step--by--step%20guide-blue?logo=read-the-docs)](INSTALL.md)

---

## 📖 Overview

**ViciDial Dynamic Portal** is a self-service web application that allows remote ViciDial agents to whitelist their own dynamic IP addresses — without requiring admin intervention. Agents authenticate through the portal, and their current IP is automatically added to the server's firewall whitelist via `firewalld`, granting them access to the ViciDial interface.

This solves a common operational headache in call center environments: agents working from home or on dynamic IPs being locked out, and having to call IT every time their IP changes.

---

## ✨ Features

- 🔐 **Agent Self-Authentication** — agents log in with their ViciDial credentials
- 🌍 **Auto IP Detection** — the portal detects the agent's current public IP automatically
- 🔥 **Firewalld Integration** — dynamically adds/removes IPs from the server's firewall whitelist
- 🧹 **IP Cleanup** — removes stale/old IPs when an agent re-authenticates from a new address
- ⚡ **Lightweight** — PHP + Shell, no heavy framework dependencies
- 🛠️ **Simple Installer** — one-shot `install.sh` sets up everything
- 🔒 **Secure** — integrates directly with ViciDial's authentication, no separate credential store

---

## 📁 Repository Structure

vicidial-dynportal/
├── bin/                  # Helper shell scripts (IP management utilities)
├── dynportal/            # PHP web portal (agent-facing UI)
├── firewalld/            # firewalld zone/policy configuration files
├── httpd/                # Apache httpd virtual host configuration
├── inc/                  # PHP include files (config, DB connection, helpers)
├── install.sh            # Automated installer script
└── valid8.php            # IP validation & credential verification logic

---

## 🧰 Requirements

| Component     | Version / Notes                          |
|---------------|------------------------------------------|
| OS            | CentOS 7/8, Rocky Linux 8/9, RHEL 8/9   |
| Web Server    | Apache httpd 2.4+                        |
| PHP           | 7.2+ (with `mysqli` and `curl` modules)  |
| Firewall      | `firewalld` (must be active)             |
| ViciDial      | Any modern version with DB access        |
| Permissions   | Root or `sudo` for install & firewall ops|

---

## 🚀 Installation

> 📖 **For the full step-by-step walkthrough, see [INSTALL.md](INSTALL.md).**  
> It covers prerequisites, Apache & firewalld config, SSL setup, cron jobs, testing, agent instructions, and troubleshooting.

### Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/FrancoSmash73/vicidial-dynportal.git
cd vicidial-dynportal

# 2. Run the installer
chmod +x install.sh
sudo ./install.sh

# 3. Edit the portal config with your ViciDial DB credentials
vi /var/www/html/dynportal/inc/defaults.inc.php

# 4. Restart services
sudo systemctl restart httpd
sudo systemctl reload firewalld
```

After that, the portal is available at:

| Protocol | URL |
|----------|-----|
| HTTP     | `http://your-server-ip:81/valid8.php` |
| HTTPS    | `https://your-server-hostname.com:446/valid8.php` |

---

## 🖥️ How It Works

Agent opens portal in browser
│
▼
Enters ViciDial username/password
│
▼
valid8.php authenticates credentials
against ViciDial database
│
▼
Portal detects agent's current IP
│
▼
bin/ script calls firewall-cmd to
add IP to whitelist zone
│
▼
Agent can now connect to ViciDial ✅

When the agent re-authenticates from a new IP, the old IP is removed and the new one is added automatically.

---

## 🔧 Usage

Agents simply navigate to the portal URL in their browser (e.g. `https://your-vicidial-server:446/valid8.php`), enter their credentials, and click **"Whitelist My IP"**. No IT intervention required.

Admins can monitor whitelisted IPs via:

```bash
sudo firewall-cmd --list-sources --zone=vicidial-agents
```

---

## 🛡️ Security Considerations

- The portal should only be accessible over **HTTPS** (configure TLS in `httpd/`).
- Credentials are validated directly against the ViciDial MySQL database — no passwords are stored by this application.
- Consider **rate-limiting** the portal endpoint to prevent brute-force login attempts (e.g. using `mod_evasive` or `fail2ban`).
- Whitelisted IPs are stored in a dedicated `firewalld` zone isolated from other rules.
- Regularly audit the whitelist and remove stale entries.

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Commit your changes: `git commit -m 'Add: my improvement'`
4. Push and open a Pull Request

---

## 📄 License

This project is open-source. See [LICENSE](LICENSE) for details.

---

## 👤 Author

**FrancoSmash73**  
GitHub: [@FrancoSmash73](https://github.com/FrancoSmash73)

---

> 💡 **Tip:** If your ViciDial agents frequently change IPs (remote/home workers, mobile data), pair this portal with a short-lived firewall rule TTL to automatically expire old whitelisted IPs without manual cleanup.
>
> 
