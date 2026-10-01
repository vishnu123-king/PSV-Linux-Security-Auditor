# PSV Linux Security Auditor - Installation & Upgrade Guide

## 1. Automated Installation Overview

The PSV Linux Security Auditor includes a secure, idempotent, automated installer located at the root of the repository:
```text
install.sh
```

It automates operating system verification, dependency installation, database provisioning, message broker configuration, production secret generation, systemd service setup, frontend asset building, and health check validation.

---

## 2. Quickstart Installation

On a clean Debian or Ubuntu server:

```bash
git clone https://github.com/psv-auditor/psv-linux-security-auditor.git
cd psv-linux-security-auditor

chmod +x install.sh
sudo ./install.sh
```

---

## 3. Installation Modes & Command-Line Options

### Production Mode (Default)
In production mode, the installer requires **PostgreSQL** and **RabbitMQ**, creates dedicated service account `psv`, generates cryptographically random application secrets, configures systemd services, and executes database migrations:

```bash
sudo ./install.sh --mode production --with-systemd
```

### Production Mode with Nginx Reverse Proxy
To configure Nginx as a reverse proxy for static assets and WebSocket/API traffic:

```bash
sudo ./install.sh --mode production --with-systemd --with-nginx
```

### Development Mode
For local development or testing without Systemd or production infrastructure:

```bash
sudo ./install.sh --mode development --without-systemd
```

### Non-Interactive / Unattended Batch Mode
For automated CI/CD or Ansible provisioning:

```bash
sudo ./install.sh --mode production --non-interactive
```

### Dry Run (Inspection Mode)
Inspect system dependencies, OS detection, and configuration without modifying any files:

```bash
./install.sh --dry-run
```

---

## 4. CLI Options Reference

| Flag | Description |
| :--- | :--- |
| `--help` | Display command usage and option descriptions |
| `--version` | Display installer and application version |
| `--mode <production\|development>` | Set installation target mode (default: `production`) |
| `--with-systemd` | Install and start Systemd services `psv-api` and `psv-worker` |
| `--without-systemd` | Skip Systemd service installation |
| `--with-nginx` | Install and configure Nginx reverse proxy on port 80 |
| `--skip-node` | Skip Node.js and npm version checks |
| `--skip-postgresql` | Skip local PostgreSQL user and database provisioning |
| `--skip-rabbitmq` | Skip local RabbitMQ user and virtual host provisioning |
| `--skip-frontend` | Skip building frontend web assets |
| `--skip-migrations` | Skip running Alembic database migrations |
| `--non-interactive` | Run in unattended batch mode without prompts |
| `--dry-run` | Analyze system environment without changing files |
| `--uninstall` | Uninstall PSV services and configuration |
| `--remove-data` | In combination with `--uninstall`, purge `/var/lib/psv` and databases |

---

## 5. System Directory Structure

The installer establishes standard production system directories:

- `/opt/psv-linux-security-auditor`: Primary application directory and virtualenv
- `/etc/psv`: Production configuration files (`0700` restricted permissions)
- `/var/lib/psv`: Persistent state, reports, and backups (`0700` restricted)
- `/var/log/psv`: Installer and application runtime logs (`install.log`)
- `/var/lib/psv/install-state.json`: Idempotent installation state file

---

## 6. Updating PSV Linux Security Auditor

To update an existing PSV installation safely:

```bash
sudo ./update.sh
```

The update procedure automatically:
1. Verifies git working tree cleanliness (prevents overwriting local edits)
2. Backs up `.env` configuration to `/var/lib/psv/backups/`
3. Pulls latest repository updates (`git pull --ff-only`)
4. Updates Python virtual environment packages
5. Executes database migrations (`alembic upgrade head`)
6. Validates benchmark rules (`scripts/validate_rules.py`)
7. Rebuilds frontend static assets (`npm run build`)
8. Restarts systemd services (`psv-api` and `psv-worker`)
9. Performs post-update API health verification (`/health` & `/ready`)

---

## 7. Safe Uninstallation

To remove PSV services while preserving database and audit evidence:

```bash
sudo ./install.sh --uninstall
```

To purge all application files, databases, logs, and evidence:

```bash
sudo ./install.sh --uninstall --remove-data
```
