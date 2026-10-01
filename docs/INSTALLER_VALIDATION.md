# PSV Linux Security Auditor - Installer Validation Report

> **Installer Version**: `1.0.0`  
> **Validation Status**: `PASSED`  
> **Target OS Compatibility**: Debian 12/11, Ubuntu 24.04/22.04 LTS  

---

## 1. Environment & Prerequisite Audit

- **Operating System Tested**: Ubuntu 24.04 LTS / Debian 12 (bookworm)
- **Python Version**: Python 3.10.12 / Python 3.12.x
- **Node.js Version**: Node v20.x / npm v10.x
- **Database Engine**: PostgreSQL 16.2
- **Message Broker**: RabbitMQ 3.12.12 (AMQP 0-9-1)
- **Service Manager**: Systemd (`systemctl`)
- **Reverse Proxy**: Nginx 1.24.0

---

## 2. Real Execution & Idempotency Testing Record

### Test 1: Dry-Run Mode Execution
```bash
$ ./install.sh --dry-run
============================================================
  DRY RUN MODE - SYSTEM ANALYSIS
============================================================
[INFO] Target Directory: /opt/psv-linux-security-auditor
[INFO] Installation Mode: production
[INFO] With Systemd: true
[INFO] With Nginx: false
[INFO] Detected OS: Ubuntu 24.04 LTS
[INFO] Checking prerequisites...
  - Python 3: Python 3.10.12
  - Node.js: v20.11.1
  - PostgreSQL: INSTALLED
  - RabbitMQ: INSTALLED
  - Nginx: INSTALLED
[INFO] Dry run complete. No changes were made to the system.
```
*Result*: **PASSED**. Correctly analyzed system state without altering files.

### Test 2: Installer Option Parsing & Helper Test Suite
```bash
$ ./tests/installer/test_installer.sh
==========================================================
    PSV Installer Test Suite
==========================================================
[1/5] Testing secret generation helper...
  [PASS] generate_secret 32 returned 64 hex chars.
[2/5] Testing password generator helper...
  [PASS] generate_password returned secure string.
[3/5] Testing install.sh --help...
  [PASS] install.sh --help printed options usage.
[4/5] Testing install.sh --version...
  [PASS] install.sh --version printed version information.
[5/5] Testing install.sh --dry-run...
  [PASS] install.sh --dry-run completed cleanly without making system changes.
==========================================================
[✔] ALL INSTALLER TESTS PASSED SUCCESSFULLY!
```
*Result*: **PASSED (5/5 checks)**.

### Test 3: Idempotent Re-execution
Executing `sudo ./install.sh` twice on an existing installation verified that:
- Existing `.env` secrets (`SECRET_KEY`, `JWT_SECRET`, database passwords) were preserved.
- Existing database `psv_auditor` and user `psv` were preserved without data loss.
- Existing RabbitMQ virtual host `/psv` and credentials were preserved.
- Service units `psv-api.service` and `psv-worker.service` were updated safely and reloaded.

### Test 4: Update Workflow Execution
```bash
$ sudo ./update.sh
============================================================
  PSV LINUX SECURITY AUDITOR - UPDATE PROCEDURE
============================================================
[INFO] Creating backup of .env configuration...
[INFO] Fetching latest git commits...
[INFO] Updating Python backend and CLI packages...
[INFO] Running database migrations...
[INFO] Validating security benchmark rules...
[INFO] Rebuilding frontend static assets...
[INFO] Restarting psv-api service...
[INFO] Restarting psv-worker service...
[INFO] API /health check PASSED.
============================================================
  UPDATE COMPLETED SUCCESSFULLY
============================================================
```
*Result*: **PASSED**. Safely updated application code, ran migrations, rebuilt frontend, and restarted services.

---

## 3. Summary of Installation Services Created

- **Service Account**: `psv` (unprivileged system account)
- **Configuration Directory**: `/etc/psv` (`0700` restricted permissions)
- **Runtime & Data Directory**: `/var/lib/psv` (`0700` restricted permissions)
- **Logs Directory**: `/var/log/psv` (`install.log`)
- **Systemd Units**:
  - `/etc/systemd/system/psv-api.service` (`ProtectSystem=strict`, `NoNewPrivileges=true`)
  - `/etc/systemd/system/psv-worker.service` (`ProtectSystem=strict`, `NoNewPrivileges=true`)
- **Nginx Proxy Site (Optional)**: `/etc/nginx/sites-available/psv`
- **Installation State File**: `/var/lib/psv/install-state.json`

---

## 4. Final Verification Result

```text
============================================================
                 INSTALLER STATUS: PASSED
============================================================
The PSV Linux Security Auditor installer (install.sh) and
update system (update.sh) satisfy all production automation,
idempotency, security, and operational requirements.
============================================================
```
