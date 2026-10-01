# PSV Linux Security Auditor - Complete Installation, Configuration & CLI Command Reference

This document provides a comprehensive operational guide for installing, configuring, managing, and executing security audits with the **PSV Linux Security Auditor** platform via the `psv` CLI command surface and production shell scripts.

---

## Table of Contents

- [1. Installation & Deployment Commands](#1-installation--deployment-commands)
  - [1.1 Production Automated Installation (`install.sh`)](#11-production-automated-installation-installsh)
  - [1.2 Manual Installation Workflow](#12-manual-installation-workflow)
  - [1.3 Systemd Service Management](#13-systemd-service-management)
  - [1.4 System Update Procedure (`update.sh`)](#14-system-update-procedure-updatesh)
- [2. Environment & Database Configuration](#2-environment--database-configuration)
  - [2.1 Configuration File (`.env`)](#21-configuration-file-env)
  - [2.2 Database Migrations (Alembic)](#22-database-migrations-alembic)
  - [2.3 Infrastructure Services (PostgreSQL & RabbitMQ)](#23-infrastructure-services-postgresql--rabbitmq)
- [3. Validation & Quality Scripts](#3-validation--quality-scripts)
  - [3.1 Benchmark Rule Pack Validation](#31-benchmark-rule-pack-validation)
  - [3.2 Installation & Production Hardening Checks](#32-installation--production-hardening-checks)
  - [3.3 Python Source Compilation & Test Suite](#33-python-source-compilation--test-suite)
- [4. Complete CLI Command Reference (`psv`)](#4-complete-cli-command-reference-psv)
  - [4.1 Global Options & System Info](#41-global-options--system-info)
  - [4.2 Control Plane & Server Control (`psv server`, `psv doctor`)](#42-control-plane--server-control-psv-server-psv-doctor)
  - [4.3 Target Host Management (`psv host`)](#43-target-host-management-psv-host)
  - [4.4 Security Audit Operations (`psv audit`)](#44-security-audit-operations-psv-audit)
  - [4.5 Finding Triage & Resolution (`psv finding`)](#45-finding-triage--resolution-psv-finding)
  - [4.6 Configuration Drift Analysis (`psv drift`)](#46-configuration-drift-analysis-psv-drift)
  - [4.7 Approval-Gated Remediation (`psv remediation`)](#47-approval-gated-remediation-psv-remediation)
  - [4.8 Finding Verification (`psv verify`)](#48-finding-verification-psv-verify)
  - [4.9 Benchmark Profiles & Rules (`psv profile`, `psv rule`)](#49-benchmark-profiles--rules-psv-profile-psv-rule)
  - [4.10 Executive Reporting (`psv report`)](#410-executive-reporting-psv-report)
  - [4.11 CLI Configuration & Login (`psv config`, `psv login`)](#411-cli-configuration--login-psv-config-psv-login)
- [5. Full End-to-End Operational Workflow](#5-full-end-to-end-operational-workflow)

---

## 1. Installation & Deployment Commands

### 1.1 Production Automated Installation (`install.sh`)

The repository includes a production-grade, idempotent bash installer (`install.sh`).

#### Make Script Executable

```bash
chmod +x install.sh update.sh
```

#### Production Installation with Systemd Services

```bash
sudo ./install.sh --mode production --with-systemd
```

#### Production Installation with Nginx Reverse Proxy

```bash
sudo ./install.sh --mode production --with-systemd --with-nginx
```

#### Development Installation (SQLite & Async Queue)

```bash
sudo ./install.sh --mode development
```

#### Non-Interactive Batch Installation

```bash
sudo ./install.sh --mode production --with-systemd --non-interactive
```

#### Dry-Run Inspection (No Changes Made)

```bash
./install.sh --dry-run
```

#### Installer Command Options

```text
Usage: sudo ./install.sh [OPTIONS]

Options:
  --help                 Show help message and exit
  --version              Show installer version
  --mode <mode>          'production' (default) or 'development'
  --with-systemd         Install and start Systemd services (default)
  --without-systemd      Skip Systemd service unit creation
  --with-nginx           Install and configure Nginx reverse proxy
  --skip-node            Skip Node.js / npm prerequisite checks
  --skip-postgresql      Skip local PostgreSQL database setup
  --skip-rabbitmq        Skip local RabbitMQ message broker setup
  --skip-frontend        Skip building frontend static assets
  --skip-migrations      Skip running database migrations
  --non-interactive      Batch execution (no interactive prompts)
  --dry-run              Inspect system without applying changes
  --uninstall            Uninstall PSV services and configuration
  --remove-data          Purge database and log directories on uninstall
```

---

### 1.2 Manual Installation Workflow

#### Step 1: Clone Repository

```bash
git clone https://github.com/vishnu123-king/PSV-Linux-Security-Auditor.git
cd PSV-Linux-Security-Auditor
```

#### Step 2: Create Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Step 3: Install Backend & CLI Packages

```bash
pip install -e .
pip install -e ./cli
```

#### Step 4: Frontend Installation & Production Build

```bash
cd frontend
npm ci
npm run build
cd ..
```

---

### 1.3 Systemd Service Management

#### Control Plane API (`psv-api`) Commands

```bash
# Check status
sudo systemctl status psv-api

# Start service
sudo systemctl start psv-api

# Stop service
sudo systemctl stop psv-api

# Restart service
sudo systemctl restart psv-api

# Enable auto-start on boot
sudo systemctl enable psv-api

# View real-time logs
sudo journalctl -u psv-api -f
```

#### Background Assessment Worker (`psv-worker`) Commands

```bash
# Check status
sudo systemctl status psv-worker

# Start service
sudo systemctl start psv-worker

# Stop service
sudo systemctl stop psv-worker

# Restart service
sudo systemctl restart psv-worker

# Enable auto-start on boot
sudo systemctl enable psv-worker

# View real-time logs
sudo journalctl -u psv-worker -f
```

---

### 1.4 System Update Procedure (`update.sh`)

To update an existing installation safely:

```bash
sudo ./update.sh
```

Workflow executed by `update.sh`:
```text
Backup .env & config ──> Git Pull ──> Upgrade Python Dependencies ──> Database Migrations ──> Rule Validation ──> Frontend Rebuild ──> Restart Services ──> Health Verification
```

---

## 2. Environment & Database Configuration

### 2.1 Configuration File (`.env`)

Initialize environment file:

```bash
cp .env.example .env
```

Key environment parameters:

```ini
APP_ENV="production"
DEBUG="false"
SECRET_KEY="generate-32-byte-hex-key"
JWT_SECRET="generate-32-byte-jwt-secret"
DATABASE_URL="postgresql+asyncpg://psv:secure_password@localhost:5432/psv_auditor"
RABBITMQ_URL="amqp://psv:secure_password@localhost:5672/psv"
INITIAL_ADMIN_EMAIL="admin@psv.local"
INITIAL_ADMIN_PASSWORD="AdminSecurePassword123!"
CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:8000"
```

---

### 2.2 Database Migrations (Alembic)

```bash
# Apply all pending database migrations
alembic upgrade head

# Check current applied migration state
alembic current

# View migration history
alembic history
```

---

### 2.3 Infrastructure Services (PostgreSQL & RabbitMQ)

#### PostgreSQL Service Commands

```bash
sudo systemctl status postgresql
sudo systemctl start postgresql
sudo systemctl restart postgresql
```

#### RabbitMQ Service Commands

```bash
sudo systemctl status rabbitmq-server
sudo systemctl start rabbitmq-server
sudo systemctl restart rabbitmq-server

# Check RabbitMQ queues
sudo rabbitmqctl list_queues -p /psv
```

---

## 3. Validation & Quality Scripts

### 3.1 Benchmark Rule Pack Validation

Validate the 60 benchmark security rules for schema compliance and duplicate IDs:

```bash
python scripts/validate_rules.py
```

Expected result:
```text
60 rules
11 YAML files
0 duplicate IDs
0 schema errors
```

---

### 3.2 Installation & Production Hardening Checks

```bash
# Check installation prerequisites and components
python scripts/verify_installation.py

# Check for weak secrets, debug mode, or SQLite in production
python scripts/verify_production_config.py
```

---

### 3.3 Python Source Compilation & Test Suite

```bash
# Compile Python byte-code across backend and CLI
python -m compileall backend cli scripts

# Run full pytest suite
pytest -v

# Run security-focused unit tests
pytest tests/test_fail_closed.py -v
pytest tests/test_ssrf_validation.py -v
pytest tests/test_command_injection.py -v
pytest tests/test_auth_hardening.py -v
pytest tests/test_authorization_idor.py -v
pytest tests/test_remediation_safety.py -v
pytest tests/test_xss_sanitization.py -v
```

---

## 4. Complete CLI Command Reference (`psv`)

### 4.1 Global Options & System Info

```bash
# Display CLI help
psv --help

# Display CLI and platform version
psv version
```

---

### 4.2 Control Plane & Server Control (`psv server`, `psv doctor`)

```bash
# Start FastAPI backend control plane server directly
psv start

# Check status of local server processes
psv server status

# Run system diagnostic checks
psv doctor
psv doctor --format json

# Start control plane in foreground or background
psv server start
psv server start --daemon

# Tail server logs
psv server logs

# Stop control plane server
psv server stop
```

---

### 4.3 Target Host Management (`psv host`)

```bash
# List all registered Linux audit targets
psv host list
psv host list --env production
psv host list --format json

# Onboard local Linux machine
psv host add-local
psv host add-local --name "my-kali-node" --address "127.0.0.1"

# Onboard remote Linux host
psv host add --name "web-prod-01" --address "192.168.1.50" --port 22 --user "psv-auditor"
psv host add --name "db-prod-01" --hostname "192.168.1.51" --port 22

# Auto-discover local IP interfaces and OS details
psv host discover

# Show host details and metadata
psv host show <HOST_ID>

# Test SSH connectivity and collector reachability
psv host test <HOST_ID>

# Remove or delete a target host
psv host remove <HOST_ID>
psv host delete <HOST_ID> --yes
```

---

### 4.4 Security Audit Operations (`psv audit`)

```bash
# Start a new security audit
psv audit run <HOST_ID_OR_NAME> --profile cis-linux-server
psv audit run local-node --profile server --no-wait

# Check audit execution status and progress
psv audit status <ASSESSMENT_ID>
psv audit show <ASSESSMENT_ID>

# List historical security audits
psv audit list
psv audit list --host local-node --status COMPLETED --limit 10
psv audit list --format json

# Cancel a running or queued audit job
psv audit cancel <ASSESSMENT_ID>
```

---

### 4.5 Finding Triage & Resolution (`psv finding`)

```bash
# List open security findings
psv finding list
psv finding list --severity CRITICAL
psv finding list --severity HIGH
psv finding list --host <HOST_ID>

# View finding details, rule context, and raw collector evidence
psv finding show <FINDING_ID>

# Acknowledge finding under review
psv finding acknowledge <FINDING_ID>

# Suppress finding with business exception reason
psv finding suppress <FINDING_ID> --reason "Compensating control active in perimeter firewall"

# Mark finding as resolved
psv finding resolve <FINDING_ID>
```

---

### 4.6 Configuration Drift Analysis (`psv drift`)

```bash
# Set an assessment as baseline state
psv drift baseline <ASSESSMENT_ID>

# Compare current state against host baseline
psv drift compare <HOST_ID_OR_NAME>
```

---

### 4.7 Approval-Gated Remediation (`psv remediation`)

```bash
# Create dry-run remediation plan & diff (does not change host)
psv remediation plan <FINDING_ID>

# Approve remediation plan (requires admin privileges)
psv remediation approve <REMEDIATION_ID> --approver "lead_security_admin"

# Execute approved remediation commands on host
psv remediation execute <REMEDIATION_ID> --yes

# Rollback remediation using recorded backup snapshot
psv remediation rollback <REMEDIATION_ID> --yes
```

---

### 4.8 Finding Verification (`psv verify`)

```bash
# Re-collect state and re-evaluate finding controls
psv verify <FINDING_ID>
```

---

### 4.9 Benchmark Profiles & Rules (`psv profile`, `psv rule`)

```bash
# List benchmark compliance profiles
psv profile list

# Show rules contained in a profile
psv profile show cis-linux-server

# List all 60 benchmark security rules
psv rule list
psv rule list --format json

# Show detailed specification and fix scripts for a rule
psv rule show SSH-01
psv rule show SYS-01

# Validate integrity of benchmark rule pack
psv rule validate
```

---

### 4.10 Executive Reporting (`psv report`)

```bash
# Generate executive report for an assessment
psv report generate <ASSESSMENT_ID>

# Export audit findings in CSV, HTML, or JSON format
psv report export <ASSESSMENT_ID> --format csv --output audit_report.csv
psv report export <ASSESSMENT_ID> --format html --output audit_report.html
```

---

### 4.11 CLI Configuration & Login (`psv config`, `psv login`)

```bash
# Set target server URL
psv config set server.url http://127.0.0.1:8000/api/v1

# Authenticate with control plane
psv login --email admin@psv.local --password AdminSecurePassword123!

# Display active CLI configuration (secrets masked)
psv config show
```

---

## 5. Full End-to-End Operational Workflow

For a newly installed Linux machine, execute the complete audit sequence:

```bash
# 1. Automated System Installation
sudo ./install.sh --mode production --with-systemd

# 2. Verify System Health & Rules
psv doctor
python scripts/validate_rules.py

# 3. Register Local Host Target
psv host add-local

# 4. Verify Local Connection & Collectors
psv host list
psv host test local-node

# 5. Execute Security Audit
psv audit run local-node --profile cis-linux-server

# 6. Check Audit Results & Findings
psv audit list
psv finding list --severity CRITICAL
psv finding show <FINDING_ID>

# 7. Generate Remediation Plan
psv remediation plan <FINDING_ID>
psv remediation approve <REMEDIATION_ID>
psv remediation execute <REMEDIATION_ID> --yes

# 8. Verify Finding Resolution & Generate Report
psv verify <FINDING_ID>
psv report generate <ASSESSMENT_ID>
```
