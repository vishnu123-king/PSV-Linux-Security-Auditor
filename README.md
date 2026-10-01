# PSV Linux Security Auditor

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](pyproject.toml)
[![Benchmark Rules](https://img.shields.io/badge/Rules-60%20Verified-green.svg)](rules/)
[![Security Hardened](https://img.shields.io/badge/Hardened-26%20Domains-success.svg)](docs/PRODUCTION_HARDENING_AUDIT.md)

> **Enterprise-grade, defensive Linux security auditing platform featuring SSH and local agentless collectors, YAML benchmark rule evaluation, real-time WebSocket progress, configuration drift detection, approval-gated remediation, and a unified CLI control surface (`psv`).**

---

## Table of Contents

- [1. System Architecture](#1-system-architecture)
- [2. Core Capabilities & Invariants](#2-core-capabilities--invariants)
- [3. Automated Installation (`install.sh`)](#3-automated-installation-installsh)
- [4. Complete CLI Command Reference (`psv`)](#4-complete-cli-command-reference-psv)
  - [4.1 Health Check & Diagnostics (`psv doctor`)](#41-health-check--diagnostics-psv-doctor)
  - [4.2 Service Control (`psv server`)](#42-service-control-psv-server)
  - [4.3 Host Target Management (`psv host`)](#43-host-target-management-psv-host)
  - [4.4 Security Audit Operations (`psv audit`)](#44-security-audit-operations-psv-audit)
  - [4.5 Finding Triage & Management (`psv finding`)](#45-finding-triage--management-psv-finding)
  - [4.6 Configuration Drift Analysis (`psv drift`)](#46-configuration-drift-analysis-psv-drift)
  - [4.7 Approval-Gated Remediation (`psv remediation`)](#47-approval-gated-remediation-psv-remediation)
  - [4.8 Benchmark Profile Management (`psv profile`)](#48-benchmark-profile-management-psv-profile)
  - [4.9 Benchmark Rule Engine (`psv rule`)](#49-benchmark-rule-engine-psv-rule)
  - [4.10 Executive Reporting (`psv report`)](#410-executive-reporting-psv-report)
  - [4.11 Authentication & Configuration (`psv config` / `psv login`)](#411-authentication--configuration-psv-config--psv-login)
  - [4.12 Production Verification (`psv verify`)](#412-production-verification-psv-verify)
- [5. Local Development Quickstart](#5-local-development-quickstart)
- [6. Production Deployment & Systemd](#6-production-deployment--systemd)
- [7. Operational & Security Documentation](#7-operational--security-documentation)

---

## 1. System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          React Web Console                             │
│               (Port 5173 Dev / Port 80 Nginx Production)               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (REST API & WebSockets - JWT Bearer)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     FastAPI Control Plane (Port 8000)                  │
│  ├── Auth & RBAC (Admin, Analyst, Operator, Viewer)                    │
│  ├── Local & Remote SSH Host Management                                │
│  ├── YAML Benchmark Rule Loader (60 Benchmark Rules)                   │
│  ├── Configuration Drift Engine                                        │
│  ├── Approval-Gated Remediation & Rollback Engine                      │
│  └── Audit Event Logger                                                │
└──────────────────┬─────────────────────────────────┬───────────────────┘
                   │                                 │
                   ▼                                 ▼
┌──────────────────────────────┐   ┌────────────────────────────────────┐
│      Database Layer          │   │        Message Broker Layer        │
│  ├── PostgreSQL (Production) │   │  ├── RabbitMQ (Production)          │
│  └── SQLite (Development)    │   │  └── Asyncio Queue (Development)   │
└──────────────────────────────┘   └─────────────────┬──────────────────┘
                                                     │
                                                     ▼
                                   ┌────────────────────────────────────┐
                                   │     Background Assessment Worker    │
                                   │  ├── 12 Agentless Collectors       │
                                   │  ├── Rule Evaluation Engine        │
                                   │  └── Real-time WS Progress         │
                                   └─────────────────┬──────────────────┘
                                                     │
                                                     ▼
                                   ┌────────────────────────────────────┐
                                   │     Linux Security Targets         │
                                   │  ├── Local Machine Inspection      │
                                   │  └── Remote SSH Targets (Key/Pass) │
                                   └────────────────────────────────────┘
```

---

## 2. Core Capabilities & Invariants

- **12 Agentless Security Collectors**: `system`, `identity`, `ssh`, `sudo`, `filesystem`, `networking`, `firewall`, `services`, `kernel`, `pam`, `logging`, and `containers`.
- **60 Executable Benchmark Rules**: Standardized CIS/DISA-STIG benchmark rules across 11 security domains.
- **Fail-Closed Invariant**: If a collector fails or times out, controls evaluate to `UNKNOWN` with explicit error diagnostics—never a false `PASS`.
- **Immutable Command Registry**: Remote execution uses strict token arrays defined in `backend/app/security/command_registry.py`. Shell string interpolation or arbitrary shell execution is strictly prohibited.
- **Approval-Gated Remediation**: Non-destructive dry-run diffs, `.psv_backup` generation, pre-application syntax validation (`sshd -t`), management port preservation (`ufw allow 22/tcp`), and atomic rollback.
- **Multi-Tenant RBAC**: 4-tier role hierarchy (`ADMIN`, `SECURITY_ANALYST`, `OPERATOR`, `VIEWER`) with organization-scoped data isolation.

---

## 3. Automated Installation (`install.sh`)

The repository includes a production-grade, idempotent bash installation script (`install.sh`) designed for Debian, Ubuntu, Kali, and RHEL-family Linux distributions.

### Basic Automated Installation

```bash
# Clone the repository
git clone https://github.com/vishnu123-king/PSV-Linux-Security-Auditor.git
cd PSV-Linux-Security-Auditor

# Run the installer with superuser privileges
sudo ./install.sh
```

### Installation Script Options

| Option | Description |
| :--- | :--- |
| `--help` | Show installer help message and exit |
| `--mode <mode>` | Set installation mode: `production` (default) or `development` |
| `--with-systemd` | Install and start Systemd services (`psv-api`, `psv-worker`) (default) |
| `--without-systemd` | Skip Systemd service unit creation |
| `--with-nginx` | Install and configure Nginx reverse proxy on port 80 |
| `--skip-node` | Skip Node.js and npm prerequisite checks |
| `--skip-postgresql` | Skip local PostgreSQL database setup (useful when using external DB) |
| `--skip-rabbitmq` | Skip local RabbitMQ message broker setup (useful when using external queue) |
| `--skip-frontend` | Skip building frontend production static assets |
| `--skip-migrations` | Skip running database schema initialization |
| `--non-interactive` | Run in non-interactive batch mode (no prompts) |
| `--dry-run` | Inspect environment and configuration without modifying system |
| `--uninstall` | Stop and remove PSV services and configuration files |
| `--remove-data` | Purge database and log directories when uninstalled |

---

## 4. Complete CLI Command Reference (`psv`)

The `psv` executable is installed into the Python environment (`.venv/bin/psv`). It provides full command-line interaction with the PSV Control Plane.

### 4.1 Health Check & Diagnostics (`psv doctor`)

Evaluates local Python environment, virtualenv binaries, database connections, message broker queues, and service status.

```bash
# Run comprehensive system diagnostic check
psv doctor
```

---

### 4.2 Service Control (`psv server`)

Manage the local PSV Control Plane API and worker processes.

```bash
# Start both API control plane and background worker
psv server start

# Start control plane in foreground / background
psv server start --daemon

# Check status of running PSV server processes
psv server status

# Tail control plane server logs
psv server logs

# Stop running PSV processes
psv server stop
```

---

### 4.3 Host Target Management (`psv host`)

Manage authorized Linux audit targets (local machine and remote SSH hosts).

```bash
# List all registered host targets
psv host list

# Automatically discover local machine network addresses and OS details
psv host discover

# Add the local machine for local security audit
psv host add local-node --hostname 127.0.0.1 --local

# Add a remote SSH host using SSH private key
psv host add web-prod-01 --hostname 192.168.1.50 --port 22 --credential-id <CRED_UUID>

# Display host target details and metadata
psv host show <HOST_ID>

# Test SSH connection and collector execution for a host target
psv host test <HOST_ID>

# Delete a host target from inventory
psv host delete <HOST_ID>
```

---

### 4.4 Security Audit Operations (`psv audit`)

Queue, monitor, and manage security benchmark audits.

```bash
# Run a security audit against a host using default or specific profile
psv audit run <HOST_ID_OR_NAME> --profile cis-debian-level1

# List all assessment executions and statuses
psv audit list

# Display detailed audit summary, compliance score, and status
psv audit show <ASSESSMENT_ID>

# Cancel an active or queued audit job
psv audit cancel <ASSESSMENT_ID>
```

---

### 4.5 Finding Triage & Management (`psv finding`)

Inspect and manage security benchmark findings resulting from audits.

```bash
# List open security findings across all hosts
psv finding list

# Filter findings by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
psv finding list --severity CRITICAL

# Filter findings by host
psv finding list --host-id <HOST_ID>

# View finding details, rule context, and raw collector evidence
psv finding show <FINDING_ID>

# Acknowledge a finding with analyst notes
psv finding acknowledge <FINDING_ID> --comment "Risk accepted for legacy service requirement"

# Suppress a finding from active alert counts
psv finding suppress <FINDING_ID> --reason "Compensating control active in perimeter firewall"
```

---

### 4.6 Configuration Drift Analysis (`psv drift`)

Compare security states across different audit baselines to detect configuration drift.

```bash
# Set a specific assessment as baseline for a host
psv drift baseline <ASSESSMENT_ID>

# Compare current security state against host baseline
psv drift compare <HOST_ID>
```

---

### 4.7 Approval-Gated Remediation (`psv remediation`)

Safely remediate failed benchmark controls with mandatory approval gates and rollbacks.

```bash
# Generate a remediation plan and dry-run diff for a finding
psv remediation plan <FINDING_ID>

# Apply approved remediation with automatic backup creation
psv remediation apply <PLAN_ID> --approve

# Rollback an applied remediation to restore pre-remediation configuration
psv remediation rollback <REMEDIATION_ID>
```

---

### 4.8 Benchmark Profile Management (`psv profile`)

Inspect available compliance benchmark profiles.

```bash
# List all registered benchmark profiles
psv profile list

# Display rules included in a specific profile
psv profile show cis-debian-level1
```

---

### 4.9 Benchmark Rule Engine (`psv rule`)

Query, inspect, and validate YAML security rules.

```bash
# List all 60 benchmark rules across security domains
psv rule list

# Show detailed specification, audit commands, and fix steps for a rule
psv rule show SSH-01

# Validate integrity and YAML schema compliance of all benchmark rules
psv rule validate
```

---

### 4.10 Executive Reporting (`psv report`)

Generate and export executive compliance and technical audit reports.

```bash
# Generate an executive compliance report for an assessment
psv report generate <ASSESSMENT_ID> --format pdf

# Export report in JSON, CSV, or HTML format
psv report export <ASSESSMENT_ID> --format csv --output report.csv
```

---

### 4.11 Authentication & Configuration (`psv config` / `psv login`)

Configure CLI server URL and authenticate user credentials.

```bash
# Set API server target endpoint
psv config set server_url http://127.0.0.1:8000/api/v1

# Authenticate with control plane
psv login --email admin@psv.local --password AdminSecurePassword123!

# Show active CLI configuration and stored access token status
psv config show
```

---

### 4.12 Production Verification (`psv verify`)

Run production compliance validation scripts.

```bash
# Run production hardening & security compliance check
psv verify
```

---

## 5. Local Development Quickstart

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Start PSV Control Plane & Worker
.venv/bin/psv start

# 3. Start Frontend Console (Terminal 2)
npm run dev

# 4. Open Web UI in Browser
# Access http://localhost:5173
```

---

## 6. Production Deployment & Systemd

In production environments, PSV runs under Systemd unit files managed by the `psv` system user.

```bash
# Check status of systemd units
sudo systemctl status psv-api
sudo systemctl status psv-worker

# View systemd journal logs
sudo journalctl -u psv-api -f
sudo journalctl -u psv-worker -f
```

---

## 7. Operational & Security Documentation

- [`docs/PRODUCTION_HARDENING_AUDIT.md`](docs/PRODUCTION_HARDENING_AUDIT.md): Hardening audit matrix.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): Threat vectors and trust boundaries.
- [`docs/DEPLOYMENT_SECURITY.md`](docs/DEPLOYMENT_SECURITY.md): Production deployment guide.
- [`SECURITY.md`](SECURITY.md): Vulnerability disclosure policy.

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
