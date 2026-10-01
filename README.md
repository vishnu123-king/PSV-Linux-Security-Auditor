# PSV Linux Security Auditor

[![CI](https://github.com/psv-auditor/psv-linux-security-auditor/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](pyproject.toml)
[![Benchmark Rules](https://img.shields.io/badge/Rules-60%20Verified-green.svg)](rules/)

> **Enterprise-grade, defensive Linux security auditing platform with SSH collectors, YAML benchmark rule engine, real-time WebSocket progress, configuration drift detection, approval-gated remediation, and CLI control surface.**

---

## 1. System Architecture

```text
React Web Console (Port 3000)
       │
       ▼ (HTTPS / WSS - JWT Bearer Auth)
FastAPI Control Plane (Port 8000)
       │
       ├── PostgreSQL 16+ (or Development SQLite async)
       ├── RabbitMQ 3.12+ (or Development in-memory queue)
       ├── Background Assessment Workers
       ├── SSH Connector (Host-key verification & timeouts)
       ├── 12 Linux Security Collectors
       ├── YAML Benchmark Rule Engine (60 Rules across 11 Domains)
       ├── Findings & Raw Evidence Storage
       ├── Configuration Drift Detection Engine
       ├── Approval-Gated Remediation & Rollback Engine
       └── REST / WebSocket API

Python `psv` CLI
       │
       ▼ (REST API)
FastAPI Control Plane
```

---

## 2. Core Capabilities & Invariants

- **12 Linux Security Collectors**: `system`, `identity`, `ssh`, `sudo`, `filesystem`, `networking`, `firewall`, `services`, `kernel`, `pam`, `logging`, `containers`.
- **60 Executable Benchmark Rules**: Loaded from strict YAML schemas; 100% verified with zero duplicate IDs.
- **Fail-Closed Invariant**: If a collector fails or times out, controls evaluate to `UNKNOWN` with diagnostic failure reasons—never to a false `PASS`.
- **Immutable Safe Command Model**: Remote execution uses static token arrays in `backend/app/security/command_registry.py`. Arbitrary remote shell APIs are strictly prohibited.
- **Diagnostic Console**: The web UI includes a secure Diagnostic Console providing whitelisted system facts and CLI services.
- **Approval-Gated Remediation**: Non-destructive dry-run diffs with backup generation (`.psv_backup`), syntax verification (`sshd -t`), management port preservation (`ufw allow 22/tcp`), and atomic rollback.
- **Multi-Tenant RBAC**: 4-tier role hierarchy (`VIEWER`, `OPERATOR`, `SECURITY_ANALYST`, `ADMIN`) with organization-scoped IDOR protection.

---

## 3. Quickstart & Local Development

### 1. Setup Virtual Environment
```bash
git clone https://github.com/psv-auditor/psv-linux-security-auditor.git
cd psv-linux-security-auditor

python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -e ./cli
```

### 2. Configure Environment
```bash
cp .env.example .env
```

### 3. Run Database Migrations
```bash
alembic upgrade head
```

### 4. Start Backend API & Assessment Worker
```bash
# Terminal 1: FastAPI API Control Plane
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Background Worker
python -m backend.app.workers.assessment_worker
```

### 5. Start React Web Console
```bash
cd frontend
npm ci
npm run dev
```

### 6. Use the `psv` CLI
```bash
psv server status
psv doctor
psv host list
psv audit run host-01 --profile cis-linux-server
psv finding list
psv drift compare host-01
```

---

## 4. Production Deployment

In production, PSV requires **PostgreSQL** and **RabbitMQ**.

### 1. Validate Production Configuration
```bash
python scripts/validate_rules.py
python scripts/verify_production_config.py
```

### 2. Run with Systemd & NGINX
```bash
# Install and start hardened systemd services
sudo cp deployment/psv-api.service /etc/systemd/system/
sudo cp deployment/psv-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now psv-api psv-worker
```

Refer to [`docs/DEPLOYMENT_SECURITY.md`](docs/DEPLOYMENT_SECURITY.md) for full NGINX reverse proxy, TLS, and PostgreSQL configuration instructions.

---

## 5. Security & Operational Documentation

- [`docs/PRODUCTION_HARDENING_AUDIT.md`](docs/PRODUCTION_HARDENING_AUDIT.md): 26-domain production hardening audit matrix.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): Threat vectors, mitigations, and trust boundaries.
- [`docs/DEPLOYMENT_SECURITY.md`](docs/DEPLOYMENT_SECURITY.md): Production deployment guide.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md): Monitoring, Prometheus metrics, and key rotation.
- [`docs/DISASTER_RECOVERY.md`](docs/DISASTER_RECOVERY.md): Backup, restore, and failure scenarios.
- [`docs/PRODUCTION_RELEASE_REPORT.md`](docs/PRODUCTION_RELEASE_REPORT.md): Final release validation report.
- [`SECURITY.md`](SECURITY.md): Vulnerability disclosure policy and SLAs.

---

## 6. License

Apache-2.0. See [LICENSE](LICENSE) for details.
