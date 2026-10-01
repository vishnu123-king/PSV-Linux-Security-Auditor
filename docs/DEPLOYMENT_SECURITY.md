# PSV Linux Security Auditor - Production Deployment Guide

## 1. Production Architecture Overview

In production, PSV Linux Security Auditor operates as an enterprise-grade control plane:
- **Reverse Proxy**: NGINX / Envoy / Cloudflare terminating TLS with strict security headers.
- **API Control Plane**: FastAPI served by Uvicorn (multi-worker) under Systemd.
- **Worker Daemon**: Python assessment worker running in background for asynchronous audit jobs.
- **Database**: PostgreSQL 16+ with SSL connections and connection pooling.
- **Message Broker**: RabbitMQ 3.12+ with AMQP TLS and dedicated virtual hosts.

---

## 2. Step-by-Step Installation

### Prerequisites
- Linux Server (Ubuntu 24.04 LTS, Debian 12, or RHEL 9)
- Python 3.12+
- PostgreSQL 16+
- RabbitMQ 3.12+
- Node.js 20+ (for building frontend)

### Step 1: Create Unprivileged User
```bash
sudo useradd -r -s /bin/false -d /opt/psv-linux-security-auditor psv
sudo mkdir -p /opt/psv-linux-security-auditor/{reports,logs}
sudo chown -R psv:psv /opt/psv-linux-security-auditor
```

### Step 2: Clone and Setup Python Environment
```bash
cd /opt/psv-linux-security-auditor
sudo -u psv git clone https://github.com/psv-auditor/psv-linux-security-auditor.git .
sudo -u psv python3.12 -m venv .venv
sudo -u psv .venv/bin/pip install --upgrade pip
sudo -u psv .venv/bin/pip install -e .
sudo -u psv .venv/bin/pip install -e ./cli
```

### Step 3: Configure Production Environment
```bash
sudo -u psv cp .env.example .env
sudo -u psv chmod 0600 .env
```
Edit `.env` with production credentials:
```ini
APP_ENV=production
DEBUG=false
SECRET_KEY=<32-char-random-hex>
JWT_SECRET=<32-char-random-hex>
DATABASE_URL=postgresql+asyncpg://psv_user:ComplexPass@localhost:5432/psv_auditor
RABBITMQ_URL=amqp://psv_app:ComplexPass@localhost:5672/psv
CORS_ORIGINS=https://security.example.internal
```

### Step 4: Run Migrations and Production Validation
```bash
sudo -u psv .venv/bin/alembic upgrade head
sudo -u psv .venv/bin/python scripts/validate_rules.py
sudo -u psv .venv/bin/python scripts/verify_production_config.py
```

### Step 5: Install Systemd Services
```bash
sudo cp deployment/psv-api.service /etc/systemd/system/
sudo cp deployment/psv-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now psv-api psv-worker
```

### Step 6: Configure NGINX Reverse Proxy
```nginx
server {
    listen 443 ssl http2;
    server_name security.example.internal;

    ssl_certificate /etc/ssl/certs/psv.crt;
    ssl_certificate_key /etc/ssl/private/psv.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Security Headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```
