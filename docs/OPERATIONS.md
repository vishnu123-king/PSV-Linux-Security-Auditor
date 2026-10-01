# PSV Linux Security Auditor - Operational Guide

## 1. Monitoring & Observability

### Health and Readiness Endpoints
- **Liveness Probe**: `GET /health` (returns process status and version)
- **Readiness Probe**: `GET /ready` (checks PostgreSQL and RabbitMQ; returns HTTP 503 if unavailable)
- **Metrics Endpoint**: `GET /api/v1/metrics` (Prometheus text format)

### Key Prometheus Metrics
- `psv_assessments_total`: Total count of executed assessments
- `psv_assessments_failed_total`: Count of failed assessments
- `psv_findings_total`: Total vulnerabilities discovered
- `psv_remediation_total`: Total remediations planned/executed
- `psv_worker_jobs_total`: Total jobs processed by workers

---

## 2. Log Management & Secret Redaction

Logs are formatted with timestamps, log levels, request correlation IDs (`X-Request-ID`), and automatic secret redaction:
```text
2026-10-01 14:00:00 [INFO] [backend.app.api.v1.hosts] Connecting to host prod-db-01 (attempt 1)...
2026-10-01 14:00:01 [INFO] [backend.app.engine.ssh] SSH connection established to 192.168.1.10:22
```

To view live systemd logs:
```bash
sudo journalctl -u psv-api -f
sudo journalctl -u psv-worker -f
```

---

## 3. Credential & Key Rotation Procedure

### Rotating JWT Secrets:
1. Generate new 32-character secret: `openssl rand -hex 32`
2. Update `JWT_SECRET` in `/opt/psv-linux-security-auditor/.env`
3. Restart API service: `sudo systemctl restart psv-api`
4. Active sessions will expire and require re-login.

### Rotating Target SSH Keys:
1. Update public key on audited target Linux hosts (`~/.ssh/authorized_keys`).
2. Update credential in PSV console or via CLI:
   ```bash
   psv host test <HOST_ID>
   ```
