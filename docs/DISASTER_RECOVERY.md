# PSV Linux Security Auditor - Disaster Recovery & Backup Plan

## 1. Backup Strategy

### PostgreSQL Database Backup
Automated daily logical backup using `pg_dump`:
```bash
# Automated backup command
pg_dump -U psv -h localhost -F c -b -v -f "/var/backups/psv/psv_auditor_$(date +%Y%m%d_%H%M%S).dump" psv_auditor
```

### Scripted Backup Execution
Use the included backup script:
```bash
./scripts/backup_db.sh
```

### Database Restore Procedure
To restore the database on a new or recovered host:
```bash
# 1. Stop services
sudo systemctl stop psv-api psv-worker

# 2. Restore database
pg_restore -U psv -d psv_auditor --clean --if-exists /var/backups/psv/psv_auditor_backup.dump

# 3. Apply any pending migrations
alembic upgrade head

# 4. Restart services
sudo systemctl start psv-api psv-worker
```

---

## 2. Recovery Scenarios

| Failure Event | Detection | Impact | Recovery Action |
| :--- | :--- | :--- | :--- |
| **PostgreSQL Outage** | `/ready` returns 503; worker retries DB transactions | API returns 503; assessments paused | Restart PostgreSQL service; check disk space; failover to standby replica |
| **RabbitMQ Outage** | `/ready` returns 503; worker disconnects | Assessment queueing suspended | Restart RabbitMQ; verify queue persistence (`psv.assessments` is durable) |
| **Worker Process Crash** | Systemd automatically restarts worker | In-progress job reassigned or timed out | Systemd restarts `psv-worker.service` within 10 seconds; check error logs |
| **Corrupted Target Host** | SSH command failures; collector reports UNKNOWN | Individual assessment marked with failure diagnostic | Audit target host independently; control plane remains stable |
