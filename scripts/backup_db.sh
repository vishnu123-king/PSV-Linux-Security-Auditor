#!/usr/bin/env bash
# Backup PostgreSQL or SQLite database
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
mkdir -p "$BACKUP_DIR"

if [ -f "psv_auditor.db" ]; then
    echo "[+] Backing up local SQLite database..."
    cp psv_auditor.db "${BACKUP_DIR}/psv_auditor_${TIMESTAMP}.db"
    echo "[✔] Backup written to ${BACKUP_DIR}/psv_auditor_${TIMESTAMP}.db"
else
    echo "[+] Backing up PostgreSQL database..."
    PGDATABASE="${POSTGRES_DB:-psv_auditor}"
    pg_dump -U "${POSTGRES_USER:-psv}" -Fc "$PGDATABASE" > "${BACKUP_DIR}/psv_${TIMESTAMP}.dump"
    echo "[✔] Backup written to ${BACKUP_DIR}/psv_${TIMESTAMP}.dump"
fi
