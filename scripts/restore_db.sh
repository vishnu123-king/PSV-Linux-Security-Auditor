#!/usr/bin/env bash
# Restore database from backup
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [[ "$BACKUP_FILE" == *.db ]]; then
    echo "[+] Restoring SQLite database from $BACKUP_FILE..."
    cp "$BACKUP_FILE" psv_auditor.db
    echo "[✔] Restored to psv_auditor.db"
else
    echo "[+] Restoring PostgreSQL database from $BACKUP_FILE..."
    PGDATABASE="${POSTGRES_DB:-psv_auditor}"
    pg_restore -U "${POSTGRES_USER:-psv}" -d "$PGDATABASE" -c "$BACKUP_FILE"
    echo "[✔] PostgreSQL restoration complete."
fi
