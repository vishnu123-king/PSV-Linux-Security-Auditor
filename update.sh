#!/usr/bin/env bash
# PSV Linux Security Auditor - System Update Script
# Safely pulls updates, runs migrations, validates rules, rebuilds frontend, and restarts services.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${SCRIPT_DIR}}"

source "${SCRIPT_DIR}/scripts/installer/common.sh"

log_stage "PSV LINUX SECURITY AUDITOR - UPDATE PROCEDURE"

# Require root
require_root

# 1. Check Git status
cd "${INSTALL_DIR}"
if [ -d ".git" ]; then
    if [ -n "$(git status --porcelain)" ]; then
        log_warn "Local uncommitted changes detected in repository:"
        git status --short
        die "Update aborted. Please commit or stash local changes before running update.sh."
    fi

    log_info "Creating backup of .env configuration..."
    backup_file "${INSTALL_DIR}/.env"

    log_info "Fetching latest git commits..."
    git pull --ff-only
else
    log_info "Not a git repository checkout. Proceeding with in-place package update..."
fi

# 2. Update Python virtualenv packages
local_venv="${INSTALL_DIR}/.venv"
if [ -d "${local_venv}" ]; then
    log_info "Updating Python backend and CLI packages..."
    "${local_venv}/bin/pip" install -e . --quiet
    "${local_venv}/bin/pip" install -e ./cli --quiet
fi

# 3. Run migrations
log_info "Running database migrations..."
if [ -f "${local_venv}/bin/alembic" ]; then
    "${local_venv}/bin/alembic" upgrade head
else
    python3 -m alembic upgrade head
fi

# 4. Validate rules
log_info "Validating security benchmark rules..."
"${local_venv}/bin/python" scripts/validate_rules.py

# 5. Rebuild frontend
if [ -d "${INSTALL_DIR}/frontend" ] && command_exists npm; then
    log_info "Rebuilding frontend static assets..."
    cd "${INSTALL_DIR}/frontend"
    if [ -f "package-lock.json" ]; then
        npm ci --quiet
    else
        npm install --quiet
    fi
    npm run build
fi

# 6. Restart systemd services
if command_exists systemctl; then
    if systemctl is-enabled psv-api >/dev/null 2>&1; then
        log_info "Restarting psv-api service..."
        systemctl restart psv-api
    fi
    if systemctl is-enabled psv-worker >/dev/null 2>&1; then
        log_info "Restarting psv-worker service..."
        systemctl restart psv-worker
    fi
fi

# 7. Health verification
sleep 3
log_info "Verifying post-update API health..."
if command_exists curl; then
    if curl -s -f "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
        log_info "API /health check PASSED."
    else
        log_warn "API /health check pending initialization."
    fi
fi

log_stage "UPDATE COMPLETED SUCCESSFULLY"
