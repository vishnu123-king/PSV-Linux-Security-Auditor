#!/usr/bin/env bash
# PSV Linux Security Auditor - Systemd Installation Module
# Installs, configures, and verifies systemd service units for API and worker processes.

set -Eeuo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${MODULE_DIR}/common.sh"

install_systemd_services() {
    local install_dir="$1"
    local service_user="${PSV_SERVICE_USER:-psv}"

    if ! command_exists systemctl; then
        log_warn "systemctl is not available. Skipping systemd service installation."
        return 0
    fi

    log_info "Installing systemd service units..."

    local api_src="${install_dir}/deployment/psv-api.service"
    local worker_src="${install_dir}/deployment/psv-worker.service"

    local api_target="/etc/systemd/system/psv-api.service"
    local worker_target="/etc/systemd/system/psv-worker.service"

    # Backup existing
    backup_file "${api_target}"
    backup_file "${worker_target}"

    # Install updated units
    cp "${api_src}" "${api_target}"
    cp "${worker_src}" "${worker_target}"

    chmod 0644 "${api_target}" "${worker_target}"

    log_info "Reloading systemd daemon..."
    systemctl daemon-reload

    log_info "Enabling psv-api and psv-worker services..."
    systemctl enable psv-api psv-worker

    log_info "Starting psv-api service..."
    systemctl restart psv-api || systemctl start psv-api

    log_info "Starting psv-worker service..."
    systemctl restart psv-worker || systemctl start psv-worker

    # Wait 3 seconds for service initialization
    sleep 3

    # Check active status
    local api_active
    api_active="$(systemctl is-active psv-api || echo "failed")"
    local worker_active
    worker_active="$(systemctl is-active psv-worker || echo "failed")"

    if [ "${api_active}" != "active" ]; then
        log_error "psv-api.service failed to start (status: ${api_active}). Service logs:"
        journalctl -u psv-api -n 50 --no-pager || true
        die "psv-api.service startup failed."
    fi

    if [ "${worker_active}" != "active" ]; then
        log_error "psv-worker.service failed to start (status: ${worker_active}). Service logs:"
        journalctl -u psv-worker -n 50 --no-pager || true
        die "psv-worker.service startup failed."
    fi

    log_info "Systemd services 'psv-api' and 'psv-worker' are active and running."
    update_state "systemd_configured" "completed"
}
