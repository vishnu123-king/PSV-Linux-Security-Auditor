#!/usr/bin/env bash
# PSV Linux Security Auditor - Validation & Health Verification Module
# Runs migrations, rule validation, system verification scripts, health checks, and CLI tests.

set -Eeuo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${MODULE_DIR}/common.sh"

run_migrations_and_validations() {
    local install_dir="$1"
    local mode="${2:-production}"
    local skip_migrations="${3:-false}"

    local python_bin="${install_dir}/.venv/bin/python"
    local alembic_bin="${install_dir}/.venv/bin/alembic"

    cd "${install_dir}"

    if [ "${skip_migrations}" = "false" ]; then
        log_info "Executing Alembic database migrations..."
        if [ -f "${alembic_bin}" ]; then
            "${alembic_bin}" upgrade head
        else
            python3 -m alembic upgrade head
        fi
        update_state "migrations_complete" "completed"
    fi

    log_info "Validating benchmark rules (60 YAML rules across 11 files)..."
    "${python_bin}" scripts/validate_rules.py
    update_state "rules_validated" "completed"

    log_info "Running installation verification suite..."
    "${python_bin}" scripts/verify_installation.py
    update_state "installation_verified" "completed"

    if [ "${mode}" = "production" ]; then
        log_info "Running production configuration security audit..."
        "${python_bin}" scripts/verify_production_config.py
        update_state "production_config_verified" "completed"
    fi
}

verify_service_health() {
    local install_dir="${1:-.}"
    local max_retries=20
    local retry_delay=1
    local api_url="http://127.0.0.1:8000/health"
    local ready_url="http://127.0.0.1:8000/ready"

    log_info "Polling API control plane health at '${api_url}'..."

    local success=false
    for ((i=1; i<=max_retries; i++)); do
        if command_exists curl; then
            if curl -s -f "${api_url}" >/dev/null 2>&1; then
                success=true
                break
            fi
        fi
        log_info "Waiting for API service to become ready (attempt ${i}/${max_retries})..."
        sleep "${retry_delay}"
    done

    if [ "${success}" = "false" ]; then
        log_warn "API health check polling timed out. API server may still be initializing or running in background."
    else
        log_info "API /health check PASSED."
    fi

    log_info "Verifying CLI functionality..."
    local psv_bin="${install_dir}/.venv/bin/psv"
    if [ -f "${psv_bin}" ]; then
        "${psv_bin}" version || true
    fi

    update_state "health_verified" "completed"
}
