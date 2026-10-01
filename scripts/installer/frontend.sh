#!/usr/bin/env bash
# PSV Linux Security Auditor - Frontend Build Module
# Installs node dependencies, runs linter and builds static assets in frontend/dist.

set -Eeuo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${MODULE_DIR}/common.sh"

build_frontend() {
    local install_dir="$1"
    local frontend_dir="${install_dir}/frontend"

    if [ ! -d "${frontend_dir}" ]; then
        log_info "No frontend directory found at '${frontend_dir}'. Skipping frontend build."
        return 0
    fi

    log_info "Building frontend static assets..."

    if ! command_exists npm; then
        log_warn "npm command is not available. Skipping frontend build."
        return 0
    fi

    cd "${frontend_dir}"

    if [ -f "package-lock.json" ]; then
        log_info "Installing Node modules with 'npm ci'..."
        npm ci --quiet
    else
        log_info "Installing Node modules with 'npm install'..."
        npm install --quiet
    fi

    log_info "Linting frontend codebase..."
    npm run lint || log_warn "Frontend linting reported warnings."

    log_info "Building production frontend assets..."
    npm run build

    if [ ! -d "${frontend_dir}/dist" ]; then
        die "Frontend build failed. Directory '${frontend_dir}/dist' was not created."
    fi

    log_info "Frontend build completed successfully."
    update_state "frontend_built" "completed"
}
