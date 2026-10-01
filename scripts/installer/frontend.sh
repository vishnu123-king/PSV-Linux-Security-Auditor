#!/usr/bin/env bash
# PSV Linux Security Auditor - Frontend Build Module
# Installs node dependencies and builds static assets in dist.

set -Eeuo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${MODULE_DIR}/common.sh"

build_frontend() {
    local install_dir="$1"

    log_info "Building frontend static assets..."

    if ! command_exists npm; then
        log_warn "npm command is not available. Skipping frontend build."
        return 0
    fi

    cd "${install_dir}"

    if [ ! -f "${install_dir}/package.json" ]; then
        log_warn "package.json not found in '${install_dir}'. Skipping frontend build."
        return 0
    fi

    log_info "Installing Node dependencies..."
    npm install --quiet

    log_info "Building production frontend assets with Vite..."
    npm run build

    if [ ! -d "${install_dir}/dist" ]; then
        die "Frontend build failed. Directory '${install_dir}/dist' was not created."
    fi

    log_info "Frontend static assets compiled successfully in '${install_dir}/dist'."
    update_state "frontend_built" "completed"
}
