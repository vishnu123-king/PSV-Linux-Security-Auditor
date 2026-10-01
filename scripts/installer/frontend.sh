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

    # Ensure node_modules and dist permissions allow unprivileged user access for dev/preview
    chmod -R 777 "${install_dir}/node_modules" 2>/dev/null || true
    chmod -R 777 "${install_dir}/dist" 2>/dev/null || true

    local real_user="${SUDO_USER:-}"
    if [ -n "${real_user}" ] && id "${real_user}" >/dev/null 2>&1; then
        local user_group
        user_group="$(id -gn "${real_user}" 2>/dev/null || echo "${real_user}")"
        chown -R "${real_user}:${user_group}" "${install_dir}/node_modules" "${install_dir}/dist" 2>/dev/null || true
    fi

    log_info "Frontend static assets compiled successfully in '${install_dir}/dist'."
    update_state "frontend_built" "completed"
}
