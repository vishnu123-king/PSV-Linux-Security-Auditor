#!/usr/bin/env bash
# PSV Linux Security Auditor - Python Environment & App User Module
# Manages system user 'psv', runtime directories, virtual environment, and package installation.

set -Eeuo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${MODULE_DIR}/common.sh"

setup_application_user_and_dirs() {
    local service_user="${PSV_SERVICE_USER:-psv}"
    local install_dir="$1"

    log_info "Configuring service user '${service_user}' and production directories..."

    if ! id "${service_user}" >/dev/null 2>&1; then
        log_info "Creating dedicated system user '${service_user}'..."
        useradd -r -s /bin/false -d "${install_dir}" "${service_user}" || true
    fi

    # Create production system directories
    local dirs=(
        "/etc/psv"
        "/var/lib/psv"
        "/var/log/psv"
        "/var/lib/psv/reports"
        "/var/lib/psv/backups"
        "/var/lib/psv/runtime"
    )

    for dir in "${dirs[@]}"; do
        mkdir -p "${dir}"
        chown -R "${service_user}:${service_user}" "${dir}"
    done

    # Restrict permissions on sensitive configuration
    chmod 0700 /etc/psv
    chmod 0700 /var/lib/psv/backups
    chmod 0755 /var/log/psv
    chmod 0755 /var/lib/psv/reports

    # Chown repository install directory
    chown -R "${service_user}:${service_user}" "${install_dir}"
    chmod -R g+rX,o+rX "${install_dir}" 2>/dev/null || true

    # Ensure parent directories leading up to install_dir are traversable (+x) by service_user
    local current=""
    IFS='/' read -ra parts <<< "${install_dir}"
    for part in "${parts[@]}"; do
        if [ -n "${part}" ]; then
            current="${current}/${part}"
            if [ -d "${current}" ]; then
                chmod o+x "${current}" 2>/dev/null || true
            fi
        fi
    done

    update_state "app_user_ready" "completed"
}

setup_python_environment() {
    local install_dir="$1"
    local venv_dir="${install_dir}/.venv"

    log_info "Setting up Python virtual environment in '${venv_dir}'..."

    if [ ! -d "${venv_dir}" ]; then
        python3 -m venv "${venv_dir}"
    fi

    # Activate and upgrade core tooling including greenlet
    "${venv_dir}/bin/python" -m pip install --upgrade pip setuptools wheel greenlet --quiet || true

    log_info "Installing PSV backend and CLI packages in editable mode..."
    cd "${install_dir}"
    "${venv_dir}/bin/pip" install -e . --quiet
    "${venv_dir}/bin/pip" install -e ./cli --quiet

    # Verify executable
    if [ ! -f "${venv_dir}/bin/psv" ]; then
        die "CLI executable 'psv' was not created in virtualenv bin directory."
    fi

    log_info "Python environment and CLI installed successfully."
    update_state "python_venv_ready" "completed"
}
