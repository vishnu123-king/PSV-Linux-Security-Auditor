#!/usr/bin/env bash
# PSV Linux Security Auditor - Installer Prerequisites Module
# Operating system detection and system package management for Debian/Ubuntu.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

detect_os() {
    log_info "Detecting operating system..."
    if [ ! -f /etc/os-release ]; then
        die "Unsupported operating system. /etc/os-release not found. Supported distributions: Debian and Ubuntu."
    fi

    source /etc/os-release
    local distro_id="${ID:-unknown}"
    local distro_like="${ID_LIKE:-}"
    local version_id="${VERSION_ID:-unknown}"

    log_info "Detected OS ID: ${distro_id}, Version: ${version_id}"

    if [[ "${distro_id}" != "ubuntu" && "${distro_id}" != "debian" && ! "${distro_like}" =~ "debian" && ! "${distro_like}" =~ "ubuntu" ]]; then
        die "Unsupported operating system '${distro_id}'. Supported distributions: Debian and Ubuntu."
    fi

    # Check systemd
    if ! command_exists systemctl; then
        log_warn "systemctl not detected. Systemd features will be unavailable."
    fi

    update_state "os_detected" "completed"
}

install_system_packages() {
    local mode="${1:-production}"
    local non_interactive="${2:-false}"
    local skip_postgres="${3:-false}"
    local skip_rabbitmq="${4:-false}"

    log_info "Installing system packages via apt-get..."

    if [ "${non_interactive}" = "true" ]; then
        export DEBIAN_FRONTEND=noninteractive
    fi

    apt-get update -qq

    local pkgs=(
        git
        curl
        wget
        ca-certificates
        build-essential
        python3
        python3-venv
        python3-dev
        libpq-dev
        pkg-config
        openssh-client
        openssh-server
    )

    if [ "${skip_postgres}" = "false" ]; then
        pkgs+=(postgresql postgresql-client)
    fi

    if [ "${skip_rabbitmq}" = "false" ]; then
        pkgs+=(rabbitmq-server)
    fi

    # Install packages safely
    log_info "Installing required APT packages: ${pkgs[*]}"
    apt-get install -y --no-install-recommends "${pkgs[@]}"

    update_state "packages_installed" "completed"
}

verify_python_version() {
    log_info "Verifying Python installation..."
    if ! command_exists python3; then
        die "Python 3 is not installed."
    fi

    local py_ver
    py_ver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    log_info "Detected Python version: ${py_ver}"

    local py_major
    py_major="$(python3 -c 'import sys; print(sys.version_info.major)')"
    local py_minor
    py_minor="$(python3 -c 'import sys; print(sys.version_info.minor)')"

    if [ "${py_major}" -lt 3 ] || { [ "${py_major}" -eq 3 ] && [ "${py_minor}" -lt 10 ]; }; then
        die "PSV Linux Security Auditor requires Python 3.10+ (detected ${py_ver}). Please upgrade Python."
    fi

    update_state "python_verified" "completed"
}

verify_node_version() {
    log_info "Verifying Node.js and npm installation..."
    if ! command_exists node; then
        log_warn "Node.js is not installed. Installing nodejs and npm via apt-get..."
        apt-get install -y nodejs npm || true
    fi

    if command_exists node; then
        local node_ver
        node_ver="$(node --version 2>/dev/null || echo "unknown")"
        log_info "Detected Node.js version: ${node_ver}"
    else
        log_warn "Node.js is unavailable. Frontend compilation will be skipped if requested."
    fi

    update_state "node_verified" "completed"
}
