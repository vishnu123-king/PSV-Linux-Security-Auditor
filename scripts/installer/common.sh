#!/usr/bin/env bash
# PSV Linux Security Auditor - Installer Common Library
# Functions for logging, state tracking, backups, secret generation, and CLI parsing.

set -Eeuo pipefail

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default Paths
STATE_FILE="/var/lib/psv/install-state.json"
LOG_DIR="/var/log/psv"
INSTALL_LOG="/var/log/psv/install.log"
BACKUP_BASE_DIR="/var/lib/psv/backups"

# Ensure log directory exists if writable
mkdir -p "${LOG_DIR}" 2>/dev/null || true
touch "${INSTALL_LOG}" 2>/dev/null || true

log_info() {
    local msg="$1"
    echo -e "${GREEN}[INFO]${NC} ${msg}"
    if [ -w "${INSTALL_LOG}" ]; then
        echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [INFO] ${msg}" >> "${INSTALL_LOG}"
    fi
}

log_warn() {
    local msg="$1"
    echo -e "${YELLOW}[WARN]${NC} ${msg}"
    if [ -w "${INSTALL_LOG}" ]; then
        echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [WARN] ${msg}" >> "${INSTALL_LOG}"
    fi
}

log_error() {
    local msg="$1"
    echo -e "${RED}[ERROR]${NC} ${msg}" >&2
    if [ -w "${INSTALL_LOG}" ]; then
        echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [ERROR] ${msg}" >> "${INSTALL_LOG}"
    fi
}

log_stage() {
    local msg="$1"
    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${CYAN}  ${msg}${NC}"
    echo -e "${BLUE}============================================================${NC}"
    if [ -w "${INSTALL_LOG}" ]; then
        echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [STAGE] ${msg}" >> "${INSTALL_LOG}"
    fi
}

die() {
    log_error "$1"
    exit 1
}

# Trap error handler
error_trap() {
    local exit_code=$?
    local line_number=$1
    local command="$2"
    log_error "Installation failed at line ${line_number} during command: '${command}' (exit code: ${exit_code})"
    log_error "Check log file for details: ${INSTALL_LOG}"
    exit "${exit_code}"
}

# Require root
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Root privileges are required to run this installer. Please re-run with: sudo $0"
    fi
}

# Check command existence
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Generate cryptographically secure secret (hex or base64)
generate_secret() {
    local bytes="${1:-32}"
    if command_exists openssl; then
        openssl rand -hex "${bytes}"
    else
        head -c "${bytes}" /dev/urandom | xxd -p | tr -d '\n'
    fi
}

# Generate secure password (alphanumeric + special)
generate_password() {
    if command_exists openssl; then
        openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 20
    else
        head -c 32 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 20
    fi
}

# Create timestamped backup of a file
backup_file() {
    local file_path="$1"
    if [ -f "${file_path}" ]; then
        local timestamp
        timestamp="$(date +%Y%m%d_%H%M%S)"
        local backup_dir="${BACKUP_BASE_DIR}/${timestamp}"
        mkdir -p "${backup_dir}"
        chmod 0700 "${backup_dir}"
        cp -p "${file_path}" "${backup_dir}/$(basename "${file_path}")"
        chmod 0600 "${backup_dir}/$(basename "${file_path}")"
        log_info "Backed up '${file_path}' to '${backup_dir}/$(basename "${file_path}")'"
    fi
}

# State management
init_state_file() {
    mkdir -p "$(dirname "${STATE_FILE}")"
    if [ ! -f "${STATE_FILE}" ]; then
        cat <<EOF > "${STATE_FILE}"
{
  "installed_at": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "mode": "unknown",
  "steps": {}
}
EOF
        chmod 0600 "${STATE_FILE}"
    fi
}

update_state() {
    local step_name="$1"
    local status="$2"
    if command_exists python3; then
        python3 -c "
import json
try:
    with open('${STATE_FILE}', 'r') as f:
        data = json.load(f)
    if 'steps' not in data:
        data['steps'] = {}
    data['steps']['${step_name}'] = '${status}'
    data['updated_at'] = '$(date -u +'%Y-%m-%dT%H:%M:%SZ')'
    with open('${STATE_FILE}', 'w') as f:
        json.dump(data, f, indent=2)
except Exception:
    pass
" 2>/dev/null || true
    fi
}

get_state() {
    local step_name="$1"
    if [ -f "${STATE_FILE}" ] && command_exists python3; then
        python3 -c "
import json
try:
    with open('${STATE_FILE}', 'r') as f:
        data = json.load(f)
    print(data.get('steps', {}).get('${step_name}', 'pending'))
except Exception:
    print('pending')
" 2>/dev/null || echo "pending"
    else
        echo "pending"
    fi
}
