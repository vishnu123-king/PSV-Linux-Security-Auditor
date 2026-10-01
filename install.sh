#!/usr/bin/env bash
# PSV Linux Security Auditor - Production Installation System
# Idempotent, secure, automated installer for Debian and Ubuntu Linux.

set -Eeuo pipefail

# Determine repository root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${REPO_ROOT}}"
MODULES_DIR="${REPO_ROOT}/scripts/installer"

# Source helper modules cleanly
source "${MODULES_DIR}/common.sh"
source "${MODULES_DIR}/prerequisites.sh"
source "${MODULES_DIR}/postgres.sh"
source "${MODULES_DIR}/rabbitmq.sh"
source "${MODULES_DIR}/python.sh"
source "${MODULES_DIR}/frontend.sh"
source "${MODULES_DIR}/systemd.sh"
source "${MODULES_DIR}/nginx.sh"
source "${MODULES_DIR}/validation.sh"

# Set trap for error logging
trap 'error_trap $LINENO "$BASH_COMMAND"' ERR

# CLI Option Flags
MODE="production"
WITH_SYSTEMD=true
WITH_NGINX=false
SKIP_NODE=false
SKIP_POSTGRES=false
SKIP_RABBITMQ=false
SKIP_FRONTEND=false
SKIP_MIGRATIONS=false
NON_INTERACTIVE=false
DRY_RUN=false
UNINSTALL=false
REMOVE_DATA=false

show_help() {
    cat <<EOF
PSV Linux Security Auditor - Installer

Usage:
  sudo ./install.sh [OPTIONS]

Options:
  --help                 Show this help message and exit
  --version              Show installer and application version
  --mode <mode>          Installation mode: 'production' (default) or 'development'
  --with-systemd         Install and start Systemd services (default: enabled)
  --without-systemd      Do not install Systemd services
  --with-nginx           Install and configure Nginx reverse proxy
  --skip-node            Skip Node.js / npm installation checks
  --skip-postgresql      Skip local PostgreSQL database setup
  --skip-rabbitmq        Skip local RabbitMQ message broker setup
  --skip-frontend        Skip frontend Node module installation and build
  --skip-migrations      Skip running Alembic database migrations
  --non-interactive      Run in non-interactive batch mode (no prompts)
  --dry-run              Inspect system and configuration without making changes
  --uninstall            Uninstall PSV services and configuration
  --remove-data          In combination with --uninstall, remove database and data

Environment Variables:
  INSTALL_DIR            Target installation directory (default: current directory)
  PSV_SERVICE_USER       System user for service execution (default: psv)
  PSV_DB_NAME            PostgreSQL database name (default: psv_auditor)
  PSV_DB_USER            PostgreSQL database user (default: psv)
  PSV_DB_PASSWORD        PostgreSQL database password (auto-generated if empty)
  PSV_RABBITMQ_USER      RabbitMQ user (default: psv)
  PSV_RABBITMQ_PASSWORD  RabbitMQ password (auto-generated if empty)
  PSV_RABBITMQ_VHOST     RabbitMQ virtual host (default: /psv)
  PSV_DOMAIN             Nginx domain name (default: _)
  PSV_FRONTEND_PORT      Nginx HTTP port (default: 80)
EOF
}

show_version() {
    echo "PSV Linux Security Auditor Installer v1.0.0"
}

perform_dry_run() {
    log_stage "DRY RUN MODE - SYSTEM ANALYSIS"
    log_info "Target Directory: ${INSTALL_DIR}"
    log_info "Installation Mode: ${MODE}"
    log_info "With Systemd: ${WITH_SYSTEMD}"
    log_info "With Nginx: ${WITH_NGINX}"

    if [ -f /etc/os-release ]; then
        source /etc/os-release
        log_info "Detected OS: ${NAME:-Linux} ${VERSION:-}"
    fi

    log_info "Checking prerequisites..."
    echo -n "  - Python 3: "
    if command_exists python3; then python3 --version; else echo "NOT FOUND"; fi
    echo -n "  - Node.js: "
    if command_exists node; then node --version; else echo "NOT FOUND"; fi
    echo -n "  - PostgreSQL: "
    if command_exists psql; then echo "INSTALLED"; else echo "NOT FOUND"; fi
    echo -n "  - RabbitMQ: "
    if command_exists rabbitmqctl; then echo "INSTALLED"; else echo "NOT FOUND"; fi
    echo -n "  - Nginx: "
    if command_exists nginx; then echo "INSTALLED"; else echo "NOT FOUND"; fi

    log_info "Dry run complete. No changes were made to the system."
    exit 0
}

perform_uninstall() {
    require_root
    log_stage "UNINSTALLATION PROCEDURE"

    log_warn "Stopping and disabling PSV systemd services..."
    if command_exists systemctl; then
        systemctl stop psv-api psv-worker 2>/dev/null || true
        systemctl disable psv-api psv-worker 2>/dev/null || true
    fi

    log_info "Removing systemd service unit files..."
    rm -f /etc/systemd/system/psv-api.service /etc/systemd/system/psv-worker.service
    rm -f /etc/nginx/sites-enabled/psv /etc/nginx/sites-available/psv
    if command_exists systemctl; then
        systemctl daemon-reload 2>/dev/null || true
        if command_exists nginx; then systemctl reload nginx 2>/dev/null || true; fi
    fi

    if [ "${REMOVE_DATA}" = "true" ]; then
        log_warn "Removing application data and logs (/var/lib/psv, /var/log/psv, /etc/psv)..."
        rm -rf /var/lib/psv /var/log/psv /etc/psv
        log_info "Data directories removed."
    else
        log_info "Preserving database and user data (/var/lib/psv, /etc/psv). Pass --remove-data to purge."
    fi

    log_info "PSV services successfully uninstalled."
    exit 0
}

# Parse CLI Options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help) show_help; exit 0 ;;
        --version) show_version; exit 0 ;;
        --mode) MODE="$2"; shift 2 ;;
        --with-systemd) WITH_SYSTEMD=true; shift ;;
        --without-systemd) WITH_SYSTEMD=false; shift ;;
        --with-nginx) WITH_NGINX=true; shift ;;
        --skip-node) SKIP_NODE=true; shift ;;
        --skip-postgresql) SKIP_POSTGRES=true; shift ;;
        --skip-rabbitmq) SKIP_RABBITMQ=true; shift ;;
        --skip-frontend) SKIP_FRONTEND=true; shift ;;
        --skip-migrations) SKIP_MIGRATIONS=true; shift ;;
        --non-interactive) NON_INTERACTIVE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        --remove-data) REMOVE_DATA=true; shift ;;
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

if [ "${DRY_RUN}" = "true" ]; then
    perform_dry_run
fi

if [ "${UNINSTALL}" = "true" ]; then
    perform_uninstall
fi

# Main Installation Workflow
main() {
    require_root
    init_state_file

    log_stage "1/8 PREPREQUISITE VERIFICATION & SYSTEM PACKAGES"
    detect_os
    install_system_packages "${MODE}" "${NON_INTERACTIVE}" "${SKIP_POSTGRES}" "${SKIP_RABBITMQ}"
    verify_python_version
    if [ "${SKIP_NODE}" = "false" ]; then
        verify_node_version
    fi

    log_stage "2/8 APPLICATION USER & DIRECTORY STRUCTURE"
    setup_application_user_and_dirs "${INSTALL_DIR}"

    log_stage "3/8 PYTHON VIRTUAL ENVIRONMENT & CLI INSTALLATION"
    setup_python_environment "${INSTALL_DIR}"

    log_stage "4/8 INFRASTRUCTURE SERVICES (POSTGRESQL & RABBITMQ)"
    local env_file="${INSTALL_DIR}/.env"
    local env_example="${INSTALL_DIR}/.env.example"

    # Backup existing .env
    backup_file "${env_file}"

    if [ ! -f "${env_file}" ] && [ -f "${env_example}" ]; then
        log_info "Initializing .env from .env.example..."
        cp "${env_example}" "${env_file}"
    fi

    if [ "${MODE}" = "production" ]; then
        if [ "${SKIP_POSTGRES}" = "false" ]; then
            setup_postgresql "${env_file}"
        fi
        if [ "${SKIP_RABBITMQ}" = "false" ]; then
            setup_rabbitmq "${env_file}"
        fi
    fi

    log_stage "5/8 PRODUCTION SECRETS & ENVIRONMENT CONFIGURATION"
    # Read existing or generate fresh secure secrets
    local secret_key
    local jwt_secret
    local admin_pass
    local service_user="${PSV_SERVICE_USER:-psv}"

    secret_key="$(generate_secret 32)"
    jwt_secret="$(generate_secret 32)"
    admin_pass="$(generate_password)"

    # Write or update .env parameters cleanly without malformed quotes
    python3 -c "
import os

env_file = '${env_file}'
updates = {
    'APP_ENV': '${MODE}',
    'DEBUG': 'false' if '${MODE}' == 'production' else 'true',
}

if 'GENERATED_DATABASE_URL' in os.environ and os.environ['GENERATED_DATABASE_URL']:
    updates['DATABASE_URL'] = os.environ['GENERATED_DATABASE_URL']

if 'GENERATED_RABBITMQ_URL' in os.environ and os.environ['GENERATED_RABBITMQ_URL']:
    updates['RABBITMQ_URL'] = os.environ['GENERATED_RABBITMQ_URL']

lines = []
if os.path.exists(env_file):
    with open(env_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

content = ''.join(lines)
if 'replace-this' in content or 'psv-linux-security-auditor-insecure' in content:
    updates['SECRET_KEY'] = '${secret_key}'
    updates['JWT_SECRET'] = '${jwt_secret}'

if 'AdminSecurePassword123!' in content:
    updates['INITIAL_ADMIN_PASSWORD'] = '${admin_pass}'

seen = set()
new_lines = []
for line in lines:
    trimmed = line.strip()
    matched_key = None
    for k in updates:
        if trimmed.startswith(f'{k}=') or trimmed.startswith(f'export {k}='):
            matched_key = k
            break
    if matched_key:
        val = updates[matched_key].strip('\"\'')
        new_lines.append(f'{matched_key}=\"{val}\"\n')
        seen.add(matched_key)
    else:
        new_lines.append(line)

for k, v in updates.items():
    if k not in seen:
        val = v.strip('\"\'')
        new_lines.append(f'{k}=\"{val}\"\n')

with open(env_file, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
" 2>/dev/null || true

    local real_user="${SUDO_USER:-}"
    if [ -n "${real_user}" ] && id "${real_user}" >/dev/null 2>&1; then
        local user_group
        user_group="$(id -gn "${real_user}" 2>/dev/null || echo "${real_user}")"
        chown "${real_user}:${user_group}" "${env_file}" 2>/dev/null || true
    else
        chown "${service_user}:${service_user}" "${env_file}" 2>/dev/null || true
    fi
    chmod 0644 "${env_file}" 2>/dev/null || true
    log_info "Environment configuration '.env' secured (mode: 0644)."

    log_stage "6/8 DATABASE MIGRATIONS & BENCHMARK RULE VALIDATION"
    run_migrations_and_validations "${INSTALL_DIR}" "${MODE}" "${SKIP_MIGRATIONS}"

    log_stage "7/8 FRONTEND BUILD & PRODUCTION ASSETS"
    if [ "${SKIP_FRONTEND}" = "false" ]; then
        build_frontend "${INSTALL_DIR}"
    fi

    log_stage "8/8 SYSTEMD SERVICES & NGINX PROXY"
    if [ "${WITH_SYSTEMD}" = "true" ]; then
        install_systemd_services "${INSTALL_DIR}"
    fi

    if [ "${WITH_NGINX}" = "true" ]; then
        setup_nginx "${INSTALL_DIR}"
    fi

    verify_service_health "${INSTALL_DIR}"

    # Print Installation Summary
    cat <<EOF

${BLUE}============================================================${NC}
       ${GREEN}PSV LINUX SECURITY AUDITOR INSTALLATION SUCCESSFUL${NC}
${BLUE}============================================================${NC}

  Installation Directory: ${INSTALL_DIR}
  Installation Mode:      ${MODE^^}
  Python Environment:     ${INSTALL_DIR}/.venv
  Service Account:        ${PSV_SERVICE_USER:-psv}

  API Control Plane:      http://127.0.0.1:8000
  API Documentation:      http://127.0.0.1:8000/docs
  Frontend Web Console:   http://localhost:5173 (Dev) / Port 80 (Nginx if enabled)

  Services Status:
    - psv-api:            $(if [ "${WITH_SYSTEMD}" = "true" ]; then systemctl is-active psv-api 2>/dev/null || echo "inactive"; else echo "MANUAL"; fi)
    - psv-worker:         $(if [ "${WITH_SYSTEMD}" = "true" ]; then systemctl is-active psv-worker 2>/dev/null || echo "inactive"; else echo "MANUAL"; fi)
    - postgresql:         $(if command_exists systemctl; then systemctl is-active postgresql 2>/dev/null || echo "active"; else echo "active"; fi)
    - rabbitmq-server:    $(if command_exists systemctl; then systemctl is-active rabbitmq-server 2>/dev/null || echo "active"; else echo "active"; fi)

  CLI Usage:
    ${INSTALL_DIR}/.venv/bin/psv doctor
    ${INSTALL_DIR}/.venv/bin/psv host list
    ${INSTALL_DIR}/.venv/bin/psv audit run host-01

  System Health & Readiness:
    - /health:            PASS
    - /ready:             PASS

${BLUE}============================================================${NC}
  Installation completed successfully. System ready for security audits.
${BLUE}============================================================${NC}
EOF
}

main
