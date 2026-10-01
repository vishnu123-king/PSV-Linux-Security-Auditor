#!/usr/bin/env bash
# PSV Linux Security Auditor - PostgreSQL Configuration Module
# Manages PostgreSQL service, database user creation, database provisioning, and connection testing.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

setup_postgresql() {
    local db_name="${PSV_DB_NAME:-psv_auditor}"
    local db_user="${PSV_DB_USER:-psv}"
    local db_pass="${PSV_DB_PASSWORD:-}"
    local env_file="$1"

    log_info "Configuring PostgreSQL database service..."

    # Ensure PostgreSQL is running
    if command_exists systemctl; then
        systemctl enable --now postgresql || service postgresql start || true
    fi

    # Check if postgres user access works via su
    if ! su - postgres -c "psql -c '\l'" >/dev/null 2>&1; then
        log_warn "Could not connect to local PostgreSQL as 'postgres' user. Checking existing DATABASE_URL in .env..."
        if [ -f "${env_file}" ] && grep -q "DATABASE_URL=postgresql" "${env_file}"; then
            log_info "Existing PostgreSQL DATABASE_URL found in .env. Preserving."
            return 0
        else
            die "PostgreSQL is not accessible. Please ensure PostgreSQL is running and local socket access is granted."
        fi
    fi

    # Check if user already exists
    local user_exists
    user_exists="$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${db_user}'\"" || echo "0")"

    if [ "${user_exists}" != "1" ]; then
        if [ -z "${db_pass}" ]; then
            db_pass="$(generate_password)"
        fi
        log_info "Creating PostgreSQL user '${db_user}'..."
        su - postgres -c "psql -c \"CREATE USER ${db_user} WITH PASSWORD '${db_pass}';\""
    else
        log_info "PostgreSQL user '${db_user}' already exists. Preserving user."
        # Extract password if present in existing .env
        if [ -z "${db_pass}" ] && [ -f "${env_file}" ]; then
            db_pass="$(grep -E '^DATABASE_URL=' "${env_file}" | sed -E 's/.*:\/\/psv:(.+)@.*/\1/' || true)"
        fi
        if [ -z "${db_pass}" ]; then
            db_pass="$(generate_password)"
            su - postgres -c "psql -c \"ALTER USER ${db_user} WITH PASSWORD '${db_pass}';\""
        fi
    fi

    # Check if database already exists
    local db_exists
    db_exists="$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${db_name}'\"" || echo "0")"

    if [ "${db_exists}" != "1" ]; then
        log_info "Creating PostgreSQL database '${db_name}'..."
        su - postgres -c "psql -c \"CREATE DATABASE ${db_name} OWNER ${db_user};\""
        su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE ${db_name} TO ${db_user};\""
    else
        log_info "PostgreSQL database '${db_name}' already exists. Preserving database data."
    fi

    local db_url="postgresql+asyncpg://${db_user}:${db_pass}@localhost:5432/${db_name}"

    # Export password for .env updating
    export GENERATED_PG_PASSWORD="${db_pass}"
    export GENERATED_DATABASE_URL="${db_url}"

    update_state "postgres_ready" "completed"
}
