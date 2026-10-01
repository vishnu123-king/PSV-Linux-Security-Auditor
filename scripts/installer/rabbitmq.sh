#!/usr/bin/env bash
# PSV Linux Security Auditor - RabbitMQ Configuration Module
# Manages RabbitMQ service, user creation, vhost provisioning, and connection testing.

set -Eeuo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${MODULE_DIR}/common.sh"

setup_rabbitmq() {
    local rmq_user="${PSV_RABBITMQ_USER:-psv}"
    local rmq_vhost="${PSV_RABBITMQ_VHOST:-/psv}"
    local rmq_pass="${PSV_RABBITMQ_PASSWORD:-}"
    local env_file="$1"

    log_info "Configuring RabbitMQ message broker service..."

    # Ensure RabbitMQ is running
    if command_exists systemctl; then
        systemctl enable --now rabbitmq-server || service rabbitmq-server start || true
    fi

    if ! command_exists rabbitmqctl; then
        die "rabbitmqctl command not found. RabbitMQ installation failed or is missing."
    fi

    # Check rabbitmqctl status
    if ! rabbitmqctl status >/dev/null 2>&1; then
        log_warn "RabbitMQ daemon is not responding to rabbitmqctl. Waiting 5 seconds..."
        sleep 5
    fi

    # Create vhost if not exists
    if ! rabbitmqctl list_vhosts | grep -q "^${rmq_vhost}$"; then
        log_info "Creating RabbitMQ virtual host '${rmq_vhost}'..."
        rabbitmqctl add_vhost "${rmq_vhost}"
    else
        log_info "RabbitMQ virtual host '${rmq_vhost}' already exists. Preserving."
    fi

    # Check if user exists
    if ! rabbitmqctl list_users | grep -q "^${rmq_user}\s"; then
        if [ -z "${rmq_pass}" ]; then
            rmq_pass="$(generate_password)"
        fi
        log_info "Creating RabbitMQ user '${rmq_user}'..."
        rabbitmqctl add_user "${rmq_user}" "${rmq_pass}"
    else
        log_info "RabbitMQ user '${rmq_user}' already exists. Preserving user."
        if [ -z "${rmq_pass}" ] && [ -f "${env_file}" ]; then
            rmq_pass="$(grep -E '^RABBITMQ_URL=' "${env_file}" | sed -E 's/.*:\/\/psv:(.+)@.*/\1/' || true)"
        fi
        if [ -z "${rmq_pass}" ]; then
            rmq_pass="$(generate_password)"
            rabbitmqctl change_password "${rmq_user}" "${rmq_pass}"
        fi
    fi

    # Grant permissions
    log_info "Setting permissions for user '${rmq_user}' on vhost '${rmq_vhost}'..."
    rabbitmqctl set_permissions -p "${rmq_vhost}" "${rmq_user}" ".*" ".*" ".*"

    local encoded_vhost
    encoded_vhost="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${rmq_vhost}', safe=''))")"
    local rmq_url="amqp://${rmq_user}:${rmq_pass}@localhost:5672/${encoded_vhost}"

    export GENERATED_RMQ_PASSWORD="${rmq_pass}"
    export GENERATED_RABBITMQ_URL="${rmq_url}"

    update_state "rabbitmq_ready" "completed"
}
