#!/usr/bin/env bash
# PSV Linux Security Auditor - Nginx Reverse Proxy Module
# Optional Nginx site configuration for serving static frontend assets and proxying API/WSS requests.

set -Eeuo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${MODULE_DIR}/common.sh"

setup_nginx() {
    local install_dir="$1"
    local domain="${PSV_DOMAIN:-_}"
    local port="${PSV_FRONTEND_PORT:-80}"

    if ! command_exists nginx; then
        log_info "Installing Nginx package..."
        apt-get install -y --no-install-recommends nginx
    fi

    log_info "Configuring Nginx site for PSV Linux Security Auditor..."

    local site_avail="/etc/nginx/sites-available/psv"
    local site_enabled="/etc/nginx/sites-enabled/psv"

    backup_file "${site_avail}"

    cat <<EOF > "${site_avail}"
server {
    listen ${port} default_server;
    listen [::]:${port} default_server;
    server_name ${domain};

    # Security Headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Static Frontend Assets
    location / {
        root ${install_dir}/frontend/dist;
        try_files \$uri \$uri/ /index.html;
        expires 1d;
        add_header Cache-Control "public, no-transform";
    }

    # API Proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    # WebSocket Proxy
    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
    }

    # Health Checks Direct
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
        proxy_set_header Host \$host;
    }

    location /ready {
        proxy_pass http://127.0.0.1:8000/ready;
        proxy_set_header Host \$host;
    }
}
EOF

    chmod 0644 "${site_avail}"

    # Enable site
    mkdir -p /etc/nginx/sites-enabled
    ln -sf "${site_avail}" "${site_enabled}"

    # Remove default site if present
    if [ -f /etc/nginx/sites-enabled/default ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi

    # Test Nginx configuration
    log_info "Testing Nginx configuration syntax..."
    nginx -t

    # Reload Nginx
    if command_exists systemctl; then
        systemctl enable --now nginx || systemctl reload nginx || service nginx reload || true
    fi

    log_info "Nginx configured and reloaded successfully."
    update_state "nginx_configured" "completed"
}
