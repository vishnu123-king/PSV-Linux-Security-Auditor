FROM ubuntu:24.04

# ==============================================================================
# PSV LINUX SECURITY AUDITOR - DISPOSABLE TEST TARGET
# NOTICE: FOR TESTING AND DEVELOPMENT USE ONLY. DO NOT DEPLOY IN PRODUCTION.
# ==============================================================================

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    curl \
    iproute2 \
    procps \
    ufw \
    iptables \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH directory and test user
RUN mkdir -p /var/run/sshd /etc/ssh /etc/sudoers.d
RUN useradd -m -s /bin/bash -u 1001 auditor-test && \
    echo "auditor-test:AuditorTestPassword123!" | chpasswd && \
    usermod -aG sudo auditor-test

# Intentionally configure controlled baseline test issues for auditor verification:
# 1. SSH root login enabled
# 2. Sudo wildcard NOPASSWD for test user
# 3. UFW inactive
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "auditor-test ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-test-user && \
    chmod 0440 /etc/sudoers.d/99-test-user

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
