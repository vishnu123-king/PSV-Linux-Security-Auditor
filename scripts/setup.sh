#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "    PSV Linux Security Auditor - Environment Setup"
echo "=========================================================="

# 1. Virtual Environment
if [ ! -d ".venv" ]; then
    echo "[+] Creating Python 3 virtual environment..."
    python3 -m venv .venv
fi

echo "[+] Activating virtual environment..."
source .venv/bin/activate

# 2. Dependencies
echo "[+] Installing backend and CLI packages in editable mode..."
pip install --upgrade pip
pip install -e .
pip install -e ./cli

# 3. Environment configuration
if [ ! -f ".env" ]; then
    echo "[+] Initializing .env from .env.example..."
    cp .env.example .env
fi

# 4. Migrations
echo "[+] Running database migrations..."
alembic upgrade head

echo "=========================================================="
echo "[✔] PSV Linux Security Auditor is ready to run!"
echo "To start backend:  uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"
echo "To start worker:   python -m backend.app.workers.assessment_worker"
echo "To use CLI:        psv server status"
echo "=========================================================="
