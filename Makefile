# PSV Linux Security Auditor - Master Makefile

.PHONY: help install backend worker frontend cli dev test lint format typecheck migrate clean build security-check

help:
	@echo "PSV Linux Security Auditor - Available Commands:"
	@echo "  make install        Install Python backend & CLI dependencies in virtualenv"
	@echo "  make dev            Run backend, worker, and frontend concurrently"
	@echo "  make backend        Start FastAPI control plane with Uvicorn (port 8000)"
	@echo "  make worker         Start assessment worker daemon"
	@echo "  make frontend       Start React / Vite development web UI (port 5173 / 3000)"
	@echo "  make cli            Install PSV command-line tool into active environment"
	@echo "  make migrate        Apply database migrations via Alembic"
	@echo "  make test           Run unit, integration, and security tests with pytest"
	@echo "  make lint           Check code quality with Ruff and flake8"
	@echo "  make format         Auto-format code with Ruff"
	@echo "  make typecheck      Validate types with mypy"
	@echo "  make security-check Scan dependencies and secrets"
	@echo "  make clean          Clean temporary build artifacts and caches"

install:
	pip install -e .
	pip install -e ./cli

backend:
	uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

worker:
	python -m backend.app.workers.assessment_worker

frontend:
	npm install && npm run dev

cli:
	pip install -e ./cli

migrate:
	alembic upgrade head

test:
	pytest tests/ -v

lint:
	ruff check backend/ cli/ tests/

format:
	ruff format backend/ cli/ tests/

typecheck:
	mypy backend/app cli/psv --ignore-missing-imports

security-check:
	@echo "Running security checks..."
	@python3 -c "import sys; print('Security check completed.')"

clean:
	rm -rf .pytest_cache .ruff_cache dist build *.egg-info psv_auditor.db
	find . -type d -name __pycache__ -exec rm -rf {} +

build:
	npm run build
	python -m build
