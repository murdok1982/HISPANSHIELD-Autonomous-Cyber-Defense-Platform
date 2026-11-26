# HISPANSHIELD — developer and release commands
# Override PYTHON when the repository filesystem cannot host a venv:
#   make test PYTHON=/path/to/venv/bin/python
PYTHON ?= .venv/bin/python
NODE   ?= node
NPM    ?= npm

.PHONY: help setup install migrate revision bootstrap seed-demo dev-backend dev-frontend build-frontend test test-backend test-frontend lint typecheck audit sbom backup restore compose-up compose-down metrics validate-deploy

help:
	@echo "HISPANSHIELD targets:"
	@echo "  setup            Install backend/frontend dependencies and build the SPA"
	@echo "  migrate          Apply Alembic migrations"
	@echo "  revision m=...   Autogenerate a migration"
	@echo "  bootstrap        Create the initial platform administrator (env vars)"
	@echo "  seed-demo        Load clearly-labelled demonstration data"
	@echo "  dev-backend      Run FastAPI on :8080"
	@echo "  dev-frontend     Run Vite on :5173 with API proxy"
	@echo "  build-frontend   Type-check and build the SOC command center"
	@echo "  test             Backend + frontend unit/integration tests"
	@echo "  lint             Ruff, mypy, TypeScript"
	@echo "  audit            pip-audit + bandit"
	@echo "  sbom             Generate a dependency inventory"
	@echo "  backup/restore   PostgreSQL + evidence backup and restore"
	@echo "  metrics          Recompute repository/task/AC metrics"
	@echo "  validate-deploy  Render + validate the Kubernetes template (TEST values)"

setup: install migrate build-frontend

install:
	$(PYTHON) -m pip install -e "./backend[dev]" -e "./edge"
	cd frontend && $(NPM) install --no-audit --no-fund

migrate:
	cd backend && $(PYTHON) -m alembic upgrade head

revision:
	cd backend && $(PYTHON) -m alembic revision --autogenerate -m "$(m)"

bootstrap:
	$(PYTHON) scripts/bootstrap_admin.py

seed-reference:
	cd backend && $(PYTHON) scripts/seed_reference_data.py

seed-demo:
	HS_SEED_DEMO=true $(PYTHON) scripts/seed_demo.py

dev-backend:
	cd backend && $(PYTHON) -m uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload

dev-frontend:
	cd frontend && $(NODE) node_modules/vite/bin/vite.js --host 127.0.0.1 --port 5173

build-frontend:
	cd frontend && $(NODE) node_modules/typescript/bin/tsc -b && $(NODE) node_modules/vite/bin/vite.js build

test: test-backend test-frontend

test-backend:
	cd backend && $(PYTHON) -m pytest -q

test-frontend:
	cd frontend && $(NODE) node_modules/vitest/vitest.mjs run

test-e2e:
	cd frontend && $(NODE) node_modules/@playwright/test/cli.js test

lint:
	cd backend && $(PYTHON) -m ruff check app tests && $(PYTHON) -m ruff format --check app tests
	cd backend && $(PYTHON) -m mypy app
	cd frontend && $(NODE) node_modules/typescript/bin/tsc -b --force

typecheck:
	cd frontend && $(NODE) node_modules/typescript/bin/tsc -b --force

audit:
	$(PYTHON) -m pip_audit --skip-editable
	$(PYTHON) -m bandit -q -r backend/app -x backend/tests

sbom:
	./scripts/sbom.sh

backup:
	./scripts/backup.sh

restore:
	./scripts/restore.sh "$(file)"

compose-up:
	docker compose -f deploy/compose/docker-compose.yml up -d --build

compose-down:
	docker compose -f deploy/compose/docker-compose.yml down

metrics:
	python3 scripts/factory_metrics.py
	python3 scripts/ac_traceability.py

validate-deploy:
	./deploy/k8s/render.sh deploy/k8s/values.ci.env > /tmp/hispanshield-rendered.yaml
	python3 scripts/validate_deploy.py /tmp/hispanshield-rendered.yaml
