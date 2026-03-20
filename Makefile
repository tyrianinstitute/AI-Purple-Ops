SHELL := /bin/bash
.PHONY: help install setup lint fmt type sec audit test smoke clean ci docs-tables docs-check toolkit toolkit.update toolkit.check

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make <target>\n\nTargets:\n"} /^[a-zA-Z_.-]+:.*?##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## One-command install (venv + deps + CLI)
	python3 -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PIP) install -e ".[dev]"
	@echo ""
	@echo "Done. Run: source .venv/bin/activate"
	@echo "Then:  aipop run --suite adversarial --adapter mock --response-mode smart"

setup: install ## Alias for install + pre-commit hooks
	$(VENV)/bin/pre-commit install || true

lint: ## Ruff check
	$(VENV)/bin/ruff check .

fmt: ## Auto-format with ruff
	$(VENV)/bin/ruff format .
	$(VENV)/bin/ruff check --fix .

type: ## mypy type-check
	$(VENV)/bin/mypy src

sec: ## Bandit SAST
	$(VENV)/bin/bandit -q -r src -ll

audit: ## pip-audit dependencies (non-fatal)
	$(PY) -m pip_audit -s moderate || true

test: ## Run pytest
	$(PYTEST)

smoke: ## Self-healing preflight + style demo
	$(PY) scripts/dev_smoke.py

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache dist build *.egg-info

evidence.test: ## Create and verify sample evidence pack
	$(PY) scripts/evidence_roundtrip.py

ci: lint type sec test ## Run all CI checks

docs-tables: ## Generate docs tables and update README
	$(PY) scripts/generate_docs_tables.py

docs-check: docs-tables ## Fail if generated docs drift
	git diff --exit-code -- docs/generated README.md

toolkit: ## Install and verify redteam tools
	@echo "=== Installing Redteam Toolkit ==="
	aipop tools install --stable || $(PY) -m cli.harness tools install --stable
	@echo ""
	@echo "=== Verifying Tool Installation ==="
	aipop tools check || $(PY) -m cli.harness tools check
	@echo ""
	@echo "=== Running Tool Health Checks ==="
	@$(PY) scripts/test_toolkit.py || echo "Toolkit test script not found - skipping"

toolkit.update: ## Update toolkit to latest versions
	aipop tools update || $(PY) -m cli.harness tools update

toolkit.check: ## Check toolkit installation status
	aipop tools check || $(PY) -m cli.harness tools check
