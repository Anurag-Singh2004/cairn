SHELL := /bin/bash
VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip
RUFF := $(VENV)/bin/ruff
PYTEST := $(VENV)/bin/pytest

TIER ?= t1
RUN  ?=

.PHONY: setup lint test test-e2e build up-t0 up-t1 down doctor demo verify report clean

setup:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

lint:
	$(RUFF) check src/ tests/
	$(RUFF) format --check src/ tests/

test:
	$(PYTEST) tests/unit/ tests/integration/ -v

test-e2e:
	$(PYTEST) tests/e2e/ -v -m docker

build:
	docker compose -f compose/compose.t1.yml build

up-t0:
	docker compose -f compose/compose.t0.yml up -d

up-t1:
	docker compose -f compose/compose.t1.yml up -d

down:
	docker compose -f compose/compose.t0.yml -f compose/compose.t1.yml down --remove-orphans 2>/dev/null; true

doctor:
	$(PY) -m cairn.cli doctor --tier $(TIER)

demo:
	$(PY) -m cairn.cli demo

verify:
	@if [ -z "$(RECEIPT)" ]; then echo "Usage: make verify RECEIPT=<path>"; exit 2; fi
	$(PY) -m cairn.cli verify $(RECEIPT)

report:
	@if [ -z "$(RUN)" ]; then echo "Usage: make report RUN=<id>"; exit 2; fi
	$(PY) -m cairn.cli report --run $(RUN)

clean:
	rm -rf runs/ .ruff_cache/ .pytest_cache/ dist/ build/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
