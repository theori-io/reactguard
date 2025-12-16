.PHONY: install fmt lint typecheck test test-integration test-xint live-up live-down live-ps live-logs live-preflight live-test live-edgecases clean

PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
PYTEST ?= $(PYTHON) -m pytest

install:
	$(PYTHON) -m pip install -e .[dev]

fmt:
	ruff check --fix .
	black .

lint:
	ruff check .

typecheck:
	mypy src tests

test:
	$(PYTEST) --ignore=tests/integration --ignore=tests/live --cov=reactguard --cov-report=term-missing

test-integration:
	$(PYTEST) tests/integration --cov=reactguard --cov-report=term-missing

test-xint:
	$(PYTEST) -q tests/integration/test_xint_compat.py

LIVE_ROOT ?= tests/live
LIVE_COMPOSE ?= docker compose
LIVE_BATCH_SIZE ?= 20
LIVE_UP_ARGS ?=
LIVE_JOBS ?= auto
LIVE_COMPOSE_FILES ?= \
	$(LIVE_ROOT)/docker-compose-nextjs.yml \
	$(LIVE_ROOT)/docker-compose-waku.yml \
	$(LIVE_ROOT)/docker-compose-react-router.yml \
	$(LIVE_ROOT)/docker-compose-expo.yml \
	$(LIVE_ROOT)/docker-compose-misc.yml \
	$(LIVE_ROOT)/docker-compose-rsc-core.yml
LIVE_COMPOSE_CMD = $(LIVE_COMPOSE) $(foreach f,$(LIVE_COMPOSE_FILES),-f $(f))
HAS_XDIST := $(shell $(PYTHON) -c "import importlib.util; print('1' if importlib.util.find_spec('xdist') else '')" 2>/dev/null)
ifneq ($(strip $(HAS_XDIST)),)
ifneq ($(strip $(LIVE_JOBS)),)
LIVE_XDIST_ARGS = -n $(LIVE_JOBS)
endif
endif

live-up:
	$(PYTHON) -m tests.live.compose_batch --batch-size $(LIVE_BATCH_SIZE) $(LIVE_UP_ARGS)

live-down:
	$(LIVE_COMPOSE_CMD) down --remove-orphans

live-ps:
	$(LIVE_COMPOSE_CMD) ps

live-logs:
	$(LIVE_COMPOSE_CMD) logs -f --tail=200 $(SERVICE)

live-preflight:
	$(PYTHON) -m tests.live.preflight

live-test:
	RUN_LIVE_TESTS=1 $(PYTEST) $(LIVE_XDIST_ARGS) tests/live

live-edgecases:
	RUN_LIVE_TESTS=1 RUN_EDGECASES=1 $(PYTEST) $(LIVE_XDIST_ARGS) tests/live/test_edgecases.py

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache
