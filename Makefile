.PHONY: install fmt lint typecheck test clean

install:
	python -m pip install -e .[dev]

fmt:
	ruff check --fix .
	black .

lint:
	ruff check .

typecheck:
	mypy src tests

test:
	pytest --ignore=tests/integration --ignore=tests/live --cov=reactguard --cov-report=term-missing

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache
