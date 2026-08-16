.PHONY: check format integration-test

check:
	.venv/bin/ruff format --check .
	.venv/bin/ruff check .
	.venv/bin/mypy
	.venv/bin/pytest

format:
	.venv/bin/ruff format .
	.venv/bin/ruff check --fix .
