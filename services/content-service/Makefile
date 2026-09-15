SHELL := /bin/sh
IMAGE ?= flashcards-content-service:local

.PHONY: install lint format-check typecheck test unit-test integration-test contract-test container-test docs image-build local-run migrate migration-check

install:
	uv sync --all-groups --frozen

lint:
	uv run ruff check

format-check:
	uv run ruff format --check

typecheck:
	uv run pyright

test:
	uv run pytest

unit-test:
	@if [ -d tests/unit ]; then uv run pytest tests/unit; else uv run pytest; fi

integration-test:
	@if [ -d tests/integration ]; then uv run pytest tests/integration; else printf '%s\n' 'Integration tests are not configured yet.'; fi

contract-test:
	@if [ -d tests/contract ]; then uv run pytest tests/contract; else printf '%s\n' 'Contract tests are not configured yet.'; fi

container-test:
	@if [ -d tests/container ]; then uv run pytest tests/container; else printf '%s\n' 'Container tests are not configured yet.'; fi

docs:
	uv run --group docs sphinx-build -E -a -W --keep-going -b html docs docs/_build/html

image-build:
	docker build --tag $(IMAGE) .

local-run:
	uv run uvicorn app.main:app --app-dir src --host 127.0.0.1 --port 8000 --reload

migrate:
	@if [ -f alembic.ini ]; then uv run alembic upgrade head; else printf '%s\n' 'Alembic is not configured for this service.'; exit 2; fi

migration-check:
	@if [ -f alembic.ini ]; then uv run alembic check; else printf '%s\n' 'Alembic is not configured for this service.'; exit 2; fi
