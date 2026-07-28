.PHONY: install lint typecheck test web-install web-lint web-typecheck web-test web-build verify up down logs migrate

install:
	python -m pip install -e ".[dev]"

lint:
	python -m ruff check apps scopegraph tests

typecheck:
	python -m mypy apps scopegraph

test:
	python -m pytest --cov=apps --cov=scopegraph --cov-report=term-missing

web-install:
	npm --prefix apps/web ci

web-lint:
	npm --prefix apps/web run lint

web-typecheck:
	npm --prefix apps/web run typecheck

web-test:
	npm --prefix apps/web run test

web-build:
	npm --prefix apps/web run build

verify: lint typecheck test web-lint web-typecheck web-test web-build

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f api worker web

migrate:
	docker compose run --rm migrate

