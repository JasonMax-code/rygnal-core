.PHONY: install format lint test security audit demo validate docker-build docker-test docker-demo docker-validate

install:
	python -m pip install --upgrade pip
	pip install -r requirements-dev.txt

format:
	ruff format src tests demo

lint:
	ruff check src tests demo

test:
	pytest -q

security:
	bandit -r src demo -c pyproject.toml

audit:
	pip-audit -r requirements-dev.txt

demo:
	python -m demo.run_demo

validate: format lint test security audit demo

docker-build:
	docker compose build

docker-test:
	docker compose run --rm rygnal pytest -q

docker-demo:
	docker compose run --rm rygnal python -m demo.run_demo

docker-validate:
	docker compose run --rm rygnal make validate
