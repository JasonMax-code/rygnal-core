# Rygnal Core

Rygnal Core is a local-first core MVP for runtime governance of AI-agent tool actions. It is not a full SaaS product, enterprise deployment, or enterprise production-ready platform. It is not enterprise production-ready.

## What Works Today

- Policy Engine v1/v2 schema
- Risk Engine v1
- Audit Logger v1
- Runtime Interceptor v1
- Approval Workflow v1
- Runtime Modes v1
- Real Scenario Runner v1
- Rygnal CLI v1
- Policy explain output
- Security hardening
- Docker setup
- CI validation

## What is Not Included Yet

- SaaS dashboard
- Login/auth system
- Billing
- Multi-tenant workspaces
- Enterprise SSO
- SIEM export
- Cloud deployment

## Install Locally

Create and activate a virtual environment:

    python -m venv .venv
    source .venv/bin/activate

Install development dependencies:

    make install

Install Rygnal Core in editable mode:

    pip install -e .

Verify the package import:

    python -c "from rygnal import Rygnal; assert Rygnal is not None; print('Rygnal import OK')"

Verify the CLI:

    rygnal --help
    rygnal version

Run the demo through the package CLI:

    rygnal demo run

Run the original module demo:

    python -m demo.run_demo

Run validation:

    make validate

## Run with Docker

    docker compose build
    docker compose run --rm rygnal python -m demo.run_demo

## Validation

    ruff format src tests demo examples
    ruff check src tests demo examples
    pytest -q
    bandit -r src demo examples -c pyproject.toml
    pip-audit -r requirements-dev.txt
    python -m demo.run_demo

## License

Private repository. No public license selected yet.

## Local Validation Environment

Use a virtual environment for local validation. Some systems block installing packages into the system Python environment, so contributors should avoid relying on global Python installs.

Recommended setup:

    python -m venv .venv
    source .venv/bin/activate
    make install-dev

Check that the editable package and CLI are available:

    make check-install

Run normal validation:

    make validate

Run validation plus package/CLI install checks:

    make validate-local

Dependency audit is included in validation:

    pip-audit -r requirements-dev.txt
