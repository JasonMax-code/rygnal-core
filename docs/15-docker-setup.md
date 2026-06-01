# Docker Setup

Docker support makes Rygnal Core reproducible across local machines, Codespaces, and future CI environments.

## Build

```bash
docker compose build
```

## Run

```bash
docker compose run --rm rygnal python -m demo.run_demo
```

## Helpful commands

```bash
docker compose build
docker compose run --rm rygnal pytest -q
``` 

The service mounts the repository into `/app` and sets `PYTHONPATH=/app/src:/app` for local development.
