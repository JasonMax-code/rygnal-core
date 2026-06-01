from pathlib import Path


def test_docker_setup_files_exist():
    required_paths = [
        "Dockerfile",
        "docker-compose.yml",
        ".dockerignore",
        "Makefile",
        "docs/15-docker-setup.md",
    ]

    for path in required_paths:
        assert Path(path).exists(), f"Missing required Docker setup file: {path}"


def test_docker_compose_references_rygnal_service():
    compose = Path("docker-compose.yml").read_text()
    assert "rygnal:" in compose
    assert "dockerfile: Dockerfile" in compose
    assert "python -m demo.run_demo" in compose


def test_dockerfile_uses_python_3_11_slim():
    dockerfile = Path("Dockerfile").read_text()
    assert "FROM python:3.11-slim" in dockerfile
    assert "WORKDIR /app" in dockerfile
    assert "COPY requirements-dev.txt pyproject.toml ./" in dockerfile
    assert 'CMD ["python", "-m", "demo.run_demo"]' in dockerfile
