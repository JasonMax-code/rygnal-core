from pathlib import Path


def test_makefile_has_local_install_targets():
    content = Path("Makefile").read_text()

    assert "install-dev:" in content
    assert "python -m pip install -e ." in content
    assert "check-install:" in content
    assert "validate-local:" in content


def test_makefile_validation_covers_examples_directory():
    content = Path("Makefile").read_text()

    assert "ruff format src tests demo examples" in content
    assert "ruff check src tests demo examples" in content
    assert "bandit -r src demo examples -c pyproject.toml" in content


def test_readme_documents_local_validation_environment():
    content = Path("README.md").read_text()

    assert "python -m venv .venv" in content
    assert "pip install -e ." in content
    assert "make validate-local" in content
    assert "pip-audit -r requirements-dev.txt" in content
