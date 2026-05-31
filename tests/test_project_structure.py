from pathlib import Path


def test_core_project_structure_exists():
    required_paths = [
        "README.md",
        "pyproject.toml",
        "requirements-dev.txt",
        "src/rygnal/__init__.py",
        "src/rygnal/interceptor.py",
        "src/rygnal/policy_engine.py",
        "src/rygnal/audit_logger.py",
        "src/rygnal/risk_engine.py",
        "src/rygnal/tool_executor.py",
        "src/rygnal/models.py",
        "policies/default_policy.yaml",
        "demo/run_demo.py",
    ]

    for path in required_paths:
        assert Path(path).exists(), f"Missing required file: {path}"


def test_default_policy_file_is_not_empty():
    policy_file = Path("policies/default_policy.yaml")
    assert policy_file.exists()
    assert policy_file.read_text().strip()
