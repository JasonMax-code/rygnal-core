import os
import subprocess
import sys
from pathlib import Path


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"src{os.pathsep}{env.get('PYTHONPATH', '')}"

    return subprocess.run(
        [sys.executable, "-m", "rygnal.cli", *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_rygnal_cli_help_works():
    result = run_cli("--help")

    assert result.returncode == 0
    assert "Rygnal Core CLI" in result.stdout
    assert "version" in result.stdout
    assert "run" in result.stdout
    assert "demo" in result.stdout
    assert "policy" in result.stdout


def test_rygnal_cli_version_works():
    result = run_cli("version")

    assert result.returncode == 0
    assert "rygnal-core" in result.stdout


def test_rygnal_cli_policy_validate_default_policy():
    result = run_cli("policy", "validate", "policies/default_policy.yaml")

    assert result.returncode == 0
    assert "Policy file valid" in result.stdout
    assert "Policy version: policy.v2" in result.stdout
    assert "Rules:" in result.stdout


def test_rygnal_cli_policy_validate_invalid_policy(tmp_path):
    bad_policy = tmp_path / "bad_policy.yaml"
    bad_policy.write_text("rules: invalid")

    result = run_cli("policy", "validate", str(bad_policy))

    assert result.returncode == 1
    assert "Policy file invalid" in result.stderr


def test_rygnal_cli_demo_run_works():
    result = run_cli("demo", "run")

    assert result.returncode == 0
    assert "Rygnal Real Scenario Runner v1" in result.stdout
    assert "Total scenarios: 7" in result.stdout
    assert "Policy" in result.stdout
    assert "Audit Event" in result.stdout


def test_pyproject_declares_rygnal_console_script():
    content = Path("pyproject.toml").read_text()

    assert "[project.scripts]" in content
    assert 'rygnal = "rygnal.cli:main"' in content
