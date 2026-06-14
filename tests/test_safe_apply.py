import shutil
import subprocess
from pathlib import Path

import pytest

from rygnal.audit_logger import AuditLogger
from rygnal.patch_diff import generate_patch_diff
from rygnal.safe_apply import (
    SafePatchApplyError,
    SafePatchApplyOutcome,
    auto_apply_safe_patch,
)


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def create_repo(path: Path) -> Path:
    path.mkdir()

    run_git(path, "init")
    run_git(path, "config", "user.email", "test@example.com")
    run_git(path, "config", "user.name", "Test User")

    (path / "README.md").write_text("# Project\n", encoding="utf-8")
    docs = path / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Before\n", encoding="utf-8")
    tests = path / "tests"
    tests.mkdir()
    (tests / "test_readme.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def clone_fixture(tmp_path: Path) -> tuple[Path, Path]:
    baseline = create_repo(tmp_path / "baseline")
    guarded = tmp_path / "guarded"
    trusted = tmp_path / "trusted"

    shutil.copytree(baseline, guarded)
    shutil.copytree(baseline, trusted)

    return guarded, trusted


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def test_auto_applies_low_risk_documentation_patch(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "usage.md").write_text("After\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    logger = AuditLogger(tmp_path / "audit.jsonl")

    result = auto_apply_safe_patch(
        patch,
        trusted,
        logger=logger,
        user_id="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_safe_apply",
    )

    assert result.outcome == SafePatchApplyOutcome.APPLIED
    assert result.applied is True
    assert result.files == ("docs/usage.md",)
    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "After\n"

    events = logger.read_events()
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].policy_id == "guarded-workspace-safe-patch-auto-apply"
    assert logger.verify_integrity() is True


def test_auto_applies_low_risk_test_patch(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    test_file = guarded / "tests" / "test_new.py"
    test_file.write_text("def test_new():\n    assert True\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    result = auto_apply_safe_patch(patch, trusted)

    assert result.applied is True
    assert (trusted / "tests" / "test_new.py").exists()


def test_source_code_patch_is_not_auto_applied(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    result = auto_apply_safe_patch(patch, trusted)

    assert result.outcome == SafePatchApplyOutcome.SKIPPED
    assert result.applied is False
    assert any(reason.code == "not-low-risk" for reason in result.skip_reasons)
    assert not (trusted / "src" / "app.py").exists()


def test_dependency_patch_is_not_auto_applied(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    result = auto_apply_safe_patch(patch, trusted)

    assert result.applied is False
    assert any(reason.code == "not-low-risk" for reason in result.skip_reasons)
    assert not (trusted / "pyproject.toml").exists()


def test_blocked_patch_is_not_auto_applied(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    result = auto_apply_safe_patch(patch, trusted)

    assert result.applied is False
    assert any(reason.code == "blocked-by-change-gate" for reason in result.skip_reasons)
    assert not (trusted / ".env").exists()


def test_ignored_workspace_changes_disable_auto_apply(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    generated = guarded / "node_modules"
    generated.mkdir()
    (generated / "cache.txt").write_text("cache\n", encoding="utf-8")
    (guarded / "docs" / "usage.md").write_text("After\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    result = auto_apply_safe_patch(patch, trusted)

    assert result.applied is False
    assert any(reason.code == "ignored-workspace-changes" for reason in result.skip_reasons)
    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"


def test_dirty_target_repository_fails_closed(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "usage.md").write_text("After\n", encoding="utf-8")
    (trusted / "README.md").write_text("# Dirty\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))

    with pytest.raises(SafePatchApplyError, match="clean"):
        auto_apply_safe_patch(patch, trusted)

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"


def test_failed_git_apply_does_not_mutate_target_repo(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "usage.md").write_text("After\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    (trusted / "docs" / "usage.md").write_text("Different baseline\n", encoding="utf-8")
    run_git(trusted, "add", ".")
    run_git(trusted, "commit", "-m", "diverge")

    with pytest.raises(SafePatchApplyError):
        auto_apply_safe_patch(patch, trusted)

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Different baseline\n"
