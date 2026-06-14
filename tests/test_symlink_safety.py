import shutil
import subprocess
from pathlib import Path

import pytest

from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import classify_patch_risk
from rygnal.patch_diff import generate_patch_diff
from rygnal.path_safety import validate_patch_paths
from rygnal.safe_apply import SafePatchApplyError, auto_apply_safe_patch


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
    (docs / "usage.md").write_text("Usage\n", encoding="utf-8")

    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def clone_fixture(tmp_path: Path) -> tuple[Path, Path]:
    baseline = create_repo(tmp_path / "baseline")
    guarded = tmp_path / "guarded"
    trusted = tmp_path / "trusted"

    shutil.copytree(baseline, guarded, symlinks=True)
    shutil.copytree(baseline, trusted, symlinks=True)

    return guarded, trusted


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def test_symlink_addition_is_classified_as_critical(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "readme-link").symlink_to("../README.md")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    report = classify_patch_risk(patch)
    file_report = next(file for file in report.files if file.path == "docs/readme-link")

    assert file_report.risk_level.value == "critical"
    assert any(reason.code == "symlink-change" for reason in file_report.reasons)

    gate = evaluate_guarded_change_gate(patch, risk_report=report)
    assert gate.blocked is True


def test_symlink_target_inside_repo_passes_path_safety(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "readme-link").symlink_to("../README.md")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    report = validate_patch_paths(patch, trusted)

    assert report.safe is True
    assert report.symlink_targets[0].path == "docs/readme-link"
    assert report.symlink_targets[0].target == "../README.md"


def test_symlink_target_escaping_repo_is_rejected(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "escape-link").symlink_to("../../outside.txt")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    report = validate_patch_paths(patch, trusted)

    assert report.safe is False
    assert any(violation.code == "symlink-target-outside-repo" for violation in report.violations)


def test_absolute_symlink_target_is_rejected(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "absolute-link").symlink_to("/etc/passwd")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    report = validate_patch_paths(patch, trusted)

    assert report.safe is False
    assert any(violation.code == "symlink-target-rooted" for violation in report.violations)


def test_unsafe_symlink_target_is_audited_before_auto_apply(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "escape-link").symlink_to("../../outside.txt")
    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    audit = AuditLogger(tmp_path / "audit.jsonl")

    with pytest.raises(SafePatchApplyError, match="path safety"):
        auto_apply_safe_patch(
            patch,
            trusted,
            logger=audit,
            user_id="test_user",
            agent_id="test_agent",
            environment="test",
            trace_id="trace_symlink_safety",
        )

    events = audit.read_events()
    assert len(events) == 1
    assert events[0].decision == "block"
    assert events[0].policy_id == "guarded-workspace-path-safety"
    assert audit.verify_integrity() is True
    assert not (tmp_path / "outside.txt").exists()
