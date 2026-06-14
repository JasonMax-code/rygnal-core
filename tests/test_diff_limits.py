import subprocess
from pathlib import Path

from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import classify_patch_risk
from rygnal.diff_limits import DiffLimitPolicy, evaluate_diff_limits
from rygnal.patch_approval import evaluate_patch_approval_requirement
from rygnal.patch_diff import generate_patch_diff
from rygnal.risk_engine import RiskLevel
from rygnal.safe_apply import SafePatchApplyOutcome, auto_apply_safe_patch


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

    docs = path / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Before\n", encoding="utf-8")

    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def clone_guarded_and_trusted(tmp_path: Path) -> tuple[Path, Path]:
    trusted = create_repo(tmp_path / "trusted")
    guarded = tmp_path / "guarded"

    run_git(tmp_path, "clone", trusted.as_posix(), guarded.as_posix())
    run_git(guarded, "config", "user.email", "test@example.com")
    run_git(guarded, "config", "user.name", "Test User")

    return guarded, trusted


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def test_small_patch_has_no_diff_limit_reasons(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    baseline = baseline_sha(repo)

    (repo / "docs" / "usage.md").write_text("After\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)
    policy = DiffLimitPolicy(
        soft_max_changed_files=10,
        soft_max_total_changed_lines=50,
        soft_max_patch_size_bytes=10_000,
        hard_max_changed_files=100,
        hard_max_total_changed_lines=500,
        hard_max_patch_size_bytes=100_000,
    )

    limit_report = evaluate_diff_limits(patch, policy=policy)
    risk_report = classify_patch_risk(patch, diff_limit_policy=policy)

    assert limit_report.reasons == ()
    assert limit_report.overall_risk_level == RiskLevel.LOW
    assert risk_report.report_reasons == ()
    assert risk_report.overall_risk_level == RiskLevel.LOW


def test_oversized_line_count_marks_patch_high_risk_and_requires_approval(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    baseline = baseline_sha(repo)

    large_docs_change = "\n".join(f"line {index}" for index in range(8)) + "\n"
    (repo / "docs" / "usage.md").write_text(large_docs_change, encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)
    policy = DiffLimitPolicy(
        soft_max_changed_files=10,
        soft_max_total_changed_lines=3,
        soft_max_patch_size_bytes=10_000,
        hard_max_changed_files=100,
        hard_max_total_changed_lines=100,
        hard_max_patch_size_bytes=100_000,
    )

    risk_report = classify_patch_risk(patch, diff_limit_policy=policy)
    requirement = evaluate_patch_approval_requirement(patch, risk_report=risk_report)

    assert risk_report.overall_risk_level == RiskLevel.HIGH
    assert any(
        reason.code == "large-diff-total_changed_lines" for reason in risk_report.report_reasons
    )
    assert requirement.required is True
    assert any(reason.code == "large-diff-total_changed_lines" for reason in requirement.reasons)


def test_oversized_patch_is_not_auto_applied(tmp_path: Path) -> None:
    guarded, trusted = clone_guarded_and_trusted(tmp_path)
    baseline = baseline_sha(guarded)

    large_docs_change = "\n".join(f"line {index}" for index in range(8)) + "\n"
    (guarded / "docs" / "usage.md").write_text(large_docs_change, encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline)
    policy = DiffLimitPolicy(
        soft_max_changed_files=10,
        soft_max_total_changed_lines=3,
        soft_max_patch_size_bytes=10_000,
        hard_max_changed_files=100,
        hard_max_total_changed_lines=100,
        hard_max_patch_size_bytes=100_000,
    )
    risk_report = classify_patch_risk(patch, diff_limit_policy=policy)

    result = auto_apply_safe_patch(patch, trusted, risk_report=risk_report)

    assert result.outcome == SafePatchApplyOutcome.SKIPPED
    assert any(reason.code == "large-diff-total_changed_lines" for reason in result.skip_reasons)
    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"


def test_hard_line_limit_marks_patch_critical_and_blocks_gate(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    baseline = baseline_sha(repo)

    large_docs_change = "\n".join(f"line {index}" for index in range(8)) + "\n"
    (repo / "docs" / "usage.md").write_text(large_docs_change, encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)
    policy = DiffLimitPolicy(
        soft_max_changed_files=10,
        soft_max_total_changed_lines=3,
        soft_max_patch_size_bytes=10_000,
        hard_max_changed_files=100,
        hard_max_total_changed_lines=5,
        hard_max_patch_size_bytes=100_000,
    )

    risk_report = classify_patch_risk(patch, diff_limit_policy=policy)
    gate = evaluate_guarded_change_gate(patch, risk_report=risk_report)

    assert risk_report.overall_risk_level == RiskLevel.CRITICAL
    assert gate.blocked is True
    assert any(reason.code == "hard-diff-total_changed_lines" for reason in gate.block_reasons)


def test_diff_limit_report_audit_summary_contains_size_reason(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    baseline = baseline_sha(repo)

    large_docs_change = "\n".join(f"line {index}" for index in range(8)) + "\n"
    (repo / "docs" / "usage.md").write_text(large_docs_change, encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)
    policy = DiffLimitPolicy(
        soft_max_changed_files=10,
        soft_max_total_changed_lines=3,
        soft_max_patch_size_bytes=10_000,
        hard_max_changed_files=100,
        hard_max_total_changed_lines=100,
        hard_max_patch_size_bytes=100_000,
    )

    limit_report = evaluate_diff_limits(patch, policy=policy)
    summary = limit_report.audit_summary

    assert summary["approval_limit_exceeded"] is True
    assert summary["hard_limit_exceeded"] is False
    assert summary["reasons"][0]["code"] == "large-diff-total_changed_lines"
    assert summary["reasons"][0]["evidence"]["observed"] > 3
