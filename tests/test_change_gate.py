import subprocess
from pathlib import Path

from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import (
    GuardedChangeGateOutcome,
    evaluate_guarded_change_gate,
    write_guarded_change_gate_audit_event,
)
from rygnal.change_risk import ChangeRiskReason, classify_patch_risk
from rygnal.patch_diff import PatchDiff, generate_patch_diff
from rygnal.risk_engine import RiskLevel


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def create_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()

    run_git(repo, "init")
    run_git(repo, "config", "user.email", "test@example.com")
    run_git(repo, "config", "user.name", "Test User")

    (repo / "README.md").write_text("# Project\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "baseline")

    return repo


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def test_low_risk_patch_passes_without_blocking(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    docs = repo / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Usage\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline_sha(repo))
    decision = evaluate_guarded_change_gate(patch)

    assert decision.outcome == GuardedChangeGateOutcome.ALLOW
    assert decision.blocked is False
    assert decision.allowed_to_continue is True
    assert decision.block_reasons == ()
    assert decision.audit_summary["blocked"] is False


def test_secret_path_is_blocked_before_any_apply_step(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    (repo / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline_sha(repo))
    decision = evaluate_guarded_change_gate(patch)

    assert decision.outcome == GuardedChangeGateOutcome.BLOCK
    assert decision.blocked is True
    assert decision.allowed_to_continue is False
    assert decision.block_reasons[0].code == "security-sensitive-path"
    assert decision.block_reasons[0].path == ".env"


def test_added_secret_content_is_blocked_and_not_leaked_in_audit_summary(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path)
    secret_value = "sk-1234567890abcdefABCDEF"
    src = repo / "src"
    src.mkdir()
    (src / "config.py").write_text(
        f'OPENAI_API_KEY = "{secret_value}"\n',
        encoding="utf-8",
    )

    patch = generate_patch_diff(repo, baseline_sha(repo))
    decision = evaluate_guarded_change_gate(patch)

    assert decision.blocked is True
    assert any(reason.code == "added-secret-openai-api-key" for reason in decision.block_reasons)
    assert secret_value not in str(decision.audit_summary)


def test_symlink_change_is_blocked(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    (repo / "escape-link").symlink_to("../outside")

    patch = generate_patch_diff(repo, baseline_sha(repo))
    decision = evaluate_guarded_change_gate(patch)

    assert decision.blocked is True
    assert any(reason.code == "symlink-change" for reason in decision.block_reasons)


def test_destructive_script_change_is_blocked(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    scripts = repo / "scripts"
    scripts.mkdir()
    (scripts / "cleanup.sh").write_text("#!/bin/sh\nrm -rf /tmp/demo\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline_sha(repo))
    decision = evaluate_guarded_change_gate(patch)

    assert decision.blocked is True
    assert any(
        reason.code == "destructive-command-recursive-force-delete"
        for reason in decision.block_reasons
    )


def test_high_risk_dependency_change_passes_to_later_approval_flow(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path)
    (repo / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline_sha(repo))
    decision = evaluate_guarded_change_gate(patch)

    assert decision.blocked is False
    assert decision.allowed_to_continue is True
    assert decision.risk_report.overall_risk_level == RiskLevel.HIGH


def test_critical_validation_reason_blocks_even_without_file_changes() -> None:
    patch = PatchDiff(
        workspace_path="/tmp/workspace",
        baseline_commit_sha="a" * 40,
        patch="",
        patch_sha256="b" * 64,
        patch_size_bytes=0,
    )
    risk_report = classify_patch_risk(
        patch,
        validation_reasons=(
            ChangeRiskReason(
                code="validator-unsafe-resolver",
                risk_level=RiskLevel.CRITICAL,
                reason="Dependency resolver reported unsafe behavior.",
                evidence=(("resolver", "pip"),),
            ),
        ),
    )

    decision = evaluate_guarded_change_gate(patch, risk_report=risk_report)

    assert decision.blocked is True
    assert decision.block_reasons[0].code == "validator-unsafe-resolver"


def test_block_gate_never_mutates_trusted_repo(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = baseline_sha(repo)
    (repo / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)
    decision = evaluate_guarded_change_gate(patch)

    assert decision.blocked is True
    assert run_git(repo, "rev-parse", "HEAD") == baseline
    assert run_git(repo, "status", "--short") == "?? .env"


def test_block_decision_writes_hash_chained_audit_event_without_raw_secret(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path)
    secret_value = "sk-1234567890abcdefABCDEF"
    src = repo / "src"
    src.mkdir()
    (src / "config.py").write_text(
        f'OPENAI_API_KEY = "{secret_value}"\n',
        encoding="utf-8",
    )

    patch = generate_patch_diff(repo, baseline_sha(repo))
    decision = evaluate_guarded_change_gate(patch)

    logger = AuditLogger(tmp_path / "audit.jsonl")
    event = write_guarded_change_gate_audit_event(
        logger,
        decision,
        user_id="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_test",
    )

    events = logger.read_events()

    assert event.decision == "block"
    assert event.allowed is False
    assert event.severity == "critical"
    assert event.policy_id == "guarded-workspace-dangerous-change-gate"
    assert len(events) == 1
    assert logger.verify_integrity() is True
    assert secret_value not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
