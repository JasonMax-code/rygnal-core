import shutil
import subprocess
from pathlib import Path

import pytest

from rygnal.approved_apply import ApprovedPatchApplyError, apply_approved_patch
from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    Severity,
    utc_now_iso,
)
from rygnal.patch_approval import (
    PatchApprovalError,
    approve_patch_request,
    create_patch_approval_request,
    reject_patch_request,
    write_patch_approval_decision_audit_event,
    write_patch_approval_request_audit_event,
)
from rygnal.patch_diff import generate_patch_diff
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

    (path / "README.md").write_text("# Project\n", encoding="utf-8")
    docs = path / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Before\n", encoding="utf-8")

    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def clone_guarded_and_trusted(tmp_path: Path) -> tuple[Path, Path]:
    baseline = create_repo(tmp_path / "baseline")
    guarded = tmp_path / "guarded"
    trusted = tmp_path / "trusted"

    shutil.copytree(baseline, guarded)
    shutil.copytree(baseline, trusted)

    return guarded, trusted


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def test_full_lifecycle_auto_applies_safe_documentation_patch(tmp_path: Path) -> None:
    guarded, trusted = clone_guarded_and_trusted(tmp_path)
    audit = AuditLogger(tmp_path / "audit.jsonl")

    (guarded / "docs" / "usage.md").write_text("After\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    gate = evaluate_guarded_change_gate(patch)

    assert gate.blocked is False

    result = auto_apply_safe_patch(
        patch,
        trusted,
        logger=audit,
        user_id="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_safe_lifecycle",
    )

    assert result.outcome == SafePatchApplyOutcome.APPLIED
    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "After\n"

    events = audit.read_events()
    assert [event.action for event in events] == ["auto_apply_safe_patch"]
    assert [event.decision for event in events] == ["allow"]
    assert audit.verify_integrity() is True


def test_full_lifecycle_requires_approval_then_applies_risky_source_patch(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_guarded_and_trusted(tmp_path)
    audit = AuditLogger(tmp_path / "audit.jsonl")

    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))

    safe_result = auto_apply_safe_patch(patch, trusted)
    assert safe_result.applied is False
    assert any(reason.code == "not-low-risk" for reason in safe_result.skip_reasons)
    assert not (trusted / "src" / "app.py").exists()

    request = create_patch_approval_request(
        patch,
        requested_by="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_risky_lifecycle",
    )
    write_patch_approval_request_audit_event(audit, request)

    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )
    write_patch_approval_decision_audit_event(audit, request, decision)

    apply_result = apply_approved_patch(
        patch,
        trusted,
        approval_request=request,
        approval_decision=decision,
        logger=audit,
    )

    assert apply_result.applied is True
    assert (trusted / "src" / "app.py").read_text(encoding="utf-8") == "print('hello')\n"

    events = audit.read_events()
    assert [event.decision for event in events] == [
        "require_approval",
        "allow",
        "allow",
    ]
    assert [event.action for event in events] == [
        "approval_requested",
        "approval_decided",
        "apply_approved_patch",
    ]
    assert audit.verify_integrity() is True


def test_full_lifecycle_blocks_secret_patch_before_approval_or_apply(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_guarded_and_trusted(tmp_path)

    secret_value = "sk-1234567890abcdefABCDEF"
    (guarded / ".env").write_text(f"OPENAI_API_KEY={secret_value}\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    gate = evaluate_guarded_change_gate(patch)

    assert gate.blocked is True

    safe_result = auto_apply_safe_patch(patch, trusted)
    assert safe_result.applied is False
    assert any(reason.code == "blocked-by-change-gate" for reason in safe_result.skip_reasons)

    with pytest.raises(PatchApprovalError, match="Blocked"):
        create_patch_approval_request(patch, requested_by="test_user")

    forged_request = ApprovalRequest(
        requested_by="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_forged_secret",
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target=patch.patch_sha256,
        policy_id="guarded-workspace-risky-patch-approval",
        reason="Forged approval.",
        severity=Severity.CRITICAL,
    )
    forged_decision = ApprovalDecision(
        approval_id=forged_request.approval_id,
        status=ApprovalStatus.APPROVED,
        approved=True,
        decided_by="reviewer",
        decided_at=utc_now_iso(),
        reason="Forged approval.",
        metadata={"patch_sha256": patch.patch_sha256},
    )

    with pytest.raises(ApprovedPatchApplyError, match="Blocked"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=forged_request,
            approval_decision=forged_decision,
        )

    assert not (trusted / ".env").exists()


def test_full_lifecycle_rejects_reused_approval_for_different_patch(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_guarded_and_trusted(tmp_path)

    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")
    patch = generate_patch_diff(guarded, baseline_sha(guarded))

    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    other_guarded = tmp_path / "other_guarded"
    shutil.copytree(trusted, other_guarded)
    other_src = other_guarded / "src"
    other_src.mkdir()
    (other_src / "other.py").write_text("print('other')\n", encoding="utf-8")
    other_patch = generate_patch_diff(other_guarded, baseline_sha(other_guarded))

    with pytest.raises(ApprovedPatchApplyError, match="bound"):
        apply_approved_patch(
            other_patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "src").exists()


def test_full_lifecycle_rejection_never_mutates_trusted_repo(tmp_path: Path) -> None:
    guarded, trusted = clone_guarded_and_trusted(tmp_path)

    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = reject_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    with pytest.raises(ApprovedPatchApplyError, match="not granted"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "src" / "app.py").exists()


def test_full_lifecycle_stale_trusted_repo_rejects_before_apply(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_guarded_and_trusted(tmp_path)

    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    (trusted / "README.md").write_text("# Trusted changed\n", encoding="utf-8")
    run_git(trusted, "add", ".")
    run_git(trusted, "commit", "-m", "trusted changed")

    with pytest.raises(ApprovedPatchApplyError, match="baseline"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "src" / "app.py").exists()
