import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from rygnal.approved_apply import ApprovedPatchApplyError, apply_approved_patch
from rygnal.audit_logger import AuditLogger
from rygnal.changed_files import ChangedFileKind
from rygnal.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    Severity,
    utc_now_iso,
)
from rygnal.patch_diff import PatchDiff, PatchFileDiff, generate_patch_diff
from rygnal.path_safety import (
    PathSafetyError,
    ensure_patch_path_forms_safe,
    ensure_patch_paths_safe,
    validate_patch_path_forms,
    validate_patch_paths,
)
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


def unsafe_patch(path: str, *, metadata_path: str | None = None) -> PatchDiff:
    patch = (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        "index 0000000000000000000000000000000000000000.."
        "1111111111111111111111111111111111111111\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        "@@ -0,0 +1 @@\n"
        "+unsafe\n"
    )

    path_for_metadata = metadata_path or path

    return PatchDiff(
        workspace_path="/tmp/guarded",
        baseline_commit_sha="a" * 40,
        patch=patch,
        patch_sha256=hashlib.sha256(patch.encode("utf-8")).hexdigest(),
        patch_size_bytes=len(patch.encode("utf-8")),
        files=(
            PatchFileDiff(
                path=path_for_metadata,
                kind=ChangedFileKind.ADDED,
                additions=1,
                deletions=0,
                new_mode="100644",
            ),
        ),
    )


@pytest.mark.parametrize(
    ("path", "code"),
    (
        ("../evil.txt", "parent-directory-path"),
        ("/tmp/evil.txt", "rooted-path"),
        ("C:/Users/test/evil.txt", "windows-rooted-path"),
        ("..\\evil.txt", "parent-directory-path"),
    ),
)
def test_unsafe_patch_path_forms_are_rejected(path: str, code: str) -> None:
    report = validate_patch_path_forms(unsafe_patch(path))

    assert report.safe is False
    assert any(violation.code == code for violation in report.violations)

    with pytest.raises(PathSafetyError):
        ensure_patch_path_forms_safe(unsafe_patch(path))


def test_patch_metadata_mismatch_is_rejected() -> None:
    report = validate_patch_path_forms(unsafe_patch("../evil.txt", metadata_path="docs/safe.txt"))

    assert report.safe is False
    assert any(violation.code == "patch-path-metadata-mismatch" for violation in report.violations)


def test_safe_repo_relative_path_is_allowed(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    docs = guarded / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("After\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    report = validate_patch_paths(patch, trusted)

    assert report.safe is True
    assert report.violations == ()
    assert ensure_patch_paths_safe(patch, trusted).safe is True


def test_safe_apply_rejects_unsafe_paths_and_writes_audit(tmp_path: Path) -> None:
    _guarded, trusted = clone_fixture(tmp_path)
    patch = unsafe_patch("../evil.txt")
    logger = AuditLogger(tmp_path / "audit.jsonl")

    with pytest.raises(SafePatchApplyError, match="path safety"):
        auto_apply_safe_patch(
            patch,
            trusted,
            logger=logger,
            user_id="test_user",
            agent_id="test_agent",
            environment="test",
            trace_id="trace_path_safety",
        )

    events = logger.read_events()
    assert len(events) == 1
    assert events[0].decision == "block"
    assert events[0].policy_id == "guarded-workspace-path-safety"
    assert logger.verify_integrity() is True
    assert not (tmp_path / "evil.txt").exists()


def test_approved_apply_rejects_unsafe_paths_even_with_forged_approval(
    tmp_path: Path,
) -> None:
    _guarded, trusted = clone_fixture(tmp_path)
    patch = unsafe_patch("../evil.txt")
    request = ApprovalRequest(
        requested_by="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_forged_path",
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target=patch.patch_sha256,
        policy_id="guarded-workspace-risky-patch-approval",
        reason="Forged approval.",
        severity=Severity.HIGH,
    )
    decision = ApprovalDecision(
        approval_id=request.approval_id,
        status=ApprovalStatus.APPROVED,
        approved=True,
        decided_by="reviewer",
        decided_at=utc_now_iso(),
        reason="Forged approval.",
        metadata={"patch_sha256": patch.patch_sha256},
    )
    logger = AuditLogger(tmp_path / "audit.jsonl")

    with pytest.raises(ApprovedPatchApplyError, match="path safety"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
            logger=logger,
        )

    events = logger.read_events()
    assert len(events) == 1
    assert events[0].decision == "block"
    assert events[0].policy_id == "guarded-workspace-path-safety"
    assert logger.verify_integrity() is True
    assert not (tmp_path / "evil.txt").exists()
