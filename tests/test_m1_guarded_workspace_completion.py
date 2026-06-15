import json
import os
import subprocess
import sys
from pathlib import Path

from rygnal.audit_logger import AuditLogger
from rygnal.change_risk import classify_patch_risk
from rygnal.guarded_runner import GuardedRunStatus, run_guarded
from rygnal.safe_apply import SafePatchApplyOutcome, auto_apply_safe_patch
from rygnal.untracked_files import UntrackedFilePolicy
from tests.guarded_runner_helpers import (
    audit_actions,
    audit_text,
    create_trusted_repo,
    git_status_porcelain,
    head_sha,
    py_command,
    unsafe_runner_config,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def changed_paths(result) -> set[str]:
    assert result.changed_file_report is not None
    return {file.path for file in result.changed_file_report.files}


def patch_paths(result) -> set[str]:
    assert result.patch_diff is not None
    return {file.path for file in result.patch_diff.files}


def assert_repo_clean(repo: Path) -> None:
    assert git_status_porcelain(repo) == ""


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}"

    return subprocess.run(
        [sys.executable, "-m", "rygnal.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_m1_guarded_run_detects_added_modified_deleted_and_renamed_without_mutating_trusted_repo(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    baseline = head_sha(trusted)

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('agent_output.txt').write_text('new file\\n'); "
                "Path('docs/usage.md').write_text('updated docs\\n'); "
                "Path('README.md').unlink(); "
                "Path('src/app.py').rename('src/app_renamed.py')"
            ),
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.baseline_commit_sha == baseline
    assert result.changed_file_report is not None
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None
    assert result.patch_diff.patch_sha256

    report_paths = changed_paths(result)
    assert "agent_output.txt" in report_paths
    assert "docs/usage.md" in report_paths
    assert "README.md" in report_paths
    assert "src/app_renamed.py" in report_paths

    patch_text = result.patch_diff.patch
    assert "agent_output.txt" in patch_text
    assert "docs/usage.md" in patch_text
    assert "README.md" in patch_text
    assert "src/app.py" in patch_text
    assert "src/app_renamed.py" in patch_text

    assert head_sha(trusted) == baseline
    assert_repo_clean(trusted)
    assert not (trusted / "agent_output.txt").exists()
    assert (trusted / "README.md").exists()
    assert (trusted / "src" / "app.py").exists()
    assert not (trusted / "src" / "app_renamed.py").exists()


def test_m1_guarded_workspace_lives_outside_trusted_repo_and_command_cwd_is_workspace(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('cwd.txt').write_text(Path.cwd().resolve().as_posix())"
            ),
            preserve_workspace=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.workspace_path is not None

    workspace = Path(result.workspace_path).resolve()
    trusted_resolved = trusted.resolve()

    assert workspace.exists()
    assert trusted_resolved not in workspace.parents
    assert workspace != trusted_resolved
    assert (workspace / "cwd.txt").read_text(encoding="utf-8") == workspace.as_posix()
    assert not (trusted / "cwd.txt").exists()
    assert_repo_clean(trusted)


def test_m1_ignored_generated_folders_do_not_create_review_noise(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('node_modules').mkdir(); "
                "Path('node_modules/generated.txt').write_text('noise'); "
                "Path('__pycache__').mkdir(); "
                "Path('__pycache__/x.pyc').write_bytes(b'noise'); "
                "Path('docs/real_change.md').write_text('review me\\n')"
            ),
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.changed_file_report is not None
    assert result.patch_diff is not None

    report_paths = changed_paths(result)
    review_patch_paths = patch_paths(result)

    assert "docs/real_change.md" in report_paths
    assert "docs/real_change.md" in review_patch_paths

    assert "node_modules/generated.txt" not in report_paths
    assert "__pycache__/x.pyc" not in report_paths
    assert "node_modules/generated.txt" not in review_patch_paths
    assert "__pycache__/x.pyc" not in review_patch_paths

    patch_text = result.patch_diff.patch
    assert "node_modules/generated.txt" not in patch_text
    assert "__pycache__/x.pyc" not in patch_text
    assert not (trusted / "docs" / "real_change.md").exists()
    assert_repo_clean(trusted)


def test_m1_protected_files_remain_visible_and_do_not_auto_apply(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('requirements.txt').write_text('fastapi\\nmalicious-package\\n'); "
                "Path('.github/workflows/ci.yml').write_text('name: compromised\\n')"
            ),
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None
    assert "requirements.txt" in patch_paths(result)
    assert ".github/workflows/ci.yml" in patch_paths(result)

    risk_report = classify_patch_risk(result.patch_diff)
    apply_result = auto_apply_safe_patch(
        result.patch_diff,
        trusted,
        risk_report=risk_report,
    )

    assert apply_result.outcome == SafePatchApplyOutcome.SKIPPED
    assert "malicious-package" not in (trusted / "requirements.txt").read_text(encoding="utf-8")
    assert "compromised" not in (trusted / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    assert_repo_clean(trusted)


def test_m1_dirty_trusted_repo_blocks_before_command_and_is_audited(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    audit = AuditLogger(tmp_path / "audit.jsonl")
    marker = trusted / "command_executed_marker.txt"

    (trusted / "README.md").write_text("dirty trusted file\\n", encoding="utf-8")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('command_executed_marker.txt').write_text('should not run')"
            ),
            audit_logger=audit,
        )
    )

    actions = audit_actions(audit)

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None
    assert result.command_result is None
    assert "uncommitted" in result.blocked_reason.lower()
    assert not marker.exists()
    assert any(action and "blocked" in action for action in actions)
    assert audit.verify_integrity()


def test_m1_untracked_trusted_file_default_blocks_and_preserve_policy_excludes_it(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    (trusted / "local_notes.txt").write_text("local only\\n", encoding="utf-8")

    blocked = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command("print('should not run')"),
        )
    )

    assert blocked.status == GuardedRunStatus.BLOCKED
    assert blocked.workspace_path is None

    preserved = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command("from pathlib import Path; Path('agent.txt').write_text('ok')"),
            preserve_workspace=True,
            untracked_policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
        )
    )

    workspace = Path(preserved.workspace_path)

    assert preserved.status == GuardedRunStatus.COMPLETED
    assert workspace.exists()
    assert (workspace / "agent.txt").exists()
    assert not (workspace / "local_notes.txt").exists()
    assert (trusted / "local_notes.txt").exists()


def test_m1_cleanup_default_removes_workspace_and_preserve_keeps_only_when_explicit(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    cleaned = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command("from pathlib import Path; Path('cleaned.txt').write_text('x')"),
        )
    )

    assert cleaned.status == GuardedRunStatus.COMPLETED
    assert cleaned.cleanup_performed is True
    assert cleaned.workspace_path is not None
    assert not Path(cleaned.workspace_path).exists()
    assert not (trusted / "cleaned.txt").exists()

    preserved = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command("from pathlib import Path; Path('preserved.txt').write_text('x')"),
            preserve_workspace=True,
        )
    )

    assert preserved.status == GuardedRunStatus.COMPLETED
    assert preserved.cleanup_performed is False
    assert preserved.workspace_path is not None
    assert Path(preserved.workspace_path).exists()
    assert (Path(preserved.workspace_path) / "preserved.txt").exists()
    assert not (trusted / "preserved.txt").exists()
    assert_repo_clean(trusted)


def test_m1_audit_lifecycle_and_redaction_for_successful_run(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(audit_path)

    stdout_secret = "STDOUT_SECRET_SHOULD_NOT_LEAK"
    stderr_secret = "STDERR_SECRET_SHOULD_NOT_LEAK"
    patch_secret = "PATCH_SECRET_SHOULD_NOT_LEAK"

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; import sys; "
                f"print({stdout_secret!r}); "
                f"print({stderr_secret!r}, file=sys.stderr); "
                f"Path('secret_output.txt').write_text({patch_secret!r})"
            ),
            audit_logger=audit,
        )
    )

    actions = audit_actions(audit)
    text = audit_text(audit_path)

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.patch_diff is not None
    assert patch_secret in result.patch_diff.patch

    expected_actions = [
        "guarded_run.requested",
        "guarded_run.backend_selected",
        "guarded_run.workspace_created",
        "guarded_run.command_started",
        "guarded_run.command_completed",
        "guarded_run.changed_files_detected",
        "guarded_run.patch_generated",
        "guarded_run.cleanup_started",
        "guarded_run.cleanup_completed",
    ]

    for action in expected_actions:
        assert action in actions

    assert "diff --git" not in text
    assert stdout_secret not in text
    assert stderr_secret not in text
    assert patch_secret not in text
    assert audit.verify_integrity()


def test_m1_cli_to_runner_smoke_uses_real_temp_repo(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_cli(
        "run",
        "--unsafe-local",
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        "from pathlib import Path; Path('cli_smoke.txt').write_text('hello\\n')",
        cwd=trusted,
    )

    assert result.returncode == 0
    assert "Status: completed" in result.stdout
    assert "cli_smoke.txt" in result.stdout
    assert "Patch SHA-256:" in result.stdout
    assert "Unsafe local execution is not a containment backend" in result.stdout
    assert not (trusted / "cli_smoke.txt").exists()
    assert_repo_clean(trusted)


def test_m1_cli_json_smoke_excludes_raw_patch_and_streams(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    stdout_secret = "CLI_JSON_STDOUT_SECRET"
    stderr_secret = "CLI_JSON_STDERR_SECRET"
    patch_secret = "CLI_JSON_PATCH_SECRET"

    result = run_cli(
        "run",
        "--unsafe-local",
        "--json",
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        (
            "from pathlib import Path; import sys; "
            f"print({stdout_secret!r}); "
            f"print({stderr_secret!r}, file=sys.stderr); "
            f"Path('json_secret.txt').write_text({patch_secret!r})"
        ),
        cwd=trusted,
    )

    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["status"] == "completed"
    assert payload["changes"]["changed_paths"] == ["json_secret.txt"]
    assert payload["patch"]["generated"] is True
    assert payload["patch"]["sha256"]
    assert stdout_secret not in result.stdout
    assert stderr_secret not in result.stdout
    assert patch_secret not in result.stdout
    assert "diff --git" not in result.stdout
    assert_repo_clean(trusted)
