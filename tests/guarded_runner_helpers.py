import subprocess
import sys
from pathlib import Path

from rygnal.audit_logger import AuditLogger
from rygnal.guarded_runner import GuardedRunConfig
from rygnal.untracked_files import UntrackedFilePolicy


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def create_trusted_repo(path: Path) -> Path:
    path.mkdir()

    run_git(path, "init")
    run_git(path, "config", "user.email", "test@example.com")
    run_git(path, "config", "user.name", "Test User")

    (path / "docs").mkdir()
    (path / "src").mkdir()
    (path / ".github" / "workflows").mkdir(parents=True)

    (path / "README.md").write_text("# Rygnal test repo\n", encoding="utf-8")
    (path / "docs" / "usage.md").write_text("before docs\n", encoding="utf-8")
    (path / "src" / "app.py").write_text("print('before')\n", encoding="utf-8")
    (path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (path / ".gitignore").write_text("__pycache__/\nnode_modules/\n", encoding="utf-8")
    (path / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\n",
        encoding="utf-8",
    )

    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def commit_all(repo: Path, message: str = "commit") -> str:
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", message)
    return head_sha(repo)


def git_status_porcelain(repo: Path) -> str:
    return run_git(repo, "status", "--porcelain", "--untracked-files=all")


def head_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def py_command(code: str) -> tuple[str, ...]:
    return (sys.executable, "-c", code)


def unsafe_runner_config(
    repo: Path,
    command: tuple[str, ...],
    *,
    audit_logger: AuditLogger | None = None,
    preserve_workspace: bool = False,
    timeout_seconds: int = 5,
    allow_dirty_override: bool = False,
    untracked_policy: UntrackedFilePolicy = UntrackedFilePolicy.BLOCK,
) -> GuardedRunConfig:
    return GuardedRunConfig(
        trusted_repo_path=repo,
        command=command,
        timeout_seconds=timeout_seconds,
        rygnal_run_root=repo.parent / "rygnal-runs",
        allow_dirty_override=allow_dirty_override,
        untracked_policy=untracked_policy,
        preserve_workspace=preserve_workspace,
        unsafe_local_requested=True,
        trace_id="trace_integration",
        audit_logger=audit_logger,
    )


def audit_text(audit_path: Path) -> str:
    return audit_path.read_text(encoding="utf-8")


def audit_actions(audit_logger: AuditLogger) -> list[str | None]:
    return [event.action for event in audit_logger.read_events()]
