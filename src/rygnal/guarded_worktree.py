"""Temporary Git worktree management for guarded agent execution.

This module establishes the isolated baseline workspace for an agent run.
It explicitly decouples workspace creation from lifecycle cleanup. The
workspace is anchored to a deterministic UUID run root and must outlive
the execution context so that downstream validators, diff generators,
and audit systems can inspect it.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import uuid
from dataclasses import dataclass
from pathlib import Path

from rygnal.audit_logger import AuditLogger
from rygnal.untracked_files import (
    UntrackedFilePolicy,
    UntrackedFilesError,
    verify_untracked_files_handled,
)


class GuardedWorktreeError(Exception):
    """Raised when guarded worktree creation or validation fails."""


@dataclass(frozen=True)
class GuardedWorktreeConfig:
    """Configuration for creating a guarded worktree."""

    trusted_repo_path: Path
    rygnal_run_root: Path = Path("/tmp/rygnal-runs")  # nosec B108
    untracked_policy: UntrackedFilePolicy = UntrackedFilePolicy.BLOCK
    audit_logger: AuditLogger | None = None


@dataclass(frozen=True)
class GuardedWorktree:
    """Immutable metadata representing a successfully created guarded worktree."""

    run_id: str
    trusted_repo_path: Path
    workspace_path: Path
    baseline_commit_sha: str


def _run_git(args: list[str], cwd: Path) -> str:
    """Execute a git command securely, preventing host environment leakage."""
    env = os.environ.copy()
    # Strip variables that can corrupt worktree generation or leak host state
    env.pop("GIT_WORK_TREE", None)
    env.pop("GIT_DIR", None)

    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() or e.stdout.strip()
        raise GuardedWorktreeError(f"Git operation failed: {error_msg}") from e


def detect_trusted_repo_root(cwd: Path | str) -> Path:
    """Detect the absolute root of the trusted Git repository."""
    target = Path(cwd).resolve()
    try:
        root_str = _run_git(["rev-parse", "--show-toplevel"], cwd=target)
        return Path(root_str).resolve()
    except GuardedWorktreeError as e:
        raise GuardedWorktreeError(f"Directory is not a valid Git repository: {target}") from e


def create_guarded_worktree(config: GuardedWorktreeConfig) -> GuardedWorktree:
    """Create an isolated, ephemeral Git worktree for execution.

    Fails closed on bare repositories. Enforces strict 0o700 directory
    permissions and guarantees the workspace is physically outside the
    trusted repository.
    """
    repo_root = config.trusted_repo_path.resolve()

    if not repo_root.is_dir():
        raise GuardedWorktreeError(f"Trusted repository path does not exist: {repo_root}")

    # Let Git natively determine if this is a valid repository (bare or normal)
    try:
        is_bare = _run_git(["rev-parse", "--is-bare-repository"], cwd=repo_root)
    except GuardedWorktreeError as e:
        raise GuardedWorktreeError(
            f"Trusted repository not found or invalid at: {repo_root}"
        ) from e

    if is_bare == "true":
        raise GuardedWorktreeError("Bare repositories are not supported for guarded execution.")

    try:
        verify_untracked_files_handled(
            repo_root,
            policy=config.untracked_policy,
            logger=config.audit_logger,
        )
    except UntrackedFilesError as exc:
        raise GuardedWorktreeError(str(exc)) from exc

    baseline_sha = _run_git(["rev-parse", "HEAD"], cwd=repo_root)
    if len(baseline_sha) != 40:
        raise GuardedWorktreeError(f"Failed to capture valid baseline commit SHA: {baseline_sha}")

    run_id = str(uuid.uuid4())
    run_dir = config.rygnal_run_root.resolve() / run_id
    workspace_path = run_dir / "worktree"

    if workspace_path.is_relative_to(repo_root):
        raise GuardedWorktreeError(
            f"Workspace path ({workspace_path}) must not be inside trusted repo ({repo_root})."
        )

    # Enforce strict permissions on the run boundary
    run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)

    try:
        _run_git(["worktree", "add", str(workspace_path), "HEAD"], cwd=repo_root)
    except GuardedWorktreeError:
        # Roll back the physical directory if Git metadata fails to initialize
        shutil.rmtree(run_dir, ignore_errors=True)
        raise

    return GuardedWorktree(
        run_id=run_id,
        trusted_repo_path=repo_root,
        workspace_path=workspace_path,
        baseline_commit_sha=baseline_sha,
    )


def run_unsafe_local_for_testing(
    worktree: GuardedWorktree, cmd: list[str]
) -> subprocess.CompletedProcess[str]:
    """Execute a command directly in the guarded worktree.

    SECURITY WARNING: This is a testing/demo stub to satisfy M1 isolation proofs.
    It does NOT apply process-tree containment or Bubblewrap namespace isolation.
    """
    return subprocess.run(  # nosec B603 B607
        cmd,
        cwd=worktree.workspace_path,
        capture_output=True,
        text=True,
        check=True,
    )
