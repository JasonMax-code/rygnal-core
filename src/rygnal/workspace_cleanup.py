"""Guarded workspace cleanup and lifecycle management.

This module enforces safe teardown and reset capabilities for ephemeral Git
worktrees. It explicitly separates filesystem lifecycle from process-tree
containment (#239) and implements strict 4-way path guards to guarantee
the host repository is never inadvertently corrupted or deleted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

# Importing models established in #127
from rygnal.guarded_worktree import GuardedWorktree, GuardedWorktreeConfig


class GuardedWorkspaceCleanupError(Exception):
    """Raised when a cleanup operation violates security boundaries or fails."""


class CleanupStatus(StrEnum):
    CLEANED_GIT = "cleaned_git"
    CLEANED_FALLBACK = "cleaned_fallback"
    RESET_SUCCESS = "reset_success"
    CLEANUP_FAILED = "cleanup_failed"


@dataclass(frozen=True)
class CleanupResult:
    """Auditable outcome of a cleanup or reset operation."""

    status: CleanupStatus
    message: str
    prune_attempted: bool = False


def _verify_deletion_guards(trusted_repo: Path, workspace: Path, run_root: Path) -> None:
    """Enforce strict path boundaries to prevent host repository deletion."""
    trusted = trusted_repo.resolve()
    ws = workspace.resolve()
    root = run_root.resolve()

    if ws == trusted:
        raise GuardedWorkspaceCleanupError("Workspace path is identical to trusted repo path.")

    if trusted in ws.parents:
        raise GuardedWorkspaceCleanupError("Workspace is nested inside the trusted repo.")

    if ws in trusted.parents:
        raise GuardedWorkspaceCleanupError("Workspace is an ancestor of the trusted repo.")

    if root not in ws.parents and ws != root:
        raise GuardedWorkspaceCleanupError("Workspace is outside the configured Rygnal run root.")


def _run_git(args: list[str], cwd: Path) -> str:
    """Execute a git command securely without host environment leakage."""
    env = os.environ.copy()
    env.pop("GIT_WORK_TREE", None)
    env.pop("GIT_DIR", None)

    try:
        result = subprocess.run(
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
        raise GuardedWorkspaceCleanupError(f"Git operation failed: {error_msg}") from e


def reset_worktree(worktree: GuardedWorktree, config: GuardedWorktreeConfig) -> CleanupResult:
    """Reset the worktree to the exact baseline commit, destroying agent changes."""
    _verify_deletion_guards(
        trusted_repo=config.trusted_repo_path,
        workspace=worktree.workspace_path,
        run_root=config.rygnal_run_root,
    )

    try:
        # Reset tracked files to the immutable baseline SHA
        # (not HEAD, which the agent may have moved)
        _run_git(["reset", "--hard", worktree.baseline_commit_sha], cwd=worktree.workspace_path)
        # Destroy all untracked files and artifacts (double -f for nested git dirs)
        _run_git(["clean", "-ffdx"], cwd=worktree.workspace_path)

        return CleanupResult(
            status=CleanupStatus.RESET_SUCCESS,
            message=f"Worktree successfully reset to {worktree.baseline_commit_sha}.",
        )
    except GuardedWorkspaceCleanupError as e:
        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message=f"Failed to reset worktree: {e}",
        )


def destroy_worktree(worktree: GuardedWorktree, config: GuardedWorktreeConfig) -> CleanupResult:
    """Physically destroy the worktree, preferring Git-aware removal to prevent metadata rot."""
    _verify_deletion_guards(
        trusted_repo=config.trusted_repo_path,
        workspace=worktree.workspace_path,
        run_root=config.rygnal_run_root,
    )

    ws_path_str = str(worktree.workspace_path)

    # Primary Strategy: Git-aware removal
    try:
        _run_git(["worktree", "remove", "--force", ws_path_str], cwd=config.trusted_repo_path)
        return CleanupResult(
            status=CleanupStatus.CLEANED_GIT,
            message="Worktree destroyed via git metadata removal.",
        )
    except GuardedWorkspaceCleanupError as git_err:
        # Fallback Strategy: Physical deletion + Prune
        fallback_msg = str(git_err)

    try:
        shutil.rmtree(worktree.workspace_path, ignore_errors=True)
        # If the parent run_id UUID directory is now empty, remove it too
        run_dir = worktree.workspace_path.parent
        if run_dir.exists() and not any(run_dir.iterdir()):
            run_dir.rmdir()

        # Force git to clean up the dangling metadata pointer
        _run_git(["worktree", "prune"], cwd=config.trusted_repo_path)

        return CleanupResult(
            status=CleanupStatus.CLEANED_FALLBACK,
            message=(
                f"Degraded cleanup: Git removal failed ({fallback_msg}). Rmtree + Prune executed."
            ),
            prune_attempted=True,
        )
    except Exception as e:
        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message=f"Critical cleanup failure: {e}",
            prune_attempted=True,  # We may have failed the physical delete but attempted the prune
        )
