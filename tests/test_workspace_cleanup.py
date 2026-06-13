import subprocess
from pathlib import Path

import pytest

from rygnal.guarded_worktree import GuardedWorktree, GuardedWorktreeConfig, create_guarded_worktree
from rygnal.workspace_cleanup import (
    CleanupStatus,
    GuardedWorkspaceCleanupError,
    _verify_deletion_guards,
    destroy_worktree,
    reset_worktree,
)
from rygnal.workspace_cleanup import (
    _run_git as real_run_git,
)


@pytest.fixture
def mock_repo_and_worktree(tmp_path: Path) -> tuple[GuardedWorktreeConfig, GuardedWorktree]:
    repo_dir = tmp_path / "trusted_repo"
    repo_dir.mkdir()

    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@rygnal.local"], cwd=repo_dir, check=True)

    (repo_dir / "base.txt").write_text("baseline")
    subprocess.run(["git", "add", "base.txt"], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True)

    config = GuardedWorktreeConfig(
        trusted_repo_path=repo_dir,
        rygnal_run_root=tmp_path / "runs",
    )
    worktree = create_guarded_worktree(config)

    return config, worktree


def test_deletion_guards_reject_dangerous_paths(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    run_root = tmp_path / "runs"

    # 1. Identity
    with pytest.raises(GuardedWorkspaceCleanupError, match="identical to trusted repo"):
        _verify_deletion_guards(trusted, trusted, run_root)

    # 2. Nested workspace
    nested_ws = trusted / "worktree"
    with pytest.raises(GuardedWorkspaceCleanupError, match="nested inside the trusted repo"):
        _verify_deletion_guards(trusted, nested_ws, run_root)

    # 3. Ancestor workspace
    ancestor_ws = tmp_path
    with pytest.raises(GuardedWorkspaceCleanupError, match="ancestor of the trusted repo"):
        _verify_deletion_guards(trusted, ancestor_ws, run_root)

    # 4. Outside run root
    outside_ws = tmp_path / "rogue_dir" / "worktree"
    with pytest.raises(
        GuardedWorkspaceCleanupError, match="outside the configured Rygnal run root"
    ):
        _verify_deletion_guards(trusted, outside_ws, run_root)


def test_reset_worktree_restores_baseline_and_cleans_untracked(mock_repo_and_worktree) -> None:
    config, worktree = mock_repo_and_worktree
    ws_path = worktree.workspace_path

    # Simulate agent mutating tracked file and adding an untracked artifact
    (ws_path / "base.txt").write_text("hacked")
    (ws_path / "malicious.js").write_text("console.log('pwned');")

    result = reset_worktree(worktree, config)

    assert result.status == CleanupStatus.RESET_SUCCESS
    assert (ws_path / "base.txt").read_text() == "baseline"
    assert not (ws_path / "malicious.js").exists()


def test_destroy_worktree_uses_git_removal_by_default(mock_repo_and_worktree) -> None:
    config, worktree = mock_repo_and_worktree

    result = destroy_worktree(worktree, config)

    assert result.status == CleanupStatus.CLEANED_GIT
    assert not worktree.workspace_path.exists()

    # Verify the host git metadata was actually cleaned
    worktrees = subprocess.run(
        ["git", "worktree", "list"], cwd=config.trusted_repo_path, capture_output=True, text=True
    ).stdout
    assert str(worktree.workspace_path) not in worktrees


def test_destroy_worktree_falls_back_to_rmtree_and_prune(
    mock_repo_and_worktree, monkeypatch
) -> None:
    config, worktree = mock_repo_and_worktree

    # Force the git worktree remove command to fail to trigger the fallback
    def mock_run_git(args: list[str], cwd: Path):
        if args[0] == "worktree" and args[1] == "remove":
            raise GuardedWorkspaceCleanupError("Mocked git lock failure")
        return real_run_git(args, cwd)

    monkeypatch.setattr("rygnal.workspace_cleanup._run_git", mock_run_git)

    result = destroy_worktree(worktree, config)

    assert result.status == CleanupStatus.CLEANED_FALLBACK
    assert result.prune_attempted is True
    assert "Mocked git lock failure" in result.message
    assert not worktree.workspace_path.exists()
