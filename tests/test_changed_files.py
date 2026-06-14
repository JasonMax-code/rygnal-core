import subprocess
from pathlib import Path

import pytest

from rygnal.changed_files import (
    ChangedFileDetectionError,
    ChangedFileKind,
    ChangedFilePathError,
    IgnoredFileReason,
    detect_changed_files,
    is_generated_or_heavy_path,
    normalize_repo_relative_path,
    parse_git_raw_diff,
)


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
    run_git(repo, "config", "core.filemode", "true")

    (repo / "tracked.txt").write_text("before\n", encoding="utf-8")
    (repo / "delete_me.txt").write_text("delete\n", encoding="utf-8")
    (repo / "old_name.txt").write_text("rename\n", encoding="utf-8")
    (repo / "script.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "baseline")

    return repo


def test_detects_tracked_and_untracked_changes(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "tracked.txt").write_text("after\n", encoding="utf-8")
    (repo / "new_added.txt").write_text("added\n", encoding="utf-8")
    run_git(repo, "add", "new_added.txt")
    (repo / "delete_me.txt").unlink()
    run_git(repo, "mv", "old_name.txt", "new_name.txt")
    (repo / "script.sh").chmod(0o755)
    (repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    by_kind = {changed_file.kind for changed_file in report.files}
    paths = {changed_file.path for changed_file in report.files}

    assert ChangedFileKind.MODIFIED in by_kind
    assert ChangedFileKind.ADDED in by_kind
    assert ChangedFileKind.DELETED in by_kind
    assert ChangedFileKind.RENAMED in by_kind
    assert ChangedFileKind.UNTRACKED in by_kind

    assert "tracked.txt" in paths
    assert "new_added.txt" in paths
    assert "delete_me.txt" in paths
    assert "new_name.txt" in paths
    assert "script.sh" in paths
    assert "untracked.txt" in paths
    assert (
        next(
            changed_file for changed_file in report.files if changed_file.path == "script.sh"
        ).mode_changed
        is True
    )


def test_rename_preserves_old_and_new_path(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    run_git(repo, "mv", "old_name.txt", "new_name.txt")

    report = detect_changed_files(repo, baseline)
    renamed = next(
        changed_file
        for changed_file in report.files
        if changed_file.kind == ChangedFileKind.RENAMED
    )

    assert renamed.old_path == "old_name.txt"
    assert renamed.path == "new_name.txt"


def test_mode_change_sets_mode_changed_flag(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "script.sh").chmod(0o755)

    report = detect_changed_files(repo, baseline)
    mode_changed = next(
        changed_file for changed_file in report.files if changed_file.path == "script.sh"
    )

    assert mode_changed.kind == ChangedFileKind.MODIFIED
    assert mode_changed.mode_changed is True


def test_untracked_generated_files_are_ignored_with_reason(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    generated_path = repo / "node_modules" / "left-pad" / "index.js"
    generated_path.parent.mkdir(parents=True)
    generated_path.write_text("module.exports = 1\n", encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    assert report.files == ()
    assert len(report.ignored_files) == 1
    assert report.ignored_files[0].path == "node_modules/left-pad/index.js"
    assert report.ignored_files[0].reason == IgnoredFileReason.GENERATED_OR_HEAVY_PATH


def test_tracked_generated_files_are_not_silently_ignored(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    run_git(repo, "init")
    run_git(repo, "config", "user.email", "test@example.com")
    run_git(repo, "config", "user.name", "Test User")

    tracked_dist = repo / "dist" / "app.js"
    tracked_dist.parent.mkdir()
    tracked_dist.write_text("before\n", encoding="utf-8")

    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "baseline")
    baseline = run_git(repo, "rev-parse", "HEAD")

    tracked_dist.write_text("after\n", encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    assert report.ignored_files == ()
    assert report.files[0].path == "dist/app.js"
    assert report.files[0].kind == ChangedFileKind.MODIFIED


def test_parse_git_raw_diff_rejects_unsafe_paths() -> None:
    raw = b":100644 100644 abcdef1 abcdef2 M\x00../escape.py\x00"

    with pytest.raises(ChangedFilePathError):
        parse_git_raw_diff(raw)


def test_normalize_repo_relative_path_rejects_absolute_and_traversal() -> None:
    with pytest.raises(ChangedFilePathError):
        normalize_repo_relative_path("/etc/passwd")

    with pytest.raises(ChangedFilePathError):
        normalize_repo_relative_path("../secrets.env")


def test_generated_path_detection_uses_segments_not_substrings() -> None:
    assert is_generated_or_heavy_path("node_modules/pkg/index.js") is True
    assert is_generated_or_heavy_path("src/node_modules_helper.py") is False


def test_report_is_deterministically_sorted(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "z_untracked.txt").write_text("z\n", encoding="utf-8")
    (repo / "a_untracked.txt").write_text("a\n", encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    assert [changed_file.path for changed_file in report.files] == [
        "a_untracked.txt",
        "z_untracked.txt",
    ]


def test_report_contains_audit_safe_summary(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "untracked.txt").write_text("secret-looking text is not read\n", encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    assert report.audit_summary["baseline_commit_sha"] == baseline
    assert report.audit_summary["changed_file_count"] == 1
    assert report.audit_summary["paths"] == ("untracked.txt",)
    assert "secret-looking text" not in str(report.audit_summary)


def test_invalid_baseline_sha_fails_closed(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)

    with pytest.raises(ChangedFileDetectionError):
        detect_changed_files(repo, "HEAD")
