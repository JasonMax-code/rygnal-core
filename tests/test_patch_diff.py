import hashlib
import subprocess
from pathlib import Path

import pytest

from rygnal.changed_files import ChangedFileKind
from rygnal.patch_diff import (
    PatchDiffGenerationError,
    generate_patch_diff,
    parse_git_numstat,
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


def file_by_path(patch, path: str):
    return next(file for file in patch.files if file.path == path)


def test_generates_reviewable_patch_for_tracked_and_untracked_changes(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "tracked.txt").write_text("after\n", encoding="utf-8")
    (repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)

    assert "diff --git a/tracked.txt b/tracked.txt" in patch.patch
    assert "diff --git a/untracked.txt b/untracked.txt" in patch.patch
    assert "--- /dev/null" in patch.patch
    assert "+++ b/untracked.txt" in patch.patch

    tracked = file_by_path(patch, "tracked.txt")
    untracked = file_by_path(patch, "untracked.txt")

    assert tracked.kind == ChangedFileKind.MODIFIED
    assert tracked.additions == 1
    assert tracked.deletions == 1

    assert untracked.kind == ChangedFileKind.UNTRACKED
    assert untracked.additions == 1
    assert untracked.deletions == 0


def test_preserves_rename_metadata_and_stats(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    run_git(repo, "mv", "old_name.txt", "new_name.txt")
    (repo / "new_name.txt").write_text("rename\nafter\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)

    renamed = file_by_path(patch, "new_name.txt")

    assert renamed.kind == ChangedFileKind.RENAMED
    assert renamed.old_path == "old_name.txt"
    assert renamed.additions == 1
    assert renamed.deletions == 0
    assert "rename from old_name.txt" in patch.patch
    assert "rename to new_name.txt" in patch.patch


def test_preserves_mode_change_metadata(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "script.sh").chmod(0o755)

    patch = generate_patch_diff(repo, baseline)

    script = file_by_path(patch, "script.sh")

    assert script.path == "script.sh"
    assert script.mode_changed is True
    assert script.old_mode == "100644"
    assert script.new_mode == "100755"
    assert "old mode 100644" in patch.patch
    assert "new mode 100755" in patch.patch


def test_ignored_generated_untracked_files_are_not_in_patch(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    generated_path = repo / "node_modules" / "left-pad" / "index.js"
    generated_path.parent.mkdir(parents=True)
    generated_path.write_text("module.exports = 1\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)

    assert patch.patch == ""
    assert patch.files == ()
    assert patch.ignored_file_count == 1
    assert patch.ignored_files[0].path == "node_modules/left-pad/index.js"


def test_audit_summary_does_not_include_raw_patch_content(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "untracked.txt").write_text("secret-looking text\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)

    assert "secret-looking text" in patch.patch
    assert "secret-looking text" not in str(patch.audit_summary)
    assert patch.audit_summary["patch_sha256"] == patch.patch_sha256
    assert patch.audit_summary["changed_file_count"] == 1


def test_patch_hash_and_size_match_raw_patch_bytes(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "tracked.txt").write_text("after\n", encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)
    patch_bytes = patch.patch.encode("utf-8", errors="surrogateescape")

    assert patch.patch_sha256 == hashlib.sha256(patch_bytes).hexdigest()
    assert patch.patch_size_bytes == len(patch_bytes)


def test_temporary_index_does_not_stage_untracked_files(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    baseline = run_git(repo, "rev-parse", "HEAD")

    (repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")

    generate_patch_diff(repo, baseline)

    status = run_git(repo, "status", "--short")

    assert "?? untracked.txt" in status


def test_parse_numstat_handles_nul_terminated_rename_records() -> None:
    raw = b"1\t2\t\x00old name.txt\x00new name.txt\x00"

    stats = parse_git_numstat(raw)

    assert stats["new name.txt"].additions == 1
    assert stats["new name.txt"].deletions == 2
    assert stats["new name.txt"].binary is False


def test_parse_numstat_marks_binary_files() -> None:
    raw = b"-\t-\tbinary.bin\x00"

    stats = parse_git_numstat(raw)

    assert stats["binary.bin"].additions is None
    assert stats["binary.bin"].deletions is None
    assert stats["binary.bin"].binary is True


def test_invalid_baseline_sha_fails_closed(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)

    with pytest.raises(PatchDiffGenerationError):
        generate_patch_diff(repo, "HEAD")


def test_preserves_heavily_rewritten_rename_with_lower_similarity_threshold(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    run_git(repo, "init")
    run_git(repo, "config", "user.email", "test@example.com")
    run_git(repo, "config", "user.name", "Test User")
    run_git(repo, "config", "core.filemode", "true")

    old_lines = [f"stable line {index}\n" for index in range(100)]
    (repo / "legacy_module.py").write_text("".join(old_lines), encoding="utf-8")

    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "baseline")
    baseline = run_git(repo, "rev-parse", "HEAD")

    run_git(repo, "mv", "legacy_module.py", "modern_module.py")

    rewritten_lines = [
        *(f"stable line {index}\n" for index in range(30)),
        *(f"new behavior {index}\n" for index in range(70)),
    ]
    (repo / "modern_module.py").write_text("".join(rewritten_lines), encoding="utf-8")

    patch = generate_patch_diff(repo, baseline)

    renamed = file_by_path(patch, "modern_module.py")

    assert renamed.kind == ChangedFileKind.RENAMED
    assert renamed.old_path == "legacy_module.py"
    assert "rename from legacy_module.py" in patch.patch
    assert "rename to modern_module.py" in patch.patch
