"""Reviewable patch generation for guarded Git worktrees.

This module consumes the deterministic changed-file inventory and generates a
reviewable Git patch plus audit-safe metadata. It does not classify risk,
approve changes, block changes, or apply patches back to the trusted repo.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess  # nosec B404
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cached_property, lru_cache
from pathlib import Path

from rygnal.changed_files import (
    DEFAULT_GENERATED_PATH_SEGMENTS,
    ChangedFile,
    ChangedFileDetectionError,
    ChangedFileKind,
    ChangedFileReport,
    IgnoredChangedFile,
    detect_changed_files,
    normalize_baseline_commit_sha,
    normalize_repo_relative_path,
)


class PatchDiffGenerationError(RuntimeError):
    """Raised when guarded workspace patch generation cannot complete safely."""


@dataclass(frozen=True)
class PatchFileDiff:
    """Patch metadata for one changed guarded-workspace file."""

    path: str
    kind: ChangedFileKind
    additions: int | None
    deletions: int | None
    binary: bool = False
    old_path: str | None = None
    old_mode: str | None = None
    new_mode: str | None = None
    mode_changed: bool = False

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        """Return file-level patch facts without raw patch content."""

        return {
            "path": self.path,
            "old_path": self.old_path,
            "kind": self.kind.value,
            "additions": self.additions,
            "deletions": self.deletions,
            "binary": self.binary,
            "old_mode": self.old_mode,
            "new_mode": self.new_mode,
            "mode_changed": self.mode_changed,
        }


@dataclass(frozen=True)
class PatchDiff:
    """Reviewable guarded-workspace patch plus audit-safe metadata."""

    workspace_path: str
    baseline_commit_sha: str
    patch: str
    patch_sha256: str
    patch_size_bytes: int
    files: tuple[PatchFileDiff, ...] = ()
    ignored_files: tuple[IgnoredChangedFile, ...] = ()

    @cached_property
    def changed_file_count(self) -> int:
        return len(self.files)

    @cached_property
    def ignored_file_count(self) -> int:
        return len(self.ignored_files)

    @cached_property
    def total_additions(self) -> int:
        return sum(file.additions or 0 for file in self.files)

    @cached_property
    def total_deletions(self) -> int:
        return sum(file.deletions or 0 for file in self.files)

    @cached_property
    def binary_file_count(self) -> int:
        return sum(1 for file in self.files if file.binary)

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        """Return patch-level facts without raw patch content."""

        return {
            "workspace_path": self.workspace_path,
            "baseline_commit_sha": self.baseline_commit_sha,
            "patch_sha256": self.patch_sha256,
            "patch_size_bytes": self.patch_size_bytes,
            "changed_file_count": self.changed_file_count,
            "ignored_file_count": self.ignored_file_count,
            "total_additions": self.total_additions,
            "total_deletions": self.total_deletions,
            "binary_file_count": self.binary_file_count,
            "files": tuple(file.audit_summary for file in self.files),
            "ignored_paths": tuple(file.path for file in self.ignored_files),
        }


@dataclass(frozen=True)
class _LineStats:
    additions: int | None
    deletions: int | None
    binary: bool


@dataclass(frozen=True)
class _PatchModeMetadata:
    old_mode: str | None = None
    new_mode: str | None = None
    mode_changed: bool = False


def generate_patch_diff(
    workspace_path: str | Path,
    baseline_commit_sha: str,
    *,
    generated_path_segments: Iterable[str] = DEFAULT_GENERATED_PATH_SEGMENTS,
) -> PatchDiff:
    """Generate a reviewable patch for guarded workspace changes."""

    try:
        report = detect_changed_files(
            workspace_path,
            baseline_commit_sha,
            generated_path_segments=generated_path_segments,
        )
    except ChangedFileDetectionError as exc:
        raise PatchDiffGenerationError(str(exc)) from exc

    return generate_patch_diff_from_report(report)


def generate_patch_diff_from_report(report: ChangedFileReport) -> PatchDiff:
    """Generate a reviewable patch from an existing changed-file report."""

    workspace = Path(report.workspace_path).resolve()

    if not workspace.exists() or not workspace.is_dir():
        raise PatchDiffGenerationError(f"Guarded workspace does not exist: {workspace}")

    try:
        baseline = normalize_baseline_commit_sha(report.baseline_commit_sha)
    except ChangedFileDetectionError as exc:
        raise PatchDiffGenerationError(str(exc)) from exc

    patch_bytes, numstat_bytes = _generate_diff_outputs(
        workspace=workspace,
        baseline_commit_sha=baseline,
        report=report,
    )
    stats_by_path = parse_git_numstat(numstat_bytes)
    mode_by_path = parse_git_patch_modes(patch_bytes)

    patch_files = tuple(
        _build_patch_file_diff(changed_file, stats_by_path, mode_by_path)
        for changed_file in report.files
    )
    patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()

    return PatchDiff(
        workspace_path=workspace.as_posix(),
        baseline_commit_sha=baseline,
        patch=_decode_git_output(patch_bytes),
        patch_sha256=patch_sha256,
        patch_size_bytes=len(patch_bytes),
        files=patch_files,
        ignored_files=report.ignored_files,
    )


def parse_git_numstat(raw_output: bytes) -> dict[str, _LineStats]:
    """Parse `git diff --numstat -z` output into per-path line stats."""

    if not raw_output:
        return {}

    fields = raw_output.split(b"\0")
    index = 0
    stats_by_path: dict[str, _LineStats] = {}

    while index < len(fields):
        header = fields[index]
        index += 1

        if not header:
            continue

        parts = header.split(b"\t", 2)
        if len(parts) != 3:
            raise PatchDiffGenerationError(f"Invalid numstat record: {header!r}")

        additions_raw, deletions_raw, path_raw = parts

        if path_raw == b"":
            if index + 1 >= len(fields):
                raise PatchDiffGenerationError("Rename numstat record missing paths.")
            _old_path = normalize_repo_relative_path(_decode_git_output(fields[index]))
            path = normalize_repo_relative_path(_decode_git_output(fields[index + 1]))
            index += 2
        else:
            path = normalize_repo_relative_path(_decode_git_output(path_raw))

        binary = additions_raw == b"-" or deletions_raw == b"-"
        additions = None if binary else _parse_line_count(additions_raw)
        deletions = None if binary else _parse_line_count(deletions_raw)

        stats_by_path[path] = _LineStats(
            additions=additions,
            deletions=deletions,
            binary=binary,
        )

    return stats_by_path


def parse_git_patch_modes(raw_patch: bytes) -> dict[str, _PatchModeMetadata]:
    """Parse mode metadata from Git patch headers.

    Git represents symlinks with mode 120000. This parser preserves that patch
    metadata so later safety gates can block unsafe symlink changes before any
    approval or apply step.
    """

    if not raw_patch:
        return {}

    modes_by_path: dict[str, _PatchModeMetadata] = {}
    current_path: str | None = None
    old_mode: str | None = None
    new_mode: str | None = None

    def flush_current_file() -> None:
        nonlocal current_path, old_mode, new_mode

        if current_path is None:
            return

        if old_mode is None and new_mode is None:
            return

        modes_by_path[current_path] = _PatchModeMetadata(
            old_mode=old_mode,
            new_mode=new_mode,
            mode_changed=bool(old_mode and new_mode and old_mode != new_mode),
        )

    for line in _decode_git_output(raw_patch).splitlines():
        if line.startswith("diff --git "):
            flush_current_file()
            _old_path, new_path = _parse_diff_git_paths(line)
            current_path = new_path
            old_mode = None
            new_mode = None
            continue

        if current_path is None:
            continue

        if line.startswith("new file mode "):
            new_mode = line.removeprefix("new file mode ").strip()
        elif line.startswith("deleted file mode "):
            old_mode = line.removeprefix("deleted file mode ").strip()
        elif line.startswith("old mode "):
            old_mode = line.removeprefix("old mode ").strip()
        elif line.startswith("new mode "):
            new_mode = line.removeprefix("new mode ").strip()

    flush_current_file()

    return modes_by_path


def _parse_diff_git_paths(line: str) -> tuple[str | None, str | None]:
    try:
        parts = shlex.split(line)
    except ValueError as exc:
        raise PatchDiffGenerationError(f"Invalid Git patch header: {line!r}") from exc

    if len(parts) < 4:
        raise PatchDiffGenerationError(f"Invalid Git patch header: {line!r}")

    return _strip_git_patch_prefix(parts[2]), _strip_git_patch_prefix(parts[3])


def _strip_git_patch_prefix(path: str) -> str | None:
    if path == "/dev/null":
        return None

    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]

    return normalize_repo_relative_path(path)


def _generate_diff_outputs(
    *,
    workspace: Path,
    baseline_commit_sha: str,
    report: ChangedFileReport,
) -> tuple[bytes, bytes]:
    untracked_paths = tuple(
        changed_file.path
        for changed_file in report.files
        if changed_file.kind == ChangedFileKind.UNTRACKED
    )

    if not untracked_paths:
        return (
            _run_git(_patch_args(baseline_commit_sha), cwd=workspace),
            _run_git(_numstat_args(baseline_commit_sha), cwd=workspace),
        )

    with _temporary_git_index(workspace) as env:
        _run_git(
            ["add", "--intent-to-add", "--", *untracked_paths],
            cwd=workspace,
            env=env,
        )

        return (
            _run_git(_patch_args(baseline_commit_sha), cwd=workspace, env=env),
            _run_git(_numstat_args(baseline_commit_sha), cwd=workspace, env=env),
        )


def _patch_args(baseline_commit_sha: str) -> list[str]:
    return [
        "diff",
        "--patch",
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--default-prefix",
        "--diff-algorithm=default",
        "-M",
        baseline_commit_sha,
        "--",
    ]


def _numstat_args(baseline_commit_sha: str) -> list[str]:
    return [
        "diff",
        "--numstat",
        "-z",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--diff-algorithm=default",
        "-M",
        baseline_commit_sha,
        "--",
    ]


@contextmanager
def _temporary_git_index(workspace: Path) -> Iterator[dict[str, str]]:
    index_path = _git_index_path(workspace)

    with tempfile.TemporaryDirectory(prefix="rygnal-patch-index-") as temp_dir:
        temp_index = Path(temp_dir) / "index"
        shutil.copy2(index_path, temp_index)

        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = temp_index.as_posix()

        yield env


def _git_index_path(workspace: Path) -> Path:
    raw_index_path = _run_git(["rev-parse", "--git-path", "index"], cwd=workspace)
    index_text = _decode_git_output(raw_index_path).strip()

    if not index_text:
        raise PatchDiffGenerationError("Git did not return an index path.")

    index_path = Path(index_text)
    if not index_path.is_absolute():
        index_path = workspace / index_path

    index_path = index_path.resolve()

    if not index_path.exists() or not index_path.is_file():
        raise PatchDiffGenerationError(f"Git index does not exist: {index_path}")

    return index_path


def _build_patch_file_diff(
    changed_file: ChangedFile,
    stats_by_path: dict[str, _LineStats],
    mode_by_path: dict[str, _PatchModeMetadata],
) -> PatchFileDiff:
    stats = stats_by_path.get(changed_file.path, _LineStats(0, 0, False))
    mode_metadata = mode_by_path.get(changed_file.path, _PatchModeMetadata())

    old_mode = changed_file.old_mode or mode_metadata.old_mode
    new_mode = changed_file.new_mode or mode_metadata.new_mode
    mode_changed = changed_file.mode_changed or mode_metadata.mode_changed

    if old_mode and new_mode and old_mode != new_mode:
        mode_changed = True

    return PatchFileDiff(
        path=changed_file.path,
        old_path=changed_file.old_path,
        kind=changed_file.kind,
        additions=stats.additions,
        deletions=stats.deletions,
        binary=stats.binary,
        old_mode=old_mode,
        new_mode=new_mode,
        mode_changed=mode_changed,
    )


def _parse_line_count(raw_count: bytes) -> int:
    try:
        return int(raw_count)
    except ValueError as exc:
        raise PatchDiffGenerationError(f"Invalid numstat line count: {raw_count!r}") from exc


def _run_git(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> bytes:
    result = subprocess.run(  # nosec B603
        [_git_executable(), *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        env=env,
    )

    if result.returncode != 0:
        stderr = _decode_git_output(result.stderr).strip()
        raise PatchDiffGenerationError(f"Git command failed: git {' '.join(args)}: {stderr}")

    return result.stdout


@lru_cache(maxsize=1)
def _git_executable() -> str:
    git_path = shutil.which("git")

    if git_path is None:
        raise PatchDiffGenerationError("Git executable was not found on PATH.")

    return git_path


def _decode_git_output(output: bytes) -> str:
    return output.decode("utf-8", errors="surrogateescape")


__all__ = [
    "PatchDiff",
    "PatchDiffGenerationError",
    "PatchFileDiff",
    "generate_patch_diff",
    "generate_patch_diff_from_report",
    "parse_git_numstat",
    "parse_git_patch_modes",
]
