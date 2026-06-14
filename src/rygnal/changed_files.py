"""Deterministic changed-file inventory for guarded Git worktrees.

This module detects what changed inside a guarded worktree after an agent run.
It does not read file contents, generate patches, classify risk, or apply
changes back to the trusted repository.
"""

from __future__ import annotations

import re
import subprocess  # nosec B404
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from pathlib import Path, PurePosixPath

BASELINE_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class ChangedFileDetectionError(RuntimeError):
    """Raised when changed-file detection cannot complete safely."""


class ChangedFilePathError(ChangedFileDetectionError):
    """Raised when Git reports an unsafe repo-relative path."""


class ChangedFileKind(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    MODE_CHANGED = "mode_changed"
    UNTRACKED = "untracked"


class IgnoredFileReason(StrEnum):
    GENERATED_OR_HEAVY_PATH = "generated_or_heavy_path"


@dataclass(frozen=True)
class ChangedFile:
    """A deterministic changed-file record produced from the guarded worktree."""

    path: str
    kind: ChangedFileKind
    old_path: str | None = None
    old_mode: str | None = None
    new_mode: str | None = None
    mode_changed: bool = False


@dataclass(frozen=True)
class IgnoredChangedFile:
    """A changed path intentionally ignored with an audit-safe reason."""

    path: str
    reason: IgnoredFileReason


@dataclass(frozen=True)
class ChangedFileReport:
    """Audit-safe changed-file inventory for a guarded worktree."""

    workspace_path: str
    baseline_commit_sha: str
    files: tuple[ChangedFile, ...] = ()
    ignored_files: tuple[IgnoredChangedFile, ...] = ()

    @cached_property
    def changed_file_count(self) -> int:
        return len(self.files)

    @cached_property
    def ignored_file_count(self) -> int:
        return len(self.ignored_files)

    @cached_property
    def counts_by_kind(self) -> dict[ChangedFileKind, int]:
        counts = dict.fromkeys(ChangedFileKind, 0)
        for changed_file in self.files:
            counts[changed_file.kind] += 1
        return counts

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "workspace_path": self.workspace_path,
            "baseline_commit_sha": self.baseline_commit_sha,
            "changed_file_count": self.changed_file_count,
            "ignored_file_count": self.ignored_file_count,
            "counts_by_kind": {kind.value: count for kind, count in self.counts_by_kind.items()},
            "paths": tuple(changed_file.path for changed_file in self.files),
            "ignored_paths": tuple(ignored_file.path for ignored_file in self.ignored_files),
        }


DEFAULT_GENERATED_PATH_SEGMENTS = frozenset(
    {
        ".coverage",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "target",
        "venv",
    }
)


def detect_changed_files(
    workspace_path: str | Path,
    baseline_commit_sha: str,
    *,
    generated_path_segments: Iterable[str] = DEFAULT_GENERATED_PATH_SEGMENTS,
) -> ChangedFileReport:
    """Detect changed files inside a guarded worktree.

    The baseline must be an immutable commit SHA from guarded worktree creation.
    The detector compares the worktree against that SHA instead of trusting
    the current branch or HEAD.
    """

    baseline = normalize_baseline_commit_sha(baseline_commit_sha)
    workspace = Path(workspace_path).resolve()

    if not workspace.exists() or not workspace.is_dir():
        raise ChangedFileDetectionError(f"Guarded workspace does not exist: {workspace}")

    raw_diff = _run_git(
        ["diff", "--raw", "-z", "-M", baseline, "--"],
        cwd=workspace,
    )
    untracked_output = _run_git(
        ["ls-files", "--others", "--exclude-standard", "-z"],
        cwd=workspace,
    )

    tracked_files = parse_git_raw_diff(raw_diff)
    untracked_files, ignored_files = _classify_untracked_files(
        untracked_output,
        generated_path_segments=generated_path_segments,
    )

    files = tuple(sorted((*tracked_files, *untracked_files), key=_changed_file_sort_key))
    ignored = tuple(sorted(ignored_files, key=lambda item: item.path))

    return ChangedFileReport(
        workspace_path=workspace.as_posix(),
        baseline_commit_sha=baseline,
        files=files,
        ignored_files=ignored,
    )


def parse_git_raw_diff(raw_output: bytes) -> tuple[ChangedFile, ...]:
    """Parse `git diff --raw -z -M` output."""

    if not raw_output:
        return ()

    fields = [field for field in raw_output.split(b"\0") if field]
    changed_files: list[ChangedFile] = []
    index = 0

    while index < len(fields):
        header = _decode_git_field(fields[index])
        index += 1

        if not header.startswith(":"):
            raise ChangedFileDetectionError(f"Invalid raw diff header: {header!r}")

        parts = header.split()
        if len(parts) < 5:
            raise ChangedFileDetectionError(f"Incomplete raw diff header: {header!r}")

        old_mode = parts[0][1:]
        new_mode = parts[1]
        old_object = parts[2]
        new_object = parts[3]
        status = parts[4]
        status_code = status[0]
        mode_changed = old_mode != new_mode

        if status_code == "R":
            if index + 1 >= len(fields):
                raise ChangedFileDetectionError("Rename record missing path fields.")
            old_path = normalize_repo_relative_path(_decode_git_field(fields[index]))
            new_path = normalize_repo_relative_path(_decode_git_field(fields[index + 1]))
            index += 2
            changed_files.append(
                ChangedFile(
                    path=new_path,
                    old_path=old_path,
                    kind=ChangedFileKind.RENAMED,
                    old_mode=old_mode,
                    new_mode=new_mode,
                    mode_changed=mode_changed,
                )
            )
            continue

        if index >= len(fields):
            raise ChangedFileDetectionError("Raw diff record missing path field.")

        path = normalize_repo_relative_path(_decode_git_field(fields[index]))
        index += 1

        changed_files.append(
            ChangedFile(
                path=path,
                kind=_kind_from_raw_status(
                    status_code=status_code,
                    old_mode=old_mode,
                    new_mode=new_mode,
                    old_object=old_object,
                    new_object=new_object,
                ),
                old_mode=old_mode,
                new_mode=new_mode,
                mode_changed=mode_changed,
            )
        )

    return tuple(changed_files)


def normalize_baseline_commit_sha(baseline_commit_sha: str) -> str:
    baseline = baseline_commit_sha.strip()
    if not BASELINE_SHA_PATTERN.fullmatch(baseline):
        raise ChangedFileDetectionError("Baseline commit must be a full 40-character SHA.")
    return baseline.lower()


def normalize_repo_relative_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    path_obj = PurePosixPath(normalized)

    if not normalized:
        raise ChangedFilePathError("Changed file path must not be empty.")
    if path_obj.is_absolute():
        raise ChangedFilePathError(f"Changed file path must be relative: {path}")
    if any(part == ".." for part in path_obj.parts):
        raise ChangedFilePathError(f"Changed file path must not traverse: {path}")

    clean_parts = tuple(part for part in path_obj.parts if part not in {"", "."})
    if not clean_parts:
        raise ChangedFilePathError("Changed file path must not be empty.")

    return PurePosixPath(*clean_parts).as_posix()


def is_generated_or_heavy_path(
    path: str,
    *,
    generated_path_segments: Iterable[str] = DEFAULT_GENERATED_PATH_SEGMENTS,
) -> bool:
    normalized = normalize_repo_relative_path(path)
    ignored_segments = {segment.lower() for segment in generated_path_segments}
    return any(part.lower() in ignored_segments for part in PurePosixPath(normalized).parts)


def _classify_untracked_files(
    raw_output: bytes,
    *,
    generated_path_segments: Iterable[str],
) -> tuple[tuple[ChangedFile, ...], tuple[IgnoredChangedFile, ...]]:
    if not raw_output:
        return (), ()

    changed_files: list[ChangedFile] = []
    ignored_files: list[IgnoredChangedFile] = []

    for field in raw_output.split(b"\0"):
        if not field:
            continue

        path = normalize_repo_relative_path(_decode_git_field(field))

        if is_generated_or_heavy_path(
            path,
            generated_path_segments=generated_path_segments,
        ):
            ignored_files.append(
                IgnoredChangedFile(
                    path=path,
                    reason=IgnoredFileReason.GENERATED_OR_HEAVY_PATH,
                )
            )
            continue

        changed_files.append(ChangedFile(path=path, kind=ChangedFileKind.UNTRACKED))

    return tuple(changed_files), tuple(ignored_files)


def _kind_from_raw_status(
    *,
    status_code: str,
    old_mode: str,
    new_mode: str,
    old_object: str,
    new_object: str,
) -> ChangedFileKind:
    if status_code == "A":
        return ChangedFileKind.ADDED
    if status_code == "D":
        return ChangedFileKind.DELETED
    if status_code == "T":
        return ChangedFileKind.MODE_CHANGED
    if status_code == "M":
        return ChangedFileKind.MODIFIED

    raise ChangedFileDetectionError(f"Unsupported Git raw status: {status_code}")


def _decode_git_field(field: bytes) -> str:
    return field.decode("utf-8", errors="surrogateescape")


def _run_git(args: list[str], *, cwd: Path) -> bytes:
    try:
        result = subprocess.run(  # nosec B603, B607
            ["git", *args],
            cwd=cwd,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace").strip()
        raise ChangedFileDetectionError(
            f"Git command failed: git {' '.join(args)}: {stderr}"
        ) from exc

    return result.stdout


def _changed_file_sort_key(changed_file: ChangedFile) -> tuple[str, str, str]:
    return (
        changed_file.path,
        changed_file.kind.value,
        changed_file.old_path or "",
    )
