"""Path safety checks for guarded workspace patch application."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from rygnal.audit_logger import AuditLogger
from rygnal.models import Decision, PolicyDecision, Severity, ToolRequest, new_trace_id
from rygnal.patch_diff import PatchDiff


class PathSafetyError(RuntimeError):
    def __init__(self, report: PatchPathSafetyReport) -> None:
        super().__init__("Patch path safety validation failed.")
        self.report = report


@dataclass(frozen=True)
class PathSafetyViolation:
    code: str
    path: str
    reason: str

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "code": self.code,
            "path": self.path,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class SymlinkTarget:
    path: str
    target: str

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "path": self.path,
            "target": self.target,
        }


@dataclass(frozen=True)
class PatchPathSafetyReport:
    patch_sha256: str
    baseline_commit_sha: str
    target_repo_path: str | None
    checked_paths: tuple[str, ...]
    symlink_targets: tuple[SymlinkTarget, ...] = ()
    violations: tuple[PathSafetyViolation, ...] = ()

    @cached_property
    def safe(self) -> bool:
        return not self.violations

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "safe": self.safe,
            "patch_sha256": self.patch_sha256,
            "baseline_commit_sha": self.baseline_commit_sha,
            "target_repo_path": self.target_repo_path,
            "checked_paths": self.checked_paths,
            "symlink_targets": tuple(
                symlink_target.audit_summary for symlink_target in self.symlink_targets
            ),
            "violations": tuple(violation.audit_summary for violation in self.violations),
        }


def validate_patch_path_forms(patch_diff: PatchDiff) -> PatchPathSafetyReport:
    return _validate_patch_paths(patch_diff, target_repo_path=None)


def validate_patch_paths(
    patch_diff: PatchDiff,
    target_repo_path: str | Path,
) -> PatchPathSafetyReport:
    return _validate_patch_paths(patch_diff, target_repo_path=Path(target_repo_path).resolve())


def ensure_patch_path_forms_safe(patch_diff: PatchDiff) -> PatchPathSafetyReport:
    report = validate_patch_path_forms(patch_diff)
    if not report.safe:
        raise PathSafetyError(report)

    return report


def ensure_patch_paths_safe(
    patch_diff: PatchDiff,
    target_repo_path: str | Path,
) -> PatchPathSafetyReport:
    report = validate_patch_paths(patch_diff, target_repo_path)
    if not report.safe:
        raise PathSafetyError(report)

    return report


def write_path_safety_audit_event(
    logger: AuditLogger,
    report: PatchPathSafetyReport,
    *,
    user_id: str = "demo_user",
    agent_id: str = "demo_agent",
    environment: str = "local",
    trace_id: str | None = None,
) -> Any:
    request = ToolRequest(
        tool_name="guarded_workspace",
        action="validate_patch_paths",
        target=report.patch_sha256,
        input=report.audit_summary,
        user_id=user_id,
        agent_id=agent_id,
        environment=environment,
        metadata={
            "trace_id": trace_id or new_trace_id(),
            "event_type": "guarded_workspace.path_safety",
            "patch_sha256": report.patch_sha256,
            "baseline_commit_sha": report.baseline_commit_sha,
        },
    )
    decision = PolicyDecision(
        decision=Decision.ALLOW if report.safe else Decision.BLOCK,
        allowed=report.safe,
        severity=Severity.LOW if report.safe else Severity.CRITICAL,
        reason=(
            "Patch paths are within the trusted repository boundary."
            if report.safe
            else "Patch contains unsafe paths."
        ),
        policy_id="guarded-workspace-path-safety",
    )

    return logger.log_decision(request, decision, metadata=report.audit_summary)


def _validate_patch_paths(
    patch_diff: PatchDiff,
    *,
    target_repo_path: Path | None,
) -> PatchPathSafetyReport:
    metadata_paths = _metadata_paths(patch_diff)
    patch_paths = _patch_paths_from_text(patch_diff.patch)
    symlink_targets = _symlink_targets_from_patch(patch_diff)
    all_paths = tuple(sorted(metadata_paths | patch_paths))
    violations: list[PathSafetyViolation] = []

    for path in all_paths:
        violations.extend(_path_violations(path, target_repo_path=target_repo_path))

    for symlink_target in symlink_targets:
        violations.extend(
            _symlink_target_violations(
                symlink_target,
                target_repo_path=target_repo_path,
            )
        )

    for path in sorted(patch_paths - metadata_paths):
        violations.append(
            PathSafetyViolation(
                code="patch-path-metadata-mismatch",
                path=path,
                reason="Raw patch references a path missing from patch metadata.",
            )
        )

    return PatchPathSafetyReport(
        patch_sha256=patch_diff.patch_sha256,
        baseline_commit_sha=patch_diff.baseline_commit_sha,
        target_repo_path=target_repo_path.as_posix() if target_repo_path else None,
        checked_paths=all_paths,
        symlink_targets=symlink_targets,
        violations=tuple(_dedupe_violations(violations)),
    )


def _metadata_paths(patch_diff: PatchDiff) -> set[str]:
    paths: set[str] = set()

    for file_diff in patch_diff.files:
        paths.add(file_diff.path)
        if file_diff.old_path:
            paths.add(file_diff.old_path)

    return paths


def _patch_paths_from_text(patch: str) -> set[str]:
    paths: set[str] = set()

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            paths.update(_paths_from_diff_git_header(line))
            continue

        if line.startswith("--- ") or line.startswith("+++ "):
            path = _path_from_file_header(line)
            if path is not None:
                paths.add(path)
            continue

        if line.startswith("rename from "):
            paths.add(line.removeprefix("rename from ").strip())
            continue

        if line.startswith("rename to "):
            paths.add(line.removeprefix("rename to ").strip())

    return paths


def _symlink_targets_from_patch(patch_diff: PatchDiff) -> tuple[SymlinkTarget, ...]:
    added_lines = _added_lines_by_path(patch_diff.patch)
    targets: list[SymlinkTarget] = []

    for file_diff in patch_diff.files:
        if file_diff.new_mode != "120000":
            continue

        lines = added_lines.get(file_diff.path, ())
        if len(lines) != 1:
            targets.append(SymlinkTarget(path=file_diff.path, target=""))
            continue

        targets.append(SymlinkTarget(path=file_diff.path, target=lines[0]))

    return tuple(targets)


def _added_lines_by_path(patch: str) -> dict[str, tuple[str, ...]]:
    added_lines: dict[str, list[str]] = {}
    current_path: str | None = None

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            current_path = None
            continue

        if line.startswith("+++ "):
            current_path = _path_from_file_header(line)
            if current_path is not None:
                added_lines.setdefault(current_path, [])
            continue

        if current_path is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            added_lines[current_path].append(line[1:])

    return {path: tuple(lines) for path, lines in added_lines.items()}


def _symlink_target_violations(
    symlink_target: SymlinkTarget,
    *,
    target_repo_path: Path | None,
) -> tuple[PathSafetyViolation, ...]:
    violations: list[PathSafetyViolation] = []
    target = symlink_target.target.strip()

    if not target:
        return (
            PathSafetyViolation(
                code="symlink-target-missing",
                path=symlink_target.path,
                reason="Symlink target could not be determined from the patch.",
            ),
        )

    if "\0" in target:
        violations.append(
            PathSafetyViolation(
                code="symlink-target-null-byte",
                path=symlink_target.path,
                reason="Symlink target must not contain null bytes.",
            )
        )

    if target.startswith(("/", "\\", "//", "\\\\")):
        violations.append(
            PathSafetyViolation(
                code="symlink-target-rooted",
                path=symlink_target.path,
                reason="Symlink target must be repository-relative.",
            )
        )

    windows_target = PureWindowsPath(target)
    if windows_target.drive or windows_target.is_absolute():
        violations.append(
            PathSafetyViolation(
                code="symlink-target-windows-rooted",
                path=symlink_target.path,
                reason="Symlink target must not use a Windows drive or UNC root.",
            )
        )

    normalized_target = target.replace("\\", "/")
    escaped = _relative_target_escapes_repo(symlink_target.path, normalized_target)
    if escaped:
        violations.append(
            PathSafetyViolation(
                code="symlink-target-outside-repo",
                path=symlink_target.path,
                reason="Symlink target escapes the trusted repository boundary.",
            )
        )

    if target_repo_path is not None and not escaped and not violations:
        root = target_repo_path.resolve(strict=False)
        link_parent = PurePosixPath(symlink_target.path).parent.as_posix()
        candidate = (root / link_parent / normalized_target).resolve(strict=False)

        if not _is_within_directory(candidate, root):
            violations.append(
                PathSafetyViolation(
                    code="symlink-target-outside-repo",
                    path=symlink_target.path,
                    reason="Symlink target resolves outside the trusted repository boundary.",
                )
            )

    return tuple(violations)


def _relative_target_escapes_repo(link_path: str, target: str) -> bool:
    link_parent = PurePosixPath(link_path).parent
    parts: list[str] = []

    for part in (*link_parent.parts, *PurePosixPath(target).parts):
        if part in {"", "."}:
            continue

        if part == "..":
            if not parts:
                return True
            parts.pop()
            continue

        parts.append(part)

    return False


def _paths_from_diff_git_header(line: str) -> set[str]:
    try:
        parts = shlex.split(line)
    except ValueError:
        return {line}

    if len(parts) < 4:
        return {line}

    paths: set[str] = set()
    for token in parts[2:4]:
        path = _strip_git_prefix(token)
        if path is not None:
            paths.add(path)

    return paths


def _path_from_file_header(line: str) -> str | None:
    try:
        parts = shlex.split(line)
    except ValueError:
        return line[4:].strip()

    if len(parts) < 2:
        return None

    return _strip_git_prefix(parts[1])


def _strip_git_prefix(path: str) -> str | None:
    if path == "/dev/null":
        return None

    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]

    return path


def _path_violations(
    path: str,
    *,
    target_repo_path: Path | None,
) -> tuple[PathSafetyViolation, ...]:
    violations: list[PathSafetyViolation] = []
    raw_path = path.strip()

    if not raw_path:
        return (
            PathSafetyViolation(
                code="empty-path",
                path=path,
                reason="Patch path must not be empty.",
            ),
        )

    if "\0" in raw_path:
        violations.append(
            PathSafetyViolation(
                code="null-byte-path",
                path=path,
                reason="Patch path must not contain null bytes.",
            )
        )

    if raw_path.startswith(("/", "\\", "//", "\\\\")):
        violations.append(
            PathSafetyViolation(
                code="rooted-path",
                path=path,
                reason="Patch path must be repository-relative, not filesystem-rooted.",
            )
        )

    windows_path = PureWindowsPath(raw_path)
    if windows_path.drive or windows_path.is_absolute():
        violations.append(
            PathSafetyViolation(
                code="windows-rooted-path",
                path=path,
                reason="Patch path must not use a Windows drive or UNC root.",
            )
        )

    normalized = raw_path.replace("\\", "/")
    posix_path = PurePosixPath(normalized)

    if any(part == ".." for part in posix_path.parts):
        violations.append(
            PathSafetyViolation(
                code="parent-directory-path",
                path=path,
                reason="Patch path must not contain parent-directory traversal.",
            )
        )

    clean_parts = tuple(part for part in posix_path.parts if part not in {"", "."})
    if not clean_parts:
        violations.append(
            PathSafetyViolation(
                code="empty-normalized-path",
                path=path,
                reason="Patch path must not normalize to an empty path.",
            )
        )
        return tuple(violations)

    clean_path = PurePosixPath(*clean_parts).as_posix()

    if target_repo_path is not None:
        candidate = (target_repo_path / clean_path).resolve(strict=False)
        root = target_repo_path.resolve(strict=False)

        if not _is_within_directory(candidate, root):
            violations.append(
                PathSafetyViolation(
                    code="outside-repo-boundary",
                    path=path,
                    reason="Patch path resolves outside the trusted repository boundary.",
                )
            )

    return tuple(violations)


def _is_within_directory(path: Path, directory: Path) -> bool:
    if path == directory:
        return True

    try:
        path.relative_to(directory)
    except ValueError:
        return False

    return True


def _dedupe_violations(
    violations: list[PathSafetyViolation],
) -> tuple[PathSafetyViolation, ...]:
    seen: set[tuple[str, str]] = set()
    deduped: list[PathSafetyViolation] = []

    for violation in violations:
        key = (violation.code, violation.path)
        if key in seen:
            continue

        seen.add(key)
        deduped.append(violation)

    return tuple(deduped)


__all__ = [
    "PatchPathSafetyReport",
    "SymlinkTarget",
    "PathSafetyError",
    "PathSafetyViolation",
    "ensure_patch_path_forms_safe",
    "ensure_patch_paths_safe",
    "validate_patch_path_forms",
    "validate_patch_paths",
    "write_path_safety_audit_event",
]
