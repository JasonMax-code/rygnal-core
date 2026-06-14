"""Intentional handling for trusted-repository untracked files."""

from __future__ import annotations

import fnmatch
import os
import subprocess  # nosec B404
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from pathlib import Path, PurePosixPath
from typing import Any

from rygnal.audit_logger import AuditLogger
from rygnal.models import Decision, PolicyDecision, Severity, ToolRequest, new_trace_id


class UntrackedFilePolicy(StrEnum):
    BLOCK = "block"
    PRESERVE_AND_WARN = "preserve_and_warn"


class UntrackedFilesError(RuntimeError):
    def __init__(self, report: UntrackedFileReport) -> None:
        super().__init__("Trusted repository has untracked files.")
        self.report = report


class UntrackedFileDecision(StrEnum):
    BLOCK = "block"
    PRESERVE_IN_TRUSTED_REPO = "preserve_in_trusted_repo"


@dataclass(frozen=True)
class UntrackedFile:
    path: str
    decision: UntrackedFileDecision
    reason: str
    sensitive: bool = False

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "path": self.path,
            "decision": self.decision.value,
            "reason": self.reason,
            "sensitive": self.sensitive,
        }


@dataclass(frozen=True)
class UntrackedFileReport:
    repo_path: str
    policy: UntrackedFilePolicy
    files: tuple[UntrackedFile, ...]

    @cached_property
    def has_untracked_files(self) -> bool:
        return bool(self.files)

    @cached_property
    def blocked(self) -> bool:
        return any(file.decision == UntrackedFileDecision.BLOCK for file in self.files)

    @cached_property
    def preserved(self) -> tuple[UntrackedFile, ...]:
        return tuple(
            file
            for file in self.files
            if file.decision == UntrackedFileDecision.PRESERVE_IN_TRUSTED_REPO
        )

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "repo_path": self.repo_path,
            "policy": self.policy.value,
            "has_untracked_files": self.has_untracked_files,
            "blocked": self.blocked,
            "counts": {
                "total": len(self.files),
                "blocked": sum(file.decision == UntrackedFileDecision.BLOCK for file in self.files),
                "preserved": len(self.preserved),
                "sensitive": sum(file.sensitive for file in self.files),
            },
            "files": tuple(file.audit_summary for file in self.files),
        }


def detect_untracked_files(
    repo_path: str | Path,
    *,
    policy: UntrackedFilePolicy = UntrackedFilePolicy.BLOCK,
) -> UntrackedFileReport:
    root = _repo_root(Path(repo_path))
    paths = _git_untracked_paths(root)

    return UntrackedFileReport(
        repo_path=root.as_posix(),
        policy=policy,
        files=tuple(_classify_untracked_path(path, policy=policy) for path in paths),
    )


def verify_untracked_files_handled(
    repo_path: str | Path,
    *,
    policy: UntrackedFilePolicy = UntrackedFilePolicy.BLOCK,
    logger: AuditLogger | None = None,
    user_id: str = "demo_user",
    agent_id: str = "demo_agent",
    environment: str = "local",
    trace_id: str | None = None,
) -> UntrackedFileReport:
    report = detect_untracked_files(repo_path, policy=policy)

    if logger is not None:
        write_untracked_file_audit_event(
            logger,
            report,
            user_id=user_id,
            agent_id=agent_id,
            environment=environment,
            trace_id=trace_id,
        )

    if report.blocked:
        raise UntrackedFilesError(report)

    return report


def write_untracked_file_audit_event(
    logger: AuditLogger,
    report: UntrackedFileReport,
    *,
    user_id: str = "demo_user",
    agent_id: str = "demo_agent",
    environment: str = "local",
    trace_id: str | None = None,
) -> Any:
    request = ToolRequest(
        tool_name="guarded_workspace",
        action="handle_untracked_files",
        target=report.repo_path,
        input=report.audit_summary,
        user_id=user_id,
        agent_id=agent_id,
        environment=environment,
        metadata={
            "trace_id": trace_id or new_trace_id(),
            "event_type": "guarded_workspace.untracked_files",
            "repo_path": report.repo_path,
        },
    )
    decision = PolicyDecision(
        decision=Decision.BLOCK if report.blocked else Decision.ALLOW,
        allowed=not report.blocked,
        severity=_report_severity(report),
        reason=_report_reason(report),
        policy_id="guarded-workspace-untracked-file-handling",
    )

    return logger.log_decision(request, decision, metadata=report.audit_summary)


def _classify_untracked_path(
    path: str,
    *,
    policy: UntrackedFilePolicy,
) -> UntrackedFile:
    normalized = _normalize_git_path(path)
    sensitive = _is_sensitive_path(normalized)

    if sensitive:
        return UntrackedFile(
            path=normalized,
            decision=UntrackedFileDecision.BLOCK,
            reason="Sensitive untracked file must be handled outside guarded execution.",
            sensitive=True,
        )

    if policy == UntrackedFilePolicy.PRESERVE_AND_WARN:
        return UntrackedFile(
            path=normalized,
            decision=UntrackedFileDecision.PRESERVE_IN_TRUSTED_REPO,
            reason=(
                "Untracked file remains only in trusted repo and is not copied "
                "to the guarded workspace."
            ),
        )

    return UntrackedFile(
        path=normalized,
        decision=UntrackedFileDecision.BLOCK,
        reason="Default policy blocks guarded runs when untracked files are present.",
    )


def _git_untracked_paths(repo_path: Path) -> tuple[str, ...]:
    output = _run_git(
        [
            "ls-files",
            "--others",
            "--exclude-standard",
            "--full-name",
            "-z",
            "--",
        ],
        cwd=repo_path,
    )

    if not output:
        return ()

    return tuple(_normalize_git_path(path) for path in output.split("\0") if path)


def _normalize_git_path(path: str) -> str:
    if "\0" in path:
        raise ValueError("Git path contains null byte.")

    normalized = path.replace("\\", "/")
    pure_path = PurePosixPath(normalized)

    if pure_path.is_absolute() or any(part == ".." for part in pure_path.parts):
        raise ValueError(f"Unsafe Git path: {path}")

    parts = tuple(part for part in pure_path.parts if part not in {"", "."})
    if not parts:
        raise ValueError("Git path is empty after normalization.")

    return PurePosixPath(*parts).as_posix()


def _is_sensitive_path(path: str) -> bool:
    lower = path.lower()
    basename = PurePosixPath(lower).name

    sensitive_names = {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials",
        "credentials.json",
    }
    sensitive_patterns = (
        ".env.*",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*secret*",
        "*token*",
        "*credential*",
    )

    return basename in sensitive_names or any(
        fnmatch.fnmatch(basename, pattern) for pattern in sensitive_patterns
    )


def _repo_root(path: Path) -> Path:
    result = _run_git(["rev-parse", "--show-toplevel"], cwd=path.resolve())
    return Path(result.strip()).resolve()


def _run_git(args: list[str], *, cwd: Path) -> str:
    env = os.environ.copy()
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)

    result = subprocess.run(  # nosec B603 B607
        ["git", *args],
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Git operation failed: {detail}")

    return result.stdout


def _report_severity(report: UntrackedFileReport) -> Severity:
    if report.blocked:
        return Severity.HIGH

    if report.has_untracked_files:
        return Severity.MEDIUM

    return Severity.LOW


def _report_reason(report: UntrackedFileReport) -> str:
    if report.blocked:
        return "Trusted repository has untracked files that block guarded execution."

    if report.has_untracked_files:
        return "Trusted repository untracked files are preserved outside the guarded workspace."

    return "Trusted repository has no untracked files."


__all__ = [
    "UntrackedFile",
    "UntrackedFileDecision",
    "UntrackedFilePolicy",
    "UntrackedFileReport",
    "UntrackedFilesError",
    "detect_untracked_files",
    "verify_untracked_files_handled",
    "write_untracked_file_audit_event",
]
