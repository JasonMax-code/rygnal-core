"""Deterministic risk classification for guarded workspace file changes.

This module classifies already-generated guarded workspace patches. It does not
approve, block, or apply patches. Later M1 issues use these machine-readable
file risk reasons for summaries, approval prompts, blocking, and audit.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property
from pathlib import PurePosixPath

from rygnal.changed_files import ChangedFileKind, normalize_repo_relative_path
from rygnal.patch_diff import PatchDiff, PatchFileDiff
from rygnal.risk_engine import RiskLevel

RISK_LEVEL_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


DOC_EXTENSIONS = {
    ".adoc",
    ".md",
    ".rst",
    ".txt",
}

DOC_FILE_NAMES = {
    "changelog",
    "code_of_conduct",
    "contributing",
    "license",
    "readme",
    "security",
}

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".swift",
    ".ts",
    ".tsx",
}

SCRIPT_EXTENSIONS = {
    ".bash",
    ".bat",
    ".cmd",
    ".fish",
    ".ps1",
    ".sh",
    ".zsh",
}

BINARY_EXTENSIONS = {
    ".bin",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".jar",
    ".o",
    ".pyc",
    ".so",
    ".wasm",
    ".war",
}

DEPENDENCY_FILE_NAMES = {
    "build.gradle",
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "gradle.lockfile",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pubspec.lock",
    "pubspec.yaml",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
}

DEPENDENCY_NAME_PATTERNS = (
    "requirements-*.txt",
    "requirements_*.txt",
    "requirements*.in",
    "requirements*.txt",
)

CI_PATH_PATTERNS = (
    ".circleci/*",
    ".github/actions/*",
    ".github/workflows/*",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "buildkite.yml",
    "jenkinsfile",
)

INFRA_PATH_PATTERNS = (
    ".dockerignore",
    ".gitignore",
    "docker-compose*.yaml",
    "docker-compose*.yml",
    "dockerfile",
    "helm/*",
    "k8s/*",
    "kubernetes/*",
    "makefile",
    "mkdocs.yml",
    "terraform/*",
    "tox.ini",
    "*.tf",
)

SECURITY_SENSITIVE_PATH_PATTERNS = (
    ".env",
    ".env.*",
    ".npmrc",
    ".pypirc",
    "*/.env",
    "*/.env.*",
    "*/.npmrc",
    "*/.pypirc",
    "*/credentials*.json",
    "*/id_dsa",
    "*/id_ecdsa",
    "*/id_ed25519",
    "*/id_rsa",
    "*/private*.key",
    "*/private*.pem",
    "*/secret.*",
    "*/secrets.*",
    "*/service-account*.json",
    "*/service_account*.json",
    "*.key",
    "*.p12",
    "*.pem",
    "*.pfx",
    "credentials*.json",
    "secret.*",
    "secrets.*",
)

AUTH_SECURITY_PATH_SEGMENTS = {
    "auth",
    "authentication",
    "iam",
    "jwt",
    "oauth",
    "permission",
    "permissions",
    "rbac",
    "security",
    "session",
    "sessions",
}

DEPLOY_PATH_SEGMENTS = {
    "deploy",
    "deployment",
    "deployments",
    "helm",
    "k8s",
    "kubernetes",
    "terraform",
}

SCRIPT_PATH_SEGMENTS = {
    "bin",
    "script",
    "scripts",
    "tool",
    "tools",
}

SECRET_ADDED_LINE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key-header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|"
            r"private[_-]?key|secret|client[_-]?secret)\b\s*[:=]\s*['\"]?[^'\"\s]{8,}"
        ),
    ),
)

DESTRUCTIVE_ADDED_LINE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("recursive-force-delete", re.compile(r"(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\b")),
    ("world-writable-permission", re.compile(r"(?i)\bchmod\s+777\b")),
    ("pipe-to-shell", re.compile(r"(?i)\b(curl|wget)\b.+\|\s*(sh|bash)\b")),
    ("disk-format", re.compile(r"(?i)\bmkfs(\.|\\s)")),
    ("raw-disk-write", re.compile(r"(?i)\bdd\s+.*\bof=/dev/")),
)


class ChangeRiskClassificationError(RuntimeError):
    """Raised when guarded change risk classification cannot complete safely."""


@dataclass(frozen=True)
class ChangeRiskReason:
    """One deterministic reason for a file or report risk classification."""

    code: str
    risk_level: RiskLevel
    reason: str
    evidence: tuple[tuple[str, object], ...] = ()

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "code": self.code,
            "risk_level": self.risk_level.value,
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class FileRiskClassification:
    """Risk classification for one changed guarded-workspace file."""

    path: str
    kind: ChangedFileKind
    risk_level: RiskLevel
    reasons: tuple[ChangeRiskReason, ...]
    additions: int | None = None
    deletions: int | None = None
    binary: bool = False
    old_path: str | None = None
    old_mode: str | None = None
    new_mode: str | None = None
    mode_changed: bool = False

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "path": self.path,
            "old_path": self.old_path,
            "kind": self.kind.value,
            "risk_level": self.risk_level.value,
            "additions": self.additions,
            "deletions": self.deletions,
            "binary": self.binary,
            "old_mode": self.old_mode,
            "new_mode": self.new_mode,
            "mode_changed": self.mode_changed,
            "reasons": tuple(reason.audit_summary for reason in self.reasons),
        }


@dataclass(frozen=True)
class ChangeRiskReport:
    """Patch-level deterministic risk report for guarded workspace changes."""

    baseline_commit_sha: str
    patch_sha256: str
    files: tuple[FileRiskClassification, ...]
    report_reasons: tuple[ChangeRiskReason, ...] = ()

    @cached_property
    def overall_risk_level(self) -> RiskLevel:
        return _highest_risk(
            (
                *(file.risk_level for file in self.files),
                *(reason.risk_level for reason in self.report_reasons),
            ),
            default=RiskLevel.LOW,
        )

    @cached_property
    def changed_file_count(self) -> int:
        return len(self.files)

    @cached_property
    def risk_counts(self) -> dict[str, int]:
        counts = Counter(file.risk_level.value for file in self.files)
        return {level.value: counts.get(level.value, 0) for level in RiskLevel}

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "baseline_commit_sha": self.baseline_commit_sha,
            "patch_sha256": self.patch_sha256,
            "overall_risk_level": self.overall_risk_level.value,
            "changed_file_count": self.changed_file_count,
            "risk_counts": self.risk_counts,
            "files": tuple(file.audit_summary for file in self.files),
            "report_reasons": tuple(reason.audit_summary for reason in self.report_reasons),
        }


def classify_patch_risk(
    patch_diff: PatchDiff,
    *,
    validation_reasons: Iterable[ChangeRiskReason] = (),
) -> ChangeRiskReport:
    """Classify each changed file in a guarded workspace patch."""

    added_lines_by_path = extract_added_lines_by_path(patch_diff.patch)
    files = tuple(
        classify_patch_file_risk(file_diff, added_lines_by_path=added_lines_by_path)
        for file_diff in patch_diff.files
    )
    report_reasons = tuple(validation_reasons)

    return ChangeRiskReport(
        baseline_commit_sha=patch_diff.baseline_commit_sha,
        patch_sha256=patch_diff.patch_sha256,
        files=files,
        report_reasons=report_reasons,
    )


def classify_patch_file_risk(
    file_diff: PatchFileDiff,
    *,
    added_lines_by_path: dict[str, tuple[str, ...]] | None = None,
) -> FileRiskClassification:
    """Classify one changed file from patch metadata and added lines."""

    path = normalize_repo_relative_path(file_diff.path)
    added_lines = (added_lines_by_path or {}).get(path, ())
    reasons = (
        *_path_risk_reasons(path),
        *_metadata_risk_reasons(file_diff),
        *_content_risk_reasons(path, added_lines),
    )

    if not reasons:
        reasons = (_baseline_path_reason(path),)

    risk_level = _highest_risk(reason.risk_level for reason in reasons)

    return FileRiskClassification(
        path=path,
        old_path=file_diff.old_path,
        kind=file_diff.kind,
        risk_level=risk_level,
        reasons=reasons,
        additions=file_diff.additions,
        deletions=file_diff.deletions,
        binary=file_diff.binary,
        old_mode=file_diff.old_mode,
        new_mode=file_diff.new_mode,
        mode_changed=file_diff.mode_changed,
    )


def extract_added_lines_by_path(patch: str) -> dict[str, tuple[str, ...]]:
    """Extract added content lines from a unified Git patch without diff headers."""

    added_lines: dict[str, list[str]] = {}
    current_path: str | None = None

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            current_path = None
            continue

        if line.startswith("+++ "):
            current_path = _parse_new_patch_path(line[4:].strip())
            if current_path is not None:
                added_lines.setdefault(current_path, [])
            continue

        if current_path is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            added_lines[current_path].append(line[1:])

    return {path: tuple(lines) for path, lines in added_lines.items()}


def _path_risk_reasons(path: str) -> tuple[ChangeRiskReason, ...]:
    reasons: list[ChangeRiskReason] = []
    lower_path = path.lower()

    if _matches_any(lower_path, SECURITY_SENSITIVE_PATH_PATTERNS):
        reasons.append(
            _reason(
                "security-sensitive-path",
                RiskLevel.CRITICAL,
                "File path indicates credential, key, secret, or environment material.",
                {"path": path},
            )
        )

    if _matches_name(lower_path, DEPENDENCY_FILE_NAMES) or _matches_name_pattern(
        lower_path, DEPENDENCY_NAME_PATTERNS
    ):
        reasons.append(
            _reason(
                "dependency-file-change",
                RiskLevel.HIGH,
                "Dependency manifest or lockfile changed.",
                {"path": path},
            )
        )

    if _matches_any(lower_path, CI_PATH_PATTERNS):
        reasons.append(
            _reason(
                "ci-config-change",
                RiskLevel.HIGH,
                "CI/CD workflow or pipeline configuration changed.",
                {"path": path},
            )
        )

    if _matches_any(lower_path, INFRA_PATH_PATTERNS) or _has_any_segment(
        lower_path, DEPLOY_PATH_SEGMENTS
    ):
        reasons.append(
            _reason(
                "infrastructure-or-deploy-change",
                RiskLevel.HIGH,
                "Infrastructure, container, deployment, or release configuration changed.",
                {"path": path},
            )
        )

    if _has_any_segment(lower_path, AUTH_SECURITY_PATH_SEGMENTS):
        reasons.append(
            _reason(
                "auth-security-path-change",
                RiskLevel.HIGH,
                "Authentication, authorization, session, or security-sensitive code path changed.",
                {"path": path},
            )
        )

    if _is_script_like_path(lower_path):
        reasons.append(
            _reason(
                "script-change",
                RiskLevel.HIGH,
                "Executable script or automation path changed.",
                {"path": path},
            )
        )

    return tuple(reasons)


def _metadata_risk_reasons(file_diff: PatchFileDiff) -> tuple[ChangeRiskReason, ...]:
    reasons: list[ChangeRiskReason] = []
    path = file_diff.path

    if file_diff.binary:
        reasons.append(
            _reason(
                "binary-file-change",
                RiskLevel.HIGH,
                "Binary file changed and cannot be reviewed as plain text.",
                {"path": path},
            )
        )

    if file_diff.old_mode == "120000" or file_diff.new_mode == "120000":
        reasons.append(
            _reason(
                "symlink-change",
                RiskLevel.CRITICAL,
                "Symlink changes can alter filesystem boundaries.",
                {"path": path},
            )
        )
    elif file_diff.mode_changed:
        reasons.append(
            _reason(
                "file-mode-change",
                RiskLevel.HIGH,
                "File mode changed, which may alter executability or access behavior.",
                {
                    "path": path,
                    "old_mode": file_diff.old_mode or "",
                    "new_mode": file_diff.new_mode or "",
                },
            )
        )

    if _extension(path.lower()) in BINARY_EXTENSIONS:
        reasons.append(
            _reason(
                "generated-executable-artifact",
                RiskLevel.HIGH,
                "Generated executable or compiled artifact changed.",
                {"path": path},
            )
        )

    return tuple(reasons)


def _content_risk_reasons(
    path: str,
    added_lines: tuple[str, ...],
) -> tuple[ChangeRiskReason, ...]:
    reasons: list[ChangeRiskReason] = []
    seen_codes: set[str] = set()

    for line in added_lines:
        for code, pattern in SECRET_ADDED_LINE_PATTERNS:
            if code in seen_codes or not pattern.search(line):
                continue

            seen_codes.add(code)
            reasons.append(
                _reason(
                    f"added-secret-{code}",
                    RiskLevel.CRITICAL,
                    "Added line appears to contain credential or secret material.",
                    {"path": path, "pattern": code},
                )
            )

        for code, pattern in DESTRUCTIVE_ADDED_LINE_PATTERNS:
            if code in seen_codes or not pattern.search(line):
                continue

            seen_codes.add(code)
            risk_level = RiskLevel.CRITICAL if _is_script_like_path(path) else RiskLevel.HIGH
            reasons.append(
                _reason(
                    f"destructive-command-{code}",
                    risk_level,
                    "Added line appears to contain a destructive command pattern.",
                    {"path": path, "pattern": code},
                )
            )

    return tuple(reasons)


def _baseline_path_reason(path: str) -> ChangeRiskReason:
    lower_path = path.lower()

    if _is_documentation_path(lower_path):
        return _reason(
            "documentation-change",
            RiskLevel.LOW,
            "Documentation-only path changed.",
            {"path": path},
        )

    if _is_test_path(lower_path):
        return _reason(
            "test-change",
            RiskLevel.LOW,
            "Test path changed without privileged file indicators.",
            {"path": path},
        )

    if _extension(lower_path) in SOURCE_EXTENSIONS:
        return _reason(
            "source-code-change",
            RiskLevel.MEDIUM,
            "Source code changed.",
            {"path": path},
        )

    return _reason(
        "project-file-change",
        RiskLevel.MEDIUM,
        "Project file changed without a lower-risk classification.",
        {"path": path},
    )


def _parse_new_patch_path(raw_path: str) -> str | None:
    if raw_path == "/dev/null":
        return None

    path = raw_path[2:] if raw_path.startswith("b/") else raw_path
    return normalize_repo_relative_path(path)


def _reason(
    code: str,
    risk_level: RiskLevel,
    reason: str,
    evidence: dict[str, object],
) -> ChangeRiskReason:
    return ChangeRiskReason(
        code=code,
        risk_level=risk_level,
        reason=reason,
        evidence=tuple(sorted(evidence.items())),
    )


def _highest_risk(
    risk_levels: Iterable[RiskLevel],
    *,
    default: RiskLevel = RiskLevel.LOW,
) -> RiskLevel:
    highest = default

    for risk_level in risk_levels:
        if RISK_LEVEL_ORDER[risk_level] > RISK_LEVEL_ORDER[highest]:
            highest = risk_level

    return highest


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _matches_name(path: str, names: set[str]) -> bool:
    return PurePosixPath(path).name in names


def _matches_name_pattern(path: str, patterns: Iterable[str]) -> bool:
    name = PurePosixPath(path).name
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _has_any_segment(path: str, segments: set[str]) -> bool:
    return any(segment in segments for segment in path.split("/"))


def _extension(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def _is_script_like_path(path: str) -> bool:
    return (
        _extension(path) in SCRIPT_EXTENSIONS
        or _has_any_segment(path, SCRIPT_PATH_SEGMENTS)
        or PurePosixPath(path).name in {"makefile", "dockerfile"}
    )


def _is_documentation_path(path: str) -> bool:
    name = PurePosixPath(path).name
    stem = PurePosixPath(path).stem
    return (
        path.startswith("docs/")
        or _extension(path) in DOC_EXTENSIONS
        or name in {"license", "notice"}
        or stem in DOC_FILE_NAMES
    )


def _is_test_path(path: str) -> bool:
    name = PurePosixPath(path).name
    stem = PurePosixPath(path).stem
    return (
        path.startswith("tests/")
        or path.startswith("test/")
        or "/tests/" in path
        or name.startswith("test_")
        or stem.endswith("_test")
    )


__all__ = [
    "ChangeRiskClassificationError",
    "ChangeRiskReason",
    "ChangeRiskReport",
    "FileRiskClassification",
    "RISK_LEVEL_ORDER",
    "classify_patch_file_risk",
    "classify_patch_risk",
    "extract_added_lines_by_path",
]
