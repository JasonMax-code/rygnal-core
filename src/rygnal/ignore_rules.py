"""Guarded workspace ignore rules for changed-file inventory.

These rules intentionally do not mirror Git ignore behavior exactly. Git ignore
rules are primarily for untracked files; Rygnal uses this module to suppress
untracked generated noise while keeping important safety-relevant files visible.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from pathlib import PurePosixPath


class GuardedIgnoreReason(StrEnum):
    GENERATED_OR_HEAVY_PATH = "generated_or_heavy_path"


DEFAULT_HEAVY_PATH_SEGMENTS = frozenset(
    {
        ".cache",
        ".coverage",
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "site-packages",
        "target",
        "venv",
    }
)

DEFAULT_VISIBLE_BASENAMES = frozenset(
    {
        ".dockerignore",
        ".env",
        ".env.example",
        ".env.local",
        ".env.production",
        ".gitattributes",
        ".gitignore",
        ".gitlab-ci.yml",
        ".npmrc",
        ".pypirc",
        "Cargo.lock",
        "Cargo.toml",
        "Dockerfile",
        "Gemfile",
        "Gemfile.lock",
        "Pipfile",
        "Pipfile.lock",
        "bun.lock",
        "bun.lockb",
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
        "go.mod",
        "go.sum",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "requirements-dev.txt",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)

DEFAULT_VISIBLE_SUFFIXES = (
    ".env",
    ".env.local",
    ".env.production",
)

DEFAULT_VISIBLE_PREFIXES = (
    ".github/workflows/",
    ".gitlab/",
)

DEFAULT_VISIBLE_GLOBS = (
    "requirements-*.txt",
    "*.lock",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
)


@dataclass(frozen=True)
class GuardedIgnoreDecision:
    path: str
    ignored: bool
    reason: GuardedIgnoreReason | None = None
    protected: bool = False

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "path": self.path,
            "ignored": self.ignored,
            "reason": self.reason.value if self.reason else None,
            "protected": self.protected,
        }


@dataclass(frozen=True)
class GuardedIgnoreRules:
    heavy_path_segments: frozenset[str] = DEFAULT_HEAVY_PATH_SEGMENTS
    visible_basenames: frozenset[str] = DEFAULT_VISIBLE_BASENAMES
    visible_suffixes: tuple[str, ...] = DEFAULT_VISIBLE_SUFFIXES
    visible_prefixes: tuple[str, ...] = DEFAULT_VISIBLE_PREFIXES
    visible_globs: tuple[str, ...] = DEFAULT_VISIBLE_GLOBS

    def decide_untracked_path(self, path: str) -> GuardedIgnoreDecision:
        normalized = normalize_guarded_path(path)

        if self.is_protected_visible_path(normalized):
            return GuardedIgnoreDecision(
                path=normalized,
                ignored=False,
                protected=True,
            )

        if self.is_heavy_or_generated_path(normalized):
            return GuardedIgnoreDecision(
                path=normalized,
                ignored=True,
                reason=GuardedIgnoreReason.GENERATED_OR_HEAVY_PATH,
            )

        return GuardedIgnoreDecision(path=normalized, ignored=False)

    def is_heavy_or_generated_path(self, path: str) -> bool:
        normalized = normalize_guarded_path(path)
        ignored_segments = {segment.lower() for segment in self.heavy_path_segments}

        return any(part.lower() in ignored_segments for part in PurePosixPath(normalized).parts)

    def is_protected_visible_path(self, path: str) -> bool:
        normalized = normalize_guarded_path(path)
        path_obj = PurePosixPath(normalized)
        lower_path = normalized.lower()
        lower_basename = path_obj.name.lower()

        visible_basenames = {name.lower() for name in self.visible_basenames}
        if lower_basename in visible_basenames:
            return True

        if any(lower_path.endswith(suffix.lower()) for suffix in self.visible_suffixes):
            return True

        if any(lower_path.startswith(prefix.lower()) for prefix in self.visible_prefixes):
            return True

        return any(
            path_obj.match(pattern) or PurePosixPath(lower_path).match(pattern.lower())
            for pattern in self.visible_globs
        )


def normalize_guarded_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    path_obj = PurePosixPath(normalized)

    if not normalized:
        raise ValueError("Guarded path must not be empty.")

    if path_obj.is_absolute():
        raise ValueError(f"Guarded path must be repository-relative: {path}")

    if any(part == ".." for part in path_obj.parts):
        raise ValueError(f"Guarded path must not traverse: {path}")

    clean_parts = tuple(part for part in path_obj.parts if part not in {"", "."})
    if not clean_parts:
        raise ValueError("Guarded path must not normalize to empty.")

    return PurePosixPath(*clean_parts).as_posix()


def build_guarded_ignore_rules(
    *,
    heavy_path_segments: Iterable[str] = DEFAULT_HEAVY_PATH_SEGMENTS,
    visible_basenames: Iterable[str] = DEFAULT_VISIBLE_BASENAMES,
    visible_suffixes: Iterable[str] = DEFAULT_VISIBLE_SUFFIXES,
    visible_prefixes: Iterable[str] = DEFAULT_VISIBLE_PREFIXES,
    visible_globs: Iterable[str] = DEFAULT_VISIBLE_GLOBS,
) -> GuardedIgnoreRules:
    return GuardedIgnoreRules(
        heavy_path_segments=frozenset(heavy_path_segments),
        visible_basenames=frozenset(visible_basenames),
        visible_suffixes=tuple(visible_suffixes),
        visible_prefixes=tuple(visible_prefixes),
        visible_globs=tuple(visible_globs),
    )


DEFAULT_GUARDED_IGNORE_RULES = GuardedIgnoreRules()


__all__ = [
    "DEFAULT_GUARDED_IGNORE_RULES",
    "DEFAULT_HEAVY_PATH_SEGMENTS",
    "DEFAULT_VISIBLE_BASENAMES",
    "DEFAULT_VISIBLE_GLOBS",
    "DEFAULT_VISIBLE_PREFIXES",
    "DEFAULT_VISIBLE_SUFFIXES",
    "GuardedIgnoreDecision",
    "GuardedIgnoreReason",
    "GuardedIgnoreRules",
    "build_guarded_ignore_rules",
    "normalize_guarded_path",
]
