"""Deterministic size limits for guarded workspace change sets.

This module evaluates already-generated patch metadata. It does not inspect raw
repository files, approve changes, or apply patches. Soft limits raise risk and
force approval. Hard limits mark the change set critical so the existing gate can
block it before approval or application.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from rygnal.patch_diff import PatchDiff
from rygnal.risk_engine import RiskLevel

RISK_LEVEL_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


@dataclass(frozen=True)
class DiffLimitPolicy:
    """Thresholds for reviewability and hard-stop enforcement.

    Soft limits mean: still reviewable, but not safe for automatic application.
    Hard limits mean: too large for the current M1 safety boundary and blocked.
    """

    soft_max_changed_files: int = 25
    soft_max_total_changed_lines: int = 800
    soft_max_patch_size_bytes: int = 100_000
    soft_max_binary_files: int = 0
    hard_max_changed_files: int = 250
    hard_max_total_changed_lines: int = 10_000
    hard_max_patch_size_bytes: int = 1_000_000
    hard_max_binary_files: int = 10

    def __post_init__(self) -> None:
        _validate_limit_pair(
            "changed_files",
            self.soft_max_changed_files,
            self.hard_max_changed_files,
        )
        _validate_limit_pair(
            "total_changed_lines",
            self.soft_max_total_changed_lines,
            self.hard_max_total_changed_lines,
        )
        _validate_limit_pair(
            "patch_size_bytes",
            self.soft_max_patch_size_bytes,
            self.hard_max_patch_size_bytes,
        )
        _validate_limit_pair(
            "binary_files",
            self.soft_max_binary_files,
            self.hard_max_binary_files,
            allow_zero_soft=True,
        )

    @cached_property
    def audit_summary(self) -> dict[str, int]:
        return {
            "soft_max_changed_files": self.soft_max_changed_files,
            "soft_max_total_changed_lines": self.soft_max_total_changed_lines,
            "soft_max_patch_size_bytes": self.soft_max_patch_size_bytes,
            "soft_max_binary_files": self.soft_max_binary_files,
            "hard_max_changed_files": self.hard_max_changed_files,
            "hard_max_total_changed_lines": self.hard_max_total_changed_lines,
            "hard_max_patch_size_bytes": self.hard_max_patch_size_bytes,
            "hard_max_binary_files": self.hard_max_binary_files,
        }


@dataclass(frozen=True)
class DiffLimitReason:
    code: str
    risk_level: RiskLevel
    reason: str
    metric: str
    observed: int
    limit: int

    @cached_property
    def evidence(self) -> tuple[tuple[str, object], ...]:
        return (
            ("limit", self.limit),
            ("metric", self.metric),
            ("observed", self.observed),
        )

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "code": self.code,
            "risk_level": self.risk_level.value,
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class DiffLimitReport:
    patch_sha256: str
    baseline_commit_sha: str
    changed_file_count: int
    total_additions: int
    total_deletions: int
    total_changed_lines: int
    patch_size_bytes: int
    binary_file_count: int
    policy: DiffLimitPolicy
    reasons: tuple[DiffLimitReason, ...]

    @cached_property
    def hard_limit_exceeded(self) -> bool:
        return any(reason.risk_level == RiskLevel.CRITICAL for reason in self.reasons)

    @cached_property
    def approval_limit_exceeded(self) -> bool:
        return any(reason.risk_level == RiskLevel.HIGH for reason in self.reasons)

    @cached_property
    def overall_risk_level(self) -> RiskLevel:
        highest = RiskLevel.LOW

        for reason in self.reasons:
            if RISK_LEVEL_ORDER[reason.risk_level] > RISK_LEVEL_ORDER[highest]:
                highest = reason.risk_level

        return highest

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "patch_sha256": self.patch_sha256,
            "baseline_commit_sha": self.baseline_commit_sha,
            "changed_file_count": self.changed_file_count,
            "total_additions": self.total_additions,
            "total_deletions": self.total_deletions,
            "total_changed_lines": self.total_changed_lines,
            "patch_size_bytes": self.patch_size_bytes,
            "binary_file_count": self.binary_file_count,
            "hard_limit_exceeded": self.hard_limit_exceeded,
            "approval_limit_exceeded": self.approval_limit_exceeded,
            "overall_risk_level": self.overall_risk_level.value,
            "policy": self.policy.audit_summary,
            "reasons": tuple(reason.audit_summary for reason in self.reasons),
        }


def _validate_limit_pair(
    metric: str,
    soft_limit: int,
    hard_limit: int,
    *,
    allow_zero_soft: bool = False,
) -> None:
    min_soft = 0 if allow_zero_soft else 1

    if soft_limit < min_soft:
        raise ValueError(f"{metric} soft limit must be at least {min_soft}.")

    if hard_limit < 1:
        raise ValueError(f"{metric} hard limit must be at least 1.")

    if soft_limit > hard_limit:
        raise ValueError(f"{metric} soft limit must be <= hard limit.")


DEFAULT_DIFF_LIMIT_POLICY = DiffLimitPolicy()


def evaluate_diff_limits(
    patch_diff: PatchDiff,
    *,
    policy: DiffLimitPolicy = DEFAULT_DIFF_LIMIT_POLICY,
) -> DiffLimitReport:
    total_changed_lines = patch_diff.total_additions + patch_diff.total_deletions

    reasons = tuple(
        reason
        for reason in (
            _limit_reason(
                metric="changed_files",
                observed=patch_diff.changed_file_count,
                soft_limit=policy.soft_max_changed_files,
                hard_limit=policy.hard_max_changed_files,
            ),
            _limit_reason(
                metric="total_changed_lines",
                observed=total_changed_lines,
                soft_limit=policy.soft_max_total_changed_lines,
                hard_limit=policy.hard_max_total_changed_lines,
            ),
            _limit_reason(
                metric="patch_size_bytes",
                observed=patch_diff.patch_size_bytes,
                soft_limit=policy.soft_max_patch_size_bytes,
                hard_limit=policy.hard_max_patch_size_bytes,
            ),
            _limit_reason(
                metric="binary_files",
                observed=patch_diff.binary_file_count,
                soft_limit=policy.soft_max_binary_files,
                hard_limit=policy.hard_max_binary_files,
            ),
        )
        if reason is not None
    )

    return DiffLimitReport(
        patch_sha256=patch_diff.patch_sha256,
        baseline_commit_sha=patch_diff.baseline_commit_sha,
        changed_file_count=patch_diff.changed_file_count,
        total_additions=patch_diff.total_additions,
        total_deletions=patch_diff.total_deletions,
        total_changed_lines=total_changed_lines,
        patch_size_bytes=patch_diff.patch_size_bytes,
        binary_file_count=patch_diff.binary_file_count,
        policy=policy,
        reasons=reasons,
    )


def _limit_reason(
    *,
    metric: str,
    observed: int,
    soft_limit: int,
    hard_limit: int,
) -> DiffLimitReason | None:
    if observed > hard_limit:
        return DiffLimitReason(
            code=f"hard-diff-{metric}",
            risk_level=RiskLevel.CRITICAL,
            reason=f"Patch exceeds hard {metric.replace('_', ' ')} limit.",
            metric=metric,
            observed=observed,
            limit=hard_limit,
        )

    if observed > soft_limit:
        return DiffLimitReason(
            code=f"large-diff-{metric}",
            risk_level=RiskLevel.HIGH,
            reason=f"Patch exceeds reviewable auto-apply {metric.replace('_', ' ')} limit.",
            metric=metric,
            observed=observed,
            limit=soft_limit,
        )

    return None


__all__ = [
    "DEFAULT_DIFF_LIMIT_POLICY",
    "DiffLimitPolicy",
    "DiffLimitReason",
    "DiffLimitReport",
    "evaluate_diff_limits",
]
