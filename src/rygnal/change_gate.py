"""Deterministic blocking gate for dangerous guarded workspace changes.

This module consumes the #131 change-risk report and decides whether a guarded
workspace patch is too dangerous to continue toward approval or application.

It does not approve changes, auto-apply patches, or apply patches back to the
trusted repository. Those behaviors belong to later M1 issues.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from typing import Any

from rygnal.audit_logger import AuditLogger
from rygnal.change_risk import (
    ChangeRiskReason,
    ChangeRiskReport,
    FileRiskClassification,
    classify_patch_risk,
)
from rygnal.models import Decision, PolicyDecision, Severity, ToolRequest, new_trace_id
from rygnal.patch_diff import PatchDiff
from rygnal.risk_engine import RiskLevel


class GuardedChangeGateOutcome(StrEnum):
    """Possible guarded change gate outcomes."""

    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True)
class GuardedChangeBlockReason:
    """One machine-readable reason why a guarded patch was blocked."""

    code: str
    risk_level: RiskLevel
    reason: str
    path: str | None = None
    evidence: tuple[tuple[str, object], ...] = ()

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        """Return audit-safe reason data without raw patch content."""

        return {
            "code": self.code,
            "risk_level": self.risk_level.value,
            "reason": self.reason,
            "path": self.path,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class GuardedChangeGateDecision:
    """Decision produced by the dangerous-change blocking gate."""

    outcome: GuardedChangeGateOutcome
    risk_report: ChangeRiskReport
    block_reasons: tuple[GuardedChangeBlockReason, ...] = ()

    @cached_property
    def blocked(self) -> bool:
        return self.outcome == GuardedChangeGateOutcome.BLOCK

    @cached_property
    def allowed_to_continue(self) -> bool:
        """Whether later approval/apply stages may continue evaluating the patch."""

        return not self.blocked

    @cached_property
    def decision(self) -> Decision:
        return Decision.BLOCK if self.blocked else Decision.ALLOW

    @cached_property
    def severity(self) -> Severity:
        return _severity_from_risk_level(self.risk_report.overall_risk_level)

    @cached_property
    def reason(self) -> str:
        if self.blocked:
            return "Guarded workspace patch blocked by deterministic dangerous-change gate."

        return "Guarded workspace patch did not match critical block rules."

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        """Return decision facts safe for JSONL audit logs."""

        return {
            "outcome": self.outcome.value,
            "blocked": self.blocked,
            "allowed_to_continue": self.allowed_to_continue,
            "decision": self.decision.value,
            "severity": self.severity.value,
            "reason": self.reason,
            "baseline_commit_sha": self.risk_report.baseline_commit_sha,
            "patch_sha256": self.risk_report.patch_sha256,
            "overall_risk_level": self.risk_report.overall_risk_level.value,
            "changed_file_count": self.risk_report.changed_file_count,
            "risk_counts": self.risk_report.risk_counts,
            "block_reasons": tuple(reason.audit_summary for reason in self.block_reasons),
            "risk_report": self.risk_report.audit_summary,
        }


def evaluate_guarded_change_gate(
    patch_diff: PatchDiff,
    *,
    risk_report: ChangeRiskReport | None = None,
) -> GuardedChangeGateDecision:
    """Evaluate whether a guarded workspace patch must be blocked."""

    report = risk_report or classify_patch_risk(patch_diff)
    block_reasons = _collect_block_reasons(report)

    outcome = GuardedChangeGateOutcome.BLOCK if block_reasons else GuardedChangeGateOutcome.ALLOW

    return GuardedChangeGateDecision(
        outcome=outcome,
        risk_report=report,
        block_reasons=block_reasons,
    )


def write_guarded_change_gate_audit_event(
    logger: AuditLogger,
    gate_decision: GuardedChangeGateDecision,
    *,
    user_id: str = "demo_user",
    agent_id: str = "demo_agent",
    environment: str = "local",
    trace_id: str | None = None,
) -> Any:
    """Write a structured audit event for a guarded change gate decision."""

    request = ToolRequest(
        tool_name="guarded_workspace",
        action="evaluate_patch_gate",
        target=gate_decision.risk_report.patch_sha256,
        input=gate_decision.audit_summary,
        user_id=user_id,
        agent_id=agent_id,
        environment=environment,
        metadata={
            "trace_id": trace_id or new_trace_id(),
            "event_type": "guarded_workspace.change_gate",
            "patch_sha256": gate_decision.risk_report.patch_sha256,
            "baseline_commit_sha": gate_decision.risk_report.baseline_commit_sha,
        },
    )

    policy_decision = PolicyDecision(
        decision=gate_decision.decision,
        allowed=gate_decision.allowed_to_continue,
        severity=gate_decision.severity,
        reason=gate_decision.reason,
        policy_id="guarded-workspace-dangerous-change-gate",
    )

    return logger.log_decision(
        request,
        policy_decision,
        metadata=gate_decision.audit_summary,
    )


def _collect_block_reasons(
    risk_report: ChangeRiskReport,
) -> tuple[GuardedChangeBlockReason, ...]:
    reasons: list[GuardedChangeBlockReason] = []

    for file_risk in risk_report.files:
        reasons.extend(_file_block_reasons(file_risk))

    for report_reason in risk_report.report_reasons:
        if report_reason.risk_level == RiskLevel.CRITICAL:
            reasons.append(_from_risk_reason(report_reason, path=None))

    return tuple(reasons)


def _file_block_reasons(
    file_risk: FileRiskClassification,
) -> tuple[GuardedChangeBlockReason, ...]:
    reasons: list[GuardedChangeBlockReason] = []

    for reason in file_risk.reasons:
        if reason.risk_level == RiskLevel.CRITICAL:
            reasons.append(_from_risk_reason(reason, path=file_risk.path))

    return tuple(reasons)


def _from_risk_reason(
    risk_reason: ChangeRiskReason,
    *,
    path: str | None,
) -> GuardedChangeBlockReason:
    return GuardedChangeBlockReason(
        code=risk_reason.code,
        risk_level=risk_reason.risk_level,
        reason=risk_reason.reason,
        path=path,
        evidence=risk_reason.evidence,
    )


def _severity_from_risk_level(risk_level: RiskLevel) -> Severity:
    if risk_level == RiskLevel.CRITICAL:
        return Severity.CRITICAL
    if risk_level == RiskLevel.HIGH:
        return Severity.HIGH
    if risk_level == RiskLevel.MEDIUM:
        return Severity.MEDIUM

    return Severity.LOW


__all__ = [
    "GuardedChangeBlockReason",
    "GuardedChangeGateDecision",
    "GuardedChangeGateOutcome",
    "evaluate_guarded_change_gate",
    "write_guarded_change_gate_audit_event",
]
