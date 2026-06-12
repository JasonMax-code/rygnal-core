"""Approval decision authorization for Rygnal.

This module validates whether an approval decision is allowed to take effect.
It is intentionally independent from roles.yaml so the engine can be tested now
and later wired to persistent role configuration.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

from rygnal.models import ApprovalDecision, ApprovalRequest, ApprovalStatus


@dataclass(frozen=True)
class ApprovalReviewerPermission:
    """Permission assigned to a reviewer for approval decisions."""

    role: str
    can_approve: bool


@dataclass(frozen=True)
class ApprovalAuthorizationResult:
    """Structured result for approval authorization checks."""

    allowed: bool
    reason: str
    metadata: dict[str, str] = field(default_factory=dict)


class ApprovalAuthorizationEngine:
    """Authorize approval decisions before they affect tool execution."""

    def __init__(
        self,
        reviewer_permissions: Mapping[str, ApprovalReviewerPermission] | None = None,
    ) -> None:
        self.reviewer_permissions = dict(reviewer_permissions or {})

    def authorize(
        self,
        *,
        approval_request: ApprovalRequest,
        approval_decision: ApprovalDecision,
        current_status: ApprovalStatus = ApprovalStatus.PENDING,
    ) -> ApprovalAuthorizationResult:
        """Return whether an approval decision is authorized."""
        if current_status != ApprovalStatus.PENDING:
            return ApprovalAuthorizationResult(
                allowed=False,
                reason="Approval request is no longer pending.",
                metadata={
                    "guard": "approval-state",
                    "current_status": current_status.value,
                },
            )

        if not approval_decision.approved:
            return ApprovalAuthorizationResult(
                allowed=True,
                reason="Approval rejection authorized.",
                metadata={},
            )

        if approval_decision.decided_by is None:
            return ApprovalAuthorizationResult(
                allowed=False,
                reason="Approval decision is missing reviewer identity.",
                metadata={"guard": "reviewer-identity"},
            )

        if approval_decision.decided_by == approval_request.requested_by:
            return ApprovalAuthorizationResult(
                allowed=False,
                reason="Requester cannot approve their own approval request.",
                metadata={
                    "guard": "self-approval",
                    "attempted_decided_by": approval_decision.decided_by,
                },
            )

        reviewer_permission = self.reviewer_permissions.get(approval_decision.decided_by)

        if reviewer_permission is None:
            if self.reviewer_permissions:
                return ApprovalAuthorizationResult(
                    allowed=False,
                    reason="Reviewer does not have approval permission.",
                    metadata={
                        "guard": "reviewer-role",
                        "attempted_decided_by": approval_decision.decided_by,
                    },
                )

            return ApprovalAuthorizationResult(
                allowed=True,
                reason="Approval decision authorized.",
                metadata={},
            )

        reviewer_role = reviewer_permission.role.strip().lower()

        if not reviewer_permission.can_approve:
            return ApprovalAuthorizationResult(
                allowed=False,
                reason=(
                    f"Reviewer role '{reviewer_permission.role}' cannot approve protected actions."
                ),
                metadata={
                    "guard": "reviewer-role",
                    "attempted_decided_by": approval_decision.decided_by,
                    "reviewer_role": reviewer_role,
                },
            )

        return ApprovalAuthorizationResult(
            allowed=True,
            reason="Approval decision authorized.",
            metadata={"reviewer_role": reviewer_role},
        )
