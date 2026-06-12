from rygnal.approval_authorization import (
    ApprovalAuthorizationEngine,
    ApprovalReviewerPermission,
)
from rygnal.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    utc_now_iso,
)


def build_approval_request(
    requested_by: str = "requester",
    approval_id: str = "approval_001",
) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=approval_id,
        requested_by=requested_by,
        agent_id="demo_agent",
        environment="local",
        tool_name="file_delete",
        action="delete_file",
        target="customer-data.csv",
        reason="Sensitive file delete requires approval.",
    )


def build_approval_decision(
    *,
    approval_id: str = "approval_001",
    decided_by: str = "security_reviewer",
    approved: bool = True,
    status: ApprovalStatus = ApprovalStatus.APPROVED,
) -> ApprovalDecision:
    return ApprovalDecision(
        approval_id=approval_id,
        status=status,
        approved=approved,
        decided_by=decided_by,
        decided_at=utc_now_iso(),
        reason="Approved after review.",
    )


def test_authorization_rejects_self_approval() -> None:
    engine = ApprovalAuthorizationEngine(
        reviewer_permissions={
            "requester": ApprovalReviewerPermission(
                role="approver",
                can_approve=True,
            )
        }
    )

    result = engine.authorize(
        approval_request=build_approval_request(requested_by="requester"),
        approval_decision=build_approval_decision(decided_by="requester"),
    )

    assert result.allowed is False
    assert result.reason
    assert result.metadata["guard"] == "self-approval"
    assert result.metadata["attempted_decided_by"] == "requester"


def test_authorization_rejects_non_pending_request_state() -> None:
    engine = ApprovalAuthorizationEngine(
        reviewer_permissions={
            "security_reviewer": ApprovalReviewerPermission(
                role="approver",
                can_approve=True,
            )
        }
    )

    result = engine.authorize(
        approval_request=build_approval_request(),
        approval_decision=build_approval_decision(),
        current_status=ApprovalStatus.APPROVED,
    )

    assert result.allowed is False
    assert result.reason
    assert result.metadata["guard"] == "approval-state"
    assert result.metadata["current_status"] == "approved"


def test_authorization_rejects_viewer_role_approval() -> None:
    engine = ApprovalAuthorizationEngine(
        reviewer_permissions={
            "readonly_reviewer": ApprovalReviewerPermission(
                role="viewer",
                can_approve=False,
            )
        }
    )

    result = engine.authorize(
        approval_request=build_approval_request(),
        approval_decision=build_approval_decision(decided_by="readonly_reviewer"),
    )

    assert result.allowed is False
    assert result.reason
    assert result.metadata["guard"] == "reviewer-role"
    assert result.metadata["attempted_decided_by"] == "readonly_reviewer"
    assert result.metadata["reviewer_role"] == "viewer"


def test_authorization_allows_valid_approver() -> None:
    engine = ApprovalAuthorizationEngine(
        reviewer_permissions={
            "security_reviewer": ApprovalReviewerPermission(
                role="approver",
                can_approve=True,
            )
        }
    )

    result = engine.authorize(
        approval_request=build_approval_request(requested_by="requester"),
        approval_decision=build_approval_decision(decided_by="security_reviewer"),
    )

    assert result.allowed is True
    assert result.reason == "Approval decision authorized."
    assert result.metadata["reviewer_role"] == "approver"
