from fastapi.testclient import TestClient

from rygnal.api import create_app
from rygnal.approval_queue import InMemoryApprovalQueue
from rygnal.models import ApprovalRequest, Severity


def make_request(
    *,
    requested_by: str = "agent_user",
    reason: str = "Risky guarded workspace patch requires approval.",
) -> ApprovalRequest:
    return ApprovalRequest(
        requested_by=requested_by,
        agent_id="agent_1",
        environment="local",
        trace_id="trace_approval_api",
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target="patch_sha256_demo",
        policy_id="guarded-workspace-risky-patch-approval",
        reason=reason,
        severity=Severity.HIGH,
        risk_assessment={
            "risk_level": "high",
            "summary": "Risky guarded workspace patch requires approval.",
        },
        metadata={
            "patch_sha256": "patch_sha256_demo",
            "api_key": "sk-live-super-secret-token",
        },
    )


def test_local_api_approval_queue_creates_and_lists_pending_requests_redacted():
    queue = InMemoryApprovalQueue()
    client = TestClient(create_app(approval_queue=queue))

    create_response = client.post("/v1/approvals", json=make_request().model_dump(mode="json"))
    assert create_response.status_code == 201

    created = create_response.json()["approval"]
    assert created["status"] == "pending"
    assert "sk-live-super-secret-token" not in create_response.text
    assert created["request"]["metadata"]["api_key"] == "[REDACTED]"

    response = client.get("/v1/approvals")
    data = response.json()

    assert response.status_code == 200
    assert data["returned_count"] == 1
    assert data["approvals"][0]["approval_id"] == created["approval_id"]
    assert data["approvals"][0]["status"] == "pending"
    assert "sk-live-super-secret-token" not in response.text


def test_local_api_approval_queue_gets_one_request():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue))

    response = client.get(f"/v1/approvals/{request.approval_id}")
    data = response.json()

    assert response.status_code == 200
    assert data["approval"]["approval_id"] == request.approval_id
    assert data["approval"]["status"] == "pending"


def test_local_api_approval_queue_returns_404_for_missing_request():
    client = TestClient(create_app(approval_queue=InMemoryApprovalQueue()))

    response = client.get(
        "/v1/approvals/app_missing",
        headers={"X-Request-ID": "req_missing_approval"},
    )

    data = response.json()

    assert response.status_code == 404
    assert data["error"]["code"] == "approval_not_found"
    assert data["error"]["request_id"] == "req_missing_approval"


def test_local_api_approval_queue_approves_request():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/approve",
        json={
            "decided_by": "human_reviewer",
            "reason": "Looks safe after review.",
        },
    )

    data = response.json()

    assert response.status_code == 200
    assert data["approval_decision"]["approval_id"] == request.approval_id
    assert data["approval_decision"]["status"] == "approved"
    assert data["approval"]["status"] == "approved"

    fetched = client.get(f"/v1/approvals/{request.approval_id}").json()
    assert fetched["approval"]["status"] == "approved"


def test_local_api_approval_queue_rejects_request():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/reject",
        json={
            "decided_by": "human_reviewer",
            "reason": "Not safe enough.",
        },
    )

    data = response.json()

    assert response.status_code == 200
    assert data["approval_decision"]["status"] == "rejected"
    assert data["approval"]["status"] == "rejected"


def test_local_api_approval_queue_rejects_self_approval_safely():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request(requested_by="agent_user"))
    client = TestClient(create_app(approval_queue=queue))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/approve",
        json={
            "decided_by": "agent_user",
            "reason": "Trying to approve my own request.",
        },
        headers={"X-Request-ID": "req_self_approval"},
    )

    data = response.json()

    assert response.status_code == 403
    assert data["error"]["code"] == "approval_denied"
    assert data["error"]["request_id"] == "req_self_approval"
    assert "own approval request" in data["error"]["message"].lower()

    fetched = client.get(f"/v1/approvals/{request.approval_id}").json()
    assert fetched["approval"]["status"] == "pending"


def test_local_api_approval_queue_rejects_double_decision():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue))

    first = client.post(
        f"/v1/approvals/{request.approval_id}/reject",
        json={
            "decided_by": "human_reviewer",
            "reason": "Not safe.",
        },
    )
    assert first.status_code == 200

    second = client.post(
        f"/v1/approvals/{request.approval_id}/approve",
        json={
            "decided_by": "another_reviewer",
            "reason": "Changed mind.",
        },
    )

    data = second.json()

    assert second.status_code == 409
    assert data["error"]["code"] == "approval_state_conflict"
