from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from rygnal.api import create_app
from rygnal.audit_logger import AuditLogger
from rygnal.audit_query import AuditQuery, query_audit_events
from rygnal.models import PolicyDecision, Severity, ToolRequest


def _request(target: str = "README.md") -> ToolRequest:
    return ToolRequest(
        tool_name="file_read",
        action="read_file",
        target=target,
        user_id="user",
        agent_id="agent",
        environment="local",
    )


def _decision(policy_id: str = "allow-readme") -> PolicyDecision:
    return PolicyDecision(
        decision="allow",
        allowed=True,
        reason="allowed",
        policy_id=policy_id,
        severity=Severity.LOW,
    )


def test_audit_query_filters_by_event_id(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    first = audit.log_decision(request=_request("README.md"), policy_decision=_decision("p1"))
    second = audit.log_decision(request=_request("docs.md"), policy_decision=_decision("p2"))

    result = query_audit_events(audit, AuditQuery(event_id=second.event_id))

    assert result.returned_count == 1
    assert result.events[0].event_id == second.event_id
    assert result.events[0].event_id != first.event_id


def test_audit_query_clamps_large_limit(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    audit.log_decision(request=_request(), policy_decision=_decision())

    result = query_audit_events(audit, AuditQuery(limit=10_000, max_limit=500))

    assert result.limit == 500
    assert result.returned_count == 1


def test_api_audit_events_survives_malformed_jsonl_line(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    event = audit.log_decision(request=_request(), policy_decision=_decision())
    audit.log_path.write_text(
        audit.log_path.read_text(encoding="utf-8") + "{bad json\n",
        encoding="utf-8",
    )

    client = TestClient(create_app(audit_logger=audit))
    response = client.get("/v1/audit/events")

    assert response.status_code == 200
    payload = response.json()
    assert payload["returned_count"] == 1
    assert payload["malformed_count"] == 1
    assert payload["events"][0]["event_id"] == event.event_id
    assert "Skipped 1 malformed audit log line(s)." in payload["warnings"]


def test_api_audit_event_by_id_returns_single_event(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    event = audit.log_decision(request=_request(), policy_decision=_decision())

    client = TestClient(create_app(audit_logger=audit))
    response = client.get(f"/v1/audit/events/{event.event_id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["event"]["event_id"] == event.event_id
    assert payload["integrity_verified"] is None


def test_api_audit_event_by_id_returns_404(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    client = TestClient(create_app(audit_logger=audit))

    response = client.get("/v1/audit/events/evt_missing")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "audit_event_not_found"


def test_api_audit_events_verify_integrity_is_lazy(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    audit.log_decision(request=_request(), policy_decision=_decision())

    client = TestClient(create_app(audit_logger=audit))

    default_response = client.get("/v1/audit/events")
    assert default_response.status_code == 200
    assert default_response.json()["integrity_verified"] is None

    verified_response = client.get("/v1/audit/events?verify_integrity=true")
    assert verified_response.status_code == 200
    assert verified_response.json()["integrity_verified"] is True


def test_api_audit_events_reports_failed_integrity_when_requested(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    audit.log_decision(request=_request(), policy_decision=_decision())
    lines = audit.log_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["reason"] = "tampered"
    audit.log_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    client = TestClient(create_app(audit_logger=audit))
    response = client.get("/v1/audit/events?verify_integrity=true")

    assert response.status_code == 200
    payload = response.json()
    assert payload["integrity_verified"] is False
