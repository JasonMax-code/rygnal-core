from fastapi.testclient import TestClient

from rygnal.api import create_app
from rygnal.audit_logger import AuditLogger


def test_local_api_health_endpoint():
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "rygnal-core"}


def test_local_api_evaluate_blocks_env_file():
    client = TestClient(create_app())

    response = client.post(
        "/v1/evaluate",
        json={
            "tool_name": "file_read",
            "action": "read_file",
            "target": ".env",
        },
    )

    data = response.json()

    assert response.status_code == 200
    assert data["risk_assessment"]["risk_level"] == "critical"
    assert data["policy_decision"]["decision"] == "block"
    assert data["policy_decision"]["allowed"] is False
    assert data["policy_decision"]["policy_id"] == "block-env-read"
    assert data["audit_event"] is None


def test_local_api_evaluate_with_audit_logger(tmp_path):
    audit_logger = AuditLogger(tmp_path / "api_audit.jsonl")
    client = TestClient(create_app(audit_logger=audit_logger))

    response = client.post(
        "/v1/evaluate",
        json={
            "tool_name": "shell_command",
            "action": "execute",
            "input": "rm -rf /tmp/demo",
        },
    )

    data = response.json()

    assert response.status_code == 200
    assert data["policy_decision"]["decision"] == "block"
    assert data["audit_event"] is not None
    assert data["audit_event"]["event_id"].startswith("evt_")
    assert (tmp_path / "api_audit.jsonl").exists()


def test_local_api_safe_request_defaults_to_allow():
    client = TestClient(create_app())

    response = client.post(
        "/v1/evaluate",
        json={
            "tool_name": "file_read",
            "action": "read_file",
            "target": "README.md",
        },
    )

    data = response.json()

    assert response.status_code == 200
    assert data["policy_decision"]["decision"] == "allow"
    assert data["policy_decision"]["allowed"] is True


class ExplodingRiskEngine:
    def assess(self, request):
        raise RuntimeError(
            "boom: leaked sk-live-super-secret-token from /workspaces/rygnal-core/.env"
        )


def test_local_api_validation_error_uses_safe_error_envelope():
    client = TestClient(create_app())

    response = client.post(
        "/v1/evaluate",
        json={
            "input": {
                "api_key": "sk-live-super-secret-token",
            },
        },
        headers={"X-Request-ID": "req_validation_safe"},
    )

    data = response.json()
    body = response.text.lower()

    assert response.status_code == 422
    assert data["error"]["code"] == "validation_error"
    assert data["error"]["request_id"] == "req_validation_safe"
    assert data["error"]["retryable"] is False
    assert "sk-live-super-secret-token" not in response.text
    assert "traceback" not in body
    assert "/workspaces/" not in body


def test_local_api_unexpected_error_does_not_leak_internal_details():
    client = TestClient(create_app(risk_engine=ExplodingRiskEngine()))

    response = client.post(
        "/v1/evaluate",
        json={
            "tool_name": "file_read",
            "action": "read_file",
            "target": "README.md",
        },
        headers={"X-Request-ID": "req_internal_safe"},
    )

    data = response.json()
    body = response.text.lower()

    assert response.status_code == 500
    assert data["error"]["code"] == "internal_server_error"
    assert data["error"]["request_id"] == "req_internal_safe"
    assert data["error"]["retryable"] is True
    assert "sk-live-super-secret-token" not in response.text
    assert "boom" not in body
    assert "traceback" not in body
    assert "/workspaces/" not in body


def test_local_api_evaluate_response_redacts_secret_like_request_input():
    client = TestClient(create_app())

    response = client.post(
        "/v1/evaluate",
        json={
            "tool_name": "external_api_send",
            "action": "send_data",
            "input": {
                "url": "https://api.example.com/collect",
                "api_key": "sk-live-super-secret-token",
            },
        },
    )

    data = response.json()

    assert response.status_code == 200
    assert "sk-live-super-secret-token" not in response.text
    assert data["request"]["input"]["api_key"] == "[REDACTED]"
