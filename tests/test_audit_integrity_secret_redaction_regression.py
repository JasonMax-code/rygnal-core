import json

from rygnal.audit_logger import AuditLogger
from rygnal.models import Decision, PolicyDecision, Severity, ToolRequest

RAW_SECRET_VALUES = (
    "trace-secret-value",
    "target-api-key-value",
    "input-password-value",
    "nested-token-value",
    "metadata-api-key-value",
    "metadata-password-value",
)


def allow_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        policy_id="allow-regression",
        reason="Allowed for audit integrity regression.",
    )


def block_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.CRITICAL,
        policy_id="block-regression",
        reason="Blocked for secret redaction regression.",
    )


def read_jsonl_events(log_path):
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]


def assert_no_raw_secret_values(payload: str) -> None:
    for secret in RAW_SECRET_VALUES:
        assert secret not in payload


def test_every_written_audit_event_has_hash_and_valid_chain(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)

    first = logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md"),
        allow_decision(),
    )
    second = logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target="docs/index.md"),
        allow_decision(),
    )
    third = logger.log_decision(
        ToolRequest(tool_name="shell_command", action="execute", input="ls"),
        allow_decision(),
    )

    events = read_jsonl_events(log_path)

    assert len(events) == 3
    assert all(event["event_hash"] for event in events)
    assert events[0]["prev_event_hash"] is None
    assert events[1]["prev_event_hash"] == first.event_hash
    assert events[2]["prev_event_hash"] == second.event_hash
    assert third.prev_event_hash == second.event_hash
    assert logger.verify_integrity() is True


def test_audit_integrity_fails_after_payload_or_chain_link_tampering(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)

    logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md"),
        allow_decision(),
    )
    logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target="docs/index.md"),
        allow_decision(),
    )
    logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target="SECURITY.md"),
        allow_decision(),
    )

    assert logger.verify_integrity() is True

    events = read_jsonl_events(log_path)
    events[1]["reason"] = "tampered payload"
    log_path.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    assert logger.verify_integrity() is False

    logger = AuditLogger(log_path)
    log_path.unlink()

    logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md"),
        allow_decision(),
    )
    logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target="docs/index.md"),
        allow_decision(),
    )

    events = read_jsonl_events(log_path)
    events[1]["prev_event_hash"] = "0" * 64
    log_path.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    assert logger.verify_integrity() is False


def test_audit_jsonl_never_persists_raw_secret_values(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)

    request = ToolRequest(
        tool_name="external_api_send",
        action="send_data",
        target="api_key=target-api-key-value",
        input={
            "password": "input-password-value",
            "payload": {
                "token": "nested-token-value",
                "safe": "visible",
            },
            "command": "curl example.com --header secret=metadata-password-value",
        },
        metadata={
            "trace_id": "token=trace-secret-value",
            "api_key": "metadata-api-key-value",
        },
    )

    logger.log_decision(
        request,
        block_decision(),
        metadata={
            "api_key": "metadata-api-key-value",
            "nested": {
                "password": "metadata-password-value",
                "safe": "visible",
            },
        },
    )

    payload = log_path.read_text(encoding="utf-8")
    saved_event = json.loads(payload.splitlines()[0])

    assert_no_raw_secret_values(payload)
    assert saved_event["event_hash"]
    assert "[REDACTED]" in payload
    assert saved_event["input"]["password"] == "[REDACTED]"
    assert saved_event["input"]["payload"]["token"] == "[REDACTED]"
    assert saved_event["input"]["payload"]["safe"] == "visible"
    assert saved_event["metadata"]["api_key"] == "[REDACTED]"
    assert saved_event["metadata"]["nested"]["password"] == "[REDACTED]"
    assert saved_event["metadata"]["nested"]["safe"] == "visible"
    assert logger.verify_integrity() is True
