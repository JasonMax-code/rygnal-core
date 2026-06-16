import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from rygnal.audit_logger import AuditLogger
from rygnal.models import Decision, PolicyDecision, Severity, ToolRequest


def make_decision(
    *,
    decision: Decision,
    allowed: bool,
    severity: Severity,
    policy_id: str | None,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        allowed=allowed,
        severity=severity,
        policy_id=policy_id,
        reason=f"{decision.value} decision.",
    )


def write_event(
    logger: AuditLogger,
    *,
    tool_name: str,
    action: str | None,
    target: str,
    trace_id: str,
    decision: Decision,
    allowed: bool,
    severity: Severity,
    policy_id: str | None,
):
    return logger.log_decision(
        ToolRequest(
            tool_name=tool_name,
            action=action,
            target=target,
            metadata={"trace_id": trace_id},
        ),
        make_decision(
            decision=decision,
            allowed=allowed,
            severity=severity,
            policy_id=policy_id,
        ),
        metadata={
            "source": "test",
            "secret_token": "super-secret-token",
            "nested": {"api_key": "super-secret-api-key", "safe": "visible"},
        },
    )


def test_query_audit_events_filters_and_paginates_jsonl(tmp_path: Path) -> None:
    from rygnal.audit_query import AuditQuery, query_audit_events

    logger = AuditLogger(tmp_path / "audit.jsonl")
    first = write_event(
        logger,
        tool_name="file_read",
        action="read_file",
        target=".env",
        trace_id="trace_1",
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.HIGH,
        policy_id="block-env-read",
    )
    second = write_event(
        logger,
        tool_name="shell_command",
        action="execute",
        target="npm test",
        trace_id="trace_2",
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        policy_id=None,
    )
    third = write_event(
        logger,
        tool_name="file_write",
        action="write_file",
        target="src/app.py",
        trace_id="trace_1",
        decision=Decision.REQUIRE_APPROVAL,
        allowed=False,
        severity=Severity.HIGH,
        policy_id="guarded-workspace-risky-patch-approval",
    )

    result = query_audit_events(
        logger.log_path,
        AuditQuery(trace_id="trace_1", limit=1, offset=1),
    )

    assert result.total_matching == 2
    assert result.returned_count == 1
    assert result.events[0].event_id == third.event_id
    assert result.events[0].trace_id == "trace_1"
    assert result.events[0].metadata["nested"]["safe"] == "visible"

    allow_result = query_audit_events(
        logger.log_path,
        AuditQuery(decision="allow", tool_name="shell_command"),
    )
    assert [event.event_id for event in allow_result.events] == [second.event_id]

    blocked_result = query_audit_events(
        logger.log_path,
        AuditQuery(severity="high", policy_id="block-env-read"),
    )
    assert [event.event_id for event in blocked_result.events] == [first.event_id]


def test_query_audit_events_supports_time_range_and_newest_first(tmp_path: Path) -> None:
    from rygnal.audit_query import AuditQuery, query_audit_events

    logger = AuditLogger(tmp_path / "audit.jsonl")
    first = write_event(
        logger,
        tool_name="file_read",
        action="read_file",
        target="README.md",
        trace_id="trace_time",
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        policy_id=None,
    )
    second = write_event(
        logger,
        tool_name="file_write",
        action="write_file",
        target="src/app.py",
        trace_id="trace_time",
        decision=Decision.REQUIRE_APPROVAL,
        allowed=False,
        severity=Severity.HIGH,
        policy_id="approval-required",
    )

    lines = [json.loads(line) for line in logger.log_path.read_text().splitlines()]
    old_time = datetime(2026, 1, 1, tzinfo=UTC)
    new_time = datetime(2026, 1, 2, tzinfo=UTC)
    lines[0]["timestamp"] = old_time.isoformat()
    lines[1]["timestamp"] = new_time.isoformat()
    logger.log_path.write_text(
        "\n".join(json.dumps(line, sort_keys=True) for line in lines) + "\n",
        encoding="utf-8",
    )

    result = query_audit_events(
        logger.log_path,
        AuditQuery(
            since=(old_time + timedelta(hours=12)).isoformat(),
            newest_first=True,
        ),
    )

    assert result.total_matching == 1
    assert [event.event_id for event in result.events] == [second.event_id]
    assert first.event_id not in {event.event_id for event in result.events}


def test_query_audit_events_handles_corrupt_jsonl_without_throwing(tmp_path: Path) -> None:
    from rygnal.audit_query import AuditQuery, query_audit_events

    logger = AuditLogger(tmp_path / "audit.jsonl")
    valid = write_event(
        logger,
        tool_name="file_read",
        action="read_file",
        target="README.md",
        trace_id="trace_valid",
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        policy_id=None,
    )

    logger.log_path.write_text(
        logger.log_path.read_text(encoding="utf-8") + "{not valid json}\n",
        encoding="utf-8",
    )

    result = query_audit_events(logger.log_path, AuditQuery())

    assert result.returned_count == 1
    assert result.events[0].event_id == valid.event_id
    assert result.malformed_count == 1
    assert result.warnings


def test_query_audit_events_never_returns_raw_secrets(tmp_path: Path) -> None:
    from rygnal.audit_query import AuditQuery, query_audit_events

    logger = AuditLogger(tmp_path / "audit.jsonl")
    write_event(
        logger,
        tool_name="external_api_send",
        action="send_data",
        target="https://example.com",
        trace_id="trace_secret",
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.CRITICAL,
        policy_id="block-secret-exfiltration",
    )

    result = query_audit_events(logger.log_path, AuditQuery())

    payload = json.dumps(result.to_dict(), sort_keys=True)
    assert "super-secret-token" not in payload
    assert "super-secret-api-key" not in payload
    assert "[REDACTED]" in payload


def test_query_audit_events_enforces_limit_bounds(tmp_path: Path) -> None:
    from rygnal.audit_query import AuditQuery, AuditQueryError, query_audit_events

    logger = AuditLogger(tmp_path / "audit.jsonl")
    write_event(
        logger,
        tool_name="file_read",
        action="read_file",
        target="README.md",
        trace_id="trace_limit",
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        policy_id=None,
    )

    try:
        query_audit_events(logger.log_path, AuditQuery(limit=10_000))
    except AuditQueryError as exc:
        assert "limit" in str(exc)
    else:
        raise AssertionError("Expected oversized limit to fail")


def test_audit_query_public_exports_are_lazy_importable() -> None:
    import rygnal

    assert rygnal.AuditQuery.__name__ == "AuditQuery"
    assert rygnal.AuditQueryResult.__name__ == "AuditQueryResult"
    assert rygnal.AuditQueryError.__name__ == "AuditQueryError"
    assert callable(rygnal.query_audit_events)
