from rygnal.audit_logger import AuditLogger
from rygnal.audit_storage import SQLiteAuditStore
from rygnal.models import Decision, PolicyDecision, Severity, ToolRequest


def make_decision(
    decision: Decision = Decision.BLOCK,
    allowed: bool = False,
    severity: Severity = Severity.HIGH,
    policy_id: str | None = "block-env-read",
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        allowed=allowed,
        severity=severity,
        policy_id=policy_id,
        reason="Test decision.",
    )


def test_sqlite_audit_store_writes_and_reads_event(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.db")
    logger = AuditLogger(tmp_path / "audit.jsonl")

    event = logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target=".env"),
        make_decision(),
    )

    store.write_event(event)

    events = store.read_events()

    assert store.count_events() == 1
    assert len(events) == 1
    assert events[0].event_id == event.event_id
    assert events[0].event_hash == event.event_hash


def test_sqlite_audit_store_gets_event_by_id(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.db")
    logger = AuditLogger(tmp_path / "audit.jsonl")

    event = logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target=".env"),
        make_decision(),
    )

    store.write_event(event)

    found = store.get_event(event.event_id)

    assert found is not None
    assert found.event_id == event.event_id
    assert found.policy_id == "block-env-read"


def test_sqlite_audit_store_finds_events_by_policy_and_decision(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.db")
    logger = AuditLogger(tmp_path / "audit.jsonl")

    blocked = logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target=".env"),
        make_decision(),
    )
    allowed = logger.log_decision(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md"),
        make_decision(
            decision=Decision.ALLOW,
            allowed=True,
            severity=Severity.LOW,
            policy_id=None,
        ),
    )

    store.write_event(blocked)
    store.write_event(allowed)

    blocked_events = store.find_events(decision="block", policy_id="block-env-read")
    allowed_events = store.find_events(decision="allow", allowed=True)

    assert [event.event_id for event in blocked_events] == [blocked.event_id]
    assert [event.event_id for event in allowed_events] == [allowed.event_id]


def test_audit_logger_can_write_to_sqlite_backend(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.db")
    logger = AuditLogger(tmp_path / "audit.jsonl", storage_backend=store)

    event = logger.log_decision(
        ToolRequest(tool_name="shell_command", action="execute", input="rm -rf /tmp/demo"),
        make_decision(
            decision=Decision.BLOCK,
            allowed=False,
            severity=Severity.CRITICAL,
            policy_id="block-dangerous-shell",
        ),
    )

    assert (tmp_path / "audit.jsonl").exists()
    assert store.count_events() == 1

    stored_event = store.get_event(event.event_id)

    assert stored_event is not None
    assert stored_event.policy_id == "block-dangerous-shell"


def test_sqlite_audit_store_limit_read_events(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.db")
    logger = AuditLogger(tmp_path / "audit.jsonl")

    first = logger.log_decision(ToolRequest(tool_name="file_read", target="a.txt"), make_decision())
    second = logger.log_decision(
        ToolRequest(tool_name="file_read", target="b.txt"),
        make_decision(),
    )

    store.write_event(first)
    store.write_event(second)

    events = store.read_events(limit=1)

    assert len(events) == 1
    assert events[0].event_id == first.event_id
