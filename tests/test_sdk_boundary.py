from pathlib import Path

from rygnal import (
    ApprovalWorkflow,
    AuditLogger,
    Decision,
    PolicyEngine,
    RiskEngine,
    RuntimeMode,
    Rygnal,
    RygnalInterceptor,
    ToolExecutor,
    ToolRequest,
)


def test_public_sdk_imports_work():
    assert Rygnal is not None
    assert RygnalInterceptor is not None
    assert ToolRequest is not None
    assert ToolExecutor is not None
    assert PolicyEngine is not None
    assert RiskEngine is not None
    assert AuditLogger is not None
    assert ApprovalWorkflow is not None
    assert RuntimeMode.ENFORCE == "enforce"


def test_rygnal_wrapper_allows_safe_registered_tool(tmp_path):
    rygnal = Rygnal.from_defaults(audit_log_path=tmp_path / "audit_log.jsonl")

    rygnal.register_tool(
        "file_read",
        lambda request: {"ok": True, "target": request.target, "content": "safe"},
    )

    result = rygnal.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.policy_decision.decision == Decision.ALLOW
    assert result.execution.executed is True
    assert result.execution.output["content"] == "safe"


def test_rygnal_wrapper_blocks_secret_file_before_execution(tmp_path):
    rygnal = Rygnal.from_defaults(audit_log_path=tmp_path / "audit_log.jsonl")
    called = {"value": False}

    def unsafe_read(request: ToolRequest) -> dict[str, str]:
        called["value"] = True
        return {"target": request.target or ""}

    rygnal.register_tool("file_read", unsafe_read)

    result = rygnal.intercept(ToolRequest(tool_name="file_read", action="read_file", target=".env"))

    assert result.policy_decision.decision == Decision.BLOCK
    assert result.execution.executed is False
    assert called["value"] is False


def test_rygnal_wrapper_writes_audit_log(tmp_path):
    audit_log_path = tmp_path / "audit_log.jsonl"
    rygnal = Rygnal.from_defaults(audit_log_path=audit_log_path)

    rygnal.register_tool(
        "file_read",
        lambda request: {"ok": True, "target": request.target},
    )

    result = rygnal.handle(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert Path(audit_log_path).exists()
    assert result.audit_event.event_id
