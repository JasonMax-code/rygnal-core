from pathlib import Path

from examples.langchain_tool_wrapper import build_demo_rygnal, build_rygnal_file_read_tool


def test_langchain_tool_allows_safe_file_read(tmp_path):
    audit_log_path = tmp_path / "audit_log.jsonl"
    rygnal = build_demo_rygnal(str(audit_log_path))
    tool = build_rygnal_file_read_tool(rygnal)

    result = tool.invoke({"target": "README.md"})

    assert result["allowed"] is True
    assert result["executed"] is True
    assert result["decision"] == "allow"
    assert result["execution_status"] == "executed"
    assert result["risk_level"] == "low"
    assert result["audit_event_id"]
    assert result["output"]["target"] == "README.md"
    assert Path(audit_log_path).exists()


def test_langchain_tool_blocks_secret_file_read(tmp_path):
    audit_log_path = tmp_path / "audit_log.jsonl"
    rygnal = build_demo_rygnal(str(audit_log_path))
    tool = build_rygnal_file_read_tool(rygnal)

    result = tool.invoke({"target": ".env"})

    assert result["allowed"] is False
    assert result["executed"] is False
    assert result["decision"] == "block"
    assert result["execution_status"] == "skipped"
    assert result["risk_level"] == "critical"
    assert result["audit_event_id"]
    assert result["output"] is None
    assert Path(audit_log_path).exists()
