from examples import (
    langchain_tool_wrapper,
    mcp_tool_call_adapter,
    openai_tool_calling_adapter,
)
from examples.shared import build_demo_rygnal
from rygnal.models import Decision, ExecutionStatus, ToolRequest


def test_example_adapters_reuse_shared_demo_rygnal_helper() -> None:
    assert mcp_tool_call_adapter.build_demo_rygnal is build_demo_rygnal
    assert langchain_tool_wrapper.build_demo_rygnal is build_demo_rygnal
    assert openai_tool_calling_adapter.build_demo_rygnal is build_demo_rygnal


def test_shared_demo_rygnal_registers_file_read_handler(tmp_path) -> None:
    rygnal = build_demo_rygnal(str(tmp_path / "audit_log.jsonl"))

    result = rygnal.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.policy_decision.decision == Decision.ALLOW
    assert result.execution.status == ExecutionStatus.EXECUTED
    assert result.execution.output == {
        "target": "README.md",
        "content": "demo content from README.md",
    }
