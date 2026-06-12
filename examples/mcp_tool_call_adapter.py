"""MCP-style tool-call adapter protected by Rygnal.

This adapter does not require a live MCP server.
It accepts an MCP-style tools/call payload and routes it through Rygnal.
"""

from __future__ import annotations

from typing import Any

from examples.shared import build_demo_rygnal
from rygnal import Decision, ExecutionStatus, Rygnal, ToolRequest

__all__ = ("build_demo_rygnal", "handle_mcp_tool_call")


def handle_mcp_tool_call(payload: dict[str, Any], rygnal: Rygnal) -> dict[str, Any]:
    """Handle one MCP-style tool call through Rygnal."""
    params = payload.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {}) or {}

    request = ToolRequest(
        tool_name=tool_name,
        action=arguments.get("action"),
        target=arguments.get("target"),
        input=arguments.get("input"),
        metadata={
            "source": "mcp_tool_call",
            "mcp_request_id": payload.get("id"),
            "mcp_method": payload.get("method"),
        },
    )

    result = rygnal.intercept(request)
    risk = _normalize_risk(result.risk_assessment)

    return {
        "jsonrpc": payload.get("jsonrpc", "2.0"),
        "id": payload.get("id"),
        "allowed": result.policy_decision.decision == Decision.ALLOW,
        "executed": result.execution.status == ExecutionStatus.EXECUTED,
        "decision": _value(result.policy_decision.decision),
        "execution_status": _value(result.execution.status),
        "risk_score": risk.get("risk_score"),
        "risk_level": risk.get("risk_level"),
        "reason": result.policy_decision.reason,
        "audit_event_id": result.audit_event.event_id,
        "result": result.execution.output if result.execution.executed else None,
    }


def _normalize_risk(risk_assessment: Any) -> dict[str, Any]:
    if isinstance(risk_assessment, dict):
        return risk_assessment

    if hasattr(risk_assessment, "model_dump"):
        return risk_assessment.model_dump(mode="json")

    return {}


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))
