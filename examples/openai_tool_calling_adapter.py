"""OpenAI-style tool-calling adapter protected by Rygnal.

This adapter does not call the OpenAI API.
It accepts an OpenAI-style tool call payload and routes it through Rygnal.
"""

from __future__ import annotations

import json
from typing import Any

from examples.shared import build_demo_rygnal
from rygnal import Decision, ExecutionStatus, Rygnal, ToolRequest

__all__ = ("build_demo_rygnal", "handle_openai_tool_call")


def handle_openai_tool_call(tool_call: dict[str, Any], rygnal: Rygnal) -> dict[str, Any]:
    """Handle one OpenAI-style tool call through Rygnal."""
    function = tool_call.get("function", {})
    tool_name = function.get("name", "")
    raw_arguments = function.get("arguments", "{}")

    arguments = _parse_arguments(raw_arguments)

    request = ToolRequest(
        tool_name=tool_name,
        action=arguments.get("action"),
        target=arguments.get("target"),
        input=arguments.get("input"),
        metadata={
            "source": "openai_tool_call",
            "tool_call_id": tool_call.get("id"),
            "tool_type": tool_call.get("type"),
        },
    )

    result = rygnal.intercept(request)
    risk = _normalize_risk(result.risk_assessment)

    return {
        "tool_call_id": tool_call.get("id"),
        "allowed": result.policy_decision.decision == Decision.ALLOW,
        "executed": result.execution.status == ExecutionStatus.EXECUTED,
        "decision": _value(result.policy_decision.decision),
        "execution_status": _value(result.execution.status),
        "risk_score": risk.get("risk_score"),
        "risk_level": risk.get("risk_level"),
        "reason": result.policy_decision.reason,
        "audit_event_id": result.audit_event.event_id,
        "output": result.execution.output if result.execution.executed else None,
    }


def _parse_arguments(raw_arguments: Any) -> dict[str, Any]:
    if isinstance(raw_arguments, dict):
        return raw_arguments

    if not raw_arguments:
        return {}

    try:
        parsed = json.loads(raw_arguments)
    except json.JSONDecodeError:
        return {"input": raw_arguments}

    if isinstance(parsed, dict):
        return parsed

    return {"input": parsed}


def _normalize_risk(risk_assessment: Any) -> dict[str, Any]:
    if isinstance(risk_assessment, dict):
        return risk_assessment

    if hasattr(risk_assessment, "model_dump"):
        return risk_assessment.model_dump(mode="json")

    return {}


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))
