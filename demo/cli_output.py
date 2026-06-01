"""CLI output formatting for Rygnal scenario runs."""

from __future__ import annotations

from typing import Any


def render_run_report(outcomes: list[Any]) -> str:
    """Render a complete CLI report for scenario outcomes."""
    lines = [
        "",
        "Rygnal Real Scenario Runner v1",
        "=" * 36,
        "",
    ]

    for index, outcome in enumerate(outcomes, start=1):
        lines.extend(render_outcome(outcome, index=index))
        lines.append("")

    lines.extend(
        [
            "Summary",
            "-" * 36,
            f"Total scenarios: {len(outcomes)}",
            "Audit log: logs/audit_log.jsonl",
            "Sandbox: demo_sandbox/",
        ]
    )

    return "\n".join(lines)


def render_outcome(outcome: Any, index: int) -> list[str]:
    """Render one scenario outcome as readable CLI lines."""
    scenario = outcome.scenario
    result = outcome.result

    risk = normalize_risk(result.risk_assessment)
    policy_decision = result.policy_decision
    execution = result.execution
    audit_event = result.audit_event

    decision = enum_value(policy_decision.decision).upper()
    execution_status = enum_value(execution.status)
    runtime_mode = enum_value(getattr(result, "runtime_mode", "unknown"))

    risk_level = enum_value(risk.get("risk_level", "unknown"))
    risk_score = risk.get("risk_score", "n/a")

    policy_id = policy_decision.policy_id or "default-allow"
    reason = policy_decision.reason
    tool_name = scenario.request.tool_name
    action = scenario.request.action or "n/a"
    target = scenario.request.target or "n/a"

    return [
        f"{index}. [{decision}] {scenario.name}",
        f"   Description : {scenario.description}",
        f"   Tool        : {tool_name}",
        f"   Action      : {action}",
        f"   Target      : {target}",
        f"   Runtime     : {runtime_mode}",
        f"   Risk        : {risk_level} / {risk_score}",
        f"   Policy      : {policy_id}",
        f"   Execution   : {execution_status}",
        f"   Reason      : {reason}",
        f"   Audit Event : {audit_event.event_id}",
    ]


def normalize_risk(risk_assessment: Any) -> dict[str, Any]:
    """Normalize risk assessment from dict or Pydantic model."""
    if isinstance(risk_assessment, dict):
        return risk_assessment

    if hasattr(risk_assessment, "model_dump"):
        return risk_assessment.model_dump(mode="json")

    return {}


def enum_value(value: Any) -> str:
    """Return enum value or plain string."""
    return str(getattr(value, "value", value))
