"""LangChain tool wrapper protected by Rygnal."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from rygnal import Decision, ExecutionStatus, Rygnal, ToolRequest


def build_rygnal_file_read_tool(rygnal: Rygnal) -> StructuredTool:
    """Build a LangChain-compatible file read tool protected by Rygnal."""

    def protected_file_read(target: str) -> dict[str, Any]:
        """Read a file through Rygnal policy, risk, approval, and audit controls."""
        result = rygnal.intercept(
            ToolRequest(
                tool_name="file_read",
                action="read_file",
                target=target,
            )
        )

        risk = _normalize_risk(result.risk_assessment)
        decision = _value(result.policy_decision.decision)
        execution_status = _value(result.execution.status)

        return {
            "allowed": result.policy_decision.decision == Decision.ALLOW,
            "executed": result.execution.status == ExecutionStatus.EXECUTED,
            "decision": decision,
            "execution_status": execution_status,
            "risk_score": risk.get("risk_score"),
            "risk_level": risk.get("risk_level"),
            "reason": result.policy_decision.reason,
            "audit_event_id": result.audit_event.event_id,
            "output": result.execution.output if result.execution.executed else None,
        }

    return StructuredTool.from_function(
        func=protected_file_read,
        name="rygnal_file_read",
        description=(
            "Read a file only after Rygnal evaluates risk, policy, approval, "
            "execution safety, and audit logging."
        ),
    )


def build_demo_rygnal(audit_log_path: str) -> Rygnal:
    """Build a demo Rygnal instance with a simple registered file read handler."""
    rygnal = Rygnal.from_defaults(audit_log_path=audit_log_path)

    def safe_file_read(request: ToolRequest) -> dict[str, str | None]:
        return {
            "target": request.target,
            "content": f"demo content from {request.target}",
        }

    rygnal.register_tool("file_read", safe_file_read)
    return rygnal


def _normalize_risk(risk_assessment: Any) -> dict[str, Any]:
    if isinstance(risk_assessment, dict):
        return risk_assessment

    if hasattr(risk_assessment, "model_dump"):
        return risk_assessment.model_dump(mode="json")

    return {}


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))
