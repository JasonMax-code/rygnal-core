"""Public SDK exports for Rygnal Core.

This module intentionally uses lazy exports instead of eager imports.
Headless entrypoints such as ``python -m rygnal.engine_api`` import the
package initializer before loading the target module, so importing
``rygnal`` must not pull optional web/API dependencies like FastAPI.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "ApprovalWorkflow",
    "AuditEvent",
    "query_audit_events",
    "AuditQueryResult",
    "AuditQueryError",
    "AuditQuery",
    "AuditLogger",
    "CLIApprovalResolver",
    "Decision",
    "ExecutionStatus",
    "GuardedCommandResult",
    "GuardedRunConfig",
    "GuardedRunResult",
    "GuardedRunStatus",
    "InterceptorResult",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyExplanation",
    "PolicyRule",
    "PolicySchema",
    "RiskAssessment",
    "RiskContext",
    "RiskEngine",
    "RiskLevel",
    "RiskScoringProfile",
    "RiskSignal",
    "RiskSignalCategory",
    "RiskSignalRegistry",
    "RuntimeMode",
    "Rygnal",
    "RygnalInterceptor",
    "SQLiteAuditStore",
    "Severity",
    "ToolExecutionResult",
    "ToolExecutor",
    "ToolRequest",
    "approve_for_testing",
    "build_cli_approval_workflow",
    "create_api_app",
    "load_default_policy_engine",
    "reject_by_default",
    "reject_for_testing",
    "run_guarded",
]

_EXPORTS: dict[str, tuple[str, str]] = {
    "ApprovalDecision": ("rygnal.models", "ApprovalDecision"),
    "ApprovalRequest": ("rygnal.models", "ApprovalRequest"),
    "ApprovalStatus": ("rygnal.models", "ApprovalStatus"),
    "ApprovalWorkflow": ("rygnal.approval", "ApprovalWorkflow"),
    "AuditEvent": ("rygnal.models", "AuditEvent"),
    "query_audit_events": ("rygnal.audit_query", "query_audit_events"),
    "AuditQueryResult": ("rygnal.audit_query", "AuditQueryResult"),
    "AuditQueryError": ("rygnal.audit_query", "AuditQueryError"),
    "AuditQuery": ("rygnal.audit_query", "AuditQuery"),
    "AuditLogger": ("rygnal.audit_logger", "AuditLogger"),
    "CLIApprovalResolver": ("rygnal.cli_approval", "CLIApprovalResolver"),
    "Decision": ("rygnal.models", "Decision"),
    "ExecutionStatus": ("rygnal.models", "ExecutionStatus"),
    "GuardedCommandResult": ("rygnal.guarded_runner", "GuardedCommandResult"),
    "GuardedRunConfig": ("rygnal.guarded_runner", "GuardedRunConfig"),
    "GuardedRunResult": ("rygnal.guarded_runner", "GuardedRunResult"),
    "GuardedRunStatus": ("rygnal.guarded_runner", "GuardedRunStatus"),
    "InterceptorResult": ("rygnal.models", "InterceptorResult"),
    "PolicyDecision": ("rygnal.models", "PolicyDecision"),
    "PolicyEngine": ("rygnal.policy_engine", "PolicyEngine"),
    "PolicyExplanation": ("rygnal.models", "PolicyExplanation"),
    "PolicyRule": ("rygnal.models", "PolicyRule"),
    "PolicySchema": ("rygnal.models", "PolicySchema"),
    "RiskAssessment": ("rygnal.risk_engine", "RiskAssessment"),
    "RiskContext": ("rygnal.risk_engine", "RiskContext"),
    "RiskEngine": ("rygnal.risk_engine", "RiskEngine"),
    "RiskLevel": ("rygnal.risk_engine", "RiskLevel"),
    "RiskScoringProfile": ("rygnal.risk_engine", "RiskScoringProfile"),
    "RiskSignal": ("rygnal.risk_engine", "RiskSignal"),
    "RiskSignalCategory": ("rygnal.risk_engine", "RiskSignalCategory"),
    "RiskSignalRegistry": ("rygnal.risk_engine", "RiskSignalRegistry"),
    "RuntimeMode": ("rygnal.models", "RuntimeMode"),
    "Rygnal": ("rygnal.core", "Rygnal"),
    "RygnalInterceptor": ("rygnal.interceptor", "RygnalInterceptor"),
    "SQLiteAuditStore": ("rygnal.audit_storage", "SQLiteAuditStore"),
    "Severity": ("rygnal.models", "Severity"),
    "ToolExecutionResult": ("rygnal.models", "ToolExecutionResult"),
    "ToolExecutor": ("rygnal.tool_executor", "ToolExecutor"),
    "ToolRequest": ("rygnal.models", "ToolRequest"),
    "approve_for_testing": ("rygnal.approval", "approve_for_testing"),
    "build_cli_approval_workflow": ("rygnal.cli_approval", "build_cli_approval_workflow"),
    "create_api_app": ("rygnal.api", "create_app"),
    "load_default_policy_engine": ("rygnal.policy_engine", "load_default_policy_engine"),
    "reject_by_default": ("rygnal.approval", "reject_by_default"),
    "reject_for_testing": ("rygnal.approval", "reject_for_testing"),
    "run_guarded": ("rygnal.guarded_runner", "run_guarded"),
}


def __getattr__(name: str) -> Any:
    try:
        module_name, source_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    module = __import__(module_name, fromlist=[source_name])
    value = getattr(module, source_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *__all__))
