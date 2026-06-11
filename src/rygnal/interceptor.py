"""Rygnal interceptor.

The interceptor is the runtime control point between AI agents and tools.
"""

from typing import Any

from rygnal.approval import ApprovalWorkflow
from rygnal.audit_logger import AuditLogger
from rygnal.models import (
    ApprovalDecision,
    Decision,
    ExecutionStatus,
    InterceptorResult,
    RuntimeMode,
    ToolExecutionResult,
    ToolRequest,
)
from rygnal.policy_engine import PolicyEngine
from rygnal.risk_engine import RiskEngine
from rygnal.tool_executor import ToolExecutor


class RygnalInterceptor:
    """Intercept AI-agent tool requests before execution."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        tool_executor: ToolExecutor,
        risk_engine: RiskEngine | None = None,
        approval_workflow: ApprovalWorkflow | None = None,
        runtime_mode: RuntimeMode | None = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.tool_executor = tool_executor
        self.risk_engine = risk_engine or RiskEngine()
        self.approval_workflow = approval_workflow
        self.runtime_mode = runtime_mode or RuntimeMode.ENFORCE

    def intercept(self, request: ToolRequest) -> InterceptorResult:
        """Assess risk, evaluate policy, audit, and optionally execute a tool request."""
        risk_assessment = self.risk_engine.assess(request)
        risk_metadata = self._risk_metadata(risk_assessment)

        policy_decision = self.policy_engine.evaluate(request, risk_assessment=risk_assessment)
        approval_decision: ApprovalDecision | None = None

        # Flatten risk metadata to top level for backward compatibility
        audit_metadata: dict[str, Any] = risk_metadata.copy()
        audit_metadata["runtime_mode"] = self.runtime_mode.value

        policy_explanation = self._policy_explanation_metadata(policy_decision)
        if policy_explanation:
            audit_metadata["policy_explanation"] = policy_explanation

        if policy_decision.decision == Decision.REQUIRE_APPROVAL:
            approval_workflow = self.approval_workflow or ApprovalWorkflow()
            approval_request, approval_decision = approval_workflow.request_approval(
                request=request,
                policy_decision=policy_decision,
                risk_assessment=risk_metadata,
            )
            audit_metadata["approval"] = {
                "approval_id": approval_request.approval_id,
                "status": approval_decision.status,
                "approved": approval_decision.approved,
                "decided_by": approval_decision.decided_by,
                "decided_at": approval_decision.decided_at,
                "reason": approval_decision.reason,
            }

        audit_event = self.audit_logger.log_decision(
            request=request,
            policy_decision=policy_decision,
            metadata=audit_metadata,
        )

        execution = self._execute_with_decision(
            request=request,
            policy_decision=policy_decision,
            approval_decision=approval_decision,
        )

        return InterceptorResult(
            request=request,
            risk_assessment=risk_metadata,
            policy_decision=policy_decision,
            audit_event=audit_event,
            execution=execution,
            approval_decision=approval_decision,
        )

    def handle(self, request: ToolRequest) -> InterceptorResult:
        """Alias for intercept."""
        return self.intercept(request)

    def _execute_with_decision(
        self,
        request: ToolRequest,
        policy_decision: Any,
        approval_decision: ApprovalDecision | None,
    ) -> ToolExecutionResult:
        # In OBSERVE mode, never execute - just skip
        if self.runtime_mode == RuntimeMode.OBSERVE:
            return ToolExecutionResult(
                status=ExecutionStatus.SKIPPED,
                executed=False,
                error="Tool execution skipped: Rygnal is in observe mode.",
            )

        # In SIMULATE mode, never execute actual tools - simulate or skip
        if self.runtime_mode == RuntimeMode.SIMULATE:
            if policy_decision.decision == Decision.ALLOW:
                return ToolExecutionResult(
                    status=ExecutionStatus.SIMULATED,
                    executed=False,
                    output="Simulated tool execution (simulate mode).",
                )
            return ToolExecutionResult(
                status=ExecutionStatus.SKIPPED,
                executed=False,
                error=f"Tool execution skipped (simulate mode): {policy_decision.decision}",
            )

        # In ENFORCE mode, respect policy decisions
        if self.runtime_mode == RuntimeMode.ENFORCE:
            if policy_decision.decision == Decision.ALLOW:
                return self.tool_executor.execute(request)

            if policy_decision.decision == Decision.SIMULATE:
                return ToolExecutionResult(
                    status=ExecutionStatus.SIMULATED,
                    executed=False,
                    output="Simulated decision. Tool was not executed.",
                )

            if policy_decision.decision == Decision.REQUIRE_APPROVAL:
                if approval_decision and approval_decision.approved:
                    return self.tool_executor.execute(request)

                return ToolExecutionResult(
                    status=ExecutionStatus.SKIPPED,
                    executed=False,
                    error="Tool execution skipped because approval was not granted.",
                )

            return ToolExecutionResult(
                status=ExecutionStatus.SKIPPED,
                executed=False,
                error=f"Tool execution skipped because decision is: {policy_decision.decision}",
            )

        # Fallback
        return ToolExecutionResult(
            status=ExecutionStatus.SKIPPED,
            executed=False,
            error=f"Tool execution skipped: unknown runtime mode {self.runtime_mode}",
        )

    @staticmethod
    def _policy_explanation_metadata(policy_decision: Any) -> dict[str, Any]:
        explanation = getattr(policy_decision, "explanation", None)

        if explanation is None:
            return {}

        if hasattr(explanation, "model_dump"):
            return explanation.model_dump(mode="json")

        if isinstance(explanation, dict):
            return explanation

        return {}

    @staticmethod
    def _risk_metadata(risk_assessment: Any) -> dict[str, Any]:
        if hasattr(risk_assessment, "model_dump"):
            return risk_assessment.model_dump(mode="json")

        if isinstance(risk_assessment, dict):
            return risk_assessment

        return {}
