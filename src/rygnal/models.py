"""Shared data models for Rygnal."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def new_event_id() -> str:
    """Return a unique audit event ID."""
    return f"evt_{uuid4().hex}"


def new_trace_id() -> str:
    """Return a unique trace ID."""
    return f"trace_{uuid4().hex}"


def new_approval_id() -> str:
    """Return a unique approval request ID."""
    return f"apr_{uuid4().hex}"


class Decision(StrEnum):
    """Possible policy decisions."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    SIMULATE = "simulate"


class Severity(StrEnum):
    """Risk severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(StrEnum):
    """Tool execution status."""

    EXECUTED = "executed"
    SKIPPED = "skipped"
    FAILED = "failed"
    SIMULATED = "simulated"


class ApprovalStatus(StrEnum):
    """Approval lifecycle status."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class RuntimeMode(StrEnum):
    """Rygnal execution runtime modes."""

    OBSERVE = "observe"
    SIMULATE = "simulate"
    ENFORCE = "enforce"


class ToolRequest(BaseModel):
    """A tool action requested by an AI agent."""

    tool_name: str
    action: str | None = None
    target: str | None = None
    input: Any | None = None
    user_id: str = "demo_user"
    agent_id: str = "demo_agent"
    environment: str = "local"
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyRule(BaseModel):
    """A single policy rule."""

    id: str
    decision: Decision
    severity: Severity = Severity.LOW
    reason: str
    priority: int = Field(default=100, ge=0, le=1000)

    tool_name: str | None = None
    action: str | None = None
    environment: str | None = None
    target_contains: str | None = None
    input_contains: str | None = None


class PolicySchema(BaseModel):
    """Validated policy file schema."""

    policy_version: str = "policy.v1"
    rules: list[PolicyRule] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    """Policy evaluation result."""

    decision: Decision
    allowed: bool
    severity: Severity
    reason: str
    policy_id: str | None = None


class ApprovalRequest(BaseModel):
    """Approval request created for human-reviewed actions."""

    approval_id: str = Field(default_factory=new_approval_id)
    created_at: str = Field(default_factory=utc_now_iso)
    trace_id: str = Field(default_factory=new_trace_id)

    requested_by: str
    agent_id: str
    environment: str

    tool_name: str
    action: str | None = None
    target: Any | None = None
    policy_id: str | None = None
    reason: str
    risk_assessment: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    """Human approval result."""

    approval_id: str
    status: ApprovalStatus
    approved: bool
    decided_by: str | None = None
    decided_at: str | None = None
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    """Tamper-evident audit event for an AI-agent tool decision."""

    schema_version: str = "audit.v1"
    event_id: str = Field(default_factory=new_event_id)
    timestamp: str = Field(default_factory=utc_now_iso)
    trace_id: str = Field(default_factory=new_trace_id)

    user_id: str
    agent_id: str
    environment: str

    tool_name: str
    action: str | None = None
    target: Any | None = None
    input: Any | None = None

    decision: Decision
    allowed: bool
    severity: Severity
    policy_id: str | None = None
    reason: str

    metadata: dict[str, Any] = Field(default_factory=dict)
    prev_event_hash: str | None = None
    event_hash: str | None = None


class ToolExecutionResult(BaseModel):
    """Result of a tool execution attempt."""

    status: ExecutionStatus
    executed: bool
    output: Any | None = None
    error: str | None = None


class InterceptorResult(BaseModel):
    """Final result returned by the Rygnal interceptor."""

    request: ToolRequest
    risk_assessment: dict[str, Any]
    policy_decision: PolicyDecision
    audit_event: AuditEvent
    execution: ToolExecutionResult
    approval_decision: ApprovalDecision | None = None
