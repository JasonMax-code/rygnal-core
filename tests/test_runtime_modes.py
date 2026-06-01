"""Tests for runtime modes (observe, simulate, enforce)."""

from pathlib import Path

from rygnal.audit_logger import AuditLogger
from rygnal.interceptor import RygnalInterceptor
from rygnal.models import ExecutionStatus, RuntimeMode, ToolRequest
from rygnal.policy_engine import load_default_policy_engine
from rygnal.risk_engine import RiskEngine
from rygnal.tool_executor import ToolExecutor


def build_interceptor(
    tmp_path: Path,
    runtime_mode: RuntimeMode = RuntimeMode.ENFORCE,
) -> RygnalInterceptor:
    """Build an interceptor with specified runtime mode."""
    executor = ToolExecutor()
    logger = AuditLogger(tmp_path / "audit_log.jsonl")

    return RygnalInterceptor(
        policy_engine=load_default_policy_engine(),
        audit_logger=logger,
        tool_executor=executor,
        risk_engine=RiskEngine(),
        runtime_mode=runtime_mode,
    )


def test_observe_mode_never_executes_allowed_tools(tmp_path):
    """In observe mode, allowed tools are never executed."""
    interceptor = build_interceptor(tmp_path, runtime_mode=RuntimeMode.OBSERVE)
    called = {"value": False}

    def safe_read(request: ToolRequest) -> dict[str, str]:
        called["value"] = True
        return {"target": request.target or "", "content": "safe"}

    interceptor.tool_executor.register("file_read", safe_read)

    result = interceptor.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert called["value"] is False
    assert result.audit_event.metadata["runtime_mode"] == "observe"


def test_observe_mode_logs_risky_actions(tmp_path):
    """In observe mode, risky actions are logged but not executed."""
    interceptor = build_interceptor(tmp_path, runtime_mode=RuntimeMode.OBSERVE)
    called = {"value": False}

    def delete_file(request: ToolRequest) -> dict[str, str]:
        called["value"] = True
        return {"deleted": request.target or ""}

    interceptor.tool_executor.register("file_delete", delete_file)

    result = interceptor.intercept(
        ToolRequest(
            tool_name="file_delete",
            action="delete_file",
            target="customer_data.csv",
        )
    )

    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert called["value"] is False
    assert result.audit_event.metadata["runtime_mode"] == "observe"


def test_simulate_mode_never_executes_tools(tmp_path):
    """In simulate mode, tools are never executed."""
    interceptor = build_interceptor(tmp_path, runtime_mode=RuntimeMode.SIMULATE)
    called = {"value": False}

    def safe_read(request: ToolRequest) -> dict[str, str]:
        called["value"] = True
        return {"target": request.target or "", "content": "safe"}

    interceptor.tool_executor.register("file_read", safe_read)

    result = interceptor.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.execution.status == ExecutionStatus.SIMULATED
    assert result.execution.executed is False
    assert called["value"] is False
    assert result.audit_event.metadata["runtime_mode"] == "simulate"


def test_simulate_mode_simulates_allowed_actions(tmp_path):
    """In simulate mode, allowed actions are simulated."""
    interceptor = build_interceptor(tmp_path, runtime_mode=RuntimeMode.SIMULATE)

    interceptor.tool_executor.register(
        "file_read",
        lambda request: {"target": request.target, "content": "safe"},
    )

    result = interceptor.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.execution.status == ExecutionStatus.SIMULATED
    assert result.execution.executed is False


def test_enforce_mode_executes_allowed_tools(tmp_path):
    """In enforce mode, allowed tools are executed."""
    interceptor = build_interceptor(tmp_path, runtime_mode=RuntimeMode.ENFORCE)
    called = {"value": False}

    def safe_read(request: ToolRequest) -> dict[str, str]:
        called["value"] = True
        return {"target": request.target or "", "content": "safe"}

    interceptor.tool_executor.register("file_read", safe_read)

    result = interceptor.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.execution.status == ExecutionStatus.EXECUTED
    assert result.execution.executed is True
    assert called["value"] is True
    assert result.audit_event.metadata["runtime_mode"] == "enforce"


def test_enforce_mode_blocks_risky_tools(tmp_path):
    """In enforce mode, risky tools are blocked."""
    interceptor = build_interceptor(tmp_path, runtime_mode=RuntimeMode.ENFORCE)
    called = {"value": False}

    def risky_delete(request: ToolRequest) -> dict[str, str]:
        called["value"] = True
        return {"deleted": request.target or ""}

    interceptor.tool_executor.register("file_delete", risky_delete)

    result = interceptor.intercept(
        ToolRequest(
            tool_name="file_delete",
            action="delete_file",
            target="customer_data.csv",
        )
    )

    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert called["value"] is False
    assert result.audit_event.metadata["runtime_mode"] == "enforce"


def test_default_runtime_mode_is_enforce(tmp_path):
    """By default, runtime mode is enforce."""
    executor = ToolExecutor()
    logger = AuditLogger(tmp_path / "audit_log.jsonl")

    interceptor = RygnalInterceptor(
        policy_engine=load_default_policy_engine(),
        audit_logger=logger,
        tool_executor=executor,
        risk_engine=RiskEngine(),
    )

    assert interceptor.runtime_mode == RuntimeMode.ENFORCE
