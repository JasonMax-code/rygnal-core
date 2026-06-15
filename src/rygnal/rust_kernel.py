"""Optional Python adapter boundary for the Rygnal Rust kernel.

This module is the only production Python code that should import the optional
``rygnal_kernel`` PyO3 extension directly. Keep all Rust/Python JSON contracts
centralized here so callers receive typed Python dataclasses instead of raw
extension-module dictionaries or strings.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from typing import Any


class RustKernelUnavailableError(RuntimeError):
    """Raised when the optional Rust kernel extension is not installed."""


class RustKernelError(RuntimeError):
    """Raised when the Rust kernel returns invalid or unusable output."""


@dataclass(frozen=True)
class RustAgentAction:
    file_path: str
    action_type: str
    raw_code: str = ""


@dataclass(frozen=True)
class RustRiskAssessment:
    criticality_index: float
    risk_level: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class RustHumanContext:
    days_since_edit: float
    days_since_burst: float
    line_ownership_ratio: float
    is_explicitly_locked: bool = False


@dataclass(frozen=True)
class RustSubjectiveRiskInput:
    file_path: str
    action_type: str
    system_risk: float
    old_code: str
    new_code: str
    human_context: RustHumanContext


@dataclass(frozen=True)
class RustSemanticMetrics:
    old_node_count: int
    new_node_count: int
    old_token_count: int
    new_token_count: int
    matched_node_count: int
    survival_ratio: float


@dataclass(frozen=True)
class RustSubjectiveRiskAssessment:
    total_criticality: float
    judgment: str
    reasons: tuple[str, ...]
    human_multiplier: float
    destruction_penalty: float
    semantic_metrics: RustSemanticMetrics


def is_rust_kernel_available() -> bool:
    try:
        importlib.import_module("rygnal_kernel")
    except ModuleNotFoundError:
        return False
    return True


def _load_kernel() -> Any:
    try:
        return importlib.import_module("rygnal_kernel")
    except ModuleNotFoundError as exc:
        raise RustKernelUnavailableError("optional Rust kernel extension is not installed") from exc


def evaluate_agent_action(action: RustAgentAction) -> RustRiskAssessment:
    payload = {
        "file_path": action.file_path,
        "action_type": action.action_type,
        "raw_code": action.raw_code,
    }

    result = _call_json_kernel_function(
        function_name="evaluate_agent_action",
        payload=payload,
        rejection_context="agent action",
    )

    try:
        return RustRiskAssessment(
            criticality_index=float(result["criticality_index"]),
            risk_level=str(result["risk_level"]),
            reasons=tuple(str(reason) for reason in result["reasons"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RustKernelError("rust kernel returned invalid assessment shape") from exc


def evaluate_subjective_risk(
    risk_input: RustSubjectiveRiskInput,
) -> RustSubjectiveRiskAssessment:
    payload = {
        "file_path": risk_input.file_path,
        "action_type": risk_input.action_type,
        "system_risk": risk_input.system_risk,
        "old_code": risk_input.old_code,
        "new_code": risk_input.new_code,
        "human_context": {
            "days_since_edit": risk_input.human_context.days_since_edit,
            "days_since_burst": risk_input.human_context.days_since_burst,
            "line_ownership_ratio": risk_input.human_context.line_ownership_ratio,
            "is_explicitly_locked": risk_input.human_context.is_explicitly_locked,
        },
    }

    result = _call_json_kernel_function(
        function_name="evaluate_subjective_risk",
        payload=payload,
        rejection_context="subjective risk input",
    )

    try:
        metrics = result["semantic_metrics"]
        return RustSubjectiveRiskAssessment(
            total_criticality=float(result["total_criticality"]),
            judgment=str(result["judgment"]),
            reasons=tuple(str(reason) for reason in result["reasons"]),
            human_multiplier=float(result["human_multiplier"]),
            destruction_penalty=float(result["destruction_penalty"]),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=int(metrics["old_node_count"]),
                new_node_count=int(metrics["new_node_count"]),
                old_token_count=int(metrics["old_token_count"]),
                new_token_count=int(metrics["new_token_count"]),
                matched_node_count=int(metrics["matched_node_count"]),
                survival_ratio=float(metrics["survival_ratio"]),
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RustKernelError("rust kernel returned invalid subjective risk shape") from exc


def _call_json_kernel_function(
    *,
    function_name: str,
    payload: dict[str, Any],
    rejection_context: str,
) -> dict[str, Any]:
    kernel = _load_kernel()

    try:
        function = getattr(kernel, function_name)
    except AttributeError as exc:
        raise RustKernelError(f"rust kernel does not expose {function_name}") from exc

    try:
        raw_result = function(json.dumps(payload))
    except ValueError as exc:
        raise RustKernelError(f"rust kernel rejected {rejection_context}: {exc}") from exc

    try:
        result = json.loads(raw_result)
    except json.JSONDecodeError as exc:
        raise RustKernelError("rust kernel returned invalid JSON") from exc

    if not isinstance(result, dict):
        raise RustKernelError("rust kernel returned non-object JSON")

    return result


__all__ = [
    "RustAgentAction",
    "RustHumanContext",
    "RustKernelError",
    "RustKernelUnavailableError",
    "RustRiskAssessment",
    "RustSemanticMetrics",
    "RustSubjectiveRiskAssessment",
    "RustSubjectiveRiskInput",
    "evaluate_agent_action",
    "evaluate_subjective_risk",
    "is_rust_kernel_available",
]
