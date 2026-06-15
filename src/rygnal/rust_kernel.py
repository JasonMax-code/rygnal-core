"""Optional Python adapter boundary for the Rygnal Rust kernel.

This module is the only production Python code that should import the optional
``rygnal_kernel`` PyO3 extension directly.
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
    kernel = _load_kernel()

    payload = {
        "file_path": action.file_path,
        "action_type": action.action_type,
        "raw_code": action.raw_code,
    }

    try:
        raw_result = kernel.evaluate_agent_action(json.dumps(payload))
    except ValueError as exc:
        raise RustKernelError(f"rust kernel rejected agent action: {exc}") from exc

    try:
        result = json.loads(raw_result)
    except json.JSONDecodeError as exc:
        raise RustKernelError("rust kernel returned invalid JSON") from exc

    try:
        return RustRiskAssessment(
            criticality_index=float(result["criticality_index"]),
            risk_level=str(result["risk_level"]),
            reasons=tuple(str(reason) for reason in result["reasons"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RustKernelError("rust kernel returned invalid assessment shape") from exc
