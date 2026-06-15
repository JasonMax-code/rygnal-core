from __future__ import annotations

import json
import sys
import types

import pytest

from rygnal.rust_kernel import (
    RustAgentAction,
    RustKernelError,
    RustKernelUnavailableError,
    RustRiskAssessment,
    evaluate_agent_action,
    is_rust_kernel_available,
)


def test_rust_kernel_adapter_reports_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "rygnal_kernel", None)

    def fake_import_module(name: str) -> object:
        if name == "rygnal_kernel":
            raise ModuleNotFoundError(name)
        raise AssertionError(name)

    monkeypatch.setattr("importlib.import_module", fake_import_module)

    assert is_rust_kernel_available() is False

    with pytest.raises(RustKernelUnavailableError):
        evaluate_agent_action(
            RustAgentAction(
                file_path="src/main.py",
                action_type="modified",
                raw_code="",
            )
        )


def test_rust_kernel_adapter_returns_structured_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_kernel = types.SimpleNamespace(
        evaluate_agent_action=lambda payload: json.dumps(
            {
                "criticality_index": 6.0,
                "risk_level": "risky",
                "reasons": ["Contains system or external attribute calls"],
            }
        )
    )

    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    result = evaluate_agent_action(
        RustAgentAction(
            file_path="src/cleanup.py",
            action_type="modified",
            raw_code='import os\nos.remove("production.db")\n',
        )
    )

    assert result == RustRiskAssessment(
        criticality_index=6.0,
        risk_level="risky",
        reasons=("Contains system or external attribute calls",),
    )


def test_rust_kernel_adapter_wraps_rust_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_action(payload: str) -> str:
        raise ValueError("Invalid action payload")

    fake_kernel = types.SimpleNamespace(evaluate_agent_action=reject_action)
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="rust kernel rejected agent action"):
        evaluate_agent_action(
            RustAgentAction(
                file_path="src/main.py",
                action_type="modified",
                raw_code="",
            )
        )


def test_rust_kernel_adapter_rejects_invalid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_kernel = types.SimpleNamespace(evaluate_agent_action=lambda payload: "not json")
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="invalid JSON"):
        evaluate_agent_action(
            RustAgentAction(
                file_path="src/main.py",
                action_type="modified",
                raw_code="",
            )
        )


def test_rust_kernel_adapter_rejects_invalid_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_kernel = types.SimpleNamespace(
        evaluate_agent_action=lambda payload: json.dumps({"risk_level": "safe"})
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="invalid assessment shape"):
        evaluate_agent_action(
            RustAgentAction(
                file_path="src/main.py",
                action_type="modified",
                raw_code="",
            )
        )
