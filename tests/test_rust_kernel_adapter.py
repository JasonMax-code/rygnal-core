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


def test_rust_kernel_adapter_returns_subjective_risk_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustHumanContext,
        RustSemanticMetrics,
        RustSubjectiveRiskAssessment,
        RustSubjectiveRiskInput,
        evaluate_subjective_risk,
    )

    fake_kernel = types.SimpleNamespace(
        evaluate_subjective_risk=lambda payload: json.dumps(
            {
                "total_criticality": 6.5,
                "judgment": "approval_required",
                "reasons": ["Python AST survival ratio is 0.5000."],
                "human_multiplier": 1.0,
                "destruction_penalty": 2.5,
                "semantic_metrics": {
                    "old_node_count": 10,
                    "new_node_count": 8,
                    "old_token_count": 4,
                    "new_token_count": 3,
                    "matched_node_count": 2,
                    "survival_ratio": 0.5,
                },
            }
        )
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    result = evaluate_subjective_risk(
        RustSubjectiveRiskInput(
            file_path="src/service.py",
            action_type="modified",
            system_risk=6.0,
            old_code="def important():\n    return True\n",
            new_code="def important():\n    return False\n",
            human_context=RustHumanContext(
                days_since_edit=0.0,
                days_since_burst=0.0,
                line_ownership_ratio=0.8,
                is_explicitly_locked=False,
            ),
        )
    )

    assert result == RustSubjectiveRiskAssessment(
        total_criticality=6.5,
        judgment="approval_required",
        reasons=("Python AST survival ratio is 0.5000.",),
        human_multiplier=1.0,
        destruction_penalty=2.5,
        semantic_metrics=RustSemanticMetrics(
            old_node_count=10,
            new_node_count=8,
            old_token_count=4,
            new_token_count=3,
            matched_node_count=2,
            survival_ratio=0.5,
        ),
    )


def test_rust_kernel_adapter_wraps_missing_subjective_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustHumanContext,
        RustKernelError,
        RustSubjectiveRiskInput,
        evaluate_subjective_risk,
    )

    fake_kernel = types.SimpleNamespace()
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="does not expose evaluate_subjective_risk"):
        evaluate_subjective_risk(
            RustSubjectiveRiskInput(
                file_path="src/service.py",
                action_type="modified",
                system_risk=1.0,
                old_code="",
                new_code="",
                human_context=RustHumanContext(
                    days_since_edit=0.0,
                    days_since_burst=0.0,
                    line_ownership_ratio=0.5,
                ),
            )
        )


def test_rust_kernel_adapter_rejects_invalid_subjective_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustHumanContext,
        RustKernelError,
        RustSubjectiveRiskInput,
        evaluate_subjective_risk,
    )

    fake_kernel = types.SimpleNamespace(
        evaluate_subjective_risk=lambda payload: json.dumps(
            {
                "total_criticality": 1.0,
                "judgment": "allow",
                "reasons": [],
            }
        )
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="invalid subjective risk shape"):
        evaluate_subjective_risk(
            RustSubjectiveRiskInput(
                file_path="src/service.py",
                action_type="modified",
                system_risk=1.0,
                old_code="",
                new_code="",
                human_context=RustHumanContext(
                    days_since_edit=0.0,
                    days_since_burst=0.0,
                    line_ownership_ratio=0.5,
                ),
            )
        )
