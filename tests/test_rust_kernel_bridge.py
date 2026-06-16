from __future__ import annotations

import json

import pytest


def test_rust_kernel_bridge_round_trip() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    result = rygnal_kernel.verify_bridge("pytest handshake")

    assert result == ("[Rust Kernel]: Connection secure. Received payload -> pytest handshake")


def test_rust_kernel_evaluates_patch_risk() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "sha256": "abc123xyz",
        "changes": [
            {"path": "src/main.py", "kind": "modified"},
            {"path": "config/db.yml", "kind": "deleted"},
        ],
    }

    result = rygnal_kernel.evaluate_patch_risk(json.dumps(payload))

    assert result == (
        "Kernel evaluated patch [abc123xyz]. Analyzed 2 files. High-risk deletions detected: 1"
    )


def test_rust_kernel_rejects_invalid_patch_json() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    bad_payload = '{"missing_sha": true, "garbage_data": [1, 2, 3]}'

    with pytest.raises(ValueError, match="Rust safety kernel failed to parse JSON"):
        rygnal_kernel.evaluate_patch_risk(bad_payload)


def test_rust_kernel_analyzes_python_code_structure() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    raw_code = """
import os

def delete_database():
    os.remove("production.db")
"""

    result = rygnal_kernel.analyze_code_structure(raw_code)

    assert "AST Parsed Successfully." in result
    assert "import_statement" in result
    assert "function_definition" in result
    assert "call" in result
    assert "attribute" in result
    assert "argument_list" in result


def test_rust_kernel_evaluates_safe_agent_action() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "file_path": "tests/test_auth.py",
        "action_type": "modified",
        "raw_code": "def test_login():\n    assert True",
    }

    result = json.loads(rygnal_kernel.evaluate_agent_action(json.dumps(payload)))

    assert result == {
        "criticality_index": 0.5,
        "risk_level": "safe",
        "reasons": [],
    }


def test_rust_kernel_evaluates_dangerous_agent_action() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "file_path": "config/database.yml",
        "action_type": "deleted",
        "raw_code": "",
    }

    result = json.loads(rygnal_kernel.evaluate_agent_action(json.dumps(payload)))

    assert result == {
        "criticality_index": 9.0,
        "risk_level": "dangerous",
        "reasons": [
            "Modifies core configuration path",
            "Destructive action: File deletion",
        ],
    }


def test_rust_kernel_evaluates_semantic_agent_action() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "file_path": "src/cleanup.py",
        "action_type": "modified",
        "raw_code": 'import os\n\ndef cleanup():\n    os.remove("production.db")\n',
    }

    result = json.loads(rygnal_kernel.evaluate_agent_action(json.dumps(payload)))

    assert result == {
        "criticality_index": 6.0,
        "risk_level": "risky",
        "reasons": [
            "Introduces or modifies dependencies (import statement)",
            "Contains system or external attribute calls",
        ],
    }


def test_rust_kernel_rejects_invalid_agent_action_payload() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    bad_payload = '{"file_path": "src/main.py"}'

    with pytest.raises(ValueError, match="Invalid action payload"):
        rygnal_kernel.evaluate_agent_action(bad_payload)


def test_rust_kernel_evaluates_subjective_risk_for_python_change() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "file_path": "src/service.py",
        "action_type": "modified",
        "system_risk": 6.0,
        "old_code": "def important_rule():\n    threshold = 3\n    return threshold\n",
        "new_code": "def important_rule():\n    threshold = 4\n    return threshold\n",
        "human_context": {
            "days_since_edit": 0.0,
            "days_since_burst": 0.0,
            "line_ownership_ratio": 0.8,
            "is_explicitly_locked": False,
        },
    }

    result = json.loads(rygnal_kernel.evaluate_subjective_risk(json.dumps(payload)))

    assert result["judgment"] in {"allow", "approval_required", "block"}
    assert 0.0 <= result["total_criticality"] <= 10.0
    assert result["human_multiplier"] == 1.0
    assert result["semantic_metrics"]["old_token_count"] >= 2
    assert result["semantic_metrics"]["matched_node_count"] >= 2
    assert 0.0 <= result["semantic_metrics"]["survival_ratio"] <= 1.0
    assert any("Python AST survival ratio" in reason for reason in result["reasons"])


def test_rust_kernel_subjective_risk_blocks_locked_file() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "file_path": "src/payment.py",
        "action_type": "modified",
        "system_risk": 1.0,
        "old_code": "def charge():\n    return True\n",
        "new_code": "def charge():\n    return False\n",
        "human_context": {
            "days_since_edit": 365.0,
            "days_since_burst": 365.0,
            "line_ownership_ratio": 0.1,
            "is_explicitly_locked": True,
        },
    }

    result = json.loads(rygnal_kernel.evaluate_subjective_risk(json.dumps(payload)))

    assert result["total_criticality"] == 10.0
    assert result["judgment"] == "block"
    assert result["human_multiplier"] == 1.0
    assert result["destruction_penalty"] == 0.0
    assert any("explicitly locked" in reason for reason in result["reasons"])


def test_rust_kernel_subjective_risk_uses_text_fallback_for_non_python() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "file_path": "README.md",
        "action_type": "modified",
        "system_risk": 2.0,
        "old_code": "A\nB\nC\n",
        "new_code": "A\nC\n",
        "human_context": {
            "days_since_edit": 0.0,
            "days_since_burst": 0.0,
            "line_ownership_ratio": 1.0,
            "is_explicitly_locked": False,
        },
    }

    result = json.loads(rygnal_kernel.evaluate_subjective_risk(json.dumps(payload)))

    assert result["semantic_metrics"]["old_token_count"] == 3
    assert result["semantic_metrics"]["matched_node_count"] == 2
    assert 0.65 <= result["semantic_metrics"]["survival_ratio"] <= 0.67
    assert any("fallback survival ratio" in reason for reason in result["reasons"])


def test_rust_kernel_subjective_risk_rejects_unknown_fields() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "file_path": "src/service.py",
        "action_type": "modified",
        "system_risk": 1.0,
        "old_code": "",
        "new_code": "",
        "human_context": {
            "days_since_edit": 0.0,
            "days_since_burst": 0.0,
            "line_ownership_ratio": 0.5,
            "is_explicitly_locked": False,
            "unexpected": True,
        },
    }

    with pytest.raises(ValueError, match="Invalid subjective risk payload"):
        rygnal_kernel.evaluate_subjective_risk(json.dumps(payload))


def test_rust_kernel_subjective_risk_rejects_invalid_numeric_context() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "file_path": "src/service.py",
        "action_type": "modified",
        "system_risk": 1.0,
        "old_code": "",
        "new_code": "",
        "human_context": {
            "days_since_edit": 0.0,
            "days_since_burst": 0.0,
            "line_ownership_ratio": 1.5,
            "is_explicitly_locked": False,
        },
    }

    with pytest.raises(ValueError, match="line_ownership_ratio"):
        rygnal_kernel.evaluate_subjective_risk(json.dumps(payload))
