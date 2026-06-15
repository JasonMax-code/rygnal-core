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
