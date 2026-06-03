from pathlib import Path

import pytest

from rygnal.models import Decision, ToolRequest
from rygnal.policy_engine import PolicyEngine, load_default_policy_engine


def test_policy_engine_loads_default_policy():
    engine = load_default_policy_engine()

    assert engine.rules
    assert len(engine.rules) >= 4


def test_blocks_env_file_read():
    engine = load_default_policy_engine()

    request = ToolRequest(
        tool_name="file_read",
        action="read_file",
        target=".env",
    )

    result = engine.evaluate(request)

    assert result.decision == Decision.BLOCK
    assert result.allowed is False
    assert result.policy_id == "block-env-read"


def test_blocks_dangerous_shell_command():
    engine = load_default_policy_engine()

    request = ToolRequest(
        tool_name="shell_command",
        action="execute",
        input="rm -rf /important-folder",
    )

    result = engine.evaluate(request)

    assert result.decision == Decision.BLOCK
    assert result.allowed is False
    assert result.policy_id == "block-dangerous-shell"


def test_file_delete_requires_approval():
    engine = load_default_policy_engine()

    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )

    result = engine.evaluate(request)

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.allowed is False
    assert result.policy_id == "approval-file-delete"


def test_external_api_send_is_simulated():
    engine = load_default_policy_engine()

    request = ToolRequest(
        tool_name="external_api_send",
        action="send_data",
        input={"url": "https://example.com", "payload": "demo"},
    )

    result = engine.evaluate(request)

    assert result.decision == Decision.SIMULATE
    assert result.allowed is True
    assert result.policy_id == "simulate-external-api-send"


def test_safe_file_read_is_allowed_by_default():
    engine = load_default_policy_engine()

    request = ToolRequest(
        tool_name="file_read",
        action="read_file",
        target="README.md",
    )

    result = engine.evaluate(request)

    assert result.decision == Decision.ALLOW
    assert result.allowed is True
    assert result.policy_id is None


def test_invalid_policy_file_raises_error(tmp_path: Path):
    bad_policy = tmp_path / "bad_policy.yaml"
    bad_policy.write_text("rules: invalid")

    with pytest.raises(ValueError):
        PolicyEngine.from_file(bad_policy)


def test_policy_engine_loads_policy_version():
    engine = load_default_policy_engine()

    assert engine.policy_version == "policy.v2"


def test_policy_rules_are_sorted_by_priority(tmp_path: Path):
    policy_file = tmp_path / "priority_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: low-priority-block
    priority: 50
    tool_name: file_read
    target_contains: README.md
    decision: block
    severity: high
    reason: Low priority block.

  - id: high-priority-allow
    priority: 10
    tool_name: file_read
    target_contains: README.md
    decision: allow
    severity: low
    reason: High priority allow.
"""
    )

    engine = PolicyEngine.from_file(policy_file)
    result = engine.evaluate(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert [rule.id for rule in engine.rules] == [
        "high-priority-allow",
        "low-priority-block",
    ]
    assert result.decision == Decision.ALLOW
    assert result.policy_id == "high-priority-allow"


def test_policy_engine_keeps_backward_compatibility_without_version(tmp_path: Path):
    policy_file = tmp_path / "legacy_policy.yaml"
    policy_file.write_text(
        """
rules:
  - id: legacy-block
    tool_name: file_read
    target_contains: .env
    decision: block
    severity: critical
    reason: Legacy policy blocks env files.
"""
    )

    engine = PolicyEngine.from_file(policy_file)

    assert engine.policy_version == "policy.v1"

    result = engine.evaluate(ToolRequest(tool_name="file_read", action="read_file", target=".env"))

    assert result.decision == Decision.BLOCK
    assert result.policy_id == "legacy-block"


def test_invalid_policy_file_mapping_raises_error(tmp_path: Path):
    bad_policy = tmp_path / "bad_mapping.yaml"
    bad_policy.write_text("- not-a-mapping")

    with pytest.raises(ValueError, match="YAML mapping"):
        PolicyEngine.from_file(bad_policy)
