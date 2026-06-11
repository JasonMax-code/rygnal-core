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
default_decision: allow
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
default_decision: allow
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


def test_policy_decision_includes_explain_output_for_matched_rule():
    engine = load_default_policy_engine()

    result = engine.evaluate(ToolRequest(tool_name="file_read", action="read_file", target=".env"))

    assert result.explanation is not None
    assert result.explanation.policy_version == "policy.v2"
    assert result.explanation.matched is True
    assert result.explanation.matched_rule_id == "block-env-read"
    assert result.explanation.matched_rule_priority == 10
    assert "tool_name" in result.explanation.matched_conditions
    assert "target_contains" in result.explanation.matched_conditions
    assert result.explanation.evaluated_rule_ids == ["block-env-read"]
    assert result.explanation.default_decision is False


def test_policy_decision_includes_explain_output_for_default_allow():
    engine = load_default_policy_engine()

    result = engine.evaluate(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.explanation is not None
    assert result.explanation.policy_version == "policy.v2"
    assert result.explanation.matched is False
    assert result.explanation.matched_rule_id is None
    assert result.explanation.matched_rule_priority is None
    assert result.explanation.matched_conditions == []
    assert result.explanation.evaluated_rule_ids == [
        "block-env-read",
        "block-dangerous-shell",
        "approval-file-delete",
        "simulate-external-api-send",
    ]
    assert result.explanation.default_decision is True


def test_policy_file_requires_explicit_default_decision(tmp_path: Path):
    policy_file = tmp_path / "missing_default_decision.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: block-env
    tool_name: file_read
    target_contains: .env
    decision: block
    severity: critical
    reason: Env files are blocked.
"""
    )

    with pytest.raises(ValueError):
        PolicyEngine.from_file(policy_file)


def test_policy_file_rejects_unknown_top_level_fields(tmp_path: Path):
    policy_file = tmp_path / "unknown_top_level_field.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
default_decision: allow
unknown_field: true
rules: []
"""
    )

    with pytest.raises(ValueError):
        PolicyEngine.from_file(policy_file)


def test_policy_file_rejects_duplicate_rule_ids(tmp_path: Path):
    policy_file = tmp_path / "duplicate_rule_ids.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
default_decision: allow
rules:
  - id: duplicate-rule
    tool_name: file_read
    target_contains: .env
    decision: block
    severity: critical
    reason: First rule.

  - id: duplicate-rule
    tool_name: shell_command
    input_contains: rm -rf
    decision: block
    severity: critical
    reason: Second rule.
"""
    )

    with pytest.raises(ValueError, match="Duplicate policy rule id"):
        PolicyEngine.from_file(policy_file)
