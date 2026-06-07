from pathlib import Path

from rygnal.models import Decision, ToolRequest
from rygnal.policy_engine import PolicyEngine


def test_policy_rule_can_match_target_equals(tmp_path: Path):
    policy_file = tmp_path / "target_equals_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: block-exact-prod-env
    priority: 5
    tool_name: file_read
    target_equals: .env.production
    decision: block
    severity: critical
    reason: Exact production env file is blocked.
"""
    )

    engine = PolicyEngine.from_file(policy_file)

    matched = engine.evaluate(
        ToolRequest(tool_name="file_read", action="read_file", target=".env.production")
    )
    unmatched = engine.evaluate(
        ToolRequest(tool_name="file_read", action="read_file", target=".env.example")
    )

    assert matched.decision == Decision.BLOCK
    assert matched.policy_id == "block-exact-prod-env"
    assert matched.explanation is not None
    assert "target_equals" in matched.explanation.matched_conditions

    assert unmatched.decision == Decision.ALLOW
    assert unmatched.policy_id is None


def test_policy_rule_can_match_input_equals(tmp_path: Path):
    policy_file = tmp_path / "input_equals_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: block-exact-dangerous-input
    priority: 5
    tool_name: shell_command
    input_equals:
      command: rm -rf /tmp/demo
    decision: block
    severity: critical
    reason: Exact dangerous command input is blocked.
"""
    )

    engine = PolicyEngine.from_file(policy_file)

    result = engine.evaluate(
        ToolRequest(
            tool_name="shell_command",
            action="execute",
            input={"command": "rm -rf /tmp/demo"},
        )
    )

    assert result.decision == Decision.BLOCK
    assert result.policy_id == "block-exact-dangerous-input"
    assert result.explanation is not None
    assert "input_equals" in result.explanation.matched_conditions


def test_policy_rule_can_match_metadata_equals(tmp_path: Path):
    policy_file = tmp_path / "metadata_equals_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: approval-for-prod-agent
    priority: 5
    tool_name: file_delete
    metadata_equals:
      agent_tier: production
      approval_required: true
    decision: require_approval
    severity: high
    reason: Production agent deletion requires approval.
"""
    )

    engine = PolicyEngine.from_file(policy_file)

    result = engine.evaluate(
        ToolRequest(
            tool_name="file_delete",
            action="delete_file",
            target="customer_data.csv",
            metadata={"agent_tier": "production", "approval_required": True},
        )
    )

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.policy_id == "approval-for-prod-agent"
    assert result.explanation is not None
    assert "metadata_equals" in result.explanation.matched_conditions


def test_policy_rule_can_match_metadata_contains(tmp_path: Path):
    policy_file = tmp_path / "metadata_contains_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: simulate-untrusted-source
    priority: 5
    metadata_contains:
      source: untrusted
    decision: simulate
    severity: medium
    reason: Untrusted source should be simulated.
"""
    )

    engine = PolicyEngine.from_file(policy_file)

    result = engine.evaluate(
        ToolRequest(
            tool_name="external_api_send",
            action="send_data",
            metadata={"source": "external-untrusted-plugin"},
        )
    )

    assert result.decision == Decision.SIMULATE
    assert result.policy_id == "simulate-untrusted-source"
    assert result.explanation is not None
    assert "metadata_contains" in result.explanation.matched_conditions


def test_metadata_rule_does_not_match_when_metadata_is_missing(tmp_path: Path):
    policy_file = tmp_path / "metadata_missing_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: block-prod-agent
    priority: 5
    metadata_equals:
      agent_tier: production
    decision: block
    severity: high
    reason: Production agent is blocked.
"""
    )

    engine = PolicyEngine.from_file(policy_file)

    result = engine.evaluate(ToolRequest(tool_name="file_read", action="read_file"))

    assert result.decision == Decision.ALLOW
    assert result.policy_id is None
    assert result.explanation is not None
    assert result.explanation.default_decision is True
