from pathlib import Path

from rygnal.models import Decision, ToolRequest
from rygnal.policy_engine import PolicyEngine
from rygnal.risk_engine import RiskEngine, RiskLevel

FIXTURE_DIR = Path("tests/fixtures/policies")


def test_policy_fixture_files_exist():
    expected_files = [
        "priority_policy.yaml",
        "risk_aware_policy.yaml",
        "metadata_policy.yaml",
    ]

    for filename in expected_files:
        assert (FIXTURE_DIR / filename).exists()


def test_priority_policy_fixture_uses_priority_order():
    engine = PolicyEngine.from_file(FIXTURE_DIR / "priority_policy.yaml")

    result = engine.evaluate(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.decision == Decision.ALLOW
    assert result.policy_id == "high-priority-allow-readme"


def test_risk_aware_policy_fixture_matches_critical_risk():
    engine = PolicyEngine.from_file(FIXTURE_DIR / "risk_aware_policy.yaml")
    request = ToolRequest(tool_name="file_read", action="read_file", target=".env")
    risk_assessment = RiskEngine().assess(request)

    result = engine.evaluate(request, risk_assessment=risk_assessment)

    assert risk_assessment.risk_level == RiskLevel.CRITICAL
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.policy_id == "require-approval-critical-risk"


def test_metadata_policy_fixture_matches_metadata_equals():
    engine = PolicyEngine.from_file(FIXTURE_DIR / "metadata_policy.yaml")

    result = engine.evaluate(
        ToolRequest(
            tool_name="file_delete",
            action="delete_file",
            target="customer_data.csv",
            metadata={"agent_tier": "production", "approval_required": True},
        )
    )

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.policy_id == "approval-production-agent-delete"


def test_metadata_policy_fixture_matches_metadata_contains():
    engine = PolicyEngine.from_file(FIXTURE_DIR / "metadata_policy.yaml")

    result = engine.evaluate(
        ToolRequest(
            tool_name="external_api_send",
            action="send_data",
            metadata={"source": "external-untrusted-plugin"},
        )
    )

    assert result.decision == Decision.SIMULATE
    assert result.policy_id == "simulate-untrusted-source"


def test_example_policy_files_load_successfully():
    example_files = [
        Path("examples/policies/risk-aware-policy.yaml"),
        Path("examples/policies/metadata-policy.yaml"),
    ]

    for policy_file in example_files:
        engine = PolicyEngine.from_file(policy_file)
        assert engine.policy_version == "policy.v2"
        assert engine.rules
