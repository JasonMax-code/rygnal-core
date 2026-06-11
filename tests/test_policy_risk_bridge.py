from pathlib import Path

from rygnal.models import Decision, ToolRequest
from rygnal.policy_engine import PolicyEngine
from rygnal.risk_engine import RiskEngine, RiskLevel


def test_policy_engine_evaluate_remains_backward_compatible():
    engine = PolicyEngine.from_file("policies/default_policy.yaml")

    result = engine.evaluate(ToolRequest(tool_name="file_read", action="read_file", target=".env"))

    assert result.decision == Decision.BLOCK
    assert result.policy_id == "block-env-read"


def test_policy_rule_can_match_risk_level(tmp_path: Path):
    policy_file = tmp_path / "risk_level_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: require-approval-for-critical-risk
    priority: 5
    risk_level: critical
    decision: require_approval
    severity: critical
    reason: Critical risk requires approval.
"""
    )

    engine = PolicyEngine.from_file(policy_file)
    request = ToolRequest(tool_name="file_read", action="read_file", target=".env")
    risk_assessment = RiskEngine().assess(request)

    result = engine.evaluate(request, risk_assessment=risk_assessment)

    assert risk_assessment.risk_level == RiskLevel.CRITICAL
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.policy_id == "require-approval-for-critical-risk"
    assert result.explanation is not None
    assert "risk_level" in result.explanation.matched_conditions


def test_policy_rule_can_match_risk_score_min(tmp_path: Path):
    policy_file = tmp_path / "risk_score_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: block-high-score-risk
    priority: 5
    risk_score_min: 85
    decision: block
    severity: critical
    reason: High risk score is blocked.
"""
    )

    engine = PolicyEngine.from_file(policy_file)
    request = ToolRequest(tool_name="shell_command", action="execute", input="rm -rf /tmp/demo")
    risk_assessment = RiskEngine().assess(request)

    result = engine.evaluate(request, risk_assessment=risk_assessment)

    assert risk_assessment.risk_score >= 85
    assert result.decision == Decision.BLOCK
    assert result.policy_id == "block-high-score-risk"
    assert result.explanation is not None
    assert "risk_score_min" in result.explanation.matched_conditions


def test_risk_aware_rule_does_not_match_without_risk_assessment(tmp_path: Path):
    policy_file = tmp_path / "risk_required_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
rules:
  - id: block-critical-risk
    priority: 5
    risk_level: critical
    decision: block
    severity: critical
    reason: Critical risk is blocked.
"""
    )

    engine = PolicyEngine.from_file(policy_file)
    request = ToolRequest(tool_name="file_read", action="read_file", target=".env")

    result = engine.evaluate(request)

    assert result.decision == Decision.ALLOW
    assert result.policy_id is None
    assert result.explanation is not None
    assert result.explanation.default_decision is True


def test_interceptor_passes_risk_assessment_into_policy_evaluation(tmp_path: Path):
    policy_file = tmp_path / "risk_runtime_policy.yaml"
    policy_file.write_text(
        """
policy_version: policy.v2
default_decision: allow
rules:
  - id: block-critical-runtime-risk
    priority: 5
    risk_level: critical
    decision: block
    severity: critical
    reason: Critical runtime risk is blocked.
"""
    )

    from rygnal.audit_logger import AuditLogger
    from rygnal.interceptor import RygnalInterceptor
    from rygnal.tool_executor import ToolExecutor

    engine = PolicyEngine.from_file(policy_file)
    interceptor = RygnalInterceptor(
        policy_engine=engine,
        audit_logger=AuditLogger(tmp_path / "audit_log.jsonl"),
        tool_executor=ToolExecutor(),
    )

    result = interceptor.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target=".env")
    )

    assert result.risk_assessment["risk_level"] == "critical"
    assert result.policy_decision.decision == Decision.BLOCK
    assert result.policy_decision.policy_id == "block-critical-runtime-risk"
    assert result.policy_decision.explanation is not None
    assert "risk_level" in result.policy_decision.explanation.matched_conditions
