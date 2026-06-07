"""Policy engine for Rygnal.

The policy engine decides whether an AI-agent tool request should be
allowed, blocked, simulated, or sent for human approval.
"""

from pathlib import Path
from typing import Any

import yaml

from rygnal.models import (
    Decision,
    PolicyDecision,
    PolicyExplanation,
    PolicyRule,
    PolicySchema,
    Severity,
    ToolRequest,
)


class PolicyEngine:
    """Evaluate AI-agent tool requests against policy rules."""

    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        policy_version: str = "policy.v1",
    ) -> None:
        self.policy_version = policy_version
        self.rules = sorted(rules or [], key=lambda rule: rule.priority)

    @classmethod
    def from_file(cls, policy_path: str | Path) -> "PolicyEngine":
        """Load policy rules from a YAML file."""
        path = Path(policy_path)

        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        data = yaml.safe_load(path.read_text()) or {}

        if not isinstance(data, dict):
            raise ValueError("Policy file must be a YAML mapping.")

        raw_rules = data.get("rules", [])

        if not isinstance(raw_rules, list):
            raise ValueError("Policy file must contain a 'rules' list.")

        policy_schema = PolicySchema(
            policy_version=data.get("policy_version", "policy.v1"),
            rules=[PolicyRule(**rule) for rule in raw_rules],
        )
        return cls(
            rules=policy_schema.rules,
            policy_version=policy_schema.policy_version,
        )

    def evaluate(
        self,
        request: ToolRequest,
        risk_assessment: Any | None = None,
    ) -> PolicyDecision:
        """Return the first matching policy decision with explain output."""
        evaluated_rule_ids: list[str] = []
        risk_context = self._risk_context(risk_assessment)

        for rule in self.rules:
            evaluated_rule_ids.append(rule.id)

            if self._matches(rule, request, risk_context):
                return PolicyDecision(
                    decision=rule.decision,
                    allowed=self._is_allowed(rule.decision),
                    severity=rule.severity,
                    reason=rule.reason,
                    policy_id=rule.id,
                    explanation=PolicyExplanation(
                        policy_version=self.policy_version,
                        matched=True,
                        matched_rule_id=rule.id,
                        matched_rule_priority=rule.priority,
                        matched_conditions=self._matched_conditions(rule),
                        evaluated_rule_ids=evaluated_rule_ids,
                        default_decision=False,
                    ),
                )

        return PolicyDecision(
            decision=Decision.ALLOW,
            allowed=True,
            severity=Severity.LOW,
            reason="No matching policy rule. Default allow.",
            policy_id=None,
            explanation=PolicyExplanation(
                policy_version=self.policy_version,
                matched=False,
                matched_rule_id=None,
                matched_rule_priority=None,
                matched_conditions=[],
                evaluated_rule_ids=evaluated_rule_ids,
                default_decision=True,
            ),
        )

    def _matches(
        self,
        rule: PolicyRule,
        request: ToolRequest,
        risk_context: dict[str, Any],
    ) -> bool:
        if rule.tool_name and rule.tool_name != request.tool_name:
            return False

        if rule.action and rule.action != request.action:
            return False

        if rule.environment and rule.environment != request.environment:
            return False

        if rule.target_equals and rule.target_equals != request.target:
            return False

        if rule.target_contains and rule.target_contains not in (request.target or ""):
            return False

        if rule.input_equals is not None and rule.input_equals != request.input:
            return False

        if rule.input_contains and rule.input_contains not in self._stringify(request.input):
            return False

        if rule.metadata_equals and not self._metadata_equals(
            request.metadata,
            rule.metadata_equals,
        ):
            return False

        if rule.metadata_contains and not self._metadata_contains(
            request.metadata,
            rule.metadata_contains,
        ):
            return False
        if rule.risk_level and rule.risk_level != risk_context.get("risk_level"):
            return False

        if rule.risk_score_min is not None:
            risk_score = risk_context.get("risk_score")
            if risk_score is None or risk_score < rule.risk_score_min:
                return False
        return True

    @staticmethod
    def _metadata_equals(
        request_metadata: dict[str, Any],
        expected_metadata: dict[str, Any],
    ) -> bool:
        """Return true when all expected metadata values match exactly."""
        for key, expected_value in expected_metadata.items():
            if request_metadata.get(key) != expected_value:
                return False

        return True

    @staticmethod
    def _metadata_contains(
        request_metadata: dict[str, Any],
        expected_metadata: dict[str, str],
    ) -> bool:
        """Return true when metadata string values contain expected text."""
        for key, expected_value in expected_metadata.items():
            actual_value = request_metadata.get(key)

            if expected_value not in PolicyEngine._stringify(actual_value):
                return False

        return True

    @staticmethod
    def _risk_context(risk_assessment: Any | None) -> dict[str, Any]:
        """Normalize optional risk assessment for policy evaluation."""
        if risk_assessment is None:
            return {}

        if hasattr(risk_assessment, "model_dump"):
            return risk_assessment.model_dump(mode="json")

        if isinstance(risk_assessment, dict):
            return risk_assessment

        return {}

    @staticmethod
    def _matched_conditions(rule: PolicyRule) -> list[str]:
        """Return the configured match conditions for a rule."""
        conditions: list[str] = []

        if rule.tool_name:
            conditions.append("tool_name")

        if rule.action:
            conditions.append("action")

        if rule.environment:
            conditions.append("environment")

        if rule.target_equals:
            conditions.append("target_equals")

        if rule.target_contains:
            conditions.append("target_contains")

        if rule.input_equals is not None:
            conditions.append("input_equals")

        if rule.input_contains:
            conditions.append("input_contains")
        if rule.metadata_equals:
            conditions.append("metadata_equals")

        if rule.metadata_contains:
            conditions.append("metadata_contains")

        if rule.risk_level:
            conditions.append("risk_level")

        if rule.risk_score_min is not None:
            conditions.append("risk_score_min")

        return conditions

    @staticmethod
    def _is_allowed(decision: Decision) -> bool:
        return decision in {Decision.ALLOW, Decision.SIMULATE}

    @staticmethod
    def _stringify(value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, str):
            return value

        return str(value)


def load_default_policy_engine() -> PolicyEngine:
    """Load the default Rygnal policy engine."""
    return PolicyEngine.from_file("policies/default_policy.yaml")
