"""Policy engine for Rygnal.

The policy engine decides whether an AI-agent tool request should be
allowed, blocked, simulated, or sent for human approval.
"""

from pathlib import Path
from typing import Any

import yaml

from rygnal.models import Decision, PolicyDecision, PolicyRule, PolicySchema, Severity, ToolRequest


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

    def evaluate(self, request: ToolRequest) -> PolicyDecision:
        """Return the first matching policy decision."""
        for rule in self.rules:
            if self._matches(rule, request):
                return PolicyDecision(
                    decision=rule.decision,
                    allowed=self._is_allowed(rule.decision),
                    severity=rule.severity,
                    reason=rule.reason,
                    policy_id=rule.id,
                )

        return PolicyDecision(
            decision=Decision.ALLOW,
            allowed=True,
            severity=Severity.LOW,
            reason="No matching policy rule. Default allow.",
            policy_id=None,
        )

    def _matches(self, rule: PolicyRule, request: ToolRequest) -> bool:
        if rule.tool_name and rule.tool_name != request.tool_name:
            return False

        if rule.action and rule.action != request.action:
            return False

        if rule.environment and rule.environment != request.environment:
            return False

        if rule.target_contains and rule.target_contains not in (request.target or ""):
            return False

        if rule.input_contains and rule.input_contains not in self._stringify(request.input):
            return False

        return True

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
