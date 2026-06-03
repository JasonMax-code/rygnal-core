"""Risk engine for Rygnal.

Risk Engine v1 provides deterministic and explainable risk scoring for
AI-agent tool requests before execution.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from rygnal.models import ToolRequest


class RiskLevel(StrEnum):
    """Risk level for an AI-agent tool request."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskSignal(BaseModel):
    """A single explainable risk signal."""

    code: str
    severity: RiskLevel
    score: int
    reason: str


class RiskAssessment(BaseModel):
    """Final risk assessment for a tool request."""

    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    reasons: list[str]
    signals: list[RiskSignal]


class RiskEngine:
    """Deterministic risk scorer for AI-agent tool requests."""

    SENSITIVE_TARGET_PATTERNS = (
        ".env",
        ".env.backup",
        "secrets.yaml",
        "secrets.yml",
        "credentials.json",
        "credential.json",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_dsa",
        "private.key",
        "private.pem",
        "service-account.json",
        "service_account.json",
        "database.yml",
        "database.yaml",
        "db.yml",
        "db.yaml",
    )

    SECRET_PATTERNS = (
        re.compile(r"(?i)\bapi[_-]?key\b\s*[:=]\s*\S+"),
        re.compile(r"(?i)\btoken\b\s*[:=]\s*\S+"),
        re.compile(r"(?i)\bsecret\b\s*[:=]\s*\S+"),
        re.compile(r"(?i)\bpassword\b\s*[:=]\s*\S+"),
        re.compile(r"(?i)\bprivate[_-]?key\b"),
        re.compile(r"(?i)\baws_access_key_id\b"),
        re.compile(r"(?i)\baws_secret_access_key\b"),
        re.compile(r"(?i)sk-[A-Za-z0-9_-]{12,}"),
    )

    DANGEROUS_SHELL_PATTERNS = (
        re.compile(r"rm\s+-rf"),
        re.compile(r"sudo\s+"),
        re.compile(r"chmod\s+777"),
        re.compile(r"curl\s+"),
        re.compile(r"wget\s+"),
        re.compile(r"nc\s+"),
        re.compile(r"bash\s+-c"),
        re.compile(r"sh\s+-c"),
        re.compile(r">\s*/etc/"),
    )

    def assess(self, request: ToolRequest) -> RiskAssessment:
        """Assess risk for a tool request."""
        signals: list[RiskSignal] = []

        signals.extend(self._tool_based_signals(request))
        signals.extend(self._target_based_signals(request))
        signals.extend(self._input_based_signals(request))

        if not signals:
            signals.append(
                RiskSignal(
                    code="baseline-low-risk",
                    severity=RiskLevel.LOW,
                    score=10,
                    reason="No risky tool, target, or input pattern detected.",
                )
            )

        risk_score = min(sum(signal.score for signal in signals), 100)
        risk_level = self._level_from_score(risk_score)
        reasons = [signal.reason for signal in signals]

        return RiskAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=reasons,
            signals=signals,
        )

    def _tool_based_signals(self, request: ToolRequest) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        tool_name = request.tool_name.lower()

        if tool_name in {"file_delete", "delete_file"}:
            signals.append(
                RiskSignal(
                    code="file-delete",
                    severity=RiskLevel.HIGH,
                    score=75,
                    reason="Agent requested file deletion.",
                )
            )

        if tool_name in {"shell_command", "terminal", "exec", "run_command"}:
            signals.append(
                RiskSignal(
                    code="shell-execution",
                    severity=RiskLevel.HIGH,
                    score=70,
                    reason="Agent requested shell or terminal execution.",
                )
            )

        if tool_name in {"external_api_send", "http_request", "webhook_send", "api_call"}:
            signals.append(
                RiskSignal(
                    code="external-data-send",
                    severity=RiskLevel.HIGH,
                    score=65,
                    reason="Agent requested sending data to an external destination.",
                )
            )

        if tool_name in {
            "database_write",
            "database_delete",
            "db_write",
            "db_delete",
            "sql_execute",
        }:
            signals.append(
                RiskSignal(
                    code="database-mutation",
                    severity=RiskLevel.HIGH,
                    score=80,
                    reason="Agent requested database modification.",
                )
            )

        if tool_name in {"database_read", "db_read", "sql_query"}:
            signals.append(
                RiskSignal(
                    code="database-read",
                    severity=RiskLevel.MEDIUM,
                    score=45,
                    reason="Agent requested database read access.",
                )
            )

        return signals

    def _target_based_signals(self, request: ToolRequest) -> list[RiskSignal]:
        target = str(request.target or "").lower()
        signals: list[RiskSignal] = []

        if not target:
            return signals

        if ".env" in target or target.endswith("env"):
            signals.append(
                RiskSignal(
                    code="env-file-access",
                    severity=RiskLevel.CRITICAL,
                    score=95,
                    reason="Agent targeted an environment secret file.",
                )
            )

        if any(pattern in target for pattern in self.SENSITIVE_TARGET_PATTERNS):
            signals.append(
                RiskSignal(
                    code="sensitive-config-target",
                    severity=RiskLevel.CRITICAL,
                    score=90,
                    reason="Agent targeted a sensitive configuration, credential, or key file.",
                )
            )

        if any(keyword in target for keyword in ("secret", "credential", "private_key", "token")):
            signals.append(
                RiskSignal(
                    code="sensitive-target",
                    severity=RiskLevel.HIGH,
                    score=70,
                    reason="Agent targeted a path or object that appears sensitive.",
                )
            )

        if any(keyword in target for keyword in ("customer", "user", "payment", "invoice")):
            signals.append(
                RiskSignal(
                    code="sensitive-business-data",
                    severity=RiskLevel.MEDIUM,
                    score=45,
                    reason="Agent targeted possible sensitive business or customer data.",
                )
            )

        return signals

    def _input_based_signals(self, request: ToolRequest) -> list[RiskSignal]:
        raw_input = self._stringify(request.input)
        signals: list[RiskSignal] = []

        if not raw_input:
            return signals

        if any(pattern.search(raw_input) for pattern in self.SECRET_PATTERNS):
            signals.append(
                RiskSignal(
                    code="secret-in-input",
                    severity=RiskLevel.CRITICAL,
                    score=95,
                    reason="Agent input appears to contain a secret or credential.",
                )
            )

        if any(pattern.search(raw_input) for pattern in self.DANGEROUS_SHELL_PATTERNS):
            signals.append(
                RiskSignal(
                    code="dangerous-shell-pattern",
                    severity=RiskLevel.CRITICAL,
                    score=90,
                    reason="Agent input contains a dangerous shell command pattern.",
                )
            )

        return signals

    @staticmethod
    def _level_from_score(score: int) -> RiskLevel:
        if score >= 85:
            return RiskLevel.CRITICAL

        if score >= 60:
            return RiskLevel.HIGH

        if score >= 30:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    @staticmethod
    def _stringify(value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, str):
            return value

        return str(value)
