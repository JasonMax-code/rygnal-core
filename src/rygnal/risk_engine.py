"""Risk engine for Rygnal.

Risk Engine v2 foundation provides deterministic, contextual, and explainable
risk scoring for AI-agent tool requests before execution.
"""

from __future__ import annotations

import re
import shlex
from collections import defaultdict
from collections.abc import Iterable
from enum import StrEnum
from ipaddress import ip_address
from typing import Any, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from rygnal.models import ToolRequest


class RiskLevel(StrEnum):
    """Risk level for an AI-agent tool request."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskSignalCategory(StrEnum):
    """Category for an explainable risk signal."""

    BASELINE = "baseline"
    CAPABILITY = "capability"
    ACTION = "action"
    ASSET = "asset"
    DATA = "data"
    DESTINATION = "destination"
    ENVIRONMENT = "environment"
    COMMAND = "command"


class RiskContext(BaseModel):
    """Normalized context used by Risk Engine v2."""

    tool_name: str
    action: str | None = None
    target: Any | None = None
    input: Any | None = None
    user_id: str
    agent_id: str
    environment: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    tool_name_normalized: str
    target_text: str = ""
    input_text: str = ""

    @classmethod
    def from_request(cls, request: ToolRequest) -> RiskContext:
        """Build normalized risk context from a tool request."""
        return cls(
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            input=request.input,
            user_id=request.user_id,
            agent_id=request.agent_id,
            environment=request.environment,
            metadata=request.metadata,
            tool_name_normalized=request.tool_name.lower(),
            target_text=str(request.target or "").lower(),
            input_text=stringify_value(request.input),
        )


class RiskSignal(BaseModel):
    """A single explainable risk signal."""

    code: str
    severity: RiskLevel
    score: int = Field(ge=0, le=100)
    reason: str
    category: RiskSignalCategory = RiskSignalCategory.BASELINE
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    reversible: bool | None = None


class RiskAssessment(BaseModel):
    """Final risk assessment for a tool request."""

    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    reasons: list[str]
    signals: list[RiskSignal]
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    explanation: str = ""


class RiskScoringProfile(BaseModel):
    """Deterministic thresholds for mapping score to risk level."""

    medium_threshold: int = 30
    high_threshold: int = 60
    critical_threshold: int = 85

    def level_from_score(self, score: int) -> RiskLevel:
        """Map a risk score to a risk level."""
        if score >= self.critical_threshold:
            return RiskLevel.CRITICAL

        if score >= self.high_threshold:
            return RiskLevel.HIGH

        if score >= self.medium_threshold:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW


class RiskSignalDetector(Protocol):
    """Protocol for risk signal detectors."""

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        """Return risk signals for the provided context."""


class ToolCapabilityDetector:
    """Detect risk based on tool capability."""

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        tool_name = context.tool_name_normalized

        if tool_name in {"file_delete", "delete_file"}:
            signals.append(
                RiskSignal(
                    code="file-delete",
                    category=RiskSignalCategory.CAPABILITY,
                    severity=RiskLevel.HIGH,
                    score=75,
                    reason="Agent requested file deletion.",
                    evidence={"tool_name": context.tool_name},
                    reversible=False,
                )
            )

        if tool_name in {"shell_command", "terminal", "exec", "run_command"}:
            signals.append(
                RiskSignal(
                    code="shell-execution",
                    category=RiskSignalCategory.CAPABILITY,
                    severity=RiskLevel.HIGH,
                    score=70,
                    reason="Agent requested shell or terminal execution.",
                    evidence={"tool_name": context.tool_name},
                    reversible=None,
                )
            )

        if tool_name in {"external_api_send", "http_request", "webhook_send", "api_call"}:
            signals.append(
                RiskSignal(
                    code="external-data-send",
                    category=RiskSignalCategory.DESTINATION,
                    severity=RiskLevel.HIGH,
                    score=65,
                    reason="Agent requested sending data to an external destination.",
                    evidence={"tool_name": context.tool_name},
                    reversible=False,
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
                    category=RiskSignalCategory.CAPABILITY,
                    severity=RiskLevel.HIGH,
                    score=80,
                    reason="Agent requested database modification.",
                    evidence={"tool_name": context.tool_name},
                    reversible=False,
                )
            )

        if tool_name in {"database_read", "db_read", "sql_query"}:
            signals.append(
                RiskSignal(
                    code="database-read",
                    category=RiskSignalCategory.CAPABILITY,
                    severity=RiskLevel.MEDIUM,
                    score=45,
                    reason="Agent requested database read access.",
                    evidence={"tool_name": context.tool_name},
                    reversible=True,
                )
            )

        return signals


class TargetSensitivityDetector:
    """Detect risk based on sensitive targets/assets."""

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

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        target = context.target_text
        signals: list[RiskSignal] = []

        if not target:
            return signals

        if ".env" in target or target.endswith("env"):
            signals.append(
                RiskSignal(
                    code="env-file-access",
                    category=RiskSignalCategory.ASSET,
                    severity=RiskLevel.CRITICAL,
                    score=95,
                    reason="Agent targeted an environment secret file.",
                    evidence={"target": context.target},
                    reversible=True,
                )
            )

        if any(pattern in target for pattern in self.SENSITIVE_TARGET_PATTERNS):
            signals.append(
                RiskSignal(
                    code="sensitive-config-target",
                    category=RiskSignalCategory.ASSET,
                    severity=RiskLevel.CRITICAL,
                    score=90,
                    reason="Agent targeted a sensitive configuration, credential, or key file.",
                    evidence={"target": context.target},
                    reversible=True,
                )
            )

        if any(keyword in target for keyword in ("secret", "credential", "private_key", "token")):
            signals.append(
                RiskSignal(
                    code="sensitive-target",
                    category=RiskSignalCategory.ASSET,
                    severity=RiskLevel.HIGH,
                    score=70,
                    reason="Agent targeted a path or object that appears sensitive.",
                    evidence={"target": context.target},
                    reversible=True,
                )
            )

        if any(keyword in target for keyword in ("customer", "user", "payment", "invoice")):
            signals.append(
                RiskSignal(
                    code="sensitive-business-data",
                    category=RiskSignalCategory.DATA,
                    severity=RiskLevel.MEDIUM,
                    score=45,
                    reason="Agent targeted possible sensitive business or customer data.",
                    evidence={"target": context.target},
                    reversible=True,
                )
            )

        return signals


class InputSensitivityDetector:
    """Detect risk based on sensitive or dangerous input content."""

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

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        raw_input = context.input_text
        signals: list[RiskSignal] = []

        if not raw_input:
            return signals

        if any(pattern.search(raw_input) for pattern in self.SECRET_PATTERNS):
            signals.append(
                RiskSignal(
                    code="secret-in-input",
                    category=RiskSignalCategory.DATA,
                    severity=RiskLevel.CRITICAL,
                    score=95,
                    reason="Agent input appears to contain a secret or credential.",
                    evidence={"input_detected": True},
                    reversible=False,
                )
            )

        if any(pattern.search(raw_input) for pattern in self.DANGEROUS_SHELL_PATTERNS):
            signals.append(
                RiskSignal(
                    code="dangerous-shell-pattern",
                    category=RiskSignalCategory.COMMAND,
                    severity=RiskLevel.CRITICAL,
                    score=90,
                    reason="Agent input contains a dangerous shell command pattern.",
                    evidence={"input_detected": True},
                    reversible=False,
                )
            )

        return signals


class NormalizedCommandRiskDetector:
    """Detect dangerous shell command variants after normalization."""

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        normalized_command = normalize_shell_command(context.input_text)

        if not normalized_command or not is_recursive_force_remove(normalized_command):
            return []

        return [
            RiskSignal(
                code="dangerous-shell-pattern",
                category=RiskSignalCategory.COMMAND,
                severity=RiskLevel.CRITICAL,
                score=90,
                confidence=0.95,
                reason=("Agent command contains recursive forced deletion after normalization."),
                evidence={
                    "normalized_command": normalized_command,
                    "pattern": "rm-recursive-force",
                },
                reversible=False,
            )
        ]


class SensitivePathRiskDetector:
    """Detect sensitive path classes beyond exact filename matching."""

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        classification = classify_sensitive_path(context.target_text)

        if classification is None:
            return []

        return [
            RiskSignal(
                code="sensitive-path-target",
                category=RiskSignalCategory.ASSET,
                severity=RiskLevel.CRITICAL,
                score=90,
                confidence=0.95,
                reason=f"Agent targeted sensitive path class: {classification}.",
                evidence={
                    "target": context.target_text,
                    "classification": classification,
                },
                reversible=False,
            )
        ]


class RiskyDestinationDetector:
    """Detect risky network destinations for data movement."""

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        signals: list[RiskSignal] = []

        for url in extract_urls(context.input_text):
            classification = classify_risky_destination(url)

            if classification is None:
                continue

            signals.append(
                RiskSignal(
                    code="risky-destination",
                    category=RiskSignalCategory.DESTINATION,
                    severity=RiskLevel.HIGH,
                    score=40,
                    confidence=0.9,
                    reason=(f"Agent targeted risky network destination: {classification}."),
                    evidence={
                        "url": url,
                        "classification": classification,
                    },
                    reversible=False,
                )
            )

        return signals


class CredentialExfiltrationCorrelationDetector:
    """Detect secret-like input being sent to an external destination.

    This is intentionally a correlation detector: secret-like content alone is
    risky, and external sending alone is risky, but both together indicate a
    likely exfiltration path and should be explained as such.
    """

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        if not is_external_data_movement(context):
            return []

        if not contains_secret_like_input(context.input_text):
            return []

        urls = extract_urls(context.input_text)

        return [
            RiskSignal(
                code="credential-exfiltration-attempt",
                category=RiskSignalCategory.DESTINATION,
                severity=RiskLevel.CRITICAL,
                score=35,
                confidence=0.95,
                reason="Agent appears to send secret-like input to an external destination.",
                evidence={
                    "sensitive_input_present": True,
                    "external_destination": True,
                    "url_count": len(urls),
                    "tool_name": context.tool_name,
                },
                reversible=False,
            )
        ]


class DestructiveActionVariantDetector:
    """Detect destructive action naming variants."""

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        if not is_destructive_action_variant(context):
            return []

        return [
            RiskSignal(
                code="destructive-action",
                category=RiskSignalCategory.CAPABILITY,
                severity=RiskLevel.HIGH,
                score=60,
                confidence=0.9,
                reason="Agent requested a destructive action variant.",
                evidence={
                    "tool_name": context.tool_name,
                    "action": context.action or "",
                },
                reversible=False,
            )
        ]


class CompoundRiskCorrelationDetector:
    """Escalate combinations of independently risky request attributes."""

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        if (
            context.environment.lower() == "production"
            and is_destructive_action_variant(context)
            and contains_sensitive_business_target(context.target_text)
        ):
            return [
                RiskSignal(
                    code="compound-risk-escalation",
                    category=RiskSignalCategory.ENVIRONMENT,
                    severity=RiskLevel.CRITICAL,
                    score=40,
                    confidence=0.95,
                    reason=("Production destructive action targets sensitive business data."),
                    evidence={
                        "environment": context.environment,
                        "action": context.action or "",
                        "target": context.target_text,
                    },
                    reversible=False,
                )
            ]

        return []


class EnvironmentDetector:
    """Detect risk based on execution environment.

    Non-local environments increase blast radius even when the individual tool
    action looks ordinary. Production keeps its legacy signal for compatibility
    and also receives the generic non-local amplification signal.
    """

    NON_LOCAL_ENVIRONMENTS = {
        "ci",
        "shared",
        "staging",
        "prod",
        "production",
    }

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        environment = context.environment.strip().lower()
        signals: list[RiskSignal] = []

        if environment in {"production", "prod"}:
            signals.append(
                RiskSignal(
                    code="production-environment",
                    category=RiskSignalCategory.ENVIRONMENT,
                    severity=RiskLevel.MEDIUM,
                    score=25,
                    reason="Agent action is running in a production environment.",
                    evidence={"environment": context.environment},
                    reversible=None,
                )
            )

        if environment in self.NON_LOCAL_ENVIRONMENTS:
            signals.append(
                RiskSignal(
                    code="non-local-environment",
                    category=RiskSignalCategory.ENVIRONMENT,
                    severity=RiskLevel.MEDIUM,
                    score=30,
                    confidence=0.9,
                    reason="Agent action is running outside a purely local environment.",
                    evidence={"environment": context.environment},
                    reversible=None,
                )
            )

        return signals


class RiskSignalRegistry:
    """Registry of deterministic risk signal detectors."""

    def __init__(self, detectors: Iterable[RiskSignalDetector] | None = None) -> None:
        self.detectors = list(detectors or [])

    @classmethod
    def default(cls) -> RiskSignalRegistry:
        """Return the default Risk Engine v2 signal registry."""
        return cls(
            detectors=[
                ToolCapabilityDetector(),
                TargetSensitivityDetector(),
                NormalizedCommandRiskDetector(),
                SensitivePathRiskDetector(),
                RiskyDestinationDetector(),
                CredentialExfiltrationCorrelationDetector(),
                DestructiveActionVariantDetector(),
                CompoundRiskCorrelationDetector(),
                InputSensitivityDetector(),
                EnvironmentDetector(),
            ]
        )

    def detect(self, context: RiskContext) -> list[RiskSignal]:
        """Run all registered detectors."""
        signals: list[RiskSignal] = []

        for detector in self.detectors:
            signals.extend(detector.detect(context))

        return signals


class RiskEngine:
    """Deterministic, contextual risk scorer for AI-agent tool requests."""

    def __init__(
        self,
        registry: RiskSignalRegistry | None = None,
        scoring_profile: RiskScoringProfile | None = None,
        trace_history_limit: int = 20,
    ) -> None:
        self.registry = registry or RiskSignalRegistry.default()
        self.scoring_profile = scoring_profile or RiskScoringProfile()
        self.trace_history_limit = trace_history_limit
        self._trace_risk_history: dict[str, list[int]] = defaultdict(list)

    def assess(self, request: ToolRequest) -> RiskAssessment:
        """Assess risk for a tool request."""
        context = RiskContext.from_request(request)
        signals = self.registry.detect(context)

        if not signals:
            signals.append(
                RiskSignal(
                    code="baseline-low-risk",
                    category=RiskSignalCategory.BASELINE,
                    severity=RiskLevel.LOW,
                    score=10,
                    confidence=0.8,
                    reason="No risky tool, target, or input pattern detected.",
                    evidence={"tool_name": request.tool_name},
                    reversible=True,
                )
            )

        preliminary_score = self._score(signals)
        cumulative_signal = self._cumulative_trace_signal(context, preliminary_score)

        if cumulative_signal is not None:
            signals.append(cumulative_signal)

        risk_score = self._score(signals)
        self._record_trace_risk(context, risk_score)

        risk_level = self.scoring_profile.level_from_score(risk_score)
        reasons = [signal.reason for signal in signals]
        confidence = self._confidence(signals)

        return RiskAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=reasons,
            signals=signals,
            confidence=confidence,
            explanation=self._explanation(risk_score, risk_level, signals),
        )

    @staticmethod
    def _score(signals: list[RiskSignal]) -> int:
        return min(sum(signal.score for signal in signals), 100)

    def _cumulative_trace_signal(
        self,
        context: RiskContext,
        current_score: int,
    ) -> RiskSignal | None:
        trace_id = trace_identity(context)

        if trace_id is None:
            return None

        if current_score < self.scoring_profile.medium_threshold:
            return None

        history = self._trace_risk_history.get(trace_id, [])
        previous_risky_events = sum(
            1 for score in history if score >= self.scoring_profile.medium_threshold
        )

        if previous_risky_events >= 2:
            return RiskSignal(
                code="cumulative-trace-risk",
                category=RiskSignalCategory.BASELINE,
                severity=RiskLevel.CRITICAL,
                score=45,
                confidence=0.9,
                reason="Multiple risky actions occurred in the same trace.",
                evidence={
                    "trace_id_present": True,
                    "previous_risky_events": previous_risky_events,
                    "history_size": len(history),
                },
                reversible=None,
            )

        if previous_risky_events >= 1:
            return RiskSignal(
                code="cumulative-trace-risk",
                category=RiskSignalCategory.BASELINE,
                severity=RiskLevel.HIGH,
                score=20,
                confidence=0.85,
                reason="Repeated risky actions are accumulating in the same trace.",
                evidence={
                    "trace_id_present": True,
                    "previous_risky_events": previous_risky_events,
                    "history_size": len(history),
                },
                reversible=None,
            )

        return None

    def _record_trace_risk(self, context: RiskContext, risk_score: int) -> None:
        trace_id = trace_identity(context)

        if trace_id is None:
            return

        history = self._trace_risk_history[trace_id]
        history.append(risk_score)

        if len(history) > self.trace_history_limit:
            del history[: len(history) - self.trace_history_limit]

    @staticmethod
    def _confidence(signals: list[RiskSignal]) -> float:
        if not signals:
            return 0.0

        return round(sum(signal.confidence for signal in signals) / len(signals), 2)

    @staticmethod
    def _explanation(
        risk_score: int,
        risk_level: RiskLevel,
        signals: list[RiskSignal],
    ) -> str:
        signal_codes = ", ".join(signal.code for signal in signals)
        return f"Risk score {risk_score} mapped to {risk_level.value} based on: {signal_codes}."


def normalize_shell_command(command: str) -> str:
    """Normalize shell-like command text for deterministic risk detection."""
    if not command:
        return ""

    collapsed = " ".join(command.strip().lower().split())

    try:
        tokens = shlex.split(collapsed)
    except ValueError:
        tokens = collapsed.split()

    if len(tokens) >= 3 and tokens[0] in {"sh", "bash"} and tokens[1] == "-c":
        return normalize_shell_command(tokens[2])

    return " ".join(tokens)


def is_recursive_force_remove(normalized_command: str) -> bool:
    """Return true for rm variants that combine recursive and force deletion."""
    try:
        tokens = shlex.split(normalized_command)
    except ValueError:
        tokens = normalized_command.split()

    if tokens and tokens[0] == "sudo":
        tokens = tokens[1:]

    if not tokens or tokens[0] != "rm":
        return False

    flags = "".join(token.lstrip("-") for token in tokens[1:] if token.startswith("-"))

    return "r" in flags and "f" in flags


def classify_sensitive_path(target: str) -> str | None:
    """Classify sensitive file-system target paths."""
    normalized_target = target.strip().replace("\\", "/").lower()

    if not normalized_target:
        return None

    if normalized_target.startswith("/etc/"):
        return "system-config"

    if normalized_target.startswith("~/.ssh/") or "/.ssh/" in normalized_target:
        return "ssh-credential"

    if "../" in normalized_target and any(
        marker in normalized_target for marker in ("secret", ".env", "credential", "token", "key")
    ):
        return "traversal-sensitive-target"

    return None


def extract_urls(value: str) -> list[str]:
    """Extract URL-like values from stringified tool input."""
    return re.findall(r"https?://[^\s'\"<>},]+", value)


def classify_risky_destination(url: str) -> str | None:
    """Classify network destinations that are risky for exfiltration."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if parsed.scheme != "https":
        return "non-https"

    if hostname == "localhost":
        return "local-network"

    try:
        host_ip = ip_address(hostname)
    except ValueError:
        return None

    if host_ip.compressed == "169.254.169.254":
        return "cloud-metadata"

    if host_ip.is_unspecified:
        return "local-network"

    if host_ip.is_loopback or host_ip.is_private or host_ip.is_link_local:
        return "private-network"

    return None


def normalized_identifier(value: str | None) -> str:
    """Normalize identifiers used in tool and action names."""
    return (value or "").strip().lower().replace("-", "_")


def is_destructive_action_variant(context: RiskContext) -> bool:
    """Return true when tool/action naming indicates destructive intent."""
    identifiers = {
        normalized_identifier(context.tool_name),
        normalized_identifier(context.action),
    }

    destructive_prefixes = (
        "delete",
        "remove",
        "destroy",
        "wipe",
        "truncate",
        "drop",
    )

    return any(
        identifier.startswith(prefix) or f"_{prefix}_" in f"_{identifier}_"
        for identifier in identifiers
        for prefix in destructive_prefixes
    )


def contains_sensitive_business_target(target: str) -> bool:
    """Return true when target text indicates sensitive business data."""
    normalized_target = target.lower()
    return any(
        keyword in normalized_target for keyword in ("customer", "user", "payment", "invoice")
    )


def contains_secret_like_input(value: str) -> bool:
    """Return true when stringified input contains credential-like material."""
    if not value:
        return False

    return any(pattern.search(value) for pattern in InputSensitivityDetector.SECRET_PATTERNS)


def is_external_data_movement(context: RiskContext) -> bool:
    """Return true when a request can move data outside the local process."""
    tool_name = context.tool_name_normalized
    action = normalized_identifier(context.action)

    if tool_name in {"external_api_send", "http_request", "webhook_send", "api_call"}:
        return True

    if action in {"send_data", "post", "put", "upload", "exfiltrate"}:
        return True

    return bool(extract_urls(context.input_text))


def trace_identity(context: RiskContext) -> str | None:
    """Return a stable trace/session identity for cumulative risk tracking."""
    for key in ("trace_id", "request_id", "session_id", "run_id"):
        value = context.metadata.get(key)

        if isinstance(value, str) and value.strip():
            return value.strip()

    return None


def stringify_value(value: Any) -> str:
    """Stringify values for deterministic pattern matching."""
    if value is None:
        return ""

    if isinstance(value, str):
        return value

    return str(value)
