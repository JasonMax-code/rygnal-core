import pytest

from rygnal.models import ToolRequest
from rygnal.risk_engine import RiskEngine, RiskLevel


def signal_codes(assessment) -> set[str]:
    return {signal.code for signal in assessment.signals}


@pytest.mark.parametrize(
    "command",
    [
        "rm    -rf   /tmp/demo",
        "rm -r -f /tmp/demo",
        "rm -fr /tmp/demo",
        "sh -c 'rm -rf /tmp/demo'",
    ],
)
def test_normalized_shell_command_variants_are_critical(command: str) -> None:
    assessment = RiskEngine().assess(
        ToolRequest(
            tool_name="shell_command",
            action="execute",
            input=command,
        )
    )

    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.risk_score >= 85
    assert "dangerous-shell-pattern" in signal_codes(assessment)

    signal = next(item for item in assessment.signals if item.code == "dangerous-shell-pattern")
    assert signal.evidence["normalized_command"]
    assert signal.confidence >= 0.9


@pytest.mark.parametrize(
    "target",
    [
        "/etc/passwd",
        "/etc/shadow",
        "~/.ssh/id_rsa",
        "../secrets.env",
    ],
)
def test_sensitive_path_classification_detects_system_and_secret_paths(target: str) -> None:
    assessment = RiskEngine().assess(
        ToolRequest(
            tool_name="file_read",
            action="read_file",
            target=target,
        )
    )

    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.risk_score >= 85
    assert "sensitive-path-target" in signal_codes(assessment)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/collect",
        "https://127.0.0.1/admin",
        "https://localhost/admin",
        "https://169.254.169.254/latest/meta-data",
    ],
)
def test_destination_classification_detects_risky_exfil_destinations(url: str) -> None:
    assessment = RiskEngine().assess(
        ToolRequest(
            tool_name="external_api_send",
            action="send_data",
            input={"url": url, "payload": "safe"},
        )
    )

    assert assessment.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert assessment.risk_score >= 60
    assert "risky-destination" in signal_codes(assessment)


@pytest.mark.parametrize(
    "action",
    [
        "remove_file",
        "destroy_file",
        "wipe_file",
    ],
)
def test_destructive_action_variants_are_detected(action: str) -> None:
    assessment = RiskEngine().assess(
        ToolRequest(
            tool_name="file_manager",
            action=action,
            target="customer_data.csv",
        )
    )

    assert assessment.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert assessment.risk_score >= 60
    assert "destructive-action" in signal_codes(assessment)


def test_cross_signal_correlation_escalates_sensitive_production_delete() -> None:
    assessment = RiskEngine().assess(
        ToolRequest(
            tool_name="file_manager",
            action="remove_file",
            target="customer_data.csv",
            environment="production",
        )
    )

    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.risk_score >= 85
    assert "compound-risk-escalation" in signal_codes(assessment)


def test_credential_exfiltration_correlation_is_explicit_and_redacted() -> None:
    secret_value = "sk-live-super-secret-token-123456"
    assessment = RiskEngine().assess(
        ToolRequest(
            tool_name="external_api_send",
            action="send_data",
            input={
                "url": "https://api.example.com/collect",
                "payload": {"api_key": secret_value},
            },
        )
    )

    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.risk_score == 100
    assert "credential-exfiltration-attempt" in signal_codes(assessment)

    signal = next(
        item for item in assessment.signals if item.code == "credential-exfiltration-attempt"
    )
    assert signal.category.value == "destination"
    assert signal.evidence["sensitive_input_present"] is True
    assert secret_value not in str(signal.evidence)
    assert secret_value not in assessment.model_dump_json()


@pytest.mark.parametrize("environment", ["ci", "staging", "shared", "prod"])
def test_non_local_environments_amplify_risk(environment: str) -> None:
    assessment = RiskEngine().assess(
        ToolRequest(
            tool_name="file_write",
            action="write_file",
            target="config/app.yml",
            input="debug: true",
            environment=environment,
        )
    )

    assert assessment.risk_score >= 30
    assert assessment.risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert "non-local-environment" in signal_codes(assessment)


def test_trace_cumulative_risk_escalates_repeated_medium_risk_actions() -> None:
    engine = RiskEngine()

    trace_id = "trace_repeated_risk"

    first = engine.assess(
        ToolRequest(
            tool_name="database_read",
            action="select",
            target="analytics_snapshot",
            metadata={"trace_id": trace_id},
        )
    )
    second = engine.assess(
        ToolRequest(
            tool_name="database_read",
            action="select",
            target="feature_flags",
            metadata={"trace_id": trace_id},
        )
    )
    third = engine.assess(
        ToolRequest(
            tool_name="database_read",
            action="select",
            target="debug_metrics",
            metadata={"trace_id": trace_id},
        )
    )

    assert first.risk_level == RiskLevel.MEDIUM
    assert second.risk_level == RiskLevel.HIGH
    assert third.risk_level == RiskLevel.CRITICAL
    assert "cumulative-trace-risk" in signal_codes(third)


def test_trace_risk_isolated_by_trace_id() -> None:
    engine = RiskEngine()

    first = engine.assess(
        ToolRequest(
            tool_name="database_read",
            action="select",
            target="analytics_snapshot",
            metadata={"trace_id": "trace_a"},
        )
    )
    second = engine.assess(
        ToolRequest(
            tool_name="database_read",
            action="select",
            target="analytics_snapshot",
            metadata={"trace_id": "trace_b"},
        )
    )

    assert "cumulative-trace-risk" not in signal_codes(first)
    assert "cumulative-trace-risk" not in signal_codes(second)
