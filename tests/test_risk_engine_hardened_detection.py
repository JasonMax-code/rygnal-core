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
