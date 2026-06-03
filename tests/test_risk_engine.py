from rygnal.models import ToolRequest
from rygnal.risk_engine import RiskEngine, RiskLevel


def test_safe_file_read_is_low_risk():
    engine = RiskEngine()

    assessment = engine.assess(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.risk_score < 30
    assert assessment.reasons


def test_env_file_access_is_critical_risk():
    engine = RiskEngine()

    assessment = engine.assess(
        ToolRequest(tool_name="file_read", action="read_file", target=".env")
    )

    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.risk_score >= 85
    assert any(signal.code == "env-file-access" for signal in assessment.signals)


def test_file_delete_is_high_risk():
    engine = RiskEngine()

    assessment = engine.assess(
        ToolRequest(tool_name="file_delete", action="delete_file", target="customer_data.csv")
    )

    assert assessment.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert assessment.risk_score >= 60
    assert any(signal.code == "file-delete" for signal in assessment.signals)


def test_dangerous_shell_command_is_critical_risk():
    engine = RiskEngine()

    assessment = engine.assess(
        ToolRequest(tool_name="shell_command", action="execute", input="rm -rf /tmp/demo")
    )

    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.risk_score >= 85
    assert any(signal.code == "dangerous-shell-pattern" for signal in assessment.signals)


def test_external_api_send_is_high_risk():
    engine = RiskEngine()

    assessment = engine.assess(
        ToolRequest(
            tool_name="external_api_send",
            action="send_data",
            input={"url": "https://example.com", "payload": "demo"},
        )
    )

    assert assessment.risk_level == RiskLevel.HIGH
    assert assessment.risk_score >= 60
    assert any(signal.code == "external-data-send" for signal in assessment.signals)


def test_secret_in_input_is_critical_risk():
    engine = RiskEngine()

    assessment = engine.assess(
        ToolRequest(
            tool_name="external_api_send",
            action="send_data",
            input={"message": "api_key=sk-test-secret-value"},
        )
    )

    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.risk_score == 100
    assert any(signal.code == "secret-in-input" for signal in assessment.signals)


def test_database_mutation_is_high_risk():
    engine = RiskEngine()

    assessment = engine.assess(
        ToolRequest(
            tool_name="database_write",
            action="update",
            target="users",
            input={"role": "admin"},
        )
    )

    assert assessment.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert any(signal.code == "database-mutation" for signal in assessment.signals)


def test_customer_data_target_adds_business_data_signal():
    engine = RiskEngine()

    assessment = engine.assess(
        ToolRequest(tool_name="file_read", action="read_file", target="customer_data.csv")
    )

    assert assessment.risk_level == RiskLevel.MEDIUM
    assert any(signal.code == "sensitive-business-data" for signal in assessment.signals)


def test_sensitive_config_targets_are_critical_risk():
    engine = RiskEngine()

    sensitive_targets = [
        ".env.backup",
        "config/secrets.yaml",
        "config/secrets.yml",
        "credentials.json",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "private.key",
        "service-account.json",
        "database.yml",
    ]

    for target in sensitive_targets:
        assessment = engine.assess(
            ToolRequest(tool_name="file_read", action="read_file", target=target)
        )

        assert assessment.risk_level == RiskLevel.CRITICAL
        assert assessment.risk_score >= 85
        assert any(signal.code == "sensitive-config-target" for signal in assessment.signals)
