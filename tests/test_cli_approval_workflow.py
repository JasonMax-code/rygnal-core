import builtins
import json

from demo.scenario_runner import ScenarioRunner
from rygnal.approval import ApprovalWorkflow
from rygnal.cli_approval import ApprovalTimeoutError, CLIApprovalResolver
from rygnal.models import ApprovalRequest, ApprovalStatus, ExecutionStatus


def make_request() -> ApprovalRequest:
    return ApprovalRequest(
        requested_by="demo_user",
        agent_id="demo_agent",
        environment="local",
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
        policy_id="approval-file-delete",
        reason="File deletion requires human approval.",
        risk_assessment={"risk_score": 100, "risk_level": "critical"},
    )


def test_cli_approval_resolver_approves_yes_response():
    output: list[str] = []
    resolver = CLIApprovalResolver(
        approver="manish",
        timeout_seconds=None,
        input_func=lambda prompt: "yes",
        output_func=output.append,
    )

    decision = resolver(make_request())

    assert decision.status == ApprovalStatus.APPROVED
    assert decision.approved is True
    assert decision.decided_by == "manish"
    assert decision.reason == "Approved from CLI."
    assert any("Rygnal Approval Required" in line for line in output)


def test_cli_approval_resolver_rejects_no_response():
    resolver = CLIApprovalResolver(
        approver="reviewer",
        timeout_seconds=None,
        input_func=lambda prompt: "no",
        output_func=lambda message: None,
    )

    decision = resolver(make_request())

    assert decision.status == ApprovalStatus.REJECTED
    assert decision.approved is False
    assert decision.decided_by == "reviewer"
    assert decision.reason == "Rejected from CLI."


def test_cli_approval_resolver_rejects_empty_response():
    resolver = CLIApprovalResolver(
        timeout_seconds=None,
        input_func=lambda prompt: "",
        output_func=lambda message: None,
    )

    decision = resolver(make_request())

    assert decision.status == ApprovalStatus.REJECTED
    assert decision.approved is False


def test_scenario_runner_executes_approval_required_action_when_cli_approved(tmp_path):
    resolver = CLIApprovalResolver(
        approver="test_reviewer",
        timeout_seconds=None,
        input_func=lambda prompt: "y",
        output_func=lambda message: None,
    )

    runner = ScenarioRunner(
        sandbox_path=tmp_path / "sandbox",
        audit_log_path=tmp_path / "audit_log.jsonl",
        approval_workflow=ApprovalWorkflow(resolver=resolver),
    )

    outcomes = runner.run_all()
    outcome = next(item for item in outcomes if item.scenario.name == "file-delete-approval")

    assert outcome.result.approval_decision is not None
    assert outcome.result.approval_decision.status == ApprovalStatus.APPROVED
    assert outcome.result.execution.status == ExecutionStatus.EXECUTED
    assert outcome.result.execution.executed is True
    assert not (tmp_path / "sandbox" / "customer_data.csv").exists()


def test_scenario_runner_rejects_approval_required_action_by_default(tmp_path):
    runner = ScenarioRunner(
        sandbox_path=tmp_path / "sandbox",
        audit_log_path=tmp_path / "audit_log.jsonl",
    )

    outcomes = runner.run_all()
    outcome = next(item for item in outcomes if item.scenario.name == "file-delete-approval")

    assert outcome.result.approval_decision is not None
    assert outcome.result.approval_decision.status == ApprovalStatus.REJECTED
    assert outcome.result.execution.status == ExecutionStatus.SKIPPED
    assert outcome.result.execution.executed is False
    assert (tmp_path / "sandbox" / "customer_data.csv").exists()


def test_cli_approval_resolver_rejects_non_interactive_without_prompt(monkeypatch):
    def fail_if_called(_prompt):
        raise AssertionError("input() must not be called in non-interactive mode")

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(builtins, "input", fail_if_called)

    output: list[str] = []
    resolver = CLIApprovalResolver(
        approver="ci_runner",
        timeout_seconds=None,
        output_func=output.append,
    )

    decision = resolver(make_request())

    assert decision.status == ApprovalStatus.REJECTED
    assert decision.approved is False
    assert decision.decided_by == "ci_runner"
    assert "non-interactive" in decision.reason.lower()
    assert "rejected by default" in decision.reason.lower()


def test_non_interactive_cli_approval_skips_execution_and_records_audit(
    tmp_path,
    monkeypatch,
):
    def fail_if_called(_prompt):
        raise AssertionError("input() must not be called in non-interactive mode")

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(builtins, "input", fail_if_called)

    resolver = CLIApprovalResolver(
        approver="ci_runner",
        timeout_seconds=None,
        output_func=lambda _message: None,
    )

    runner = ScenarioRunner(
        sandbox_path=tmp_path / "sandbox",
        audit_log_path=tmp_path / "audit_log.jsonl",
        approval_workflow=ApprovalWorkflow(resolver=resolver),
    )

    outcomes = runner.run_all()
    outcome = next(item for item in outcomes if item.scenario.name == "file-delete-approval")

    assert outcome.result.approval_decision is not None
    assert outcome.result.approval_decision.status == ApprovalStatus.REJECTED
    assert outcome.result.execution.status == ExecutionStatus.SKIPPED
    assert outcome.result.execution.executed is False
    assert (tmp_path / "sandbox" / "customer_data.csv").exists()

    audit_log = (tmp_path / "audit_log.jsonl").read_text()
    assert "non-interactive" in audit_log.lower()
    assert "rejected by default" in audit_log.lower()


def test_cli_approval_resolver_timeout_rejects_with_metadata():
    def raise_timeout(_prompt):
        raise ApprovalTimeoutError("approval timed out")

    resolver = CLIApprovalResolver(
        approver="timeout_reviewer",
        timeout_seconds=None,
        input_func=raise_timeout,
        output_func=lambda _message: None,
    )

    decision = resolver(make_request())

    assert decision.status == ApprovalStatus.REJECTED
    assert decision.approved is False
    assert decision.decided_by == "timeout_reviewer"
    assert "timed out" in decision.reason.lower()
    assert "rejected by default" in decision.reason.lower()
    assert decision.metadata["guard"] == "approval-timeout"
    assert decision.metadata["approval_outcome"] == "timeout"
    assert decision.metadata["rejected_by_default"] is True


def test_cli_approval_timeout_skips_execution_and_records_audit_metadata(tmp_path):
    def raise_timeout(_prompt):
        raise ApprovalTimeoutError("approval timed out")

    resolver = CLIApprovalResolver(
        approver="timeout_reviewer",
        timeout_seconds=None,
        input_func=raise_timeout,
        output_func=lambda _message: None,
    )

    runner = ScenarioRunner(
        sandbox_path=tmp_path / "sandbox",
        audit_log_path=tmp_path / "audit_log.jsonl",
        approval_workflow=ApprovalWorkflow(resolver=resolver),
    )

    outcomes = runner.run_all()
    outcome = next(item for item in outcomes if item.scenario.name == "file-delete-approval")

    assert outcome.result.approval_decision is not None
    assert outcome.result.approval_decision.status == ApprovalStatus.REJECTED
    assert outcome.result.approval_decision.approved is False
    assert outcome.result.execution.status == ExecutionStatus.SKIPPED
    assert outcome.result.execution.executed is False
    assert (tmp_path / "sandbox" / "customer_data.csv").exists()

    events = [json.loads(line) for line in (tmp_path / "audit_log.jsonl").read_text().splitlines()]
    approval_event = next(event for event in events if event["metadata"].get("approval"))

    approval_metadata = approval_event["metadata"]["approval"]["metadata"]
    assert approval_metadata["guard"] == "approval-timeout"
    assert approval_metadata["approval_outcome"] == "timeout"
    assert approval_metadata["rejected_by_default"] is True
