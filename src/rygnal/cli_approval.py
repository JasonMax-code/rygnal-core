"""CLI-based approval resolver for Rygnal.

This module provides a simple human-in-the-loop approval flow for local
development and v0.1 demos.
"""

from __future__ import annotations

import signal
import sys
from collections.abc import Callable
from typing import Any

from rygnal.approval import ApprovalWorkflow
from rygnal.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    utc_now_iso,
)

NON_INTERACTIVE_REJECTION_REASON = (
    "Approval requested in non-interactive terminal mode. Rejected by default."
)
TIMEOUT_REJECTION_REASON = "Approval timed out. Rejected by default."
INTERRUPTED_REJECTION_REASON = "Approval was interrupted. Rejected by default."


class ApprovalTimeoutError(TimeoutError):
    """Raised when CLI approval times out."""


class CLIApprovalResolver:
    """Resolve approval requests using terminal input."""

    def __init__(
        self,
        approver: str = "cli_user",
        timeout_seconds: int | None = 30,
        input_func: Callable[[str], str] | None = None,
        output_func: Callable[[str], Any] | None = None,
    ) -> None:
        self.approver = approver
        self.timeout_seconds = timeout_seconds
        self.input_func = input_func or input
        self.output_func = output_func or print

    def __call__(self, approval_request: ApprovalRequest) -> ApprovalDecision:
        """Ask a human to approve or reject an approval request."""
        self._print_request_summary(approval_request)

        if self._is_non_interactive_terminal():
            self.output_func("Non-interactive terminal detected. Rejected by default.")
            return self._reject(
                approval_request,
                reason=NON_INTERACTIVE_REJECTION_REASON,
                metadata=_default_rejection_metadata(
                    guard="non-interactive-terminal",
                    approval_outcome="non_interactive",
                ),
            )

        try:
            response = self._read_input("Approve this action? [y/N]: ")
        except ApprovalTimeoutError:
            return self._reject(
                approval_request,
                reason=TIMEOUT_REJECTION_REASON,
                metadata=_default_rejection_metadata(
                    guard="approval-timeout",
                    approval_outcome="timeout",
                ),
            )
        except (EOFError, KeyboardInterrupt):
            return self._reject(
                approval_request,
                reason=INTERRUPTED_REJECTION_REASON,
                metadata=_default_rejection_metadata(
                    guard="approval-interrupted",
                    approval_outcome="interrupted",
                ),
            )

        normalized = response.strip().lower()

        if normalized in {"y", "yes", "approve", "approved"}:
            return ApprovalDecision(
                approval_id=approval_request.approval_id,
                status=ApprovalStatus.APPROVED,
                approved=True,
                decided_by=self.approver,
                decided_at=utc_now_iso(),
                reason="Approved from CLI.",
            )

        return self._reject(
            approval_request,
            reason="Rejected from CLI.",
        )

    def _print_request_summary(self, approval_request: ApprovalRequest) -> None:
        risk_score = approval_request.risk_assessment.get("risk_score", "n/a")
        risk_level = approval_request.risk_assessment.get("risk_level", "unknown")

        self.output_func("")
        self.output_func("Rygnal Approval Required")
        self.output_func("-" * 32)
        self.output_func(f"Approval ID : {approval_request.approval_id}")
        self.output_func(f"Tool        : {approval_request.tool_name}")
        self.output_func(f"Action      : {approval_request.action or 'n/a'}")
        self.output_func(f"Target      : {approval_request.target or 'n/a'}")
        self.output_func(f"Environment : {approval_request.environment}")
        self.output_func(f"Risk        : {risk_level} / {risk_score}")
        self.output_func(f"Reason      : {approval_request.reason}")
        self.output_func("")

    def _is_non_interactive_terminal(self) -> bool:
        return self.input_func is input and not sys.stdin.isatty()

    def _read_input(self, prompt: str) -> str:
        if not self.timeout_seconds:
            return self.input_func(prompt)

        if self.input_func is not input or not hasattr(signal, "SIGALRM"):
            return self.input_func(prompt)

        previous_handler = signal.signal(signal.SIGALRM, _raise_timeout)
        signal.alarm(self.timeout_seconds)

        try:
            return self.input_func(prompt)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)

    def _reject(
        self,
        approval_request: ApprovalRequest,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> ApprovalDecision:
        return ApprovalDecision(
            approval_id=approval_request.approval_id,
            status=ApprovalStatus.REJECTED,
            approved=False,
            decided_by=self.approver,
            decided_at=utc_now_iso(),
            reason=reason,
            metadata=metadata or {},
        )


def build_cli_approval_workflow(
    approver: str = "cli_user",
    timeout_seconds: int | None = 30,
) -> ApprovalWorkflow:
    """Build an ApprovalWorkflow backed by terminal approval."""
    return ApprovalWorkflow(
        resolver=CLIApprovalResolver(
            approver=approver,
            timeout_seconds=timeout_seconds,
        )
    )


def _raise_timeout(_signum: int, _frame: Any) -> None:
    raise ApprovalTimeoutError("CLI approval timed out.")


def _default_rejection_metadata(
    *,
    guard: str,
    approval_outcome: str,
) -> dict[str, Any]:
    return {
        "guard": guard,
        "approval_outcome": approval_outcome,
        "rejected_by_default": True,
    }
