package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Rygnal/rygnal-core/internal/engineclient"
)

type blockingPromptReader struct{}

func (blockingPromptReader) Read(_ []byte) (int, error) {
	select {}
}

func approvalPromptFixture() engineclient.RunCompletedData {
	return engineclient.RunCompletedData{
		Status:            "approval_required",
		RunID:             "run_123",
		BaselineCommitSHA: strings.Repeat("b", 40),
		Changes: engineclient.ChangesInfo{
			ChangedFileCount: 2,
		},
		Patch: engineclient.PatchInfo{
			Generated: true,
			SHA256:    strings.Repeat("a", 64),
		},
		Risk: engineclient.RiskInfo{
			Present: true,
			Level:   "high",
			Reasons: []string{"High-risk guarded patch requires review."},
		},
		Approval: engineclient.ApprovalInfo{
			Required:   true,
			ApprovalID: "apr_123",
			Reason:     "Patch requires human approval.",
		},
	}
}

func TestPromptForApprovalApproves(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer

	decision, err := promptForApproval(
		ctx,
		strings.NewReader("approve\n"),
		&out,
		approvalPromptFixture(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Status != localDecisionApproved {
		t.Fatalf("expected approved, got %q", decision.Status)
	}

	if decision.Reason != defaultInteractiveApprovalReason {
		t.Fatalf("unexpected reason: %q", decision.Reason)
	}

	if !strings.Contains(out.String(), "Type approve or reject.") {
		t.Fatalf("expected prompt instructions in output:\n%s", out.String())
	}
}

func TestPromptForApprovalRetriesTypoThenApproves(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer

	decision, err := promptForApproval(
		ctx,
		strings.NewReader("approv\napprove\n"),
		&out,
		approvalPromptFixture(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Status != localDecisionApproved {
		t.Fatalf("expected approved, got %q", decision.Status)
	}

	if !strings.Contains(out.String(), "Invalid input. Please type 'approve' or 'reject'.") {
		t.Fatalf("expected retry guidance in output:\n%s", out.String())
	}
}

func TestPromptForApprovalStopsAfterInvalidAttempts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer

	_, err := promptForApproval(
		ctx,
		strings.NewReader("yes\nno\nmaybe\n"),
		&out,
		approvalPromptFixture(),
	)

	if !errors.Is(err, errApprovalPromptInvalidAttempts) {
		t.Fatalf("expected invalid-attempts error, got %v", err)
	}
}

func TestPromptForApprovalRejectsWithReason(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer

	decision, err := promptForApproval(
		ctx,
		strings.NewReader("reject\nNeeds manual review\n"),
		&out,
		approvalPromptFixture(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Status != localDecisionRejected {
		t.Fatalf("expected rejected, got %q", decision.Status)
	}

	if decision.Reason != "Needs manual review" {
		t.Fatalf("unexpected reason: %q", decision.Reason)
	}
}

func TestPromptForApprovalRetriesEmptyRejectReason(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer

	decision, err := promptForApproval(
		ctx,
		strings.NewReader("reject\n\nNeeds manual review\n"),
		&out,
		approvalPromptFixture(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Status != localDecisionRejected {
		t.Fatalf("expected rejected, got %q", decision.Status)
	}

	if decision.Reason != "Needs manual review" {
		t.Fatalf("unexpected reason: %q", decision.Reason)
	}

	if !strings.Contains(out.String(), "Reject reason is required. Please enter a reason.") {
		t.Fatalf("expected retry guidance in output:\n%s", out.String())
	}
}

func TestPromptForApprovalRejectRequiresReasonAfterAttempts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer

	_, err := promptForApproval(
		ctx,
		strings.NewReader("reject\n\n\n\n"),
		&out,
		approvalPromptFixture(),
	)

	if !errors.Is(err, errApprovalPromptReasonRequired) {
		t.Fatalf("expected rejection reason error, got %v", err)
	}
}

func TestPromptForApprovalEmptyEOFCancels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer

	_, err := promptForApproval(
		ctx,
		strings.NewReader(""),
		&out,
		approvalPromptFixture(),
	)

	if !errors.Is(err, errApprovalPromptCancelled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestPromptForApprovalRejectReasonEOFCancels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer

	_, err := promptForApproval(
		ctx,
		strings.NewReader("reject\n"),
		&out,
		approvalPromptFixture(),
	)

	if !errors.Is(err, errApprovalPromptCancelled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestPromptForApprovalTimeoutWritesNoDecision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	var out bytes.Buffer

	_, err := promptForApproval(
		ctx,
		blockingPromptReader{},
		&out,
		approvalPromptFixture(),
	)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestRenderApprovalPromptNoDecisionPrintsManualNextSteps(t *testing.T) {
	var out bytes.Buffer

	renderApprovalPromptNoDecision(&out, "run_123", "Approval prompt cancelled.")

	output := out.String()

	for _, expected := range []string{
		"Approval prompt cancelled.",
		"No approval decision was written.",
		"Run remains approval_required.",
		"rygnal approve run_123 --yes",
		"rygnal reject run_123 --reason \"...\"",
		"rygnal apply run_123 --yes",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected %q in output:\n%s", expected, output)
		}
	}
}
