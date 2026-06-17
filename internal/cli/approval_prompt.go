package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Rygnal/rygnal-core/internal/engineclient"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	defaultInteractiveApprovalReason = "Approved from interactive approval prompt."
	maxApprovalPromptAttempts        = 3
)

var (
	errApprovalPromptCancelled       = errors.New("approval prompt cancelled")
	errApprovalPromptInvalidAttempts = errors.New("approval prompt invalid input limit exceeded")
	errApprovalPromptReasonRequired  = errors.New("reject requires a reason")
)

type approvalPromptDecision struct {
	Status string
	Reason string
}

type approvalPromptLineResult struct {
	value string
	err   error
}

func defaultApprovalPromptIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) &&
		term.IsTerminal(int(os.Stdout.Fd()))
}

func maybePromptForApproval(
	cmd *cobra.Command,
	opts *runOptions,
	store localReviewStore,
	lastEvent *engineclient.EngineEvent,
	deps runDependencies,
) (bool, error) {
	if !opts.promptApproval {
		return false, nil
	}

	if lastEvent == nil || lastEvent.Status != "approval_required" {
		return false, nil
	}

	data, err := engineclient.DecodeRunCompletedData(*lastEvent)
	if err != nil {
		return false, err
	}

	if strings.TrimSpace(data.RunID) == "" {
		data.RunID = strings.TrimSpace(lastEvent.RequestID)
	}
	if strings.TrimSpace(data.RunID) == "" {
		return false, errors.New("approval prompt cannot resolve run id")
	}

	out := cmd.OutOrStdout()
	isTerminal := deps.isTerminal
	if isTerminal == nil {
		isTerminal = defaultApprovalPromptIsTerminal
	}

	if !isTerminal() {
		renderApprovalPromptNoDecision(
			out,
			data.RunID,
			"Approval prompt was requested, but stdin/stdout is not interactive.",
		)
		return false, nil
	}

	baseCtx := cmd.Context()
	if baseCtx == nil {
		baseCtx = context.Background()
	}

	ctx, cancel := context.WithTimeout(baseCtx, opts.promptTimeout)
	defer cancel()

	decision, err := promptForApproval(ctx, cmd.InOrStdin(), out, data)
	switch {
	case err == nil:
		// Continue below and write the decision.
	case errors.Is(err, context.DeadlineExceeded):
		renderApprovalPromptNoDecision(out, data.RunID, "Approval prompt timed out.")
		return false, nil
	case errors.Is(err, errApprovalPromptCancelled):
		renderApprovalPromptNoDecision(out, data.RunID, "Approval prompt cancelled.")
		return false, nil
	case errors.Is(err, errApprovalPromptInvalidAttempts):
		renderApprovalPromptNoDecision(
			out,
			data.RunID,
			"Approval prompt stopped after too many invalid attempts.",
		)
		return false, nil
	case errors.Is(err, errApprovalPromptReasonRequired):
		renderApprovalPromptNoDecision(
			out,
			data.RunID,
			"Approval prompt stopped because reject requires a reason.",
		)
		return false, nil
	default:
		renderApprovalPromptNoDecision(
			out,
			data.RunID,
			fmt.Sprintf("Approval prompt failed: %s.", err),
		)
		return false, nil
	}

	decisionOpts := &decisionOptions{
		status: decision.Status,
		reason: decision.Reason,
		yes:    decision.Status == localDecisionApproved,
	}

	if err := withLocalReviewLock(store, func() error {
		return runDecisionCommandLocked(cmd, store, data.RunID, decisionOpts)
	}); err != nil {
		return false, err
	}

	return true, nil
}

func promptForApproval(
	ctx context.Context,
	in io.Reader,
	out io.Writer,
	data engineclient.RunCompletedData,
) (approvalPromptDecision, error) {
	reader := bufio.NewReader(in)

	renderApprovalPromptSummary(out, data)

	for attempt := 1; attempt <= maxApprovalPromptAttempts; attempt++ {
		fmt.Fprint(out, "Decision: ")

		value, err := readApprovalPromptLine(ctx, reader)
		if errors.Is(err, io.EOF) {
			return approvalPromptDecision{}, errApprovalPromptCancelled
		}
		if err != nil {
			return approvalPromptDecision{}, err
		}

		switch strings.ToLower(strings.TrimSpace(value)) {
		case "approve":
			return approvalPromptDecision{
				Status: localDecisionApproved,
				Reason: defaultInteractiveApprovalReason,
			}, nil

		case "reject":
			reason, err := promptForRejectReason(ctx, reader, out)
			if err != nil {
				return approvalPromptDecision{}, err
			}

			return approvalPromptDecision{
				Status: localDecisionRejected,
				Reason: reason,
			}, nil

		default:
			if attempt == maxApprovalPromptAttempts {
				return approvalPromptDecision{}, errApprovalPromptInvalidAttempts
			}

			fmt.Fprintln(out, "Invalid input. Please type 'approve' or 'reject'.")
		}
	}

	return approvalPromptDecision{}, errApprovalPromptInvalidAttempts
}

func renderApprovalPromptSummary(out io.Writer, data engineclient.RunCompletedData) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Interactive approval prompt")
	fmt.Fprintf(out, "Run ID: %s\n", data.RunID)
	if data.Approval.Reason != "" {
		fmt.Fprintf(out, "Reason: %s\n", data.Approval.Reason)
	}
	if data.Approval.ApprovalID != "" {
		fmt.Fprintf(out, "Approval ID: %s\n", data.Approval.ApprovalID)
	}
	if data.Patch.SHA256 != "" {
		fmt.Fprintf(out, "Patch digest: sha256:%s\n", shortValue(data.Patch.SHA256, 12))
	}
	if data.Risk.Level != "" {
		fmt.Fprintf(out, "Risk level: %s\n", data.Risk.Level)
	}
	fmt.Fprintf(out, "Files changed: %d\n", data.Changes.ChangedFileCount)

	if len(data.Risk.Reasons) > 0 {
		fmt.Fprintln(out, "Risk reasons:")
		for _, reason := range data.Risk.Reasons {
			if strings.TrimSpace(reason) != "" {
				fmt.Fprintf(out, "  - %s\n", reason)
			}
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Type approve or reject.")
}

func promptForRejectReason(
	ctx context.Context,
	reader *bufio.Reader,
	out io.Writer,
) (string, error) {
	for attempt := 1; attempt <= maxApprovalPromptAttempts; attempt++ {
		fmt.Fprint(out, "Reason: ")

		reason, err := readApprovalPromptLine(ctx, reader)
		if errors.Is(err, io.EOF) {
			return "", errApprovalPromptCancelled
		}
		if err != nil {
			return "", err
		}

		reason = strings.TrimSpace(reason)
		if reason != "" {
			return reason, nil
		}

		if attempt == maxApprovalPromptAttempts {
			return "", errApprovalPromptReasonRequired
		}

		fmt.Fprintln(out, "Reject reason is required. Please enter a reason.")
	}

	return "", errApprovalPromptReasonRequired
}

func readApprovalPromptLine(ctx context.Context, reader *bufio.Reader) (string, error) {
	resultCh := make(chan approvalPromptLineResult, 1)

	go func() {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if errors.Is(err, io.EOF) && line != "" {
			err = nil
		}

		resultCh <- approvalPromptLineResult{
			value: line,
			err:   err,
		}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-resultCh:
		return result.value, result.err
	}
}

func renderApprovalPromptNoDecision(
	out interface{ Write([]byte) (int, error) },
	runID string,
	message string,
) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, message)
	fmt.Fprintln(out, "No approval decision was written.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Run remains approval_required.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintf(out, "  rygnal approve %s --yes\n", runID)
	fmt.Fprintf(out, "  rygnal reject %s --reason \"...\"\n", runID)
	fmt.Fprintf(out, "  rygnal apply %s --yes\n", runID)
}
