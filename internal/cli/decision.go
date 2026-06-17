package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

const (
	decisionRecordFileName = "decision.json"
	localDecisionSchema    = "rygnal.local_decision.v1"

	localDecisionApproved = "approved"
	localDecisionRejected = "rejected"
)

type localDecisionRecord struct {
	Schema            string `json:"schema"`
	RunID             string `json:"run_id"`
	Status            string `json:"status"`
	DecidedAt         string `json:"decided_at"`
	DecidedBy         string `json:"decided_by"`
	Reason            string `json:"reason,omitempty"`
	PatchSHA256       string `json:"patch_sha256,omitempty"`
	BaselineCommitSHA string `json:"baseline_commit_sha,omitempty"`
}

type decisionOptions struct {
	yes       bool
	reason    string
	decidedBy string
	status    string
}

func newApproveCmd() *cobra.Command {
	opts := &decisionOptions{
		status:    localDecisionApproved,
		decidedBy: "local-user",
		reason:    "Approved for local apply.",
	}

	cmd := &cobra.Command{
		Use:   "approve [run_id]",
		Short: "Approve a local Rygnal review run for apply",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			return runDecisionCommand(cmd, runID, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.yes, "yes", false, "Confirm approval decision")
	cmd.Flags().StringVar(&opts.reason, "reason", opts.reason, "Approval reason")
	cmd.Flags().StringVar(&opts.decidedBy, "decided-by", opts.decidedBy, "Decision actor")

	return cmd
}

func newRejectCmd() *cobra.Command {
	opts := &decisionOptions{
		status:    localDecisionRejected,
		decidedBy: "local-user",
	}

	cmd := &cobra.Command{
		Use:   "reject [run_id]",
		Short: "Reject a local Rygnal review run",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			return runDecisionCommand(cmd, runID, opts)
		},
	}

	cmd.Flags().StringVar(&opts.reason, "reason", "", "Rejection reason")
	cmd.Flags().StringVar(&opts.decidedBy, "decided-by", opts.decidedBy, "Decision actor")

	return cmd
}

func runDecisionCommand(cmd *cobra.Command, runID string, opts *decisionOptions) error {
	store, err := localReviewStoreFromCurrentRepo()
	if err != nil {
		return err
	}

	return withLocalReviewLock(store, func() error {
		return runDecisionCommandLocked(cmd, store, runID, opts)
	})
}

func runDecisionCommandLocked(cmd *cobra.Command, store localReviewStore, runID string, opts *decisionOptions) error {
	if opts.status == localDecisionApproved && !opts.yes {
		return fmt.Errorf("refusing to approve without explicit --yes confirmation")
	}

	if opts.status == localDecisionRejected && opts.reason == "" {
		return fmt.Errorf("reject requires --reason")
	}

	record, err := selectRunReviewRecord(store, runID)
	if err != nil {
		return err
	}

	if record.Decision != nil {
		return fmt.Errorf("run %s already has a decision: %s", record.RunID, record.Decision.Status)
	}

	if record.Patch.SHA256 == "" {
		return fmt.Errorf("run %s has no patch digest to bind a decision to", record.RunID)
	}

	decision := localDecisionRecord{
		Schema:            localDecisionSchema,
		RunID:             record.RunID,
		Status:            opts.status,
		DecidedAt:         time.Now().UTC().Format(time.RFC3339),
		DecidedBy:         opts.decidedBy,
		Reason:            opts.reason,
		PatchSHA256:       record.Patch.SHA256,
		BaselineCommitSHA: record.Baseline,
	}

	decisionPath := filepath.Join(store.runDir(record.RunID), decisionRecordFileName)
	if err := writeLocalDecisionRecord(decisionPath, decision); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Rygnal decision: %s\n", record.RunID)
	fmt.Fprintf(out, "Status: %s\n", decision.Status)
	fmt.Fprintf(out, "Patch digest: sha256:%s\n", shortValue(decision.PatchSHA256, 12))
	if decision.BaselineCommitSHA != "" {
		fmt.Fprintf(out, "Baseline: %s\n", shortValue(decision.BaselineCommitSHA, 12))
	}
	if decision.Reason != "" {
		fmt.Fprintf(out, "Reason: %s\n", decision.Reason)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	if decision.Status == localDecisionApproved {
		fmt.Fprintf(out, "  rygnal apply %s --yes\n", record.RunID)
	} else {
		fmt.Fprintf(out, "  rygnal audit show %s\n", record.RunID)
	}

	return nil
}

func selectRunReviewRecord(store localReviewStore, runID string) (runReviewRecord, error) {
	if runID == "" {
		return latestRunReviewRecord(store)
	}
	return findRunReviewRecord(store, runID)
}

func writeLocalDecisionRecord(path string, decision localDecisionRecord) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("decision record already exists")
	}

	payload, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		return fmt.Errorf("encode decision record: %w", err)
	}

	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("write decision record: %w", err)
	}

	return nil
}

func readLocalDecisionRecord(path string) (localDecisionRecord, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return localDecisionRecord{}, err
	}

	var decision localDecisionRecord
	if err := json.Unmarshal(payload, &decision); err != nil {
		return localDecisionRecord{}, fmt.Errorf("decode decision record %s: %w", path, err)
	}

	return decision, nil
}

func decisionStatus(record runReviewRecord) string {
	if record.Decision == nil {
		return "undecided"
	}
	return record.Decision.Status
}

func renderDecision(out interface{ Write([]byte) (int, error) }, record runReviewRecord) {
	if record.Decision == nil {
		fmt.Fprintln(out, "Decision: undecided")
		return
	}

	fmt.Fprintf(out, "Decision: %s\n", record.Decision.Status)
	if record.Decision.DecidedAt != "" {
		fmt.Fprintf(out, "Decided at: %s\n", record.Decision.DecidedAt)
	}
	if record.Decision.DecidedBy != "" {
		fmt.Fprintf(out, "Decided by: %s\n", record.Decision.DecidedBy)
	}
	if record.Decision.PatchSHA256 != "" {
		fmt.Fprintf(out, "Decision patch digest: sha256:%s\n", shortValue(record.Decision.PatchSHA256, 12))
	}
	if record.Decision.Reason != "" {
		fmt.Fprintf(out, "Decision reason: %s\n", record.Decision.Reason)
	}
}

func assertDecisionAllowsApply(record runReviewRecord) error {
	if record.Decision != nil && record.Decision.Status == localDecisionRejected {
		return fmt.Errorf("run %s was rejected: %s", record.RunID, valueOrDash(record.Decision.Reason))
	}

	if record.Decision != nil && record.Decision.PatchSHA256 != "" && record.Patch.SHA256 != "" && record.Decision.PatchSHA256 != record.Patch.SHA256 {
		return fmt.Errorf("decision patch digest does not match review patch digest for run %s", record.RunID)
	}

	if record.Approval.Required {
		if record.Decision == nil {
			return fmt.Errorf("run %s requires approval before apply; run `rygnal approve %s --yes` or `rygnal reject %s --reason ...`", record.RunID, record.RunID, record.RunID)
		}

		if record.Decision.Status != localDecisionApproved {
			return fmt.Errorf("run %s requires an approved decision before apply; current decision: %s", record.RunID, record.Decision.Status)
		}
	}

	return nil
}
