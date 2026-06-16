package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type auditOptions struct {
	jsonMode bool
	noColor  bool
	last     int
}

func newAuditCmd() *cobra.Command {
	opts := &auditOptions{last: 10}

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Review local Rygnal run history",
		Long:  "Review local Rygnal run history, summaries, and Git-style code diffs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditList(cmd, opts)
		},
	}

	cmd.Flags().IntVar(&opts.last, "last", 10, "Number of recent runs to show")
	cmd.Flags().BoolVar(&opts.jsonMode, "json", false, "Output audit data as JSON")

	showCmd := &cobra.Command{
		Use:   "show [run_id]",
		Short: "Show a local Rygnal run summary",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := "latest"
			if len(args) > 0 {
				runID = args[0]
			}
			return runAuditShow(cmd, runID)
		},
	}

	diffCmd := &cobra.Command{
		Use:   "diff [run_id]",
		Short: "Show a Git-style visual diff for a local Rygnal run",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := "latest"
			if len(args) > 0 {
				runID = args[0]
			}
			return runAuditDiff(cmd, runID, opts)
		},
	}
	diffCmd.Flags().BoolVar(&opts.noColor, "no-color", false, "Disable ANSI diff colors")

	cmd.AddCommand(showCmd)
	cmd.AddCommand(diffCmd)

	return cmd
}

func runAuditList(cmd *cobra.Command, opts *auditOptions) error {
	store, err := localReviewStoreFromCurrentRepo()
	if err != nil {
		return err
	}

	records, err := listRunReviewRecords(store)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()

	if len(records) == 0 {
		if opts.jsonMode {
			fmt.Fprintln(out, "[]")
			return nil
		}

		fmt.Fprintln(out, "Rygnal audit")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "No local Rygnal runs found.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Run first:")
		fmt.Fprintln(out, "  rygnal run -- <agent_command>")
		return nil
	}

	limit := opts.last
	if limit <= 0 || limit > len(records) {
		limit = len(records)
	}

	if opts.jsonMode {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(records[:limit])
	}

	fmt.Fprintln(out, "Rygnal audit")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%-14s  %-18s  %-8s  %-5s  %s\n", "RUN", "STATUS", "RISK", "FILES", "PATCH")
	for _, record := range records[:limit] {
		risk := record.Risk.Level
		if risk == "" {
			risk = "-"
		}

		patch := "-"
		if record.Patch.SHA256 != "" {
			patch = shortValue(record.Patch.SHA256, 12)
		}

		fmt.Fprintf(
			out,
			"%-14s  %-18s  %-8s  %-5d  %s\n",
			shortValue(record.RunID, 14),
			valueOrDash(record.Status),
			risk,
			record.Changes.ChangedFileCount,
			patch,
		)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintln(out, "  rygnal audit show")
	fmt.Fprintln(out, "  rygnal audit diff")

	return nil
}

func runAuditShow(cmd *cobra.Command, runID string) error {
	store, err := localReviewStoreFromCurrentRepo()
	if err != nil {
		return err
	}

	record, err := findRunReviewRecord(store, runID)
	if err != nil {
		return err
	}

	renderRunReviewSummary(cmd, record)
	return nil
}

func renderRunReviewSummary(cmd *cobra.Command, record runReviewRecord) {
	out := cmd.OutOrStdout()
	data := record.Summary

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Rygnal audit run")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Run ID: %s\n", record.RunID)
	fmt.Fprintf(out, "Status: %s\n", valueOrDash(record.Status))
	fmt.Fprintf(out, "Backend: %s\n", data.Backend.Name)
	fmt.Fprintf(out, "Containment verified: %s\n", yesNo(data.Backend.ContainmentVerified))
	fmt.Fprintf(out, "Baseline: %s\n", shortValue(data.BaselineCommitSHA, 7))

	if data.Command.Present {
		if data.Command.ExitCode != nil {
			fmt.Fprintf(out, "Agent command: exit_code=%d duration=%dms\n", *data.Command.ExitCode, data.Command.DurationMs)
		} else if data.Command.TimedOut {
			fmt.Fprintf(out, "Agent command: timed_out duration=%dms\n", data.Command.DurationMs)
		}
	}

	fmt.Fprintf(out, "Changed files: %d\n", data.Changes.ChangedFileCount)

	if data.Patch.Generated {
		fmt.Fprintf(out, "Patch digest: sha256:%s\n", shortValue(data.Patch.SHA256, 12))
	}

	if data.Risk.Present {
		fmt.Fprintf(out, "Risk level: %s\n", data.Risk.Level)
	}

	if data.Approval.Required {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Approval required")
		fmt.Fprintf(out, "Approval ID: %s\n", data.Approval.ApprovalID)
		fmt.Fprintf(out, "Reason: %s\n", data.Approval.Reason)
	}

	if data.BlockedReason != "" {
		fmt.Fprintf(out, "Blocked reason: %s\n", data.BlockedReason)
	}

	renderWarnings(out, record.Warnings)

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	if record.Patch.Generated {
		if record.RunID != "" {
			fmt.Fprintf(out, "  rygnal audit diff %s\n", record.RunID)
		} else {
			fmt.Fprintln(out, "  rygnal audit diff")
		}
	} else {
		fmt.Fprintln(out, "  rygnal audit")
	}
}

func runAuditDiff(cmd *cobra.Command, runID string, opts *auditOptions) error {
	store, err := localReviewStoreFromCurrentRepo()
	if err != nil {
		return err
	}

	record, err := findRunReviewRecord(store, runID)
	if err != nil {
		return err
	}

	patchPath := record.PatchPath
	if patchPath == "" {
		patchPath = store.runDir(record.RunID) + string(os.PathSeparator) + patchFileName
	}

	payload, err := os.ReadFile(patchPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("no reviewable diff artifact found for run %s", record.RunID)
	}
	if err != nil {
		return fmt.Errorf("read review diff: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Rygnal diff: %s\n", record.RunID)
	fmt.Fprintf(out, "Status: %s\n", valueOrDash(record.Status))
	if record.Risk.Level != "" {
		fmt.Fprintf(out, "Risk: %s\n", record.Risk.Level)
	}
	fmt.Fprintln(out)

	renderVisualDiff(out, string(payload), opts.noColor)

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintln(out, "  Review the red/green changes before approving or applying.")
	return nil
}

func localReviewStoreFromCurrentRepo() (localReviewStore, error) {
	repoRoot, err := resolveGitRoot()
	if err != nil {
		return localReviewStore{}, err
	}
	return newLocalReviewStore(repoRoot)
}

func renderVisualDiff(out interface{ Write([]byte) (int, error) }, diff string, noColor bool) {
	lines := strings.Split(diff, "\n")
	for _, line := range lines {
		if line == "" {
			fmt.Fprintln(out)
			continue
		}
		fmt.Fprintln(out, colorizeDiffLine(line, noColor))
	}
}

func colorizeDiffLine(line string, noColor bool) string {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return line
	}

	const (
		reset  = "\x1b[0m"
		red    = "\x1b[31m"
		green  = "\x1b[32m"
		yellow = "\x1b[33m"
		cyan   = "\x1b[36m"
		gray   = "\x1b[90m"
	)

	switch {
	case strings.HasPrefix(line, "diff --git"):
		return cyan + line + reset
	case strings.HasPrefix(line, "@@"):
		return yellow + line + reset
	case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---"):
		return gray + line + reset
	case strings.HasPrefix(line, "+"):
		return green + line + reset
	case strings.HasPrefix(line, "-"):
		return red + line + reset
	default:
		return line
	}
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
