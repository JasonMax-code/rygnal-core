package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const applyRecordFileName = "apply.json"

type applyOptions struct {
	yes bool
}

type localApplyRecord struct {
	ArtifactSchema    string `json:"artifact_schema"`
	RunID             string `json:"run_id"`
	Status            string `json:"status"`
	PatchSHA256       string `json:"patch_sha256"`
	BaselineCommitSHA string `json:"baseline_commit_sha"`
	AppliedFromHEAD   string `json:"applied_from_head"`
	AppliedAt         string `json:"applied_at"`
	AppliedWith       string `json:"applied_with"`
	Staged            bool   `json:"staged"`
}

func newApplyCmd() *cobra.Command {
	opts := &applyOptions{}

	cmd := &cobra.Command{
		Use:   "apply [run_id]",
		Short: "Safely apply a reviewed Rygnal run",
		Long: `Safely apply a reviewed Rygnal run.

Rygnal verifies the saved diff digest, baseline commit, clean working tree,
and Git applicability before applying anything to the trusted repository.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := "latest"
			if len(args) > 0 {
				runID = args[0]
			}
			return runApply(cmd, runID, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.yes, "yes", false, "Confirm that the reviewed diff should be applied")

	return cmd
}

func runApply(cmd *cobra.Command, runID string, opts *applyOptions) error {
	if !opts.yes {
		return fmt.Errorf("refusing to apply without explicit --yes confirmation")
	}

	store, err := localReviewStoreFromCurrentRepo()
	if err != nil {
		return err
	}

	record, err := findRunReviewRecord(store, runID)
	if err != nil {
		return err
	}

	if record.Approval.Required {
		return fmt.Errorf("run %s still requires approval; refusing to apply without an approval decision", record.RunID)
	}

	patchPath := record.PatchPath
	if patchPath == "" {
		patchPath = filepath.Join(store.runDir(record.RunID), patchFileName)
	}

	patch, err := os.ReadFile(patchPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("no reviewable diff artifact found for run %s", record.RunID)
	}
	if err != nil {
		return fmt.Errorf("read review diff: %w", err)
	}
	if len(bytes.TrimSpace(patch)) == 0 {
		return fmt.Errorf("review diff for run %s is empty", record.RunID)
	}

	if err := assertPatchDigestMatches(record, patch); err != nil {
		return err
	}

	applyRecordPath := filepath.Join(store.runDir(record.RunID), applyRecordFileName)
	if _, err := os.Stat(applyRecordPath); err == nil {
		return fmt.Errorf("run %s was already applied; refusing to apply twice", record.RunID)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("check apply record: %w", err)
	}

	currentHead, err := gitOutput(store.trustedRepo, "rev-parse", "HEAD")
	if err != nil {
		return err
	}

	if record.Baseline != "" && currentHead != record.Baseline {
		return fmt.Errorf(
			"saved diff was generated from baseline %s, but current HEAD is %s",
			shortValue(record.Baseline, 12),
			shortValue(currentHead, 12),
		)
	}

	status, err := gitOutput(store.trustedRepo, "status", "--porcelain")
	if err != nil {
		return err
	}
	if strings.TrimSpace(status) != "" {
		return fmt.Errorf("working tree is not clean; apply requires a clean repository")
	}

	if err := runGitApply(store.trustedRepo, patch, "--check", "--index", "-"); err != nil {
		return fmt.Errorf("saved diff does not apply cleanly: %w", err)
	}

	if err := runGitApply(store.trustedRepo, patch, "--index", "-"); err != nil {
		return fmt.Errorf("apply saved diff: %w", err)
	}

	applyRecord := localApplyRecord{
		ArtifactSchema:    "rygnal.local_apply.v1",
		RunID:             record.RunID,
		Status:            "applied",
		PatchSHA256:       record.Patch.SHA256,
		BaselineCommitSHA: record.Baseline,
		AppliedFromHEAD:   currentHead,
		AppliedAt:         time.Now().UTC().Format(time.RFC3339),
		AppliedWith:       "git apply --index -",
		Staged:            true,
	}

	payload, err := json.MarshalIndent(applyRecord, "", "  ")
	if err != nil {
		return fmt.Errorf("encode apply record: %w", err)
	}

	if err := os.WriteFile(applyRecordPath, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("write apply record: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Rygnal apply: %s\n", record.RunID)
	fmt.Fprintln(out, "Status: applied")
	if record.Patch.SHA256 != "" {
		fmt.Fprintf(out, "Patch digest: sha256:%s\n", shortValue(record.Patch.SHA256, 12))
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Applied to working tree and index.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintln(out, "  git diff --cached")
	fmt.Fprintln(out, "  git commit")

	return nil
}

func assertPatchDigestMatches(record runReviewRecord, patch []byte) error {
	actual := sha256Hex(string(patch))

	if record.Patch.SHA256 != "" && actual != record.Patch.SHA256 {
		return fmt.Errorf(
			"review diff digest mismatch: expected %s, got %s",
			shortValue(record.Patch.SHA256, 12),
			shortValue(actual, 12),
		)
	}

	if record.PatchDigest != "" && actual != record.PatchDigest {
		return fmt.Errorf(
			"review artifact digest mismatch: expected %s, got %s",
			shortValue(record.PatchDigest, 12),
			shortValue(actual, 12),
		)
	}

	return nil
}

func runGitApply(repoRoot string, patch []byte, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", repoRoot, "apply"}, args...)...)
	cmd.Stdin = bytes.NewReader(patch)

	output, err := cmd.CombinedOutput()
	if err != nil {
		details := strings.TrimSpace(string(output))
		if details == "" {
			details = err.Error()
		}
		return fmt.Errorf("%s", details)
	}

	return nil
}
