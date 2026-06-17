package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Rygnal/rygnal-core/internal/engineclient"
	"github.com/spf13/cobra"
)

type runOptions struct {
	unsafeLocal bool
	jsonMode    bool
	debugMode   bool
	timeoutSec  int
}

type runDependencies struct {
	runEngine         func(context.Context, engineclient.EngineOptions, engineclient.EventHandler) (engineclient.Result, error)
	resolveGitRoot    func() (string, error)
	resolveEngineRoot func() (string, error)
	newRequestID      func() (string, error)
}

func defaultRunDependencies() runDependencies {
	return runDependencies{
		runEngine:         engineclient.RunEngine,
		resolveGitRoot:    resolveGitRoot,
		resolveEngineRoot: resolveEngineRoot,
		newRequestID:      newRequestID,
	}
}

func newRunCmd() *cobra.Command {
	return newRunCmdWithDependencies(defaultRunDependencies())
}

func newRunCmdWithDependencies(deps runDependencies) *cobra.Command {
	opts := &runOptions{}

	cmd := &cobra.Command{
		Use:   "run -- [agent_command]",
		Short: "Execute an AI agent within the Rygnal safety wrapper",
		Long: `Spawns and monitors an agent command.

The double-dash '--' is strictly required to isolate Rygnal flags from
arguments passed down to the target agent.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateRunArgs(cmd, args, opts)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExecutionPipeline(cmd, opts, args, deps)
		},
	}

	cmd.Flags().BoolVar(
		&opts.unsafeLocal,
		"unsafe-local",
		false,
		"Enable local execution path without kernel containment boundaries",
	)
	cmd.Flags().BoolVar(
		&opts.jsonMode,
		"json",
		false,
		"Output raw engine events strictly in NDJSON stream format",
	)
	cmd.Flags().BoolVar(
		&opts.debugMode,
		"debug",
		false,
		"Expose internal engine standard error logs on failure",
	)
	cmd.Flags().IntVar(
		&opts.timeoutSec,
		"timeout",
		300,
		"Maximum process execution runtime context duration in seconds",
	)

	return cmd
}

func validateRunArgs(cmd *cobra.Command, args []string, opts *runOptions) error {
	dashIdx := cmd.ArgsLenAtDash()
	if dashIdx == -1 {
		return errors.New("invalid CLI syntax: the double-dash '--' separator is required before the agent command")
	}

	if len(args) == 0 {
		return errors.New("invalid CLI syntax: agent command cannot be empty")
	}

	if opts.timeoutSec <= 0 {
		return errors.New("invalid CLI syntax: --timeout must be greater than zero")
	}

	return nil
}

func runExecutionPipeline(
	cmd *cobra.Command,
	opts *runOptions,
	agentArgs []string,
	deps runDependencies,
) error {
	repoRoot, err := deps.resolveGitRoot()
	if err != nil {
		return err
	}

	engineRoot, err := deps.resolveEngineRoot()
	if err != nil {
		return err
	}

	requestID, err := deps.newRequestID()
	if err != nil {
		return err
	}

	store, err := newLocalReviewStore(repoRoot)
	if err != nil {
		return err
	}
	if err := store.ensure(); err != nil {
		return err
	}

	if opts.unsafeLocal && !opts.jsonMode {
		fmt.Fprintln(
			cmd.ErrOrStderr(),
			"WARNING: Running with --unsafe-local. Host containment boundaries are deactivated.",
		)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(opts.timeoutSec)*time.Second,
	)
	defer cancel()

	engineOpts := engineclient.EngineOptions{
		RequestID:       requestID,
		TrustedRepoPath: repoRoot,
		AgentArgs:       append([]string(nil), agentArgs...),
		AuditLogPath:    store.auditPath,
		IncludeRawPatch: !opts.jsonMode,
		UnsafeLocal:     opts.unsafeLocal,
		DebugMode:       opts.debugMode,
		TimeoutSec:      opts.timeoutSec,
		WorkDir:         engineRoot,
		Stderr:          cmd.ErrOrStderr(),
	}

	result, err := deps.runEngine(ctx, engineOpts, func(rawLine string, event engineclient.EngineEvent) error {
		if opts.jsonMode {
			fmt.Fprintln(cmd.OutOrStdout(), rawLine)
			return nil
		}

		return renderHumanEngineEvent(cmd, event)
	})
	if err != nil {
		return err
	}

	if !opts.jsonMode {
		if err := persistRunReviewArtifact(repoRoot, requestID, result.LastEvent); err != nil {
			return err
		}
	}

	return exitErrorForLastEvent(result.LastEvent)
}

func renderHumanEngineEvent(cmd *cobra.Command, event engineclient.EngineEvent) error {
	switch event.Event {
	case "engine.started", "request.accepted", "command.started", "workspace.cleaned":
		return nil
	case "run.started":
		fmt.Fprintln(cmd.OutOrStdout(), "Rygnal guarded run started")
	case "workspace.created":
		runID := fieldFromData(event.Data, "run_id")
		if runID != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Workspace ready: %s\n", runID)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Workspace ready")
		}
	case "command.finished":
		exitCode := fieldFromData(event.Data, "exit_code")
		durationMs := fieldFromData(event.Data, "duration_ms")
		if exitCode != "" && durationMs != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Agent command finished: exit_code=%s duration=%sms\n", exitCode, durationMs)
		} else if exitCode != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Agent command finished: exit_code=%s\n", exitCode)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Agent command finished")
		}
	case "approval.required":
		data, err := engineclient.DecodeRunCompletedData(event)
		if err != nil {
			return err
		}
		renderApprovalRequired(cmd, data)
	case "run.completed":
		if event.Status == "approval_required" {
			return nil
		}

		data, err := engineclient.DecodeRunCompletedData(event)
		if err != nil {
			return err
		}
		renderRunCompleted(cmd, data)
	case "run.failed":
		fmt.Fprintf(cmd.ErrOrStderr(), "Run failed: status=%s\n", event.Status)
	case "engine.error":
		if event.Error != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Engine error: %s\n", event.Error.Message)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Engine error: status=%s\n", event.Status)
		}
	default:
		return nil
	}

	return nil
}

func renderRunCompleted(cmd *cobra.Command, data engineclient.RunCompletedData) {
	out := cmd.OutOrStdout()

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Rygnal guarded run")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Status: %s\n", data.Status)
	fmt.Fprintf(out, "Backend: %s\n", data.Backend.Name)
	fmt.Fprintf(out, "Containment verified: %s\n", yesNo(data.Backend.ContainmentVerified))
	fmt.Fprintln(out, "Trusted repo: hidden")
	fmt.Fprintln(out, "Workspace: hidden")
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

	if data.BlockedReason != "" {
		fmt.Fprintf(out, "Blocked reason: %s\n", data.BlockedReason)
	}

	renderWarnings(out, data.Warnings)

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintln(out, "  rygnal audit")
}

func renderApprovalRequired(cmd *cobra.Command, data engineclient.RunCompletedData) {
	out := cmd.OutOrStdout()

	fmt.Fprintln(out, "Rygnal guarded run")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Status: %s\n", data.Status)
	fmt.Fprintf(out, "Backend: %s\n", data.Backend.Name)
	fmt.Fprintf(out, "Containment verified: %s\n", yesNo(data.Backend.ContainmentVerified))
	fmt.Fprintln(out, "Trusted repo: hidden")
	fmt.Fprintln(out, "Workspace: hidden")
	fmt.Fprintf(out, "Baseline: %s\n", shortValue(data.BaselineCommitSHA, 7))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Approval required")
	fmt.Fprintf(out, "Reason: %s\n", data.Approval.Reason)
	fmt.Fprintf(out, "Approval ID: %s\n", data.Approval.ApprovalID)
	fmt.Fprintf(out, "Patch digest: sha256:%s\n", shortValue(data.Patch.SHA256, 12))
	fmt.Fprintf(out, "Risk level: %s\n", data.Risk.Level)
	fmt.Fprintf(out, "Files changed: %d\n", data.Changes.ChangedFileCount)

	if len(data.Risk.Reasons) > 0 {
		fmt.Fprintln(out, "High-risk reasons:")
		for _, reason := range data.Risk.Reasons {
			fmt.Fprintf(out, "  - %s\n", reason)
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintln(out, "  1. Inspect the audit trail: rygnal audit")
	fmt.Fprintln(out, "  2. Review the patch digest before approving.")
	fmt.Fprintln(out, "  3. Approve/apply only through Rygnal.")
	fmt.Fprintln(out, "  4. Do not manually copy changes from the disposable workspace.")
}

func renderWarnings(out interface{ Write([]byte) (int, error) }, warnings []string) {
	normalized := normalizeWarnings(warnings)
	if len(normalized) == 0 {
		return
	}

	fmt.Fprintln(out, "Warnings:")
	for _, warning := range normalized {
		fmt.Fprintf(out, "  - %s\n", warning)
	}
}

func normalizeWarnings(warnings []string) []string {
	seen := make(map[string]struct{}, len(warnings))
	normalized := make([]string, 0, len(warnings))

	for _, warning := range warnings {
		value := strings.TrimSpace(warning)
		if value == "" {
			continue
		}

		if strings.Contains(value, "Unsafe local execution is not a containment backend") {
			value = "Unsafe local mode is not a containment boundary."
		}

		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	return normalized
}

func exitErrorForLastEvent(event *engineclient.EngineEvent) error {
	if event == nil {
		return nil
	}

	switch event.Status {
	case "completed":
		return nil
	case "command_failed":
		return ExitError{Code: ExitCommandFailed}
	case "blocked":
		return ExitError{Code: ExitBlocked}
	case "approval_required":
		return ExitError{Code: ExitApprovalRequired}
	case "timed_out":
		return ExitError{Code: ExitTimedOut}
	case "cleanup_failed":
		return ExitError{Code: ExitCleanupFailed}
	default:
		return nil
	}
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}

	return "no"
}

func shortValue(value string, maxLen int) string {
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}

	return value[:maxLen]
}

func fieldFromData(data json.RawMessage, key string) string {
	if len(data) == 0 {
		return ""
	}

	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return ""
	}

	value, ok := object[key]
	if !ok {
		return ""
	}

	return fmt.Sprint(value)
}

func resolveGitRoot() (string, error) {
	command := exec.Command("git", "rev-parse", "--show-toplevel")

	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("trusted repo root could not be resolved; run inside a Git repository: %w", err)
	}

	root := strings.TrimSpace(string(output))
	if root == "" {
		return "", errors.New("trusted repo root could not be resolved")
	}

	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve absolute trusted repo root: %w", err)
	}

	return absoluteRoot, nil
}

func resolveEngineRoot() (string, error) {
	if configuredRoot := os.Getenv("RYGNAL_ENGINE_ROOT"); configuredRoot != "" {
		return validateEngineRoot(configuredRoot)
	}

	executablePath, err := os.Executable()
	if err == nil {
		if root, rootErr := findEngineRoot(filepath.Dir(executablePath)); rootErr == nil {
			return root, nil
		}
	}

	cwd, err := os.Getwd()
	if err == nil {
		if root, rootErr := findEngineRoot(cwd); rootErr == nil {
			return root, nil
		}
	}

	return "", errors.New("Rygnal engine root could not be resolved; set RYGNAL_ENGINE_ROOT=/path/to/rygnal-core")
}

func validateEngineRoot(root string) (string, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve absolute engine root: %w", err)
	}

	engineAPIPath := filepath.Join(absoluteRoot, "src", "rygnal", "engine_api.py")
	if _, err := os.Stat(engineAPIPath); err != nil {
		return "", fmt.Errorf("invalid Rygnal engine root %q: %w", absoluteRoot, err)
	}

	return absoluteRoot, nil
}

func findEngineRoot(start string) (string, error) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}

	for {
		if root, err := validateEngineRoot(current); err == nil {
			return root, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return "", errors.New("engine root not found")
}

func newRequestID() (string, error) {
	var payload [16]byte
	if _, err := rand.Read(payload[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}

	return hex.EncodeToString(payload[:]), nil
}
