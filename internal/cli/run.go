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

	return exitErrorForLastEvent(result.LastEvent)
}

func renderHumanEngineEvent(cmd *cobra.Command, event engineclient.EngineEvent) error {
	switch event.Event {
	case "engine.started":
		fmt.Fprintln(cmd.OutOrStdout(), "Rygnal engine started")
	case "request.accepted":
		fmt.Fprintln(cmd.OutOrStdout(), "Request accepted by Python engine")
	case "run.started":
		fmt.Fprintln(cmd.OutOrStdout(), "Guarded run started")
	case "workspace.created":
		runID := fieldFromData(event.Data, "run_id")
		if runID != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Workspace created: %s\n", runID)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Workspace created")
		}
	case "command.started":
		fmt.Fprintln(cmd.OutOrStdout(), "Agent command started")
	case "command.finished":
		exitCode := fieldFromData(event.Data, "exit_code")
		if exitCode != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Agent command finished: exit_code=%s\n", exitCode)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Agent command finished")
		}
	case "workspace.cleaned":
		fmt.Fprintln(cmd.OutOrStdout(), "Workspace cleaned")
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
		fmt.Fprintf(cmd.OutOrStdout(), "Run completed: status=%s\n", event.Status)
	case "run.failed":
		fmt.Fprintf(cmd.ErrOrStderr(), "Run failed: status=%s\n", event.Status)
	case "engine.error":
		if event.Error != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Engine error: %s\n", event.Error.Message)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Engine error: status=%s\n", event.Status)
		}
	default:
		fmt.Fprintf(cmd.OutOrStdout(), "Engine event: %s status=%s\n", event.Event, event.Status)
	}

	return nil
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
	fmt.Fprintln(out, "Next steps:")
	fmt.Fprintln(out, "  1. Review the patch through Rygnal audit/patch inspection.")
	fmt.Fprintln(out, "  2. Approve only if the patch matches your intent.")
	fmt.Fprintln(out, "  3. Apply through Rygnal's approved patch flow.")
	fmt.Fprintln(out, "  4. Do not manually copy changes from the disposable workspace.")
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
