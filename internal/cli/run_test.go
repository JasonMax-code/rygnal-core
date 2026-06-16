package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Rygnal/rygnal-core/internal/engineclient"
)

func TestVersionCommand(t *testing.T) {
	stdout, stderr, err := executeForTest("version")

	if err != nil {
		t.Fatalf("version returned error: %v", err)
	}

	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	if !strings.Contains(stdout, "rygnal version 0.1.0") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
}

func TestRunRequiresDoubleDashSeparator(t *testing.T) {
	_, _, err := executeForTest("run", "python", "agent.py")

	if err == nil {
		t.Fatal("expected missing -- separator to fail")
	}

	if !strings.Contains(err.Error(), "double-dash '--' separator is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRejectsEmptyAgentCommand(t *testing.T) {
	_, _, err := executeForTest("run", "--")

	if err == nil {
		t.Fatal("expected empty agent command to fail")
	}

	if !strings.Contains(err.Error(), "agent command cannot be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRejectsInvalidTimeout(t *testing.T) {
	_, _, err := executeForTest("run", "--timeout", "0", "--", "python", "agent.py")

	if err == nil {
		t.Fatal("expected invalid timeout to fail")
	}

	if !strings.Contains(err.Error(), "--timeout must be greater than zero") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunJSONPassesRawEngineNDJSON(t *testing.T) {
	deps := fakeRunDependencies(t)

	stdout, stderr, err := executeForTestWithDeps(
		deps,
		"run",
		"--json",
		"--unsafe-local",
		"--timeout",
		"45",
		"--",
		"python",
		"agent.py",
	)

	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	if stderr != "" {
		t.Fatalf("expected empty stderr in json mode, got %q", stderr)
	}

	if !strings.Contains(stdout, `"event":"engine.started"`) {
		t.Fatalf("expected raw engine NDJSON, got %q", stdout)
	}

	if !strings.Contains(stdout, `"event":"run.completed"`) {
		t.Fatalf("expected final raw event, got %q", stdout)
	}
}

func TestRunHumanRendersEngineLifecycle(t *testing.T) {
	deps := fakeRunDependencies(t)

	stdout, stderr, err := executeForTestWithDeps(
		deps,
		"run",
		"--unsafe-local",
		"--timeout",
		"45",
		"--",
		"python",
		"agent.py",
		"--verbose",
	)

	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	if !strings.Contains(stderr, "WARNING: Running with --unsafe-local") {
		t.Fatalf("expected unsafe-local warning, got stderr %q", stderr)
	}

	expectedFragments := []string{
		"Rygnal guarded run",
		"Status: completed",
		"Next:",
		"rygnal audit",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("stdout missing %q:\n%s", fragment, stdout)
		}
	}

	if strings.Contains(stdout, "Request accepted by Python engine") {
		t.Fatalf("human output should not expose Python engine internals:\n%s", stdout)
	}
}

func TestRunHumanRendersApprovalRequiredAndReturnsExitCode(t *testing.T) {
	deps := fakeApprovalRequiredRunDependencies(t)

	stdout, stderr, err := executeForTestWithDeps(
		deps,
		"run",
		"--",
		"python",
		"agent.py",
	)

	if err == nil {
		t.Fatal("expected approval-required exit error")
	}

	code, ok := ExitCode(err)
	if !ok {
		t.Fatalf("expected typed exit error, got %T: %v", err, err)
	}

	if code != ExitApprovalRequired {
		t.Fatalf("expected exit code %d, got %d", ExitApprovalRequired, code)
	}

	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	expectedFragments := []string{
		"Rygnal guarded run",
		"Status: approval_required",
		"Approval required",
		"Reason: Dependency file changed",
		"Approval ID: apr_test",
		"Patch digest: sha256:abc123def456",
		"Risk level: high",
		"Files changed: 1",
		"  - dependency-file-change",
		"Inspect the audit trail: rygnal audit",
		"Review the patch digest before approving.",
		"Approve/apply only through Rygnal.",
		"Do not manually copy changes from the disposable workspace.",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("stdout missing %q:\n%s", fragment, stdout)
		}
	}

	if strings.Contains(stdout, "Run completed: status=approval_required") {
		t.Fatalf("approval_required run.completed should not render duplicate generic line:\n%s", stdout)
	}

	if strings.Contains(stdout, "Request accepted by Python engine") {
		t.Fatalf("human output should not expose Python engine internals:\n%s", stdout)
	}
}

func TestExitCodeIgnoresOrdinaryErrors(t *testing.T) {
	code, ok := ExitCode(errors.New("ordinary failure"))

	if ok {
		t.Fatalf("ordinary errors must not expose typed exit code, got %d", code)
	}
}

func TestRunPropagatesEngineError(t *testing.T) {
	deps := fakeRunDependencies(t)
	deps.runEngine = func(
		context.Context,
		engineclient.EngineOptions,
		engineclient.EventHandler,
	) (engineclient.Result, error) {
		return engineclient.Result{}, errors.New("engine bridge failed")
	}

	_, _, err := executeForTestWithDeps(deps, "run", "--", "python", "agent.py")

	if err == nil {
		t.Fatal("expected engine error")
	}

	if !strings.Contains(err.Error(), "engine bridge failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func fakeApprovalRequiredRunDependencies(t *testing.T) runDependencies {
	t.Helper()

	return runDependencies{
		resolveGitRoot: func() (string, error) {
			return "/tmp/trusted-repo", nil
		},
		resolveEngineRoot: func() (string, error) {
			return "/tmp/rygnal-engine-root", nil
		},
		newRequestID: func() (string, error) {
			return "test-request-id", nil
		},
		runEngine: func(
			_ context.Context,
			_ engineclient.EngineOptions,
			handler engineclient.EventHandler,
		) (engineclient.Result, error) {
			approvalData := []byte(`{
				"status":"approval_required",
				"run_id":"run_test",
				"trusted_repo":{"absolute_path_returned":false,"digest":"repo_digest"},
				"workspace_path_returned":false,
				"baseline_commit_sha":"1234567890abcdef",
				"backend":{"name":"guarded-worktree","safe_by_default":true,"containment_verified":true},
				"cleanup":{"performed":true,"status":"cleaned"},
				"command":{"present":true,"exit_code":0,"timed_out":false,"duration_ms":10},
				"changes":{"changed_file_count":1,"ignored_file_count":0,"files":[{"path":"pyproject.toml","kind":"modified","old_path":"","mode_changed":false}]},
				"patch":{"generated":true,"sha256":"abc123def4567890","size_bytes":123},
				"risk":{"present":true,"level":"high","reasons":["dependency-file-change"],"counts":{"high":1}},
				"blocked_reason":"",
				"approval":{"required":true,"approval_id":"apr_test","target":"abc123def4567890","policy_id":"patch-risk-gate","severity":"high","reason":"Dependency file changed"},
				"warnings":[]
			}`)

			approval := engineclient.EngineEvent{
				ProtocolVersion: engineclient.ProtocolVersion,
				RequestID:       "test-request-id",
				Event:           "approval.required",
				OK:              true,
				Status:          "approval_required",
				Data:            approvalData,
			}
			completed := engineclient.EngineEvent{
				ProtocolVersion: engineclient.ProtocolVersion,
				RequestID:       "test-request-id",
				Event:           "run.completed",
				OK:              true,
				Status:          "approval_required",
				Data:            approvalData,
			}

			if err := handler(
				`{"protocol_version":"rygnal.engine.v1","request_id":"test-request-id","timestamp":"2026-06-15T00:00:00.000Z","event":"approval.required","ok":true,"status":"approval_required","data":{}}`,
				approval,
			); err != nil {
				return engineclient.Result{}, err
			}

			if err := handler(
				`{"protocol_version":"rygnal.engine.v1","request_id":"test-request-id","timestamp":"2026-06-15T00:00:00.000Z","event":"run.completed","ok":true,"status":"approval_required","data":{}}`,
				completed,
			); err != nil {
				return engineclient.Result{}, err
			}

			return engineclient.Result{
				EventCount: 2,
				LastEvent:  &completed,
			}, nil
		},
	}
}

func fakeRunDependencies(t *testing.T) runDependencies {
	t.Helper()

	return runDependencies{
		resolveGitRoot: func() (string, error) {
			return "/tmp/trusted-repo", nil
		},
		resolveEngineRoot: func() (string, error) {
			return "/tmp/rygnal-engine-root", nil
		},
		newRequestID: func() (string, error) {
			return "test-request-id", nil
		},
		runEngine: func(
			_ context.Context,
			opts engineclient.EngineOptions,
			handler engineclient.EventHandler,
		) (engineclient.Result, error) {
			if opts.TrustedRepoPath != "/tmp/trusted-repo" {
				t.Fatalf("unexpected trusted repo path: %q", opts.TrustedRepoPath)
			}

			if opts.WorkDir != "/tmp/rygnal-engine-root" {
				t.Fatalf("unexpected engine workdir: %q", opts.WorkDir)
			}

			if opts.RequestID != "test-request-id" {
				t.Fatalf("unexpected request id: %q", opts.RequestID)
			}

			if strings.Join(opts.AgentArgs, " ") != "python agent.py --verbose" &&
				strings.Join(opts.AgentArgs, " ") != "python agent.py" {
				t.Fatalf("unexpected agent args: %v", opts.AgentArgs)
			}

			started := engineclient.EngineEvent{
				ProtocolVersion: engineclient.ProtocolVersion,
				RequestID:       "test-request-id",
				Event:           "engine.started",
				OK:              true,
				Status:          "starting",
				Data:            []byte(`{}`),
			}
			accepted := engineclient.EngineEvent{
				ProtocolVersion: engineclient.ProtocolVersion,
				RequestID:       "test-request-id",
				Event:           "request.accepted",
				OK:              true,
				Status:          "accepted",
				Data:            []byte(`{"action":"guarded_run.start"}`),
			}
			completed := engineclient.EngineEvent{
				ProtocolVersion: engineclient.ProtocolVersion,
				RequestID:       "test-request-id",
				Event:           "run.completed",
				OK:              true,
				Status:          "completed",
				Data:            []byte(`{"status":"completed"}`),
			}

			if err := handler(
				`{"protocol_version":"rygnal.engine.v1","request_id":"test-request-id","timestamp":"2026-06-15T00:00:00.000Z","event":"engine.started","ok":true,"status":"starting","data":{},"error":null}`,
				started,
			); err != nil {
				return engineclient.Result{}, err
			}

			if err := handler(
				`{"protocol_version":"rygnal.engine.v1","request_id":"test-request-id","timestamp":"2026-06-15T00:00:00.000Z","event":"request.accepted","ok":true,"status":"accepted","data":{"action":"guarded_run.start"},"error":null}`,
				accepted,
			); err != nil {
				return engineclient.Result{}, err
			}

			if err := handler(
				`{"protocol_version":"rygnal.engine.v1","request_id":"test-request-id","timestamp":"2026-06-15T00:00:00.000Z","event":"run.completed","ok":true,"status":"completed","data":{"status":"completed"},"error":null}`,
				completed,
			); err != nil {
				return engineclient.Result{}, err
			}

			return engineclient.Result{
				EventCount: 3,
				LastEvent:  &completed,
			}, nil
		},
	}
}

func executeForTest(args ...string) (string, string, error) {
	return executeForTestWithDeps(defaultRunDependencies(), args...)
}

func executeForTestWithDeps(deps runDependencies, args ...string) (string, string, error) {
	cmd := NewRootCommand()
	cmd.SetArgs(args)

	for _, command := range cmd.Commands() {
		if command.Name() == "run" {
			cmd.RemoveCommand(command)
			break
		}
	}
	cmd.AddCommand(newRunCmdWithDependencies(deps))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()

	return stdout.String(), stderr.String(), err
}

func TestNormalizeWarningsDeduplicatesUnsafeLocalMessages(t *testing.T) {
	warnings := normalizeWarnings([]string{
		"Unsafe local execution is not a containment backend and must never be selected by default.",
		"POSIX process groups are not a security boundary.",
		"Unsafe local execution is not a containment backend.",
		"  ",
		"POSIX process groups are not a security boundary.",
	})

	expected := []string{
		"Unsafe local mode is not a containment boundary.",
		"POSIX process groups are not a security boundary.",
	}

	if len(warnings) != len(expected) {
		t.Fatalf("expected %d warnings, got %d: %#v", len(expected), len(warnings), warnings)
	}

	for idx, warning := range warnings {
		if warning != expected[idx] {
			t.Fatalf("warning %d: expected %q, got %q", idx, expected[idx], warning)
		}
	}
}
