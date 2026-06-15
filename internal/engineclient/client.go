package engineclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const (
	ProtocolVersion = "rygnal.engine.v1"
	DefaultModule   = "rygnal.engine_api"
)

type DebugOptions struct {
	IncludeRawPatch bool `json:"include_raw_patch"`
	IncludeStdout   bool `json:"include_stdout"`
	IncludeStderr   bool `json:"include_stderr"`
}

type EngineRequest struct {
	ProtocolVersion      string       `json:"protocol_version"`
	Action               string       `json:"action"`
	RequestID            string       `json:"request_id"`
	TrustedRepoPath      string       `json:"trusted_repo_path"`
	Command              []string     `json:"command"`
	TimeoutSeconds       int          `json:"timeout_seconds"`
	UnsafeLocalRequested bool         `json:"unsafe_local_requested"`
	Environment          string       `json:"environment"`
	UserID               string       `json:"user_id"`
	AgentID              string       `json:"agent_id"`
	Debug                DebugOptions `json:"debug"`
}

type EngineEvent struct {
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id"`
	Timestamp       string          `json:"timestamp"`
	Event           string          `json:"event"`
	OK              bool            `json:"ok"`
	Status          string          `json:"status"`
	Data            json.RawMessage `json:"data"`
	Error           *EngineError    `json:"error"`
}

type EngineError struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Details json.RawMessage `json:"details"`
}

type EngineOptions struct {
	RequestID       string
	TrustedRepoPath string
	AgentArgs       []string

	UnsafeLocal bool
	DebugMode   bool
	TimeoutSec  int

	PythonPath string
	Module     string
	WorkDir    string
	Env        []string

	Stderr io.Writer
}

type Result struct {
	EventCount int
	LastEvent  *EngineEvent
}

type EventHandler func(rawLine string, event EngineEvent) error

var (
	ErrPythonNotFound = errors.New("python runtime not found")
	ErrProtocol       = errors.New("engine protocol error")
)

func RunEngine(ctx context.Context, opts EngineOptions, handler EventHandler) (Result, error) {
	if len(opts.AgentArgs) == 0 {
		return Result{}, fmt.Errorf("agent command cannot be empty")
	}

	if opts.TrustedRepoPath == "" {
		return Result{}, fmt.Errorf("trusted repository path cannot be empty")
	}

	if !filepath.IsAbs(opts.TrustedRepoPath) {
		return Result{}, fmt.Errorf("trusted repository path must be absolute")
	}

	if opts.TimeoutSec <= 0 {
		return Result{}, fmt.Errorf("timeout must be greater than zero seconds")
	}

	pythonBin, err := resolvePythonBinary(opts.PythonPath, opts.WorkDir)
	if err != nil {
		return Result{}, err
	}

	module := opts.Module
	if module == "" {
		module = DefaultModule
	}

	request := buildRequest(opts)
	requestPayload, err := json.Marshal(request)
	if err != nil {
		return Result{}, fmt.Errorf("marshal engine request: %w", err)
	}

	cmd := exec.CommandContext(ctx, pythonBin, "-m", module)
	cmd.Dir = opts.WorkDir
	cmd.Env = buildEnvironment(opts)

	configureManagedProcess(cmd)
	cmd.WaitDelay = 2 * time.Second
	cmd.Cancel = func() error {
		return terminateProcessTree(cmd)
	}

	stderrBuffer := newBoundedBuffer(defaultStderrLimitBytes)
	if opts.DebugMode {
		if opts.Stderr != nil {
			cmd.Stderr = opts.Stderr
		} else {
			cmd.Stderr = os.Stderr
		}
	} else {
		cmd.Stderr = stderrBuffer
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return Result{}, fmt.Errorf("open engine stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("open engine stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start engine subprocess: %w", err)
	}

	if _, err := stdinPipe.Write(append(requestPayload, '\n')); err != nil {
		_ = terminateProcessTree(cmd)
		_ = cmd.Wait()
		return Result{}, fmt.Errorf("write engine request: %w", err)
	}

	if err := stdinPipe.Close(); err != nil {
		_ = terminateProcessTree(cmd)
		_ = cmd.Wait()
		return Result{}, fmt.Errorf("close engine stdin pipe: %w", err)
	}

	result, streamErr := readNDJSONStream(stdoutPipe, handler)
	waitErr := cmd.Wait()

	if streamErr != nil {
		return result, streamErr
	}

	if ctx.Err() != nil {
		return result, fmt.Errorf("engine execution timed out or was cancelled: %w", ctx.Err())
	}

	if waitErr != nil {
		return result, engineExitError(waitErr, stderrBuffer.String(), opts.DebugMode)
	}

	return result, nil
}

func buildRequest(opts EngineOptions) EngineRequest {
	return EngineRequest{
		ProtocolVersion:      ProtocolVersion,
		Action:               "guarded_run.start",
		RequestID:            opts.RequestID,
		TrustedRepoPath:      opts.TrustedRepoPath,
		Command:              append([]string(nil), opts.AgentArgs...),
		TimeoutSeconds:       opts.TimeoutSec,
		UnsafeLocalRequested: opts.UnsafeLocal,
		Environment:          "local",
		UserID:               "local_user",
		AgentID:              "go_cli",
		Debug: DebugOptions{
			IncludeRawPatch: false,
			IncludeStdout:   false,
			IncludeStderr:   false,
		},
	}
}

func readNDJSONStream(stdout io.Reader, handler EventHandler) (Result, error) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	result := Result{}

	for scanner.Scan() {
		rawLine := scanner.Text()

		var event EngineEvent
		if err := json.Unmarshal([]byte(rawLine), &event); err != nil {
			return result, fmt.Errorf("%w: engine stdout contained non-JSON line: %q", ErrProtocol, rawLine)
		}

		if event.ProtocolVersion != ProtocolVersion {
			return result, fmt.Errorf(
				"%w: unexpected protocol version %q",
				ErrProtocol,
				event.ProtocolVersion,
			)
		}

		result.EventCount++
		eventCopy := event
		result.LastEvent = &eventCopy

		if handler != nil {
			if err := handler(rawLine, event); err != nil {
				return result, err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("read engine stdout stream: %w", err)
	}

	return result, nil
}

func resolvePythonBinary(explicitPath string, workDir string) (string, error) {
	if explicitPath != "" {
		if _, err := os.Stat(explicitPath); err != nil {
			return "", fmt.Errorf("configured python runtime is not usable: %w", err)
		}
		return explicitPath, nil
	}

	if envPython := os.Getenv("RYGNAL_PYTHON"); envPython != "" {
		if _, err := os.Stat(envPython); err != nil {
			return "", fmt.Errorf("RYGNAL_PYTHON is not usable: %w", err)
		}
		return envPython, nil
	}

	searchRoot := workDir
	if searchRoot == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve current working directory: %w", err)
		}
		searchRoot = cwd
	}

	venvPython := filepath.Join(searchRoot, ".venv", "bin", "python")
	if runtime.GOOS == "windows" {
		venvPython = filepath.Join(searchRoot, ".venv", "Scripts", "python.exe")
	}

	if _, err := os.Stat(venvPython); err == nil {
		return venvPython, nil
	}

	if systemPython, err := exec.LookPath("python3"); err == nil {
		return systemPython, nil
	}

	if systemPython, err := exec.LookPath("python"); err == nil {
		return systemPython, nil
	}

	return "", ErrPythonNotFound
}

func buildEnvironment(opts EngineOptions) []string {
	env := os.Environ()

	if len(opts.Env) > 0 {
		env = append(env, opts.Env...)
	}

	if opts.WorkDir != "" {
		srcPath := filepath.Join(opts.WorkDir, "src")
		if _, err := os.Stat(srcPath); err == nil {
			env = upsertEnv(env, "PYTHONPATH", srcPath)
		}
	}

	return env
}

func upsertEnv(env []string, key string, value string) []string {
	prefix := key + "="
	for index, item := range env {
		if len(item) >= len(prefix) && item[:len(prefix)] == prefix {
			env[index] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func engineExitError(waitErr error, stderr string, debugMode bool) error {
	if debugMode || stderr == "" {
		return fmt.Errorf("engine terminated abnormally: %w", waitErr)
	}

	return fmt.Errorf(
		"engine terminated abnormally: %w; rerun with --debug to show engine stderr",
		waitErr,
	)
}
