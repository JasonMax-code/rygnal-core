# M1 Real Guarded Runner

**Status:** M1 implementation note  
**Scope:** Core Python runner only  
**Primary API:** `rygnal.guarded_runner.run_guarded`

## What this runner does

The M1 real guarded runner executes an argv-style command inside a disposable
guarded Git worktree, captures changed files, generates reviewable patch
metadata, emits lifecycle audit events, and cleans up the workspace by default.

The trusted repository is used only as the source of the baseline commit. The
command never runs inside the trusted repository.

## What this runner does not do

The runner does not:

- apply patches to the trusted repository
- request or resolve human approval
- implement the final CLI UX
- implement Go CLI, Rust internals, SDK adapters, SaaS, or dashboard work
- resolve dependency requests
- run final deterministic validators

Those actions remain separate downstream lifecycle steps.

## Security model

The core invariant is:

> An agent command must never directly mutate the trusted repository.

The runner creates a temporary Git worktree outside the trusted repository and
runs the command inside that guarded workspace. After execution, it detects
changes against the immutable baseline commit SHA and generates patch metadata
for later validators, risk classification, approval, and apply flows.

## Backend selection

The runner uses the existing execution backend selector:

- Bubblewrap is the preferred Linux backend when namespace probing succeeds.
- Helper-backed Bubblewrap, systemd-user, and configured container backends are
  routed through existing backend selection.
- Backends without a command runner implementation fail closed in M1.
- Unsafe local execution is never selected silently.

## Bubblewrap backend

The Bubblewrap backend is intentionally conservative. It:

- uses fixed argv only
- uses `shell=False`
- unshares user, PID, and network namespaces
- binds only the guarded workspace as writable
- binds required runtime paths read-only
- does not mount the trusted repository
- does not mount the host home directory
- does not mount `~/.ssh`, `~/.aws`, browser profiles, host virtualenvs, or
  private registry configuration
- captures stdout and stderr
- enforces timeout

The backend is a first Linux execution path, not a claim of perfect sandboxing.

## Unsafe local backend

Unsafe local execution exists only for deterministic tests and explicit local
development. It is never safe by default and is always reported as unverified
containment.

Even in unsafe local mode, the command runs in the guarded worktree, not in the
trusted repository.

## Dirty repository and untracked files

Tracked dirty changes in the trusted repository block by default. The dirty
override must be explicit.

Untracked-file handling is delegated to the existing guarded worktree policy:

- default policy blocks untracked trusted-repo files
- preserve-and-warn keeps normal untracked files only in the trusted repo
- sensitive untracked files block execution

Unrelated trusted-repo untracked files are not copied into the guarded workspace.

## Timeout behavior

Timeout is returned as a structured `TIMED_OUT` result. The runner still attempts
to capture changed files and patch metadata after timeout so evidence is not
hidden.

## Failed command behavior

A non-zero command returns `FAILED`, but changed-file detection and patch
generation still run when possible. Failed commands must not hide workspace
evidence.

## Cleanup behavior

Cleanup is performed by default through existing guarded workspace cleanup
functions. Cleanup uses path guards to avoid deleting or corrupting the trusted
repository.

When `preserve_workspace=True`, cleanup is skipped intentionally and the result
contains a warning.

Cleanup failure is surfaced as `CLEANUP_FAILED`.

## Audit lifecycle

The runner emits lifecycle events such as:

- `guarded_run.requested`
- `guarded_run.blocked`
- `guarded_run.backend_selected`
- `guarded_run.backend_blocked`
- `guarded_run.workspace_created`
- `guarded_run.command_started`
- `guarded_run.command_completed`
- `guarded_run.command_failed`
- `guarded_run.command_timed_out`
- `guarded_run.changed_files_detected`
- `guarded_run.patch_generated`
- `guarded_run.cleanup_started`
- `guarded_run.cleanup_completed`
- `guarded_run.cleanup_failed`

Audit metadata includes structured facts such as run ID, workspace path, baseline
SHA, backend name, containment status, exit code, duration, changed-file counts,
patch SHA-256, and cleanup status.

Audit metadata must not include raw patch content, raw host environment
variables, credentials, private registry tokens, or raw stdout/stderr. Command
streams are represented by byte length and SHA-256 hash.

## Future CLI

The future command:

```bash
rygnal run -- <agent command>
