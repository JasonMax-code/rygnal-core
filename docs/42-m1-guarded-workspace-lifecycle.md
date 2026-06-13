# M1 Guarded Workspace Lifecycle

**Status:** Design contract for M1 implementation
**Milestone:** M1: Guarded Workspace Core
**Issue:** #126

## Goal

Define the full M1 guarded workspace lifecycle before runtime implementation starts.

This issue is the governing design contract for M1. It must prevent the team from forgetting the senior architecture rules while implementing later M1 issues.

## Core principle

Rygnal must never allow an agent to mutate the trusted repository directly.

The agent operates only inside a disposable guarded workspace. The trusted repository receives only reviewed, validated, and policy-approved patches.

## Required lifecycle

1. Detect host OS and supported sandbox backend.
2. Fail closed if no verified containment backend is available.
3. Create an isolated run directory outside the trusted repository.
4. Create a temporary Git worktree for the agent run.
5. Initialize a baseline checkpoint inside the guarded worktree.
6. Run the agent command only inside the guarded workspace.
7. Prefer patch-only editing over full-file overwrite behavior.
8. Capture changed files and generated diff.
9. Run deterministic validators before human approval.
10. Classify changed-file and dependency risk.
11. Require approval for risky patches or dependency changes.
12. Apply only approved patches back to the trusted repository.
13. Audit every lifecycle stage.
14. Clean up safely after success, failure, or interruption.

## Sandbox backend strategy

M1 must define an `ExecutionBackend` abstraction instead of hardcoding a single platform primitive.

Initial backend policy:

- Linux: Bubblewrap-first using rootless Linux namespaces where capability checks pass.
- Alpine/OpenRC: supported when Bubblewrap is installed and namespace capability checks pass. Lack of systemd alone is not a reason to block.
- macOS: route to a future Seatbelt / sandbox-exec style backend instead of silently falling back to unsafe local execution.
- Windows: block native guarded execution unless a supported WSL2/Linux backend is available.
- systemd-run --user: optional Linux backend only, not the primary Linux strategy.
- Rootless Podman/Docker: optional explicitly configured backends only, not silent fallbacks.
- Local unrestricted execution is allowed only as an explicit unsafe developer mode and must never be the default.

Unsupported platform behavior must be fail-closed when no verified containment backend works.

Fail closed means no verified containment backend is available. It must not mean "no systemd found."

## Bubblewrap-first Linux routing

Required Linux backend routing:

1. If `bwrap` exists and namespace capability checks pass, use `LinuxBubblewrapBackend`.
2. If running inside an official Rygnal CI image, use the preinstalled Bubblewrap backend.
3. If an enterprise/offline install provides a signed `rygnal-sandbox-helper`, use that helper-backed Bubblewrap backend.
4. If `systemd-run --user` exists, it may be used as an optional backend, but it is not the primary Linux strategy.
5. Rootless Podman or Docker may be used only as explicit configured backends, not silent fallbacks.
6. If no verified containment backend works, guarded execution fails closed.
7. Local unrestricted execution is allowed only with an explicit unsafe developer flag.

Distribution decision:

- Do not hide-bundle Bubblewrap inside the main Rygnal binary.
- Prefer system package manager Bubblewrap on developer machines.
- Provide official Rygnal CI/container images with Bubblewrap preinstalled.
- Provide a separately signed, version-pinned sandbox helper package later for enterprise/offline environments.
- Never silently degrade to unsafe local execution.

## Filesystem isolation rules

The guarded workspace must not be created as a normal subdirectory inside the trusted repository.

Required model:

- Trusted repo: read-only source of baseline state.
- Guarded worktree: writable disposable workspace.
- Resolver environment: separate disposable environment for dependency validation.
- Runtime reports: stored under the isolated run directory.

The sandbox must not expose user secrets or host configuration directories such as:

- `~/.ssh`
- `~/.aws`
- browser profiles
- global package caches
- host `.venv`
- private registry config files unless explicitly scoped and approved

## Dependency governance rules

Dependency changes are privileged actions, not normal code edits.

The agent may propose dependency intent, but it must not directly run host package installation commands.

Required dependency model:

1. Detect manifest and lockfile changes.
2. Treat new or changed dependencies as governed requests.
3. Resolve dependencies only inside an isolated resolver environment.
4. Avoid shared writable caches.
5. Allow per-run writable caches only.
6. Allow shared caches only if read-only and hash-verified.
7. Capture full transitive dependency deltas.
8. Run vulnerability scanning before approval.
9. Require approval for networked resolution, private registry access, or new transitive dependency trees.
10. Redact all tokens, registry credentials, and resolver secrets from audit output.

A Python virtual environment is not considered a security boundary. It is only a package isolation mechanism.

## Network policy rules

Default M1 network posture should be restricted.

Required network model:

- Runtime sandbox is offline by default.
- Dependency resolution requiring network access must be explicit and audited.
- Network allowlists must be scoped to approved registries where possible.
- Private registry authentication must use short-lived scoped tokens.
- Host SAML/OIDC/browser/session credentials must not be mounted into the sandbox.

## Validation pipeline

Before a patch can be applied to the trusted repository, M1 must define deterministic validators.

Minimum validation stages:

1. Diff integrity check.
2. Path traversal and absolute path rejection.
3. Symlink safety handling.
4. Large diff and changed-file limit checks.
5. Syntax validation for supported languages.
6. Test or smoke validation where configured.
7. AST-aware deletion checks where available.
8. Secret scanning for new content and diffs.
9. Dependency delta and vulnerability checks when manifests change.
10. PolicyEngine decision over the final patch risk.

LLM judges may be future advisory tools, but they must not be the primary enforcement boundary for M1.

## Failure handling model

M1 must distinguish validation failure from sandbox integrity failure.

Validation failure:

- Do not apply the patch.
- Reset the guarded worktree to the baseline checkpoint.
- Preserve enough run context for retry.
- Audit the failed validator and reason.

Sandbox integrity failure:

- Terminate the full sandbox process tree.
- Destroy the guarded workspace.
- Block the run.
- Audit the violation.

Examples of sandbox integrity failures:

- write outside the allowed workspace
- unexpected access to host secret paths
- network access outside allowlist
- orphan process escape attempt
- unsafe symlink escape
- dependency installer suspicious behavior

## Process containment requirements

The sandbox must track the full process tree, not only the parent process.

M1 design must specify how Rygnal handles:

- child processes
- orphaned processes
- process groups
- timeouts
- cancellation
- cleanup after interruption

If a backend cannot reliably terminate the full process tree, it must not be considered safe for default guarded execution.

## Audit requirements

M1 must define audit events for at least:

- workspace creation
- backend selection
- unsupported backend block
- command start
- command completion or failure
- changed-file capture
- diff generation
- validator pass/fail
- dependency resolution request
- dependency risk summary
- approval requested
- approval granted or rejected
- patch applied
- patch skipped
- workspace reset
- workspace cleanup
- sandbox violation

Audit output must continue to follow M0 redaction guarantees.

## Edge cases to document

The design must explicitly cover:

- dirty trusted repository
- untracked files
- ignored files and generated folders
- path traversal
- absolute patch paths
- symlink changes
- large diffs
- dependency manifest changes
- private registry access
- failed command
- syntax/test failure
- interrupted run
- cleanup failure
- unsupported OS
- sandbox backend unavailable
- orphan child processes
- Alpine/OpenRC with Bubblewrap
- CI/CD execution using official Rygnal images
- missing Bubblewrap setup guidance

## What this issue does not require

This issue is design-only.

It does not require implementing the runtime worktree runner, patch application, sandbox backend, dependency resolver, or validators yet.

Those must be implemented in follow-up M1 issues after this lifecycle contract is documented.

## Acceptance criteria

- A lifecycle design document is added under `docs/`.
- The document clearly defines trusted repo, guarded worktree, resolver environment, sandbox backend, validation pipeline, failure handling, dependency governance, and audit behavior.
- The document includes the cross-platform backend strategy.
- The document states that Linux guarded execution is Bubblewrap-first.
- The document states that Alpine/OpenRC with working Bubblewrap is supported.
- The document states that lack of systemd alone is not a reason to block.
- The document states that unsupported safe backends fail closed only when no verified containment backend works.
- The document states that `venv` is not a security boundary.
- The document forbids shared writable dependency caches.
- The document defines baseline checkpoint + reset behavior for validation failures.
- The document defines destroy behavior for sandbox integrity failures.
- The document states that process-tree containment is required.
- The document explains why M1 builds on M0 safety guarantees.
- A documentation regression test is added to ensure these required sections remain present.
- No runtime implementation is required in this issue.

## Senior implementation correction

M1/M3 Linux guarded execution must be Bubblewrap-first, not systemd-first.

Fail closed means no verified containment backend is available. It must not mean no systemd found.

Alpine/OpenRC with working Bubblewrap is a supported target.

The primary Linux path is LinuxBubblewrapBackend. systemd-run --user is optional only, not the primary portability strategy.
