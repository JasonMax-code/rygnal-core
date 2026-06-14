# M1 Guarded Runner Test Plan

**Status:** M1 completion gate  
**Scope:** Tests for `run_guarded()` and the existing M1 patch lifecycle

## Purpose

The real guarded runner is not considered complete only because it has unit
tests. It is complete only when real temporary Git repositories prove the core
contract:

> An agent command must never directly mutate the trusted repository.

The command must run in a disposable guarded workspace. The runner must capture
command result, changed files, patch metadata, audit lifecycle events, and
cleanup behavior. Trusted repository mutation must happen only later through
separate safe-apply or approved-apply flows.

## Test layers

### Core runner tests

`tests/test_guarded_runner.py` validates:

- config validation
- dirty trusted repo blocking
- untracked-file policy
- backend fail-closed behavior
- explicit unsafe-local mode
- workspace isolation
- command success, failure, and timeout
- changed-file detection
- patch generation
- audit lifecycle
- cleanup and preserve behavior
- conditional Bubblewrap execution

### Integration tests

`tests/test_guarded_runner_integration.py` validates that runner output works
with current M1 patch lifecycle modules:

- docs-only runner patch can be auto-applied after the runner returns
- source-code runner patch is skipped by auto-apply and requires approval
- approved source-code patch applies only after approval
- dangerous secret patch is blocked by the change gate
- stale baseline is rejected by approved apply
- audit event order and hash-chain integrity hold

### Hostile scenario tests

`tests/test_guarded_runner_hostile.py` validates hostile or suspicious commands:

- parent-directory writes do not mutate the trusted repo
- absolute path writes in unsafe-local mode are visible as unsafe-local caveats
- symlinks to outside targets are reported and blocked downstream
- large changes skip auto-apply
- dependency manifest changes stay visible and are not auto-applied
- fake secrets are not written to audit logs
- failed commands preserve changed-file evidence
- timeouts preserve changed-file evidence
- child process attempts do not dirty the trusted repo
- common secret-path writes are captured and blocked downstream

## Unsafe-local limitation

Unsafe local is not a containment backend. Tests using unsafe local prove that
the runner does not use the trusted repository as command cwd and does not
directly mutate the trusted repository for normal relative workspace writes.

Unsafe local cannot prove host-level isolation for absolute-path writes or child
process containment. Bubblewrap-specific tests are conditional and should be run
in a Linux CI job that supports user namespaces.

## Bubblewrap testing

Bubblewrap tests are skipped when `bwrap` or namespace support is unavailable.
They should eventually be exercised in a dedicated CI job.

## Manual verification

```bash
mkdir -p /tmp/rygnal-manual
cd /tmp/rygnal-manual
git init trusted
cd trusted
git config user.email test@example.com
git config user.name "Test User"
echo "# Manual Test" > README.md
git add .
git commit -m "baseline"
