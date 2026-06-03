# Policy Engine v2 YAML Schema

Policy Engine v2 introduces a stronger YAML policy structure while keeping backward compatibility with v1 policy files.

## Goal

Make policy files easier to validate, sort, explain, and evolve without adding OPA/Rego yet.

## New Fields

### policy_version

The policy file can now declare a version.

Example:

policy_version: policy.v2

### priority

Rules can now define priority.

Lower numbers run first.

Example:

priority: 10

## Backward Compatibility

Policy files without policy_version still load as policy.v1.

Rules without priority still use default priority 100.

## Current v2 Schema

- policy_version
- rules
- rule id
- priority
- tool_name
- action
- environment
- target_contains
- input_contains
- decision
- severity
- reason

## Why This Matters

Priority prevents ambiguous rule ordering.
Policy versioning gives Rygnal a safer path for future schema changes.
Validation makes broken policy files fail early.

## Not Included Yet

- OPA/Rego backend
- policy bundles
- organization-level policy management
- advanced condition language
- external policy server

## Future Work

- Richer match fields
- Policy schema examples
- Policy test fixtures
- Policy explain output
- Optional OPA/Rego adapter later
