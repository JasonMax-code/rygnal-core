# Policy Test Fixtures and Examples

This document explains the reusable policy fixtures and example policies.

## Goal

Make policy testing easier, safer, and more consistent.

## Test Fixtures

Policy fixtures live in:

    tests/fixtures/policies/

Current fixtures:

- `priority_policy.yaml`
- `risk_aware_policy.yaml`
- `metadata_policy.yaml`

These files are used by tests to verify policy behavior without repeating YAML inside every test.

## Example Policies

Example policies live in:

    examples/policies/

Current examples:

- `risk-aware-policy.yaml`
- `metadata-policy.yaml`

These files are for learning, demos, and local testing.

## Why This Matters

Reusable fixtures help prevent accidental regressions when policy matching changes.

They also make future policy engine work easier to review.

## Not Production Bundles

These examples are not production-ready policy bundles.

Production policy bundles should be designed separately with stronger coverage, versioning, and security review.
