# Policy Engine v2 Research

This document researches the next direction for Rygnal Policy Engine v2.

## Current Policy Engine v1

Policy Engine v1 uses simple YAML-based rules to decide whether a tool action should be allowed, blocked, simulated, or require approval.

## Why v2 Is Needed

As Rygnal moves toward real agent integrations, the policy layer needs stronger structure, clearer rule matching, versioning, and better maintainability.

## Current Limitations

- Simple YAML rules only
- Limited contextual matching
- No policy versioning
- No policy priority model
- No reusable policy bundles
- No organization-level policy management
- No formal policy testing framework beyond current unit tests
- No OPA/Rego support yet

## Policy Engine v2 Goals

- Keep developer experience simple
- Support clearer matching for tool, action, target, input, environment, runtime mode, and risk level
- Support policy IDs and versioning
- Support explicit priority ordering
- Support testable policy examples
- Support better denial/approval reasons
- Prepare for future policy backends

## Option A: Improved YAML Policy Engine

This option keeps YAML as the primary policy format but improves schema, matching, validation, versioning, and tests.

### Pros

- Fastest path
- Easy for developers to understand
- Low dependency risk
- Good for local-first SDK usage
- Easier to document and test quickly

### Cons

- Less powerful than a mature policy language
- Can become complex if too many custom rules are added
- Enterprise teams may want standard policy tooling later

## Option B: OPA/Rego Direction

This option explores Open Policy Agent and Rego as a future policy backend.

### Pros

- Mature policy-as-code model
- Strong enterprise story
- Good for complex authorization and governance logic
- Policy can be separated from application code

### Cons

- More complexity
- More learning required
- More integration work
- Not ideal for fastest local MVP iteration
- Could slow down current product development if added too early

## Recommendation

For the next production step, Rygnal should build Policy Engine v2 as an improved YAML-based engine with schema validation, priority, versioning, and richer matching.

OPA/Rego should remain a researched future backend, not the immediate default.

## Short-Term Plan

1. Improve YAML policy schema
2. Add policy version field
3. Add priority field
4. Add richer match fields
5. Add policy validation tests
6. Add examples for allow, block, simulate, and require_approval

## Long-Term Plan

1. Add optional OPA/Rego adapter
2. Support enterprise policy bundles
3. Add policy test fixtures
4. Add policy explain output
5. Add organization-level policy management

## Decision

Do not replace the current policy engine with OPA/Rego yet.

Build a stronger YAML Policy Engine v2 first, while keeping OPA/Rego as a future optional backend.
