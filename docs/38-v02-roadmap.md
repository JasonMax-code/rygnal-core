# Rygnal Core v0.2 Roadmap

## Goal

Plan the next Rygnal Core milestone after v0.1.

v0.2 should move Rygnal from a local core MVP toward a stronger developer-facing security product foundation.

## v0.2 Theme

From local runtime core to local developer product.

## What v0.2 Should Focus On

- stronger local API foundation
- queryable audit visibility
- approval queue direction
- role-based approval direction
- policy bundle direction
- better developer usability
- clearer release discipline

## Completed Foundation Before v0.2

Rygnal already has:

- Policy Engine v2 schema direction
- Risk Engine v2 foundation
- Policy Risk Bridge
- Richer Policy Match Fields
- Policy fixtures and examples
- SQLite Audit Storage
- Local FastAPI Service
- Approval Queue API Design
- Role-Based Approval Design
- Policy Bundles Research
- Audit Viewer Dashboard Plan

## Recommended v0.2 Work Items

### 1. Audit Query API

Add read-only audit query endpoints using SQLite audit storage.

Possible endpoints:

- GET /v1/audit/events
- GET /v1/audit/events/{event_id}
- GET /v1/audit/summary

### 2. Approval RBAC Models

Add model foundation for role-based approval.

Possible models:

- RolePermission
- ApprovalEntry
- ApprovalAuthorizationResult

### 3. roles.yaml Foundation

Add policies/roles.yaml as operator-editable role configuration.

Keep it separate from default_policy.yaml.

### 4. ApprovalAuthorizationEngine

Add approval authorization logic.

Required checks:

- requester cannot approve own request
- request must be pending
- reviewer role must have permission
- environment must match role permission

### 5. Approval API Foundation

Add local approval queue endpoints after authorization logic exists.

Possible endpoints:

- GET /v1/approvals
- GET /v1/approvals/{approval_id}
- POST /v1/approvals/{approval_id}/approve
- POST /v1/approvals/{approval_id}/reject

### 6. Audit Viewer API Support

Add API support needed before any dashboard UI.

Focus on read-only audit data.

Do not build dashboard UI before audit query APIs exist.

### 7. Policy Bundle Fixtures

Add initial bundle-shaped example files.

Do not implement full bundle loading until conflict rules are designed.

## What v0.2 Should Not Include Yet

- SaaS dashboard
- production auth
- billing
- multi-tenancy
- enterprise SSO
- cloud deployment
- full dashboard UI
- ABAC
- SIEM export
- remote policy registry
- policy marketplace

## v0.2 Success Criteria

A developer should be able to:

1. install Rygnal locally
2. run the CLI
3. run the local API
4. evaluate tool requests through API
5. log audit events to SQLite
6. query audit events through API
7. understand approval RBAC design
8. test policies with fixtures
9. understand what is still not production-ready

## Release Discipline

Before v0.2 release:

- all tests pass
- ruff format passes
- ruff check passes
- bandit passes
- pip-audit passes
- demo runner works
- API tests pass
- release notes are updated
- roadmap is reviewed
- limitations are documented

## Decision

v0.2 should stay local-first and developer-focused.

Do not jump to SaaS, dashboard, or enterprise features before API, audit, approval, and policy foundations are stable.
