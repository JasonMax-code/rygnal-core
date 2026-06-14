# Security Policy

Rygnal Core is a local-first runtime security and governance layer for AI-agent tool actions.

## Supported Versions

Rygnal Core is currently pre-1.0. Security fixes are provided on a best-effort basis for the latest `main` branch and the latest tagged release.

| Version | Supported |
|---|---|
| main | yes |
| latest tagged release | best effort |
| older releases | no |

## Reporting a Vulnerability

Please do not open public GitHub issues for security vulnerabilities.

Report privately using GitHub Security Advisories if enabled, or contact the maintainers directly.

Security-sensitive reports include:

- sandbox escape
- unsafe local execution fallback
- policy bypass
- approval bypass
- audit tampering
- secret leakage
- patch validation bypass
- dependency resolver escape
- arbitrary command execution
- unsafe write outside guarded workspace

## Security Model

Rygnal must fail closed for safety-critical failures.

Examples:

- missing policy: block or require approval
- missing verified containment backend: block
- invalid approval state: block
- dirty trusted repository: block by default
- failed validation: do not apply patch
- dependency change: require governance/approval
- unsafe local execution: explicit developer/testing mode only

## Current Maturity

Rygnal Core is currently a local-first MVP and should not be presented as an enterprise production runtime yet.

Production, multi-tenant, SaaS, SSO, SIEM, regulatory compliance, and hosted control-plane guarantees are out of scope until explicitly documented in a future release.
