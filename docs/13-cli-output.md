# CLI Output v1

CLI Output v1 improves the readability of Rygnal scenario runs.

## Goal

Make this command easy to understand:

```bash
python -m demo.run_demo
```

## Output Includes

- Scenario name
- Description
- Tool name
- Action
- Target
- Runtime mode
- Policy decision
- Risk score and risk level
- Execution status
- Policy reason
- Audit event ID

## Why This Matters

The CLI output is the first product-facing experience for Rygnal Core.

It should make security decisions clear enough for engineering review, demos, and future product validation.
