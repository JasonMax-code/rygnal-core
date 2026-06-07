# Richer Policy Match Fields

This feature expands Policy Engine matching beyond basic contains checks.

## Goal

Make Rygnal policies more precise for real-world AI-agent tool governance.

## New Match Fields

- `target_equals`
- `input_equals`
- `metadata_equals`
- `metadata_contains`

## Behavior

`target_equals` matches the exact request target.

`input_equals` matches the exact request input object.

`metadata_equals` requires all configured metadata keys and values to match exactly.

`metadata_contains` checks whether metadata string values contain expected text.

## Compatibility

Existing policy files still work.

Existing fields still work:

- `tool_name`
- `action`
- `environment`
- `target_contains`
- `input_contains`
- `risk_level`
- `risk_score_min`

## Not Included Yet

- nested metadata path matching
- regex matching
- list contains matching
- signal ID matching
- chain-risk matching
