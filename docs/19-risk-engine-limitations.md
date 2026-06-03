# Risk Engine Coverage v1

Risk Engine Coverage v1 improves detection for sensitive configuration, credential, key, and database-related targets.

## Goal

Make risk scoring more realistic for common secret and configuration files that AI agents may try to access.

## Newly Covered Sensitive Targets

- .env.backup
- secrets.yaml
- secrets.yml
- credentials.json
- .npmrc
- .pypirc
- id_rsa
- id_dsa
- private.key
- private.pem
- service-account.json
- service_account.json
- database.yml
- database.yaml
- db.yml
- db.yaml

## Current Risk Engine Limitations

- Risk Engine v1 is deterministic and rules-based.
- It does not use machine learning or threat intelligence.
- It does not yet support configurable scoring weights.
- It does not yet support organization-specific risk profiles.
- It may miss unknown or renamed sensitive files.

## Future Improvements

- Configurable sensitive target patterns
- Configurable score weights
- Environment-aware risk scoring
- Agent identity and user role context
- Policy-aware risk thresholds
- Better handling of encoded or obfuscated targets
