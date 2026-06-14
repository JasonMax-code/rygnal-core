# Contributing to Rygnal Core

Thank you for contributing to Rygnal Core.

Rygnal is safety-sensitive infrastructure. Contributions must prioritize correctness, fail-closed behavior, auditability, and test evidence over feature speed.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e . -r requirements-dev.txt
