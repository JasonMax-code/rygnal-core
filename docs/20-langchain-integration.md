# LangChain Integration Prototype

This integration proves that a LangChain tool call can be routed through Rygnal before execution.

## Goal

Protect LangChain tool calls with Rygnal policy, risk scoring, approval logic, audit logging, and safe execution behavior.

## What This Includes

- Real LangChain Core StructuredTool wrapper
- Rygnal-protected file read tool
- Safe file read allowed through Rygnal
- Secret file read blocked through Rygnal
- Audit event generated for each tool call
- Tests that run without paid API keys

## Why No Live Paid API Demo Yet

Paid API calls are intentionally not required for tests or CI.

This keeps contributor setup stable, avoids leaking secrets, avoids accidental cost, and prevents CI failures from missing API keys or rate limits.

## Run Local Integration Tests

pytest -q tests/test_langchain_integration.py

## Security Notes

- Never commit API keys
- Never require paid API calls in CI
- Keep live provider demos separate and optional
- Keep tool execution behind Rygnal
- Audit every protected tool call

## Future Work

- Add optional live OpenAI demo in a separate issue
- Add OpenAI tool-calling integration
- Add MCP integration prototype
- Add real agent framework examples
