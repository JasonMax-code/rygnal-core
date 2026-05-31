# Rygnal

Runtime security and governance control layer for AI agent actions.

## What is Rygnal?

Rygnal intercepts AI-agent tool calls before execution and decides whether to allow, block, simulate, or require human approval.

## Core Flow

AI Agent -> Rygnal Interceptor -> Policy Engine -> Decision -> Tool Execution / Block -> Audit Log

## MVP Goal

Build a local demo where an AI agent tries risky actions and Rygnal catches them before execution.
