from pathlib import Path

DOC_PATH = Path("docs/42-m1-guarded-workspace-lifecycle.md")


def read_doc() -> str:
    return DOC_PATH.read_text(encoding="utf-8")


def test_m1_guarded_workspace_lifecycle_doc_exists() -> None:
    assert DOC_PATH.exists()


def test_m1_guarded_workspace_lifecycle_required_sections() -> None:
    doc = read_doc()

    required_sections = [
        "## Goal",
        "## Core principle",
        "## Required lifecycle",
        "## Sandbox backend strategy",
        "## Filesystem isolation rules",
        "## Dependency governance rules",
        "## Network policy rules",
        "## Validation pipeline",
        "## Failure handling model",
        "## Process containment requirements",
        "## Audit requirements",
        "## Edge cases to document",
        "## What this issue does not require",
        "## Acceptance criteria",
    ]

    for section in required_sections:
        assert section in doc


def test_m1_guarded_workspace_lifecycle_captures_bubblewrap_first_routing() -> None:
    doc = read_doc()

    required_phrases = [
        "Bubblewrap-first",
        "not systemd-first",
        "Alpine/OpenRC with working Bubblewrap is a supported target",
        "LinuxBubblewrapBackend",
        "official Rygnal CI image",
        "signed `rygnal-sandbox-helper`",
        "`systemd-run --user` exists, it may be used as an optional backend",
        "Rootless Podman or Docker may be used only as explicit configured backends",
        "If no verified containment backend works, guarded execution fails closed",
        "Never silently degrade to unsafe local execution",
    ]

    for phrase in required_phrases:
        assert phrase in doc


def test_m1_guarded_workspace_lifecycle_captures_senior_safety_rules() -> None:
    doc = read_doc()

    required_phrases = [
        "Rygnal must never allow an agent to mutate the trusted repository directly",
        "A Python virtual environment is not considered a security boundary",
        "Avoid shared writable caches",
        "Runtime sandbox is offline by default",
        "LLM judges may be future advisory tools",
        "must not be the primary enforcement boundary",
        "Validation failure",
        "Sandbox integrity failure",
        "Terminate the full sandbox process tree",
        "M0 redaction guarantees",
    ]

    for phrase in required_phrases:
        assert phrase in doc


def test_m1_guarded_workspace_lifecycle_defines_boundaries() -> None:
    doc = read_doc()

    required_terms = [
        "Trusted repo",
        "Guarded worktree",
        "Resolver environment",
        "sandbox backend",
        "baseline checkpoint",
        "approved patches",
    ]

    for term in required_terms:
        assert term in doc


def test_m1_guarded_workspace_lifecycle_covers_dependency_and_network_risk() -> None:
    doc = read_doc()

    required_terms = [
        "Dependency changes are privileged actions",
        "transitive dependency deltas",
        "short-lived scoped tokens",
        "shared writable dependency caches",
        "private registry access",
        "SAML/OIDC",
        "network access outside allowlist",
    ]

    for term in required_terms:
        assert term in doc
