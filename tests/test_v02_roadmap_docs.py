from pathlib import Path


def test_v02_roadmap_doc_exists():
    assert Path("docs/38-v02-roadmap.md").exists()


def test_v02_roadmap_mentions_core_focus_areas():
    content = Path("docs/38-v02-roadmap.md").read_text()

    required_terms = [
        "Audit Query API",
        "Approval RBAC Models",
        "roles.yaml Foundation",
        "ApprovalAuthorizationEngine",
        "Approval API Foundation",
        "Policy Bundle Fixtures",
    ]

    for term in required_terms:
        assert term in content


def test_v02_roadmap_defines_not_included_yet():
    content = Path("docs/38-v02-roadmap.md").read_text()

    required_terms = [
        "SaaS dashboard",
        "production auth",
        "multi-tenancy",
        "enterprise SSO",
        "ABAC",
    ]

    for term in required_terms:
        assert term in content


def test_v02_roadmap_defines_success_criteria():
    content = Path("docs/38-v02-roadmap.md").read_text()

    required_terms = [
        "run the local API",
        "log audit events to SQLite",
        "query audit events through API",
        "test policies with fixtures",
        "not production-ready",
    ]

    for term in required_terms:
        assert term in content
