from pathlib import Path


def test_policy_fixtures_doc_exists():
    assert Path("docs/31-policy-test-fixtures.md").exists()


def test_policy_fixtures_doc_mentions_fixture_paths():
    content = Path("docs/31-policy-test-fixtures.md").read_text()

    required_terms = [
        "tests/fixtures/policies/",
        "examples/policies/",
        "priority_policy.yaml",
        "risk_aware_policy.yaml",
        "metadata_policy.yaml",
        "not production-ready policy bundles",
    ]

    for term in required_terms:
        assert term in content
