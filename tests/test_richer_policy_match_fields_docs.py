from pathlib import Path


def test_richer_policy_match_fields_doc_exists():
    assert Path("docs/30-richer-policy-match-fields.md").exists()


def test_richer_policy_match_fields_doc_mentions_new_fields():
    content = Path("docs/30-richer-policy-match-fields.md").read_text()

    required_terms = [
        "target_equals",
        "input_equals",
        "metadata_equals",
        "metadata_contains",
        "Existing policy files still work",
    ]

    for term in required_terms:
        assert term in content
