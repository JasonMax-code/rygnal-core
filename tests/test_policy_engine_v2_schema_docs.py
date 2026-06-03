from pathlib import Path


def test_policy_engine_v2_schema_doc_exists():
    assert Path("docs/24-policy-engine-v2-schema.md").exists()


def test_policy_engine_v2_schema_doc_mentions_version_and_priority():
    content = Path("docs/24-policy-engine-v2-schema.md").read_text()

    assert "policy_version" in content
    assert "priority" in content
    assert "Lower numbers run first" in content


def test_policy_engine_v2_schema_doc_mentions_backward_compatibility():
    content = Path("docs/24-policy-engine-v2-schema.md").read_text()

    assert "Backward Compatibility" in content
    assert "policy.v1" in content
    assert "default priority 100" in content
