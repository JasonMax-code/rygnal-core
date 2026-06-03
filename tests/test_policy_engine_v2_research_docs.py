from pathlib import Path


def test_policy_engine_v2_research_doc_exists():
    assert Path("docs/23-policy-engine-v2-research.md").exists()


def test_policy_engine_v2_research_has_recommendation():
    content = Path("docs/23-policy-engine-v2-research.md").read_text()

    assert "Recommendation" in content
    assert "improved YAML-based engine" in content
    assert "OPA/Rego" in content
    assert "Do not replace the current policy engine with OPA/Rego yet" in content


def test_policy_engine_v2_research_documents_limitations():
    content = Path("docs/23-policy-engine-v2-research.md").read_text()

    required_terms = [
        "No policy versioning",
        "No policy priority model",
        "Limited contextual matching",
        "No OPA/Rego support yet",
    ]

    for term in required_terms:
        assert term in content
