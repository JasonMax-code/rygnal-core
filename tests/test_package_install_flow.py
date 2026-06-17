from pathlib import Path


def test_readme_exists_and_mentions_rygnal():
    content = Path("README.md").read_text(encoding="utf-8")

    assert content.strip()
    assert "Rygnal" in content
