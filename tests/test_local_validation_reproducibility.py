from pathlib import Path


def test_readme_exists_and_is_not_empty():
    content = Path("README.md").read_text(encoding="utf-8")

    assert content.strip()
    assert "Rygnal" in content
