from pathlib import Path


def read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_readme_exists_and_is_not_empty():
    content = read("README.md")

    assert content.strip()
    assert "Rygnal" in content
