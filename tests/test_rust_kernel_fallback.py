from __future__ import annotations

from rygnal import rust_kernel


def test_python_fallback_validation(monkeypatch) -> None:
    monkeypatch.setattr(rust_kernel, "_load_kernel_optional", lambda: None)

    assert rust_kernel.rust_kernel_status().available is False
    assert rust_kernel.engine_version() == "python-fallback"

    assert rust_kernel.validate_repo_relative_path("./docs//usage.md") == {
        "safe": True,
        "normalized_path": "docs/usage.md",
        "error_code": None,
        "reason": None,
        "is_sentinel": False,
    }

    assert rust_kernel.validate_patch_path("/dev/null") == {
        "safe": True,
        "normalized_path": None,
        "error_code": None,
        "reason": None,
        "is_sentinel": True,
    }


def test_python_fallback_reports_stable_error_codes(monkeypatch) -> None:
    monkeypatch.setattr(rust_kernel, "_load_kernel_optional", lambda: None)

    assert rust_kernel.validate_repo_relative_path("")["error_code"] == "empty-path"
    assert rust_kernel.validate_repo_relative_path("/etc/passwd")["error_code"] == "absolute-path"
    assert (
        rust_kernel.validate_repo_relative_path("../secrets.env")["error_code"]
        == "parent-traversal"
    )
    assert (
        rust_kernel.validate_repo_relative_path("..\\secrets.env")["error_code"]
        == "parent-traversal"
    )
    assert (
        rust_kernel.validate_repo_relative_path("C:/Users/test/secrets.env")["error_code"]
        == "windows-rooted-path"
    )
    assert rust_kernel.validate_repo_relative_path("safe\0path")["error_code"] == "null-byte"


def test_python_fallback_classifies_sensitivity(monkeypatch) -> None:
    monkeypatch.setattr(rust_kernel, "_load_kernel_optional", lambda: None)

    assert rust_kernel.classify_path_sensitivity(".env")["category"] == "secret"
    assert rust_kernel.classify_path_sensitivity(".github/workflows/ci.yml")["category"] == "ci"
    assert rust_kernel.classify_path_sensitivity("policies/default.yaml")["category"] == "policy"
    assert rust_kernel.classify_path_sensitivity("Cargo.toml")["category"] == "dependency"
    assert rust_kernel.classify_path_sensitivity("config/settings.yml")["category"] == "config"
    assert (
        rust_kernel.classify_path_sensitivity("node_modules/pkg/index.js")["category"]
        == "generated"
    )
    assert rust_kernel.classify_path_sensitivity("tests/test_api.py")["category"] == "test"
    assert rust_kernel.classify_path_sensitivity("docs/guide.md")["category"] == "documentation"
    assert rust_kernel.classify_path_sensitivity("src/rygnal/api.py")["category"] == "normal"
