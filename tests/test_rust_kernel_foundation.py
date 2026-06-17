from __future__ import annotations

import pytest

from rygnal import rust_kernel

rygnal_kernel = pytest.importorskip("rygnal_kernel")


def test_rust_kernel_exposes_foundation_api() -> None:
    assert isinstance(rygnal_kernel.engine_version(), str)
    assert rygnal_kernel.engine_version()

    assert rygnal_kernel.validate_repo_relative_path("./docs//usage.md") == {
        "safe": True,
        "normalized_path": "docs/usage.md",
        "error_code": None,
        "reason": None,
        "is_sentinel": False,
    }

    assert (
        rygnal_kernel.validate_repo_relative_path("src\\rygnal\\api.py")["normalized_path"]
        == "src/rygnal/api.py"
    )

    assert rygnal_kernel.validate_patch_path("a/src/main.py")["normalized_path"] == "src/main.py"
    assert (
        rygnal_kernel.validate_patch_path("b/docs/guide.md")["normalized_path"] == "docs/guide.md"
    )


def test_rust_kernel_treats_dev_null_as_patch_sentinel() -> None:
    assert rygnal_kernel.validate_patch_path("/dev/null") == {
        "safe": True,
        "normalized_path": None,
        "error_code": None,
        "reason": None,
        "is_sentinel": True,
    }


@pytest.mark.parametrize(
    ("path", "error_code"),
    [
        ("", "empty-path"),
        ("/etc/passwd", "absolute-path"),
        ("../secrets.env", "parent-traversal"),
        ("..\\secrets.env", "parent-traversal"),
        ("C:/Users/test/secrets.env", "windows-rooted-path"),
        ("safe\0path", "null-byte"),
    ],
)
def test_rust_kernel_reports_stable_repo_relative_error_codes(
    path: str,
    error_code: str,
) -> None:
    report = rygnal_kernel.validate_repo_relative_path(path)

    assert report["safe"] is False
    assert report["normalized_path"] is None
    assert report["error_code"] == error_code
    assert report["reason"]


@pytest.mark.parametrize(
    ("path", "error_code"),
    [
        ("b/../evil.txt", "parent-traversal"),
        ("C:/Users/test/evil.txt", "windows-rooted-path"),
    ],
)
def test_rust_kernel_reports_stable_patch_error_codes(path: str, error_code: str) -> None:
    report = rygnal_kernel.validate_patch_path(path)

    assert report["safe"] is False
    assert report["normalized_path"] is None
    assert report["error_code"] == error_code
    assert report["reason"]


@pytest.mark.parametrize(
    ("path", "expected_category", "expected_severity"),
    [
        (".env", "secret", "critical"),
        (".github/workflows/ci.yml", "ci", "high"),
        ("policies/default.yaml", "policy", "high"),
        ("Cargo.toml", "dependency", "high"),
        ("config/settings.yml", "config", "medium"),
        ("node_modules/pkg/index.js", "generated", "low"),
        ("tests/test_api.py", "test", "low"),
        ("docs/guide.md", "documentation", "low"),
        ("src/rygnal/api.py", "normal", "medium"),
    ],
)
def test_rust_kernel_classifies_path_sensitivity(
    path: str,
    expected_category: str,
    expected_severity: str,
) -> None:
    result = rygnal_kernel.classify_path_sensitivity(path)

    assert result["category"] == expected_category
    assert result["severity"] == expected_severity
    assert result["reason"]


def test_python_wrapper_uses_native_kernel_when_available() -> None:
    status = rust_kernel.rust_kernel_status()

    assert status.available is True
    assert status.version == rygnal_kernel.engine_version()
    assert rust_kernel.validate_patch_path("/dev/null")["is_sentinel"] is True
    assert (
        rust_kernel.validate_repo_relative_path("./docs//usage.md")["normalized_path"]
        == "docs/usage.md"
    )
    assert rust_kernel.classify_path_sensitivity(".env")["category"] == "secret"
