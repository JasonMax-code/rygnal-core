import subprocess
from pathlib import Path

from rygnal.change_risk import (
    ChangeRiskReason,
    classify_patch_risk,
    extract_added_lines_by_path,
)
from rygnal.changed_files import ChangedFileKind
from rygnal.patch_diff import PatchDiff, PatchFileDiff, generate_patch_diff
from rygnal.risk_engine import RiskLevel


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def create_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()

    run_git(repo, "init")
    run_git(repo, "config", "user.email", "test@example.com")
    run_git(repo, "config", "user.name", "Test User")
    run_git(repo, "config", "core.filemode", "true")

    (repo / "README.md").write_text("# Project\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "baseline")

    return repo


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def risk_for_path(report, path: str):
    return next(file for file in report.files if file.path == path)


def classify_repo_changes(repo: Path):
    return classify_patch_risk(generate_patch_diff(repo, baseline_sha(repo)))


def test_documentation_changes_are_low_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    docs = repo / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Usage\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "docs/usage.md")
    assert file_risk.risk_level == RiskLevel.LOW
    assert file_risk.reasons[0].code == "documentation-change"
    assert report.overall_risk_level == RiskLevel.LOW


def test_normal_source_changes_are_medium_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/app.py")
    assert file_risk.risk_level == RiskLevel.MEDIUM
    assert file_risk.reasons[0].code == "source-code-change"


def test_simple_test_changes_are_low_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "tests/test_app.py")
    assert file_risk.risk_level == RiskLevel.LOW
    assert file_risk.reasons[0].code == "test-change"


def test_dependency_manifest_changes_are_high_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    (repo / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "pyproject.toml")
    assert file_risk.risk_level == RiskLevel.HIGH
    assert any(reason.code == "dependency-file-change" for reason in file_risk.reasons)


def test_ci_workflow_changes_are_high_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    workflow = repo / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "ci.yml").write_text("name: ci\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, ".github/workflows/ci.yml")
    assert file_risk.risk_level == RiskLevel.HIGH
    assert any(reason.code == "ci-config-change" for reason in file_risk.reasons)


def test_secret_paths_are_critical_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    (repo / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, ".env")
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert any(reason.code == "security-sensitive-path" for reason in file_risk.reasons)


def test_added_secret_content_is_critical_and_audit_safe(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    secret_value = "sk-1234567890abcdefABCDEF"
    src = repo / "src"
    src.mkdir()
    (src / "config.py").write_text(
        f'OPENAI_API_KEY = "{secret_value}"\n',
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/config.py")
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert any(reason.code == "added-secret-openai-api-key" for reason in file_risk.reasons)
    assert secret_value not in str(report.audit_summary)


def test_destructive_script_content_is_critical(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    scripts = repo / "scripts"
    scripts.mkdir()
    (scripts / "cleanup.sh").write_text("#!/bin/sh\nrm -rf /tmp/demo\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "scripts/cleanup.sh")
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert any(
        reason.code == "destructive-command-recursive-force-delete" for reason in file_risk.reasons
    )


def test_binary_file_changes_are_high_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    (repo / "artifact.bin").write_bytes(b"\x00\x01\x02\x03")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "artifact.bin")
    assert file_risk.risk_level == RiskLevel.HIGH
    assert any(reason.code == "binary-file-change" for reason in file_risk.reasons)
    assert any(reason.code == "generated-executable-artifact" for reason in file_risk.reasons)


def test_symlink_changes_are_critical_risk() -> None:
    patch_file = PatchFileDiff(
        path="escape-link",
        kind=ChangedFileKind.UNTRACKED,
        additions=1,
        deletions=0,
        new_mode="120000",
    )
    patch = PatchDiff(
        workspace_path="/tmp/workspace",
        baseline_commit_sha="a" * 40,
        patch="diff --git a/escape-link b/escape-link\n",
        patch_sha256="b" * 64,
        patch_size_bytes=42,
        files=(patch_file,),
    )

    report = classify_patch_risk(patch)

    file_risk = risk_for_path(report, "escape-link")
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert any(reason.code == "symlink-change" for reason in file_risk.reasons)


def test_validation_reasons_can_raise_report_level_without_file_changes() -> None:
    reason = ChangeRiskReason(
        code="validator-large-diff",
        risk_level=RiskLevel.HIGH,
        reason="External validator marked patch as large.",
        evidence=(("changed_file_count", 200),),
    )
    patch = PatchDiff(
        workspace_path="/tmp/workspace",
        baseline_commit_sha="a" * 40,
        patch="",
        patch_sha256="b" * 64,
        patch_size_bytes=0,
    )

    report = classify_patch_risk(patch, validation_reasons=(reason,))

    assert report.files == ()
    assert report.overall_risk_level == RiskLevel.HIGH
    assert report.audit_summary["report_reasons"][0]["code"] == "validator-large-diff"


def test_extract_added_lines_ignores_patch_headers() -> None:
    patch = """diff --git a/app.py b/app.py
index 0000000..1111111 100644
--- a/app.py
+++ b/app.py
@@ -1 +1,2 @@
-old
+new
+token = "abc123456789"
"""

    added_lines = extract_added_lines_by_path(patch)

    assert added_lines == {"app.py": ("new", 'token = "abc123456789"')}
