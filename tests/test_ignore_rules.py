import subprocess
from pathlib import Path

from rygnal.changed_files import (
    ChangedFileKind,
    detect_changed_files,
    is_generated_or_heavy_path,
    is_protected_visible_path,
)
from rygnal.ignore_rules import (
    GuardedIgnoreReason,
    build_guarded_ignore_rules,
)


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def create_repo(path: Path) -> Path:
    path.mkdir()

    run_git(path, "init")
    run_git(path, "config", "user.email", "test@example.com")
    run_git(path, "config", "user.name", "Test User")

    (path / "README.md").write_text("# Project\n", encoding="utf-8")
    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def test_default_ignore_rules_ignore_heavy_generated_paths() -> None:
    assert is_generated_or_heavy_path("node_modules/pkg/index.js") is True
    assert is_generated_or_heavy_path(".venv/lib/python/site.py") is True
    assert is_generated_or_heavy_path("dist/app.js") is True


def test_default_ignore_rules_keep_important_files_visible() -> None:
    assert is_protected_visible_path("node_modules/pkg/package.json") is True
    assert is_protected_visible_path("dist/.env") is True
    assert is_protected_visible_path(".github/workflows/ci.yml") is True
    assert is_protected_visible_path("build/requirements-dev.txt") is True


def test_untracked_heavy_folder_is_ignored_but_manifest_stays_visible(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    baseline = baseline_sha(repo)

    node_modules = repo / "node_modules" / "pkg"
    node_modules.mkdir(parents=True)
    (node_modules / "index.js").write_text("console.log('generated')\n", encoding="utf-8")
    (node_modules / "package.json").write_text('{"name":"pkg"}\n', encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    assert any(
        ignored.path == "node_modules/pkg/index.js"
        and ignored.reason == GuardedIgnoreReason.GENERATED_OR_HEAVY_PATH
        for ignored in report.ignored_files
    )
    assert any(file.path == "node_modules/pkg/package.json" for file in report.files)


def test_tracked_heavy_folder_change_stays_visible(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")

    generated = repo / "dist"
    generated.mkdir()
    (generated / "bundle.js").write_text("v1\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "add generated artifact")
    baseline = baseline_sha(repo)

    (generated / "bundle.js").write_text("v2\n", encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    assert report.ignored_files == ()
    assert report.files[0].path == "dist/bundle.js"


def test_tracked_manifest_inside_heavy_folder_stays_visible(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    node_modules = repo / "node_modules" / "pkg"
    node_modules.mkdir(parents=True)
    (node_modules / "package.json").write_text('{"name":"pkg"}\n', encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "add manifest")
    baseline = baseline_sha(repo)

    (node_modules / "package.json").write_text('{"name":"pkg","v":2}\n', encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    assert report.ignored_files == ()
    assert report.files[0].path == "node_modules/pkg/package.json"
    assert report.files[0].kind == ChangedFileKind.MODIFIED


def test_security_sensitive_file_inside_heavy_folder_stays_visible(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    baseline = baseline_sha(repo)

    cache = repo / ".cache"
    cache.mkdir()
    (cache / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    report = detect_changed_files(repo, baseline)

    assert report.ignored_files == ()
    assert report.files[0].path == ".cache/.env"


def test_custom_ignore_rules_prepare_future_config_override(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    baseline = baseline_sha(repo)

    snapshots = repo / "snapshots"
    snapshots.mkdir()
    (snapshots / "large.txt").write_text("generated\n", encoding="utf-8")

    rules = build_guarded_ignore_rules(heavy_path_segments={"snapshots"})

    report = detect_changed_files(repo, baseline, ignore_rules=rules)

    assert report.files == ()
    assert report.ignored_files[0].path == "snapshots/large.txt"
