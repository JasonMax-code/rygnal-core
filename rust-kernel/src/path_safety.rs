use std::fmt;

const WINDOWS_DRIVE_SEPARATOR: u8 = b':';

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSafetyError {
    Empty,
    Absolute(String),
    ParentTraversal(String),
    WindowsRooted(String),
    NullByte,
}

impl PathSafetyError {
    pub fn code(&self) -> &'static str {
        match self {
            PathSafetyError::Empty => "empty-path",
            PathSafetyError::Absolute(_) => "absolute-path",
            PathSafetyError::ParentTraversal(_) => "parent-traversal",
            PathSafetyError::WindowsRooted(_) => "windows-rooted-path",
            PathSafetyError::NullByte => "null-byte",
        }
    }
}

impl fmt::Display for PathSafetyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathSafetyError::Empty => write!(formatter, "path must not be empty"),
            PathSafetyError::Absolute(path) => {
                write!(formatter, "path must be repository-relative: {path}")
            }
            PathSafetyError::ParentTraversal(path) => {
                write!(
                    formatter,
                    "path must not traverse outside the repository: {path}"
                )
            }
            PathSafetyError::WindowsRooted(path) => {
                write!(formatter, "windows-rooted path is not allowed: {path}")
            }
            PathSafetyError::NullByte => write!(formatter, "path must not contain NUL bytes"),
        }
    }
}

impl std::error::Error for PathSafetyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathValidationOutcome {
    pub safe: bool,
    pub normalized_path: Option<String>,
    pub error_code: Option<&'static str>,
    pub reason: Option<String>,
    pub is_sentinel: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSensitivity {
    pub category: String,
    pub severity: String,
    pub reason: String,
}

pub fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn check_repo_relative_path(path: &str) -> PathValidationOutcome {
    match validate_repo_relative_path(path) {
        Ok(normalized_path) => PathValidationOutcome {
            safe: true,
            normalized_path: Some(normalized_path),
            error_code: None,
            reason: None,
            is_sentinel: false,
        },
        Err(err) => unsafe_outcome(err),
    }
}

pub fn check_patch_path(path: &str) -> PathValidationOutcome {
    match validate_patch_path(path) {
        Ok(normalized_path) => PathValidationOutcome {
            safe: true,
            normalized_path,
            error_code: None,
            reason: None,
            is_sentinel: path.trim() == "/dev/null",
        },
        Err(err) => unsafe_outcome(err),
    }
}

pub fn validate_repo_relative_path(path: &str) -> Result<String, PathSafetyError> {
    normalize_repo_relative_path(path)
}

pub fn validate_patch_path(path: &str) -> Result<Option<String>, PathSafetyError> {
    let trimmed = path.trim();

    if trimmed == "/dev/null" {
        return Ok(None);
    }

    let path_without_git_prefix = trimmed
        .strip_prefix("a/")
        .or_else(|| trimmed.strip_prefix("b/"))
        .unwrap_or(trimmed);

    normalize_repo_relative_path(path_without_git_prefix).map(Some)
}

pub fn classify_path_sensitivity(path: &str) -> Result<PathSensitivity, PathSafetyError> {
    let normalized = normalize_repo_relative_path(path)?;
    let lower = normalized.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    let file_name = segments.last().copied().unwrap_or_default();

    if is_secret_path(&segments, file_name) {
        return Ok(sensitivity(
            "secret",
            "critical",
            "path appears to contain secrets or credentials",
        ));
    }

    if is_ci_path(&segments) {
        return Ok(sensitivity(
            "ci",
            "high",
            "path modifies CI/CD automation or workflow configuration",
        ));
    }

    if is_policy_path(&segments) {
        return Ok(sensitivity(
            "policy",
            "high",
            "path modifies Rygnal policy configuration",
        ));
    }

    if is_dependency_path(file_name) {
        return Ok(sensitivity(
            "dependency",
            "high",
            "path modifies dependency or package manager metadata",
        ));
    }

    if is_config_path(&segments, file_name) {
        return Ok(sensitivity(
            "config",
            "medium",
            "path modifies configuration or settings",
        ));
    }

    if is_generated_path(&segments) {
        return Ok(sensitivity(
            "generated",
            "low",
            "path is generated, cached, vendored, or build output",
        ));
    }

    if is_test_path(&segments, file_name) {
        return Ok(sensitivity(
            "test",
            "low",
            "path appears to be test code or test data",
        ));
    }

    if is_documentation_path(&segments, file_name) {
        return Ok(sensitivity(
            "documentation",
            "low",
            "path appears to be documentation",
        ));
    }

    Ok(sensitivity(
        "normal",
        "medium",
        "path has no special sensitivity classification",
    ))
}

fn unsafe_outcome(err: PathSafetyError) -> PathValidationOutcome {
    PathValidationOutcome {
        safe: false,
        normalized_path: None,
        error_code: Some(err.code()),
        reason: Some(err.to_string()),
        is_sentinel: false,
    }
}

fn sensitivity(category: &str, severity: &str, reason: &str) -> PathSensitivity {
    PathSensitivity {
        category: category.to_string(),
        severity: severity.to_string(),
        reason: reason.to_string(),
    }
}

fn normalize_repo_relative_path(path: &str) -> Result<String, PathSafetyError> {
    if path.contains('\0') {
        return Err(PathSafetyError::NullByte);
    }

    let normalized = path.replace('\\', "/").trim().to_string();

    if normalized.is_empty() {
        return Err(PathSafetyError::Empty);
    }

    if normalized.starts_with('/') {
        return Err(PathSafetyError::Absolute(path.to_string()));
    }

    if has_windows_drive_prefix(&normalized) {
        return Err(PathSafetyError::WindowsRooted(path.to_string()));
    }

    let mut clean_parts: Vec<&str> = Vec::new();

    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(PathSafetyError::ParentTraversal(path.to_string())),
            value => clean_parts.push(value),
        }
    }

    if clean_parts.is_empty() {
        return Err(PathSafetyError::Empty);
    }

    Ok(clean_parts.join("/"))
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();

    bytes.len() >= 2 && bytes[1] == WINDOWS_DRIVE_SEPARATOR && bytes[0].is_ascii_alphabetic()
}

fn is_secret_path(segments: &[&str], file_name: &str) -> bool {
    file_name == ".env"
        || file_name.starts_with(".env.")
        || file_name.ends_with(".pem")
        || file_name.ends_with(".key")
        || file_name.ends_with(".p12")
        || file_name.ends_with(".pfx")
        || segments.iter().any(|segment| {
            matches!(
                *segment,
                "secrets" | ".secrets" | "credentials" | ".credentials"
            )
        })
}

fn is_ci_path(segments: &[&str]) -> bool {
    segments.starts_with(&[".github", "workflows"])
        || segments.starts_with(&[".gitlab"])
        || segments
            .iter()
            .any(|segment| matches!(*segment, ".circleci"))
}

fn is_policy_path(segments: &[&str]) -> bool {
    segments.first().copied() == Some("policies")
        || segments
            .iter()
            .any(|segment| matches!(*segment, "policies"))
}

fn is_dependency_path(file_name: &str) -> bool {
    matches!(
        file_name,
        "go.mod"
            | "go.sum"
            | "cargo.toml"
            | "cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "pyproject.toml"
            | "requirements.txt"
            | "requirements-dev.txt"
            | "poetry.lock"
            | "pipfile"
            | "pipfile.lock"
    )
}

fn is_config_path(segments: &[&str], file_name: &str) -> bool {
    file_name.contains("config")
        || file_name.contains("settings")
        || matches!(
            file_name,
            ".gitignore"
                | ".dockerignore"
                | "dockerfile"
                | "docker-compose.yml"
                | "docker-compose.yaml"
        )
        || segments
            .iter()
            .any(|segment| matches!(*segment, "config" | "configs" | ".config"))
}

fn is_generated_path(segments: &[&str]) -> bool {
    segments.iter().any(|segment| {
        matches!(
            *segment,
            "node_modules"
                | "__pycache__"
                | ".pytest_cache"
                | "target"
                | "dist"
                | "build"
                | ".mypy_cache"
                | ".ruff_cache"
                | ".venv"
                | "vendor"
        )
    })
}

fn is_test_path(segments: &[&str], file_name: &str) -> bool {
    segments
        .iter()
        .any(|segment| matches!(*segment, "test" | "tests" | "__tests__"))
        || file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
        || file_name.ends_with("_test.go")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".test.tsx")
}

fn is_documentation_path(segments: &[&str], file_name: &str) -> bool {
    segments
        .iter()
        .any(|segment| matches!(*segment, "docs" | "doc" | "documentation"))
        || matches!(file_name, "readme.md" | "license" | "license.md")
        || file_name.ends_with(".md")
        || file_name.ends_with(".rst")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_version_matches_crate_version() {
        assert_eq!(engine_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn validates_and_normalizes_repo_relative_paths() {
        assert_eq!(
            validate_repo_relative_path("./docs//usage.md").unwrap(),
            "docs/usage.md"
        );
        assert_eq!(
            validate_repo_relative_path("src\\rygnal\\api.py").unwrap(),
            "src/rygnal/api.py"
        );
    }

    #[test]
    fn rejects_unsafe_repo_relative_paths_with_stable_codes() {
        assert_eq!(check_repo_relative_path("").error_code, Some("empty-path"));
        assert_eq!(
            check_repo_relative_path("/etc/passwd").error_code,
            Some("absolute-path")
        );
        assert_eq!(
            check_repo_relative_path("../secrets.env").error_code,
            Some("parent-traversal")
        );
        assert_eq!(
            check_repo_relative_path("..\\secrets.env").error_code,
            Some("parent-traversal")
        );
        assert_eq!(
            check_repo_relative_path("C:/Users/test/secrets.env").error_code,
            Some("windows-rooted-path")
        );
        assert_eq!(
            check_repo_relative_path("safe\0path").error_code,
            Some("null-byte")
        );
    }

    #[test]
    fn validates_patch_paths_with_git_prefixes() {
        assert_eq!(
            validate_patch_path("a/src/main.py").unwrap(),
            Some("src/main.py".to_string())
        );
        assert_eq!(
            validate_patch_path("b/docs/guide.md").unwrap(),
            Some("docs/guide.md".to_string())
        );
        assert_eq!(
            validate_patch_path("plain/path.txt").unwrap(),
            Some("plain/path.txt".to_string())
        );
    }

    #[test]
    fn treats_dev_null_as_patch_sentinel() {
        assert_eq!(validate_patch_path("/dev/null").unwrap(), None);

        let outcome = check_patch_path("/dev/null");

        assert!(outcome.safe);
        assert_eq!(outcome.normalized_path, None);
        assert_eq!(outcome.error_code, None);
        assert!(outcome.is_sentinel);
    }

    #[test]
    fn rejects_unsafe_patch_paths_with_stable_codes() {
        assert_eq!(
            check_patch_path("b/../evil.txt").error_code,
            Some("parent-traversal")
        );
        assert_eq!(
            check_patch_path("C:/Users/test/evil.txt").error_code,
            Some("windows-rooted-path")
        );
    }

    #[test]
    fn classifies_path_sensitivity_with_severity() {
        assert_eq!(
            classify_path_sensitivity(".env").unwrap().category,
            "secret"
        );
        assert_eq!(
            classify_path_sensitivity(".env").unwrap().severity,
            "critical"
        );

        assert_eq!(
            classify_path_sensitivity(".github/workflows/ci.yml")
                .unwrap()
                .category,
            "ci"
        );
        assert_eq!(
            classify_path_sensitivity("policies/default.yaml")
                .unwrap()
                .category,
            "policy"
        );
        assert_eq!(
            classify_path_sensitivity("Cargo.toml").unwrap().category,
            "dependency"
        );
        assert_eq!(
            classify_path_sensitivity("config/settings.yml")
                .unwrap()
                .category,
            "config"
        );
        assert_eq!(
            classify_path_sensitivity("node_modules/pkg/index.js")
                .unwrap()
                .category,
            "generated"
        );
        assert_eq!(
            classify_path_sensitivity("tests/test_api.py")
                .unwrap()
                .category,
            "test"
        );
        assert_eq!(
            classify_path_sensitivity("docs/guide.md").unwrap().category,
            "documentation"
        );
        assert_eq!(
            classify_path_sensitivity("src/rygnal/api.py")
                .unwrap()
                .category,
            "normal"
        );
    }
}
