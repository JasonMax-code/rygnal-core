use crate::models::SemanticMetrics;
use std::collections::BTreeMap;
use tree_sitter::{Node, Parser};

#[derive(Debug)]
pub enum AstError {
    LanguageLoad(String),
    ParseFailed,
    InvalidUtf8(String),
}

impl std::fmt::Display for AstError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AstError::LanguageLoad(message) => {
                write!(formatter, "failed to load Python grammar: {message}")
            }
            AstError::ParseFailed => write!(formatter, "tree-sitter failed to parse Python code"),
            AstError::InvalidUtf8(message) => {
                write!(
                    formatter,
                    "tree-sitter produced invalid UTF-8 span: {message}"
                )
            }
        }
    }
}

impl std::error::Error for AstError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxFeatures {
    pub named_node_count: usize,
    pub semantic_tokens: BTreeMap<String, usize>,
}

pub fn analyze_python_survival(
    old_code: &str,
    new_code: &str,
) -> Result<SemanticMetrics, AstError> {
    let old_features = extract_python_features(old_code)?;
    let new_features = extract_python_features(new_code)?;

    let old_token_count = old_features
        .semantic_tokens
        .values()
        .try_fold(0usize, |acc, value| acc.checked_add(*value))
        .unwrap_or(usize::MAX);

    let new_token_count = new_features
        .semantic_tokens
        .values()
        .try_fold(0usize, |acc, value| acc.checked_add(*value))
        .unwrap_or(usize::MAX);

    let matched_node_count =
        count_multiset_intersection(&old_features.semantic_tokens, &new_features.semantic_tokens);

    let survival_ratio = if old_token_count == 0 {
        1.0
    } else {
        matched_node_count as f64 / old_token_count as f64
    };

    Ok(SemanticMetrics {
        old_node_count: old_features.named_node_count,
        new_node_count: new_features.named_node_count,
        old_token_count,
        new_token_count,
        matched_node_count,
        survival_ratio: clamp_unit(survival_ratio),
    })
}

fn extract_python_features(code: &str) -> Result<SyntaxFeatures, AstError> {
    let mut parser = Parser::new();
    let language = tree_sitter_python::language();

    parser
        .set_language(language)
        .map_err(|err| AstError::LanguageLoad(err.to_string()))?;

    let tree = parser.parse(code, None).ok_or(AstError::ParseFailed)?;
    let root = tree.root_node();

    let mut features = SyntaxFeatures {
        named_node_count: count_named_nodes(root),
        semantic_tokens: BTreeMap::new(),
    };

    collect_semantic_tokens(root, code.as_bytes(), &mut features.semantic_tokens)?;

    Ok(features)
}

fn count_named_nodes(node: Node<'_>) -> usize {
    let mut count = usize::from(node.is_named());

    for index in 0..node.child_count() {
        if let Some(child) = node.child(index) {
            count = count.saturating_add(count_named_nodes(child));
        }
    }

    count
}

fn collect_semantic_tokens(
    node: Node<'_>,
    source: &[u8],
    tokens: &mut BTreeMap<String, usize>,
) -> Result<(), AstError> {
    match node.kind() {
        "function_definition" => {
            if let Some(name) = child_text_by_field(node, "name", source)? {
                add_token(tokens, "function", &name);
            }
        }
        "class_definition" => {
            if let Some(name) = child_text_by_field(node, "name", source)? {
                add_token(tokens, "class", &name);
            }
        }
        "assignment" => {
            if let Some(left) = node.child_by_field_name("left") {
                collect_assignment_identifiers(left, source, tokens)?;
            }
        }
        "import_statement" | "import_from_statement" => {
            collect_import_identifiers(node, source, tokens)?;
        }
        _ => {}
    }

    for index in 0..node.child_count() {
        if let Some(child) = node.child(index) {
            collect_semantic_tokens(child, source, tokens)?;
        }
    }

    Ok(())
}

fn collect_assignment_identifiers(
    node: Node<'_>,
    source: &[u8],
    tokens: &mut BTreeMap<String, usize>,
) -> Result<(), AstError> {
    match node.kind() {
        "identifier" => {
            add_token(tokens, "variable", &node_text(node, source)?);
        }
        "tuple" | "list" | "pattern_list" => {
            for index in 0..node.child_count() {
                if let Some(child) = node.child(index) {
                    collect_assignment_identifiers(child, source, tokens)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn collect_import_identifiers(
    node: Node<'_>,
    source: &[u8],
    tokens: &mut BTreeMap<String, usize>,
) -> Result<(), AstError> {
    match node.kind() {
        "identifier" | "dotted_name" => {
            add_token(tokens, "import", &node_text(node, source)?);
        }
        _ => {
            for index in 0..node.child_count() {
                if let Some(child) = node.child(index) {
                    collect_import_identifiers(child, source, tokens)?;
                }
            }
        }
    }

    Ok(())
}

fn child_text_by_field(
    node: Node<'_>,
    field_name: &str,
    source: &[u8],
) -> Result<Option<String>, AstError> {
    match node.child_by_field_name(field_name) {
        Some(child) => node_text(child, source).map(Some),
        None => Ok(None),
    }
}

fn node_text(node: Node<'_>, source: &[u8]) -> Result<String, AstError> {
    let text = node
        .utf8_text(source)
        .map_err(|err| AstError::InvalidUtf8(err.to_string()))?;

    Ok(text.trim().to_string())
}

fn add_token(tokens: &mut BTreeMap<String, usize>, category: &str, value: &str) {
    let normalized = value.trim();

    if normalized.is_empty() {
        return;
    }

    let key = format!("{category}:{normalized}");
    let count = tokens.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

fn count_multiset_intersection(
    old_tokens: &BTreeMap<String, usize>,
    new_tokens: &BTreeMap<String, usize>,
) -> usize {
    old_tokens
        .iter()
        .map(|(token, old_count)| {
            let new_count = new_tokens.get(token).copied().unwrap_or(0);
            (*old_count).min(new_count)
        })
        .fold(0usize, usize::saturating_add)
}

fn clamp_unit(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }

    value.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_survival_preserves_functions_and_variables() {
        let old_code = r#"
import os

class Worker:
    pass

def cleanup():
    target = "production.db"
    os.remove(target)
"#;
        let new_code = r#"
import os

class Worker:
    pass

def cleanup():
    target = "staging.db"
    print(target)
"#;

        let metrics = analyze_python_survival(old_code, new_code).expect("valid Python code");

        assert!(metrics.old_node_count > 0);
        assert!(metrics.new_node_count > 0);
        assert!(metrics.old_token_count >= 4);
        assert!(metrics.matched_node_count >= 3);
        assert!(metrics.survival_ratio > 0.5);
        assert!(metrics.survival_ratio <= 1.0);
    }

    #[test]
    fn python_survival_penalizes_removed_semantic_tokens() {
        let old_code = r#"
def important_business_rule():
    account_limit = 100
    fraud_threshold = 3
    return account_limit
"#;
        let new_code = r#"
def replacement():
    return 1
"#;

        let metrics = analyze_python_survival(old_code, new_code).expect("valid Python code");

        assert!(metrics.old_token_count >= 3);
        assert_eq!(metrics.matched_node_count, 0);
        assert_eq!(metrics.survival_ratio, 0.0);
    }

    #[test]
    fn empty_old_code_has_full_survival_ratio() {
        let metrics = analyze_python_survival("", "def created():\n    return True\n")
            .expect("valid Python code");

        assert_eq!(metrics.old_token_count, 0);
        assert_eq!(metrics.survival_ratio, 1.0);
    }
}
