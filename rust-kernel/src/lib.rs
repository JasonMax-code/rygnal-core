use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use tree_sitter::Parser;

#[derive(Deserialize, Debug)]
struct FileChange {
    path: String,
    kind: String,
}

#[derive(Deserialize, Debug)]
struct GitPatch {
    sha256: String,
    changes: Vec<FileChange>,
}

#[derive(Deserialize, Debug)]
struct AgentAction {
    file_path: String,
    action_type: String,
    raw_code: String,
}

#[derive(Serialize, Debug)]
struct RiskAssessment {
    criticality_index: f64,
    risk_level: String,
    reasons: Vec<String>,
}

#[pyfunction]
fn verify_bridge(payload: String) -> PyResult<String> {
    Ok(format!(
        "[Rust Kernel]: Connection secure. Received payload -> {}",
        payload
    ))
}

#[pyfunction]
fn evaluate_patch_risk(json_payload: String) -> PyResult<String> {
    let patch: GitPatch = serde_json::from_str(&json_payload).map_err(|err| {
        PyValueError::new_err(format!("Rust safety kernel failed to parse JSON: {}", err))
    })?;

    let deleted_paths: Vec<&str> = patch
        .changes
        .iter()
        .filter(|change| change.kind == "deleted")
        .map(|change| change.path.as_str())
        .collect();

    Ok(format!(
        "Kernel evaluated patch [{}]. Analyzed {} files. High-risk deletions detected: {}",
        patch.sha256,
        patch.changes.len(),
        deleted_paths.len()
    ))
}

#[pyfunction]
fn analyze_code_structure(raw_code: String) -> PyResult<String> {
    let mut parser = Parser::new();

    let language = tree_sitter_python::language();
    parser
        .set_language(language)
        .map_err(|err| PyValueError::new_err(format!("Failed to load Python grammar: {}", err)))?;

    let tree = parser
        .parse(&raw_code, None)
        .ok_or_else(|| PyValueError::new_err("Tree-Sitter failed to parse the provided code"))?;

    let root_node = tree.root_node();

    Ok(format!(
        "AST Parsed Successfully.\nNode Count: {}\nStructure: {}",
        root_node.child_count(),
        root_node.to_sexp()
    ))
}

#[pyfunction]
fn evaluate_agent_action(json_payload: String) -> PyResult<String> {
    let action: AgentAction = serde_json::from_str(&json_payload)
        .map_err(|err| PyValueError::new_err(format!("Invalid action payload: {}", err)))?;

    let mut base_score: f64 = 0.0;
    let mut risk_reasons: Vec<String> = Vec::new();

    if action.file_path.contains("config") || action.file_path.contains("settings") {
        base_score += 4.0;
        risk_reasons.push("Modifies core configuration path".to_string());
    } else if action.file_path.starts_with("tests/") {
        base_score += 0.5;
    } else {
        base_score += 2.0;
    }

    if action.action_type == "deleted" {
        base_score += 5.0;
        risk_reasons.push("Destructive action: File deletion".to_string());
    }

    if !action.raw_code.is_empty() && action.action_type != "deleted" {
        let mut parser = Parser::new();
        let language = tree_sitter_python::language();

        parser.set_language(language).map_err(|err| {
            PyValueError::new_err(format!("Failed to load Python grammar: {}", err))
        })?;

        let tree = parser
            .parse(&action.raw_code, None)
            .ok_or_else(|| PyValueError::new_err("Tree-Sitter failed to parse action raw_code"))?;

        let s_exp = tree.root_node().to_sexp();

        if s_exp.contains("import_statement") {
            base_score += 2.5;
            risk_reasons.push("Introduces or modifies dependencies (import statement)".to_string());
        }

        if s_exp.contains("call") && s_exp.contains("attribute") {
            base_score += 1.5;
            risk_reasons.push("Contains system or external attribute calls".to_string());
        }
    }

    let criticality_index = base_score.min(10.0);

    let risk_level = if criticality_index >= 7.5 {
        "dangerous"
    } else if criticality_index >= 4.0 {
        "risky"
    } else {
        "safe"
    };

    let assessment = RiskAssessment {
        criticality_index,
        risk_level: risk_level.to_string(),
        reasons: risk_reasons,
    };

    serde_json::to_string(&assessment)
        .map_err(|err| PyValueError::new_err(format!("Failed to serialize assessment: {}", err)))
}

#[pymodule]
fn rygnal_kernel(_py: Python, module: &PyModule) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_bridge, module)?)?;
    module.add_function(wrap_pyfunction!(evaluate_patch_risk, module)?)?;
    module.add_function(wrap_pyfunction!(analyze_code_structure, module)?)?;
    module.add_function(wrap_pyfunction!(evaluate_agent_action, module)?)?;
    Ok(())
}
