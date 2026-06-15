use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::Deserialize;

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

/// A simple tracer bullet function to prove Python -> Rust execution.
#[pyfunction]
fn verify_bridge(payload: String) -> PyResult<String> {
    Ok(format!(
        "[Rust Kernel]: Connection secure. Received payload -> {}",
        payload
    ))
}

/// Parses a JSON patch summary and calculates a basic risk metric.
///
/// Safety rules:
/// - never uses unwrap/expect
/// - maps JSON/schema errors into Python ValueError
/// - accepts one contiguous JSON string boundary from Python
#[pyfunction]
fn evaluate_patch_risk(json_payload: String) -> PyResult<String> {
    let patch: GitPatch = serde_json::from_str(&json_payload).map_err(|err| {
        PyValueError::new_err(format!(
            "Rust safety kernel failed to parse JSON: {}",
            err
        ))
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

#[pymodule]
fn rygnal_kernel(_py: Python, module: &PyModule) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_bridge, module)?)?;
    module.add_function(wrap_pyfunction!(evaluate_patch_risk, module)?)?;
    Ok(())
}
