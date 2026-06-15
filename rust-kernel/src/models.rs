use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileChange {
    pub path: String,
    pub kind: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GitPatch {
    pub sha256: String,
    pub changes: Vec<FileChange>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AgentAction {
    pub file_path: String,
    pub action_type: String,
    pub raw_code: String,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct RiskAssessment {
    pub criticality_index: f64,
    pub risk_level: String,
    pub reasons: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct HumanContext {
    pub days_since_edit: f64,
    pub days_since_burst: f64,
    pub line_ownership_ratio: f64,
    pub is_explicitly_locked: bool,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SubjectiveRiskInput {
    pub file_path: String,
    pub action_type: String,
    pub system_risk: f64,
    pub old_code: String,
    pub new_code: String,
    pub human_context: HumanContext,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
pub struct SemanticMetrics {
    pub old_node_count: usize,
    pub new_node_count: usize,
    pub old_token_count: usize,
    pub new_token_count: usize,
    pub matched_node_count: usize,
    pub survival_ratio: f64,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct SubjectiveRiskAssessment {
    pub total_criticality: f64,
    pub judgment: String,
    pub reasons: Vec<String>,
    pub human_multiplier: f64,
    pub destruction_penalty: f64,
    pub semantic_metrics: SemanticMetrics,
}
