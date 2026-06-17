use crate::ast::{analyze_python_survival, AstError};
use crate::models::{HumanContext, SemanticMetrics, SubjectiveRiskAssessment, SubjectiveRiskInput};

const MAX_CRITICALITY: f64 = 10.0;
const APPROVAL_THRESHOLD: f64 = 4.0;
const BLOCK_THRESHOLD: f64 = 7.5;
const MAX_AST_INPUT_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub enum SubjectiveRiskError {
    InvalidInput(String),
    Ast(AstError),
}

impl std::fmt::Display for SubjectiveRiskError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubjectiveRiskError::InvalidInput(message) => write!(formatter, "{message}"),
            SubjectiveRiskError::Ast(err) => write!(formatter, "{err}"),
        }
    }
}

impl std::error::Error for SubjectiveRiskError {}

impl From<AstError> for SubjectiveRiskError {
    fn from(value: AstError) -> Self {
        SubjectiveRiskError::Ast(value)
    }
}

pub fn evaluate_subjective_risk(
    input: &SubjectiveRiskInput,
) -> Result<SubjectiveRiskAssessment, SubjectiveRiskError> {
    validate_input(input)?;

    if input.human_context.is_explicitly_locked {
        return Ok(SubjectiveRiskAssessment {
            total_criticality: MAX_CRITICALITY,
            judgment: "block".to_string(),
            reasons: vec![
                "Human context marks this file as explicitly locked.".to_string(),
                "Locked files require human intervention before autonomous modification."
                    .to_string(),
            ],
            human_multiplier: 1.0,
            destruction_penalty: 0.0,
            semantic_metrics: empty_semantic_metrics(),
        });
    }

    let semantic_metrics = semantic_metrics_for_input(input)?;
    let human_multiplier = human_effort_multiplier(input.human_context);
    let normalized_system_risk = clamp_criticality(input.system_risk);
    let destruction_penalty = destruction_penalty(
        semantic_metrics.survival_ratio,
        input.human_context.line_ownership_ratio,
        &input.action_type,
    );

    let total_criticality =
        clamp_criticality((normalized_system_risk * human_multiplier) + destruction_penalty);

    let judgment = judgment_for(total_criticality);
    let reasons = build_reasons(
        input,
        normalized_system_risk,
        human_multiplier,
        destruction_penalty,
        semantic_metrics,
        judgment,
    );

    Ok(SubjectiveRiskAssessment {
        total_criticality,
        judgment: judgment.to_string(),
        reasons,
        human_multiplier,
        destruction_penalty,
        semantic_metrics,
    })
}

pub fn human_effort_multiplier(context: HumanContext) -> f64 {
    let days_since_edit = context.days_since_edit.max(0.0);
    let days_since_burst = context.days_since_burst.max(0.0);

    let recency =
        0.8 * 2_f64.powf(-(days_since_edit / 14.0)) + 0.2 * 2_f64.powf(-(days_since_burst / 180.0));

    clamp_unit(recency)
}

fn semantic_metrics_for_input(
    input: &SubjectiveRiskInput,
) -> Result<SemanticMetrics, SubjectiveRiskError> {
    if input.old_code.is_empty() && input.new_code.is_empty() {
        return Ok(empty_semantic_metrics());
    }

    let combined_bytes = input.old_code.len().saturating_add(input.new_code.len());

    if combined_bytes > MAX_AST_INPUT_BYTES {
        return Ok(text_survival_metrics(&input.old_code, &input.new_code));
    }

    if is_python_path(&input.file_path) {
        return analyze_python_survival(&input.old_code, &input.new_code)
            .map_err(SubjectiveRiskError::from);
    }

    Ok(text_survival_metrics(&input.old_code, &input.new_code))
}

fn destruction_penalty(survival_ratio: f64, ownership_ratio: f64, action_type: &str) -> f64 {
    let survival_ratio = clamp_unit(survival_ratio);
    let ownership_ratio = clamp_unit(ownership_ratio);
    let destroyed_ratio = 1.0 - survival_ratio;

    let base_penalty = if action_type == "deleted" { 5.0 } else { 4.0 };

    let ownership_weight = 0.5 + (0.5 * ownership_ratio);

    clamp_criticality(base_penalty * destroyed_ratio * ownership_weight)
}

fn build_reasons(
    input: &SubjectiveRiskInput,
    normalized_system_risk: f64,
    human_multiplier: f64,
    destruction_penalty: f64,
    semantic_metrics: SemanticMetrics,
    judgment: &str,
) -> Vec<String> {
    let mut reasons = Vec::new();

    reasons.push(format!(
        "System risk {:.2} adjusted by human recency multiplier {:.4}.",
        normalized_system_risk, human_multiplier
    ));

    if is_python_path(&input.file_path) {
        reasons.push(format!(
            "Python AST survival ratio is {:.4} ({}/{} semantic tokens survived).",
            semantic_metrics.survival_ratio,
            semantic_metrics.matched_node_count,
            semantic_metrics.old_token_count
        ));
    } else {
        reasons.push(format!(
            "Non-Python or large-file fallback survival ratio is {:.4}.",
            semantic_metrics.survival_ratio
        ));
    }

    if destruction_penalty > 0.0 {
        reasons.push(format!(
            "Destruction penalty {:.2} added for removed human-authored semantic structure.",
            destruction_penalty
        ));
    }

    if input.human_context.line_ownership_ratio >= 0.75 {
        reasons.push(format!(
            "High human ownership ratio {:.2} increases deletion/destruction sensitivity.",
            input.human_context.line_ownership_ratio
        ));
    }

    reasons.push(format!("Final subjective judgment: {judgment}."));

    reasons
}

fn validate_input(input: &SubjectiveRiskInput) -> Result<(), SubjectiveRiskError> {
    if input.file_path.trim().is_empty() {
        return Err(SubjectiveRiskError::InvalidInput(
            "subjective risk input file_path must not be empty".to_string(),
        ));
    }

    if input.action_type.trim().is_empty() {
        return Err(SubjectiveRiskError::InvalidInput(
            "subjective risk input action_type must not be empty".to_string(),
        ));
    }

    validate_finite_non_negative("system_risk", input.system_risk)?;
    validate_finite_non_negative("days_since_edit", input.human_context.days_since_edit)?;
    validate_finite_non_negative("days_since_burst", input.human_context.days_since_burst)?;

    if !input.human_context.line_ownership_ratio.is_finite() {
        return Err(SubjectiveRiskError::InvalidInput(
            "line_ownership_ratio must be finite".to_string(),
        ));
    }

    if !(0.0..=1.0).contains(&input.human_context.line_ownership_ratio) {
        return Err(SubjectiveRiskError::InvalidInput(
            "line_ownership_ratio must be between 0.0 and 1.0".to_string(),
        ));
    }

    Ok(())
}

fn validate_finite_non_negative(name: &str, value: f64) -> Result<(), SubjectiveRiskError> {
    if !value.is_finite() {
        return Err(SubjectiveRiskError::InvalidInput(format!(
            "{name} must be finite"
        )));
    }

    if value < 0.0 {
        return Err(SubjectiveRiskError::InvalidInput(format!(
            "{name} must be non-negative"
        )));
    }

    Ok(())
}

fn text_survival_metrics(old_code: &str, new_code: &str) -> SemanticMetrics {
    let old_lines = normalized_non_empty_lines(old_code);
    let new_lines = normalized_non_empty_lines(new_code);

    let matched = old_lines
        .iter()
        .filter(|line| new_lines.contains(line))
        .count();

    let survival_ratio = if old_lines.is_empty() {
        1.0
    } else {
        matched as f64 / old_lines.len() as f64
    };

    SemanticMetrics {
        old_node_count: 0,
        new_node_count: 0,
        old_token_count: old_lines.len(),
        new_token_count: new_lines.len(),
        matched_node_count: matched,
        survival_ratio: clamp_unit(survival_ratio),
    }
}

fn normalized_non_empty_lines(code: &str) -> Vec<String> {
    code.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn empty_semantic_metrics() -> SemanticMetrics {
    SemanticMetrics {
        old_node_count: 0,
        new_node_count: 0,
        old_token_count: 0,
        new_token_count: 0,
        matched_node_count: 0,
        survival_ratio: 1.0,
    }
}

fn judgment_for(total_criticality: f64) -> &'static str {
    if total_criticality >= BLOCK_THRESHOLD {
        "block"
    } else if total_criticality >= APPROVAL_THRESHOLD {
        "approval_required"
    } else {
        "allow"
    }
}

fn is_python_path(path: &str) -> bool {
    path.ends_with(".py") || path.ends_with(".pyi")
}

fn clamp_criticality(value: f64) -> f64 {
    if !value.is_finite() {
        return MAX_CRITICALITY;
    }

    value.clamp(0.0, MAX_CRITICALITY)
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

    fn input_with_context(context: HumanContext) -> SubjectiveRiskInput {
        SubjectiveRiskInput {
            file_path: "src/service.py".to_string(),
            action_type: "modified".to_string(),
            system_risk: 6.0,
            old_code: "def important_rule():\n    threshold = 3\n    return threshold\n"
                .to_string(),
            new_code: "def important_rule():\n    threshold = 4\n    return threshold\n"
                .to_string(),
            human_context: context,
        }
    }

    fn context() -> HumanContext {
        HumanContext {
            days_since_edit: 0.0,
            days_since_burst: 0.0,
            line_ownership_ratio: 0.8,
            is_explicitly_locked: false,
        }
    }

    #[test]
    fn recency_formula_matches_expected_half_life_weights() {
        let multiplier = human_effort_multiplier(HumanContext {
            days_since_edit: 14.0,
            days_since_burst: 180.0,
            line_ownership_ratio: 0.5,
            is_explicitly_locked: false,
        });

        assert!((multiplier - 0.5).abs() < 0.000001);
    }

    #[test]
    fn explicitly_locked_file_blocks_immediately() {
        let mut context = context();
        context.is_explicitly_locked = true;
        let assessment =
            evaluate_subjective_risk(&input_with_context(context)).expect("valid assessment");

        assert_eq!(assessment.total_criticality, 10.0);
        assert_eq!(assessment.judgment, "block");
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("explicitly locked")));
    }

    #[test]
    fn semantic_destruction_can_require_approval() {
        let input = SubjectiveRiskInput {
            new_code: "def replacement():\n    return 1\n".to_string(),
            ..input_with_context(context())
        };

        let assessment = evaluate_subjective_risk(&input).expect("valid assessment");

        assert!(assessment.semantic_metrics.survival_ratio < 0.5);
        assert!(assessment.destruction_penalty > 0.0);
        assert!(matches!(
            assessment.judgment.as_str(),
            "approval_required" | "block"
        ));
    }

    #[test]
    fn non_python_uses_text_survival_fallback() {
        let input = SubjectiveRiskInput {
            file_path: "README.md".to_string(),
            old_code: "A\nB\nC\n".to_string(),
            new_code: "A\nC\n".to_string(),
            ..input_with_context(context())
        };

        let assessment = evaluate_subjective_risk(&input).expect("valid assessment");

        assert_eq!(assessment.semantic_metrics.old_token_count, 3);
        assert_eq!(assessment.semantic_metrics.matched_node_count, 2);
        assert!((assessment.semantic_metrics.survival_ratio - 0.666666).abs() < 0.01);
    }

    #[test]
    fn invalid_ownership_ratio_is_rejected() {
        let input = input_with_context(HumanContext {
            line_ownership_ratio: 2.0,
            ..context()
        });

        let err = evaluate_subjective_risk(&input).expect_err("ownership ratio must fail");

        assert!(err.to_string().contains("line_ownership_ratio"));
    }
}
