//! Explain the strongest failure classification present in an execution result.
//!
//! This is deliberately a read-only report. ExecuteResult v1 is not a stage
//! trace, so unrecorded funnel stages remain UNOBSERVED instead of being
//! guessed from the final decision.
use realm_v6::execute::ExecuteResult;
use serde_json::{Value, json};
use std::{env, fs, path::Path};

fn diagnosis(result: &ExecuteResult) -> Value {
    let (category, failure_point, explanation, next_action) = match result.reason_code.as_str() {
        "CAPSULE_OBSERVER_UNAVAILABLE" => (
            "unsupported_capability",
            "measured_capsule_observer",
            "No measured capsule observer is configured; arbitrary command execution was not attempted.",
            "Provide a supported measured observer and rerun from a fresh workspace.",
        ),
        "SUPERVISOR_UNAVAILABLE" => (
            "supervisor_error",
            "firecracker_supervisor",
            "The configured supervisor returned an error before producing an authoritative observation.",
            "Inspect the supervisor detail in unsupported_effects and correct that launch or runtime failure.",
        ),
        code if code.starts_with("C1_POLICY_REFUSED_UNAUTHORIZED_PATH_") => (
            "policy_violation",
            "effect_policy_check",
            "The observed run touched a path outside the request's allowed path set.",
            "Correct the task or explicitly authorize the path in the run contract.",
        ),
        code if code.starts_with("C1_CLAIM_REFUSED_") => (
            "mediation_claim_failure",
            "checked_mediation_claim",
            "The observed execution could not produce the checked C1 mediation claim.",
            "Use the claim error below to repair the missing or inconsistent evidence, then rerun.",
        ),
        "C1_OBSERVATION_COMPLETE" => (
            "terminal_authority_join_unavailable",
            "same_run_terminal_join",
            "The C1 observation completed, but this checkpoint has quarantined public ACCEPT until the same-run terminal-authority join exists.",
            "Supply a host-issued closure, semantic-verification, immutable-freeze, and generation-parent join before enabling ACCEPT.",
        ),
        _ => (
            "unclassified_reason_code",
            "unknown",
            "The result contains a reason code this diagnostic version does not recognize.",
            "Add an explicit reason-code mapping; do not infer ACCEPT from this report.",
        ),
    };

    let stages = [
        "environment_preflight",
        "measured_launch",
        "process_custody_setup",
        "agent_runtime_startup",
        "broker_mediation",
        "effect_frontier_generation",
        "evidence_completeness",
        "semantic_verification",
        "proof_engine_consistency",
        "terminal_closure",
        "same_run_authority_join",
        "checked_for_publication",
        "realm_run_creation",
        "generation_preparation",
        "receipt_journal_durability",
        "lifecycle_transition",
        "authority_head_advance",
        "full_from_genesis_verification",
        "public_accept",
    ]
    .into_iter()
    .map(|name| json!({"stage": name, "status": "UNOBSERVED"}))
    .collect::<Vec<_>>();

    json!({
        "schema_version": 1,
        "run_id": result.run_id,
        "execution_id": result.execution_id,
        "task_success": result.task_success,
        "admission": result.verifier_decision,
        "reason_code": result.reason_code,
        "category": category,
        "failure_point": failure_point,
        "explanation": explanation,
        "next_action": next_action,
        "observed_effects": result.observed_effects,
        "unsupported_effects": result.unsupported_effects,
        "evidence_root": result.evidence_root,
        "runtime_ms": result.runtime_ms,
        "overhead_ms": result.overhead_ms,
        "funnel_stages": stages,
        "trace_limit": "ExecuteResult v1 does not retain per-stage outcomes. All funnel statuses are UNOBSERVED; the failure_point is the narrowest classification supported by its reason_code."
    })
}

fn main() {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("usage: diagnose EXECUTION-RESULT.json");
        std::process::exit(2);
    };
    let path = Path::new(&path);
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("could not read execution result: {error}");
            std::process::exit(2);
        }
    };
    let result: ExecuteResult = match serde_json::from_slice(&bytes) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("execution result is malformed or unsupported: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&diagnosis(&result)).unwrap()
    );
}
