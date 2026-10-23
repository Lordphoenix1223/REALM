//! Canonical execution representation passed from BrokerRpc to a backend.
//!
//! The envelope binds a validated tool call to the exact command and
//! workspace contract that a backend may execute. It is transport data, not
//! an independent capability or authority boundary.

use serde::{Deserialize, Serialize};

use crate::measured_launch::domain_hash;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEnvelope {
    pub protocol: u16,
    pub run_id: String,
    pub tool_call_id: String,
    pub tool_id: String,
    pub capability_ref: String,
    pub effect_contract_identity: String,
    pub input_workspace_identity: String,
    pub execution_id: String,
    pub capsule_id: String,
    pub challenge: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub safe_environment: Vec<String>,
    pub timeout_ms: u64,
    /// Measured initial filesystem-world root, distinct from the runtime's
    /// opaque input workspace identity above.
    pub workspace_identity: String,
    pub effect_contract: Vec<String>,
}

impl TaskEnvelope {
    /// Stable identity for the exact serialized execution representation.
    pub fn identity(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(self)?;
        Ok(domain_hash("REALM::TaskInvocation", 1, &bytes))
    }

    pub fn matches_identity(&self, expected: &str) -> bool {
        self.identity().is_ok_and(|identity| identity == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> TaskEnvelope {
        TaskEnvelope {
            protocol: 1,
            run_id: "run".into(),
            tool_call_id: "call".into(),
            tool_id: "shell.exec".into(),
            capability_ref: "cap:shell.exec".into(),
            effect_contract_identity: "effect-contract".into(),
            input_workspace_identity: "input-workspace".into(),
            execution_id: "e".repeat(64),
            capsule_id: "capsule".into(),
            challenge: "challenge".into(),
            argv: vec!["/bin/true".into()],
            cwd: "/workspace".into(),
            safe_environment: vec!["PATH=/usr/bin:/bin".into()],
            timeout_ms: 1000,
            workspace_identity: "workspace".into(),
            effect_contract: vec!["filesystem:write:result.txt".into()],
        }
    }

    #[test]
    fn task_envelope_mutation_after_validation_changes_its_identity() {
        let validated = envelope();
        let expected = validated.identity().unwrap();
        assert!(validated.matches_identity(&expected));
        let policy = crate::measured_launch::PolicyIdentity::new(
            "test-policy".into(),
            "1".into(),
            b"policy",
            &serde_json::to_vec(&validated).unwrap(),
        );
        assert_eq!(policy.task_blake3(), expected);

        let mut foreign_run = validated.clone();
        foreign_run.run_id = "foreign-run".into();
        let mut foreign_challenge = validated.clone();
        foreign_challenge.challenge = "foreign-challenge".into();
        let mut foreign_call = validated.clone();
        foreign_call.tool_call_id = "foreign-call".into();
        for forged in [foreign_run, foreign_challenge, foreign_call] {
            assert!(!forged.matches_identity(&expected));
        }
        let mut mutated = validated;
        mutated.argv.push("/etc/unauthorized".into());
        assert!(!mutated.matches_identity(&expected));
    }
}
