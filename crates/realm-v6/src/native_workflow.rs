//! Native two-step commitments. Data is not a run owner or an authority token.
use crate::coding_submission::SubmissionContract;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeTaskRole {
    Api,
    Cli,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeApiPredecessor {
    pub submission: SubmissionContract,
    pub packet_blake3: String,
    pub referee_root: String,
    pub packet_hex: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSubtask {
    pub workflow: String,
    pub role: NativeTaskRole,
    pub attempt: usize,
    pub history_prefix_blake3: String,
    pub predecessor: Option<NativeApiPredecessor>,
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl NativeSubtask {
    pub fn allows_action(&self, action: &serde_json::Value) -> bool {
        match action["tool"].as_str() {
            Some("write") => match self.role {
                NativeTaskRole::Api => matches!(
                    action["path"].as_str(),
                    Some("totals.py" | "test_totals.py")
                ),
                NativeTaskRole::Cli => matches!(
                    action["path"].as_str(),
                    Some("report.py" | "test_totals.py")
                ),
            },
            Some("read" | "list" | "check" | "finish") => true,
            _ => false,
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if !hex(&self.workflow) || !hex(&self.history_prefix_blake3) || self.attempt >= 4 {
            return Err("native workflow/attempt commitment differs");
        }
        match (self.role, &self.predecessor) {
            (NativeTaskRole::Api, None) => Ok(()),
            (NativeTaskRole::Cli, Some(p)) => {
                p.submission.validate()?;
                if !hex(&p.packet_blake3) || !hex(&p.referee_root) || p.packet_hex.len() > 32768 {
                    return Err("native predecessor commitment differs");
                }
                p.packet()?;
                Ok(())
            }
            _ => Err("native API/CLI predecessor relationship differs"),
        }
    }
}

impl NativeApiPredecessor {
    pub fn packet(&self) -> Result<crate::coding_submission::Submission, &'static str> {
        if self.packet_hex.is_empty()
            || self.packet_hex.len() > 32768
            || !self.packet_hex.len().is_multiple_of(2)
        {
            return Err("native API packet bound");
        }
        let raw: Result<Vec<u8>, _> = self
            .packet_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|c| {
                let v = std::str::from_utf8(c).map_err(|_| "packet hex")?;
                if !c
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                {
                    return Err("canonical packet hex");
                }
                u8::from_str_radix(v, 16).map_err(|_| "packet hex")
            })
            .collect();
        let raw = raw?;
        if blake3::hash(&raw).to_hex().as_str() != self.packet_blake3 {
            return Err("predecessor packet bytes differ");
        }
        self.submission.decode(&raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    Pass,
    Refused,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAttemptReceipt {
    pub role: NativeTaskRole,
    pub outcome: AttemptOutcome,
    pub evidence: Box<crate::coding_semantics::CodingSemanticEvidence>,
    pub packet_hex: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkflowReceipt {
    pub schema: String,
    pub workflow: String,
    pub ledger: String,
    pub prior: Vec<NativeAttemptReceipt>,
}
impl NativeWorkflowReceipt {
    pub fn validate(
        &self,
        current: &crate::coding_semantics::CodingSemanticEvidence,
    ) -> Result<(), &'static str> {
        use crate::coding_semantics::{API_SCOPE, REFUSAL_SCOPE, SCOPE};
        let final_step = current
            .prelaunch
            .native_subtask
            .as_ref()
            .ok_or("native workflow final scope missing")?;
        if self.schema != "realm.native-two-subtask-history/v1"
            || !hex(&self.workflow)
            || self.workflow != final_step.workflow
            || self.prior.is_empty()
            || self.prior.len() > 3
            || final_step.role != NativeTaskRole::Cli
            || final_step.attempt != self.prior.len()
            || current.scope != SCOPE
            || self.ledger.len() > 1024 * 1024
        {
            return Err("native workflow shape/final task differs");
        }
        let mut previous = "0".repeat(64);
        let mut begins = Vec::new();
        let mut retained = Vec::new();
        let mut nonce = None;
        let mut opened = false;
        for raw in self.ledger.lines() {
            let row = crate::strict_json::parse(raw.as_bytes())
                .map_err(|_| "strict native ledger required")?;
            let body = &row["body"];
            let head =
                blake3::hash(&serde_json::to_vec(body).map_err(|_| "native ledger encoding")?)
                    .to_hex()
                    .to_string();
            if body["workflow"] != self.workflow
                || body["previous"] != previous
                || row["blake3"] != head
                || body["authority"] != "NONE"
            {
                return Err("native ledger chain/workflow differs");
            }
            let n = body["owner_nonce"]
                .as_str()
                .ok_or("native ledger nonce absent")?;
            if !hex(n) || nonce.as_ref().is_some_and(|s: &String| s != n) {
                return Err("native ledger owner changed");
            }
            nonce = Some(n.to_owned());
            if !opened && body["phase"] != "OPEN" {
                return Err("original native ledger OPEN missing");
            }
            match body["phase"].as_str() {
                Some("OPEN") if !opened && previous == "0".repeat(64) => {
                    opened = true;
                }
                Some("BEGIN") => {
                    if body["data"]["attempt"].as_u64() != Some(begins.len() as u64)
                        || begins.len() != retained.len()
                    {
                        return Err("native attempt intent omitted/reordered");
                    }
                    begins.push((
                        head.clone(),
                        body["data"]["task"].as_u64().ok_or("native task absent")?,
                    ));
                }
                Some("RETAINED") => {
                    if body["data"]["attempt"].as_u64() != Some(retained.len() as u64)
                        || begins.len() != retained.len() + 1
                    {
                        return Err("native retirement lacks original intent");
                    }
                    retained.push(body["data"].clone());
                }
                _ => return Err("incomplete/aborted/rejected native attempt prevents publication"),
            }
            previous = head;
        }
        if begins.len() != self.prior.len() + 1 || retained.len() != begins.len() {
            return Err("native attempts or closure missing");
        }
        let mut api = None;
        let mut seen = std::collections::BTreeSet::new();
        let mut counts = [0; 2];
        for i in 0..begins.len() {
            let (role, outcome, evidence, packet) = if i < self.prior.len() {
                let r = &self.prior[i];
                if r.evidence.workflow.is_some() {
                    return Err("recursive native histories forbidden");
                }
                r.evidence.validate_shape()?;
                (r.role, r.outcome, r.evidence.as_ref(), Some(&r.packet_hex))
            } else {
                (NativeTaskRole::Cli, AttemptOutcome::Pass, current, None)
            };
            let scope = &evidence.prelaunch;
            let step = scope
                .native_subtask
                .as_ref()
                .ok_or("native task registration missing")?;
            let task = usize::from(role == NativeTaskRole::Cli);
            counts[task] += 1;
            if counts[task] > 2
                || begins[i].1 != task as u64
                || step.attempt != i
                || step.role != role
                || step.workflow != self.workflow
                || step.history_prefix_blake3 != begins[i].0
                || scope.source_commit != current.prelaunch.source_commit
                || scope.submission.task_sha256 != current.prelaunch.submission.task_sha256
                || scope.submission.worker_sha256 != current.prelaunch.submission.worker_sha256
                || !seen.insert(scope.submission.run_id.clone())
            {
                return Err("native attempt source/role/run/prefix differs");
            }
            let expected = if outcome == AttemptOutcome::Refused {
                REFUSAL_SCOPE
            } else if role == NativeTaskRole::Api {
                API_SCOPE
            } else {
                SCOPE
            };
            if evidence.scope != expected
                || retained[i]["outcome"]
                    != if outcome == AttemptOutcome::Pass {
                        "PASS"
                    } else {
                        "REFUSED"
                    }
            {
                return Err("native refusal promoted or result changed");
            }
            let original = &retained[i]["original"];
            let identity = original
                .get("referee_identity")
                .unwrap_or(&original["referee"]);
            if original["custody"]["custodian_root"] != evidence.custody_root
                || original["custody"]["packet_blake3"] != evidence.packet_blake3
                || original["custody"]["prelaunch_scope"]
                    != serde_json::to_value(scope).map_err(|_| "scope encoding")?
                || identity
                    != evidence
                        .referee_identity_record
                        .as_ref()
                        .ok_or("original referee missing")?
                || original["retirement"]["run_id"] != scope.submission.run_id
                || original["retirement"]["native_terminal_kernel_observation"]
                    != evidence
                        .runtime_provenance_record
                        .as_ref()
                        .ok_or("native observations missing")?["terminal"]
            {
                return Err("native custody/referee/retirement substituted");
            }
            if role == NativeTaskRole::Api {
                if api.is_some() {
                    return Err("API attempt after successful API");
                }
                if outcome == AttemptOutcome::Pass {
                    let p = NativeApiPredecessor {
                        submission: scope.submission.clone(),
                        packet_hex: packet.ok_or("API packet absent")?.clone(),
                        packet_blake3: evidence.packet_blake3.clone(),
                        referee_root: evidence.referee_root.clone(),
                    };
                    p.packet()?;
                    api = Some(p);
                }
            } else {
                if step.predecessor.as_ref() != api.as_ref() || api.is_none() {
                    return Err("native CLI predecessor differs");
                }
                if outcome == AttemptOutcome::Pass && i + 1 != begins.len() {
                    return Err("native CLI retried after success");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn role_effects_and_predecessor_are_not_interchangeable() {
        let mut step = NativeSubtask {
            workflow: "a".repeat(64),
            role: NativeTaskRole::Api,
            attempt: 0,
            history_prefix_blake3: "b".repeat(64),
            predecessor: None,
        };
        assert!(step.validate().is_ok());
        for path in ["totals.py", "test_totals.py"] {
            assert!(step.allows_action(&serde_json::json!({"tool":"write","path":path})));
        }
        for action in [
            serde_json::json!({"tool":"write","path":"report.py"}),
            serde_json::json!({"tool":"shell","command":"true"}),
            serde_json::json!({"tool":"write","path":"../totals.py"}),
        ] {
            assert!(!step.allows_action(&action));
        }
        step.role = NativeTaskRole::Cli;
        assert!(step.validate().is_err());
        assert!(!step.allows_action(&serde_json::json!({"tool":"write","path":"totals.py"})));
        assert!(step.allows_action(&serde_json::json!({"tool":"write","path":"report.py"})));
    }
    #[test]
    fn missing_history_cannot_promote_a_registered_final_task() {
        let mut receipt = crate::coding_semantics::tests::fixture()
            .semantic_evidence
            .unwrap();
        receipt.prelaunch.native_subtask = Some(NativeSubtask {
            workflow: "a".repeat(64),
            role: NativeTaskRole::Cli,
            attempt: 1,
            history_prefix_blake3: "b".repeat(64),
            predecessor: None,
        });
        let history = NativeWorkflowReceipt {
            schema: "realm.native-two-subtask-history/v1".into(),
            workflow: "a".repeat(64),
            ledger: String::new(),
            prior: Vec::new(),
        };
        assert!(history.validate(&receipt).is_err());
        assert!(receipt.validate_shape().is_err());
    }
    // Data-only structural fixture. It cannot construct ANY native owner,
    // qualification, signature, publication or destination capability.
    fn data_receipt(
        step: NativeSubtask,
        api: bool,
    ) -> crate::coding_semantics::CodingSemanticEvidence {
        use serde_json::json;
        let mut r = crate::coding_semantics::tests::fixture()
            .semantic_evidence
            .unwrap();
        r.scope = if api {
            crate::coding_semantics::API_SCOPE
        } else {
            crate::coding_semantics::SCOPE
        }
        .into();
        r.prelaunch.submission.run_id = if api { "1" } else { "2" }.repeat(64);
        r.prelaunch.native_subtask = Some(step);
        let mut identity = json!({"domain":if api {"realm.owned-native-api-check/v1"}else{"realm.owned-coding-task-check/v2"},
            "prelaunch_scope":r.prelaunch,"binding":r.prelaunch.submission,"packet":r.packet_blake3,
            "native_custody":r.custody_root,"broker_completion":r.broker_completion_root,
            "measurement":r.measurement_root,"barrier":r.barrier_root,"request_blake3":r.consumed_request_blake3,
            "subject_packet_blake3":r.packet_blake3});
        for key in [
            "process",
            "python",
            "bwrap",
            "sources",
            "seed",
            "result_blake3",
        ] {
            identity[key] = json!("SYNTHETIC_DATA_ONLY");
        }
        r.referee_root = blake3::hash(&serde_json::to_vec(&identity).unwrap())
            .to_hex()
            .to_string();
        r.referee_identity_record = Some(identity.clone());
        let observation = json!({"domain":"realm.native-coding-provenance/v2","resources_raw_json":"TEST_ONLY",
            "resources_root":blake3::hash(b"TEST_ONLY").to_hex().to_string(),"measurement":r.measurement_root,
            "scope":r.prelaunch,"frontier":r.frontier_root,"barrier":r.barrier_root,
            "referee_root":r.referee_root,"referee_identity_record":identity,"terminal":{"TEST_ONLY":true}});
        r.provenance_root = blake3::hash(&serde_json::to_vec(&observation).unwrap())
            .to_hex()
            .to_string();
        r.runtime_provenance_record = Some(observation);
        r.validate_shape().unwrap();
        r
    }
    fn append(
        ledger: &mut String,
        previous: &mut String,
        phase: &str,
        data: serde_json::Value,
    ) -> String {
        let body = serde_json::json!({"workflow":"a".repeat(64),"previous":previous,"authority":"NONE",
            "owner_nonce":"b".repeat(64),"phase":phase,"data":data});
        let head = blake3::hash(&serde_json::to_vec(&body).unwrap())
            .to_hex()
            .to_string();
        *previous = head.clone();
        ledger.push_str(
            &serde_json::to_string(&serde_json::json!({"body":body,"blake3":head})).unwrap(),
        );
        ledger.push('\n');
        head
    }
    fn retained(
        r: &crate::coding_semantics::CodingSemanticEvidence,
        index: usize,
    ) -> serde_json::Value {
        serde_json::json!({"attempt":index,"outcome":"PASS","original":{
            "referee":r.referee_identity_record,"retirement":{"run_id":r.prelaunch.submission.run_id,
            "native_terminal_kernel_observation":r.runtime_provenance_record.as_ref().unwrap()["terminal"]},
            "custody":{"custodian_root":r.custody_root,"packet_blake3":r.packet_blake3,"prelaunch_scope":r.prelaunch}}})
    }
    #[test]
    fn history_data_rejects_omission_substitution_incomplete_and_outcome_promotion() {
        let mut ledger = String::new();
        let mut head = "0".repeat(64);
        append(&mut ledger, &mut head, "OPEN", serde_json::json!({}));
        let prefix = append(
            &mut ledger,
            &mut head,
            "BEGIN",
            serde_json::json!({"attempt":0,"task":0}),
        );
        let mut api = data_receipt(
            NativeSubtask {
                workflow: "a".repeat(64),
                role: NativeTaskRole::Api,
                attempt: 0,
                history_prefix_blake3: prefix,
                predecessor: None,
            },
            true,
        );
        let raw = crate::coding_semantics::tests::fixture().submission;
        // Bind the real parser's valid packet bytes; no claim these were executed.
        api.prelaunch.submission = crate::coding_semantics::tests::fixture()
            .contract
            .submission;
        let packet_blake3 = blake3::hash(&raw).to_hex().to_string();
        let mut api_step = api.prelaunch.native_subtask.clone().unwrap();
        let mut original = data_receipt(api_step.clone(), true);
        // Use the valid packet contract (including run) in the structural receipt.
        original.prelaunch.submission = api.prelaunch.submission.clone();
        // Rebuild identity through data_receipt with fixture binding is cumbersome;
        // update its exact committed preimages before testing the shared validator.
        original.packet_blake3 = packet_blake3.clone();
        let id = original.referee_identity_record.as_mut().unwrap();
        id["prelaunch_scope"] = serde_json::to_value(&original.prelaunch).unwrap();
        id["binding"] = serde_json::to_value(&original.prelaunch.submission).unwrap();
        id["packet"] = packet_blake3.clone().into();
        id["subject_packet_blake3"] = packet_blake3.clone().into();
        original.referee_root = blake3::hash(&serde_json::to_vec(id).unwrap())
            .to_hex()
            .to_string();
        let obs = original.runtime_provenance_record.as_mut().unwrap();
        obs["scope"] = serde_json::to_value(&original.prelaunch).unwrap();
        obs["referee_root"] = original.referee_root.clone().into();
        obs["referee_identity_record"] = id.clone();
        original.provenance_root = blake3::hash(&serde_json::to_vec(obs).unwrap())
            .to_hex()
            .to_string();
        original.validate_shape().unwrap();
        append(&mut ledger, &mut head, "RETAINED", retained(&original, 0));
        let prefix = append(
            &mut ledger,
            &mut head,
            "BEGIN",
            serde_json::json!({"attempt":1,"task":1}),
        );
        api_step.role = NativeTaskRole::Cli;
        api_step.attempt = 1;
        api_step.history_prefix_blake3 = prefix;
        api_step.predecessor = Some(NativeApiPredecessor {
            submission: original.prelaunch.submission.clone(),
            packet_blake3,
            referee_root: original.referee_root.clone(),
            packet_hex: raw.iter().map(|b| format!("{b:02x}")).collect(),
        });
        let current = data_receipt(api_step, false);
        append(&mut ledger, &mut head, "RETAINED", retained(&current, 1));
        let record = NativeWorkflowReceipt {
            schema: "realm.native-two-subtask-history/v1".into(),
            workflow: "a".repeat(64),
            ledger,
            prior: vec![NativeAttemptReceipt {
                role: NativeTaskRole::Api,
                outcome: AttemptOutcome::Pass,
                evidence: Box::new(original),
                packet_hex: raw.iter().map(|b| format!("{b:02x}")).collect(),
            }],
        };
        record.validate(&current).unwrap();
        assert!(current.runtime_qualification.is_none());
        for case in 0..6 {
            let mut changed = record.clone();
            let mut final_r = current.clone();
            match case {
                0 => changed.prior.clear(),
                1 => changed.prior[0].outcome = AttemptOutcome::Refused,
                2 => {
                    final_r
                        .prelaunch
                        .native_subtask
                        .as_mut()
                        .unwrap()
                        .predecessor
                        .as_mut()
                        .unwrap()
                        .referee_root = "f".repeat(64)
                }
                3 => {
                    changed.ledger = changed
                        .ledger
                        .lines()
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join("\n")
                }
                4 => {
                    changed.ledger = changed
                        .ledger
                        .lines()
                        .take(4)
                        .collect::<Vec<_>>()
                        .join("\n")
                }
                _ => changed.prior[0].evidence.custody_root = "f".repeat(64),
            }
            assert!(changed.validate(&final_r).is_err(), "case {case}");
        }
    }
}
