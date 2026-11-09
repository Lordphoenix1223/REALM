//! Receiver boundary for the producer's portable qualification receipt.
//! Decoding yields data only; publication and destination capabilities require
//! independent admission and the existing canonical lifecycle/native checks.
use super::*;
use realm_v6::coding_semantics::CodingSemanticEvidence;

pub const MAX_QUALIFICATION_RECEIPT: usize = 2 * 1024 * 1024;

/// Strict, bounded transport decoding shared by receiving and contract tests.
/// No signer, runtime or publication authority is established by this function.
pub fn decode_receipt(bytes: &[u8]) -> Result<CodingSemanticEvidence> {
    if bytes.is_empty() || bytes.len() > MAX_QUALIFICATION_RECEIPT {
        return refuse("coding qualification receipt exceeds transport bound");
    }
    let receipt: CodingSemanticEvidence = coding_transfer::strict_json(bytes)?;
    receipt
        .validate_shape()
        .map_err(|e| ApplyError::Refuse(e.into()))?;
    Ok(receipt)
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkflowTrust {
    pub workflow: String,
    pub prior_admissions: Vec<realm_v6::runtime_admission::SignedRuntimeAdmission>,
}

/// Trust inputs are independently provisioned; receipt data cannot choose them.
pub fn check_workflow_receipt(
    receipt: &CodingSemanticEvidence,
    final_admission: &realm_v6::runtime_admission::SignedRuntimeAdmission,
    trust: &NativeWorkflowTrust,
) -> Result<()> {
    receipt
        .validate_shape()
        .map_err(|e| ApplyError::Refuse(e.into()))?;
    let history = receipt.workflow.as_ref().ok_or_else(|| {
        ApplyError::Refuse("INCOMPLETE: native original attempt history absent".into())
    })?;
    if trust.workflow != history.workflow || trust.prior_admissions.len() != history.prior.len() {
        return refuse("independent native workflow/attempt policy differs");
    }
    realm_v6::runtime_admission::check_qualified_receipt(receipt, final_admission)
        .map_err(ApplyError::Refuse)?;
    for (attempt, permitted) in history.prior.iter().zip(&trust.prior_admissions) {
        realm_v6::runtime_admission::check_qualified_receipt(&attempt.evidence, permitted)
            .map_err(|e| {
                ApplyError::Refuse(format!(
                    "INCOMPLETE: original native attempt lacks trusted qualification: {e}"
                ))
            })?;
    }
    Ok(())
}

/// Check the shared producer contract against the receiver's independently
/// supplied permitted statement. This produces no destination capability;
/// canonical publication/native validation remains mandatory at its caller.
pub fn check_receipt(
    receipt: &CodingSemanticEvidence,
    permitted: &realm_v6::runtime_admission::SignedRuntimeAdmission,
) -> Result<()> {
    receipt
        .validate_shape()
        .map_err(|e| ApplyError::Refuse(e.into()))?;
    if receipt.prelaunch.native_subtask.is_some() || receipt.workflow.is_some() {
        return refuse(
            "INCOMPLETE: independently provisioned all-attempt workflow policy required",
        );
    }
    realm_v6::runtime_admission::check_qualified_receipt(receipt, permitted)
        .map_err(|e| ApplyError::Refuse(format!("REFUSE_UNVERIFIED_BOUNDARY: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_rejects_ambiguous_unknown_and_unbounded_qualification_data() {
        for bytes in [
            b"".as_slice(),
            br#"{"scope":"one","scope":"two"}"#,
            br#"{"runtime_provenance_record":{"x":1,"x":2}}"#,
            br#"{"qualified":true}"#,
            br#"{"scope":1.5}"#,
        ] {
            assert!(decode_receipt(bytes).is_err());
        }
        assert!(decode_receipt(&vec![b' '; MAX_QUALIFICATION_RECEIPT + 1]).is_err());
    }
}
