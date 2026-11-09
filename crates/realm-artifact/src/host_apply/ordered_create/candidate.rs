//! Canonical coding projection inspection. Structural validity grants no authority.
use super::*;

#[derive(Debug, Serialize)]
pub struct CandidateInspection {
    pub artifact_blake3: String,
    pub semantic_root: String,
    pub run_id: String,
    pub execution_id: String,
    pub effect_contract: String,
    pub operations: Vec<CreateOperation>,
    pub authority: String,
}

pub(in crate::host_apply) fn decode(bytes: &[u8]) -> Result<ArtifactBundle> {
    if bytes.len() as u64 > MAX_TRANSFER_BYTES {
        return refuse("coding artifact exceeds transfer budget");
    }
    let b = ArtifactBundle::unpack_coding(bytes)?;
    b.validate_at(ValidationLevel::ContentComplete)?;
    // The portable parser accepts structural JSON. Receiving this restricted
    // profile additionally demands exactly the canonical transport encoding.
    // This also refuses duplicate keys in nested maps and alternate blob order.
    if b.pack()? != bytes {
        return refuse("noncanonical coding artifact serialization");
    }
    if b.run.lifecycle != crate::Lifecycle::Sealed
        || !b.run.unknown_effects.is_empty()
        || b.run.proposed_effects.len() != 3
        || b.run.outputs.len() != 3
    {
        return refuse("sealed three-create projection with no unknown effects required");
    }
    for (i, path) in PATHS.iter().enumerate() {
        let effect = &b.run.proposed_effects[i];
        let output = &b.run.outputs[i];
        if effect.kind != "create"
            || effect.target != *path
            || effect.before.is_some()
            || effect.after.as_ref() != Some(&output.digest)
            || output.size == 0
            || output.size > MAX_FILE
        {
            return refuse("unsupported path, operation, order, initial state or output binding");
        }
    }
    Ok(b)
}

/// Inspect claims and content commitments, without authenticating publication.
/// This return type is intentionally not accepted by any application API.
pub fn inspect(bytes: &[u8]) -> Result<CandidateInspection> {
    let b = decode(bytes)?;
    Ok(CandidateInspection {
        artifact_blake3: digest(bytes),
        semantic_root: b.semantic_identity()?.value,
        run_id: b.run.run.run_id.clone(),
        execution_id: b.run.run.execution_id.clone(),
        effect_contract: b.run.effect_contract.identity.clone(),
        operations: b
            .run
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| CreateOperation {
                index: i,
                path: PATHS[i].into(),
                content_blake3: digest(&b.blobs[&o.digest.value]),
                bytes: o.size,
                mode: 0o600,
                requires_completed: i,
            })
            .collect(),
        authority: "NONE: structural inspection only".into(),
    })
}

/// Candidate bytes alone cannot establish operator trust or publication. Use
/// coding_transfer::verify_transfer with independent policy and detached proof.
pub fn verify(bytes: &[u8]) -> Result<VerifiedCreateBatch> {
    inspect(bytes)?;
    refuse(
        "REFUSE_UNVERIFIED_BOUNDARY: detached publication proof, independently authenticated policy and native coding authority required; use realm artifact verify-coding FILE PROOF POLICY",
    )
}
