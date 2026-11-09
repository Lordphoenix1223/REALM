#![no_main]
use libfuzzer_sys::fuzz_target;
use realm_artifact::ArtifactBundle;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(mut bundle) = ArtifactBundle::unpack(bytes) {
        for state in [
            realm_artifact::Lifecycle::Executing,
            realm_artifact::Lifecycle::Checkpointed,
            realm_artifact::Lifecycle::Frozen,
            realm_artifact::Lifecycle::Sealed,
        ] {
            let _ = bundle.transition(state);
            let _ = bundle.validate();
        }
    }
});
