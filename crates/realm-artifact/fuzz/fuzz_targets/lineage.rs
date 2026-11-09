#![no_main]
use libfuzzer_sys::fuzz_target;
use realm_artifact::ArtifactBundle;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(bundle) = ArtifactBundle::unpack(bytes) {
        let _ = bundle.validate();
        let _ = bundle.transport_identity();
    }
});
