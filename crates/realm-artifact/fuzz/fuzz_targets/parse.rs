#![no_main]
use libfuzzer_sys::fuzz_target;
use realm_artifact::ArtifactBundle;

fuzz_target!(|bytes: &[u8]| {
    let _ = ArtifactBundle::unpack(bytes);
});
