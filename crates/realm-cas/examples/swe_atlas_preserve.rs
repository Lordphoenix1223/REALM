//! Preserve and reopen diagnostic bytes using the real REALM CAS.
//! This example does not create a verified execution, receipt, or ACCEPT.
use realm_cas::PreimageStore;
use std::{env, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: swe_atlas_preserve CAS_DIRECTORY DIAGNOSTIC_FILE".into());
    }
    let bytes = fs::read(&args[2])?;
    let store = PreimageStore::open(&args[1])?;
    let reference = store.put_bytes(&bytes)?;
    // Reopen through the canonical verifier; a reference alone is insufficient.
    if store.get_bytes(&reference)? != bytes {
        return Err("CAS reopen did not match source bytes".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "schema": "realm.research.native-cas/v1",
            "authority": "NON_AUTHORIZING",
            "reference": reference,
            "reopened_bytes_equal": true,
            "execution_verification": "NOT_VERIFIED",
            "official_score": null
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn canonical_cas_reopens_and_refuses_corrupt_preservation() {
        let name = format!(
            "realm-atlas-cas-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = env::temp_dir().join(name);
        let store = PreimageStore::open(&directory).unwrap();
        let bytes = b"{\"authority\":\"NON_AUTHORIZING\",\"official_score\":null}";
        let reference = store.put_bytes(bytes).unwrap();
        assert_eq!(store.get_bytes(&reference).unwrap(), bytes);
        fs::write(store.blob_path(&reference.hash), b"corrupt").unwrap();
        assert!(store.get_bytes(&reference).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
