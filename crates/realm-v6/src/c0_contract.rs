//! Bounded specification for the existing static C0 read/create/write program.
//! This is an operator specification, never a launch or publication capability.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct C0FileContract {
    pub input_bytes: Vec<u8>,
    pub input_mode: u32,
    pub output_path: String,
    pub output_bytes: Vec<u8>,
    pub output_mode: u32,
}
impl C0FileContract {
    pub fn frozen() -> Self {
        Self {
            input_bytes: b"abc".to_vec(),
            input_mode: 0o644,
            output_path: "output.txt".into(),
            output_bytes: b"ABC".to_vec(),
            output_mode: 0o600,
        }
    }
    pub fn commitments(&self) -> Result<(String, String, String), serde_json::Error> {
        use crate::filesystem_world::{FilesystemObject, FilesystemWorld};
        use std::collections::BTreeMap;
        let file = |bytes: &[u8], mode| FilesystemObject::File {
            content_blake3: blake3::hash(bytes).to_hex().to_string(),
            mode,
        };
        let entries =
            BTreeMap::from([("input.txt".into(), file(&self.input_bytes, self.input_mode))]);
        let before = FilesystemWorld {
            root: blake3::hash(&serde_json::to_vec(&entries)?)
                .to_hex()
                .to_string(),
            entries,
        };
        let mut entries = before.entries.clone();
        entries.insert(
            self.output_path.clone(),
            file(&self.output_bytes, self.output_mode),
        );
        let after = FilesystemWorld {
            root: blake3::hash(&serde_json::to_vec(&entries)?)
                .to_hex()
                .to_string(),
            entries,
        };
        let delta = blake3::hash(&serde_json::to_vec(&crate::filesystem_world::delta(
            &before, &after,
        ))?)
        .to_hex()
        .to_string();
        Ok((before.root, after.root, delta))
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.input_bytes.len() > 128
            || !matches!(self.input_mode, 0o400 | 0o600 | 0o644)
            || self.output_mode != 0o600
        {
            return Err("unsupported C0 length or file mode");
        }
        if self.output_path.is_empty()
            || self.output_path.len() > 64
            || self.output_path == "input.txt"
            || self.output_path == "."
            || self.output_path == ".."
            || !self
                .output_path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("C0 output must be one safe distinct basename");
        }
        if self.output_bytes
            != self
                .input_bytes
                .iter()
                .map(|b| b ^ 0x20)
                .collect::<Vec<_>>()
        {
            return Err("C0 contract differs from pinned XOR-0x20 program semantics");
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_and_bounded_matrix_validate() {
        for input in [
            vec![],
            vec![0],
            b"different text".to_vec(),
            (0..128).collect(),
        ] {
            for mode in [0o400, 0o600, 0o644] {
                let mut c = C0FileContract::frozen();
                c.input_bytes = input.clone();
                c.input_mode = mode;
                c.output_path = "result-2.bin".into();
                c.output_bytes = input.iter().map(|b| b ^ 0x20).collect();
                assert!(c.validate().is_ok());
            }
        }
    }
    #[test]
    fn invalid_specifications_refuse_before_launch() {
        let c = C0FileContract::frozen();
        assert!(c.validate().is_ok());
        for path in [
            "",
            "input.txt",
            "../output",
            "a/b",
            "a\\b",
            ".",
            "..",
            "quote\"",
            "line\n",
        ] {
            let mut bad = c.clone();
            bad.output_path = path.into();
            assert!(bad.validate().is_err());
        }
        let mut bad = c.clone();
        bad.output_bytes = b"BAD".to_vec();
        assert!(bad.validate().is_err());
        let mut bad = c.clone();
        bad.input_bytes = vec![0; 129];
        bad.output_bytes = vec![0x20; 129];
        assert!(bad.validate().is_err());
        let mut bad = c.clone();
        bad.input_mode = 0o666;
        assert!(bad.validate().is_err());
        let mut bad = c;
        bad.output_mode = 0o644;
        assert!(bad.validate().is_err());
    }
}
