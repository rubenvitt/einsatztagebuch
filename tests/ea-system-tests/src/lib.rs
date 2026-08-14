use std::path::{Path, PathBuf};

/// Returns the repository root used by cross-crate system tests.
#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[test]
    fn workspace_root_locates_the_real_root_manifest() {
        let root = super::workspace_root();
        let manifest: toml::Value = fs::read_to_string(root.join("Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();

        assert_eq!(manifest["workspace"]["resolver"].as_str(), Some("2"));
    }

    #[test]
    fn suite_one_literal_has_one_dag_neutral_owner() {
        assert_eq!(ea_types::SUITE_ID_V1, "EINSATZARCHIV-SUITE-1");
        assert_eq!(ea_crypto::SUITE_ID, ea_types::SUITE_ID_V1);
        assert_eq!(ea_schema::SUITE_ID_V1, ea_types::SUITE_ID_V1);
    }
}
