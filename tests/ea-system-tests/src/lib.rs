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
}
