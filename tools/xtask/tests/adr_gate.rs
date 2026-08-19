//! Couples the ratified local-database decision to the dependency inventory.
//!
//! `docs/adr/0001-toolchain-and-cryptography-dependencies.md:75-77` rejects
//! OpenSSL and `ring` as suite-wide abstractions, and `:152-153` makes any new
//! dependency class a fresh ADR with primary-source and RustSec review. Before
//! this gate no test connected an ADR to `[workspace.dependencies]` at all, so
//! a database dependency could have landed with the decision explained
//! afterwards instead of ratified beforehand. The literal-and-section shape
//! mirrors the only other document gate in this repository,
//! `require_document_literals` over `FORMAT_PACKAGE_SECTIONS` and
//! `FORMAT_PACKAGE_LITERALS` (`tools/xtask/src/main.rs`).
//!
//! It is deliberately a separate test target and touches neither
//! `stage_one_documents` nor any `STAGE_ONE_*` constant: the Stage 1 gate is
//! closed, and Stage 2 gate content belongs to its own task.

use std::{fs, path::PathBuf};
use toml::Value;

const ADR_PATH: &str = "docs/adr/0002-local-database-encryption.md";

const ADR_SECTIONS: [&str; 6] = [
    "## Context",
    "## Decision",
    "## Rejected alternatives",
    "## Primary-source and RustSec review",
    "## Full-encryption scope",
    "## Consequences",
];

const ADR_LITERALS: [&str; 5] = [
    "OpenSSL and `ring` as suite-wide abstractions",
    "RustSec advisory database",
    "write-ahead log, all indexes, and every temporary spill file",
    "no plaintext temporary file",
    "docs/adr/0001-toolchain-and-cryptography-dependencies.md",
];

const DATABASE_DEPENDENCIES: [&str; 2] = ["rusqlite", "libsqlite3-sys"];

/// Reads the workspace root the way every check in `workspace.rs` does.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn adr_0002_exists_and_carries_its_mandatory_sections() {
    let adr = fs::read_to_string(workspace_root().join(ADR_PATH))
        .expect("ADR 0002 must exist before any database dependency is pinned");
    for section in ADR_SECTIONS {
        assert!(adr.contains(section), "ADR 0002 is missing {section}");
    }
    for literal in ADR_LITERALS {
        assert!(
            adr.contains(literal),
            "ADR 0002 is missing the literal {literal}"
        );
    }
}

#[test]
fn every_database_dependency_is_pinned_and_named_by_adr_0002() {
    let root = workspace_root();
    let adr = fs::read_to_string(root.join(ADR_PATH))
        .expect("ADR 0002 must exist before any database dependency is pinned");
    let manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let shared = manifest["workspace"]["dependencies"].as_table().unwrap();
    for name in DATABASE_DEPENDENCIES {
        let spec = shared
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be a shared workspace dependency"));
        let version = spec.get("version").and_then(Value::as_str).unwrap();
        assert!(version.starts_with('='), "{name} must be pinned exactly");
        assert!(
            adr.contains(&format!("`{name}`")) && adr.contains(version),
            "ADR 0002 must name {name} with the pinned version {version}"
        );
        // The two assertions above are satisfied independently, so swapping the
        // pins of two reviewed crates would leave both substrings present and
        // neither of them attached to the right crate. The pin is therefore also
        // required to stand on the same line as the crate name it belongs to.
        assert!(
            adr.lines()
                .any(|line| line.contains(&format!("`{name}`")) && line.contains(version)),
            "ADR 0002 must carry {name} and its pin {version} on one line"
        );
        let features = spec["features"].as_array().unwrap();
        for feature in features {
            let feature = feature.as_str().unwrap();
            assert!(
                adr.contains(feature),
                "ADR 0002 must justify the {name} feature {feature}"
            );
        }
        // A bare `contains` over a feature name is satisfied by any incidental
        // mention: `cache` passes because the ADR names it as a feature that
        // stays DISABLED, so silently enabling it would not fail a test. The
        // reviewed selection is therefore also required as one exact ledger
        // line, rebuilt here from the manifest, so that an added, removed or
        // reordered feature has to pass through the review to reach the gate.
        let ledger = format!(
            "{name} = [{}]",
            features
                .iter()
                .map(|feature| format!("\"{}\"", feature.as_str().unwrap()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(
            adr.contains(&ledger),
            "ADR 0002 must carry the reviewed feature selection verbatim: {ledger}"
        );
    }
}
