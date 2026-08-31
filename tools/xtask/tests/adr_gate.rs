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

/// ADR 0004 ratifies the Stage 3 server dependency class.
///
/// `docs/adr/` carries 0001 and 0002 today; 0003 is claimed by
/// `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md:372`
/// for the release supply chain, so the server decision is 0004.
const SERVER_ADR_PATH: &str = "docs/adr/0004-server-runtime-and-dependency-class.md";

const SERVER_ADR_SECTIONS: [&str; 6] = [
    "## Context",
    "## Decision",
    "## Rejected alternatives",
    "## Primary-source and RustSec review",
    "## OCI base image",
    "## Consequences",
];

const SERVER_ADR_LITERALS: [&str; 6] = [
    "docs/adr/0001-toolchain-and-cryptography-dependencies.md",
    "docs/adr/0002-local-database-encryption.md",
    "RustSec advisory database",
    "S3-kompatibler Object Store",
    "bucket versioning",
    "no member of this stage consumes",
];

/// The classes ADR 0004 ratifies: async runtime, HTTP server, PostgreSQL
/// driver, S3 client and TLS stack, plus the trait-object helper that the
/// server crates' abstractions need and the four crates of the HTTP CLIENT
/// family that `crates/ea-sync-client` uploads through.
///
/// The client family — `hyper`, `hyper-util`, `http`, `http-body-util` — is the
/// same dependency class and therefore the same gate: it speaks the protocol
/// this server serves, it terminates on the same `rustls`/`ring` selection, and
/// hyper 1.x already lay in the graph through `axum`. Reaching it through that
/// transitive edge instead of a reviewed pin is exactly the drift this list
/// exists to stop, and a hand-rolled HTTP/1.1 writer in production code — the
/// only alternative that adds no pin — would be an unreviewed second wire
/// implementation.
///
/// The list is EVERY entry of the server class, not the headline crate of each
/// class. `aws-smithy-http-client` and `tokio-rustls` are the two whose feature
/// selection ADR 0004 itself calls load-bearing — `:225` because reaching the
/// connector through `aws-sdk-s3`'s own `rustls` feature would silently select
/// the legacy hyper 0.14 stack, and `:227` because a `tokio-rustls` that
/// re-enabled `tls12` would put TLS 1.2 back on the listening side alone.
/// Leaving them out would have left exactly the two drifts ungated that the
/// document argues hardest about.
///
/// `sqlx-core` and `sqlx-postgres` are the third such entry, for a reason the
/// document measures rather than asserts: the facade features `macros` and
/// `migrate` carry weak references to `sqlx-sqlite`, whose
/// `libsqlite3-sys >=0.30.1, <0.38.0` collides with ADR 0002's `=0.38.0` over
/// `links = "sqlite3"` and stops the workspace resolving. The `migrate`
/// capability therefore sits on the two subcrates. Re-adding either feature to
/// the facade must pass through this gate.
const SERVER_RUNTIME_DEPENDENCIES: [&str; 14] = [
    "async-trait",
    "aws-sdk-s3",
    "aws-smithy-http-client",
    "axum",
    "http",
    "http-body-util",
    "hyper",
    "hyper-util",
    "rustls",
    "sqlx",
    "sqlx-core",
    "sqlx-postgres",
    "tokio",
    "tokio-rustls",
];

/// Reads the workspace root the way every check in `workspace.rs` does.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Rebuilds the reviewed feature selection in the exact ledger form both ADR
/// gates require. A crate without a `features` array yields `name = []`, so an
/// added feature still has to pass through the review.
fn reviewed_feature_ledger_line(name: &str, spec: &Value) -> String {
    let features = spec
        .get("features")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    format!(
        "{name} = [{}]",
        features
            .iter()
            .map(|feature| format!("\"{}\"", feature.as_str().unwrap()))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Reads the shared dependency table of the root manifest.
fn shared_dependencies() -> toml::map::Map<String, Value> {
    let manifest: Value = fs::read_to_string(workspace_root().join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    manifest["workspace"]["dependencies"]
        .as_table()
        .unwrap()
        .clone()
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
        let ledger = reviewed_feature_ledger_line(name, spec);
        assert!(
            adr.contains(&ledger),
            "ADR 0002 must carry the reviewed feature selection verbatim: {ledger}"
        );
    }
}

/// Couples the Stage 3 server dependency class to ADR 0004 before it is used.
///
/// The shape is the one `every_database_dependency_is_pinned_and_named_by_adr_0002`
/// established: every class exactly pinned, its pin on the same line as its
/// name, and the reviewed feature selection as one verbatim ledger line. It is
/// a second instance of the same gate and not a generalization of it, because
/// ADR 0002 and ADR 0004 ratify different classes and must stay separable.
#[test]
fn server_runtime_dependency_class_is_ratified_before_use() {
    let adr = fs::read_to_string(workspace_root().join(SERVER_ADR_PATH))
        .expect("ADR 0004 must exist before any server dependency is pinned");
    for section in SERVER_ADR_SECTIONS {
        assert!(adr.contains(section), "ADR 0004 is missing {section}");
    }
    for literal in SERVER_ADR_LITERALS {
        assert!(
            adr.contains(literal),
            "ADR 0004 is missing the literal {literal}"
        );
    }
    let shared = shared_dependencies();
    for name in SERVER_RUNTIME_DEPENDENCIES {
        let spec = shared
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be a shared workspace dependency"));
        let version = spec
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name} must carry an explicit version"));
        assert!(version.starts_with('='), "{name} must be pinned exactly");
        assert!(
            adr.lines()
                .any(|line| line.contains(&format!("`{name}`")) && line.contains(version)),
            "ADR 0004 must carry {name} and its pin {version} on one line"
        );
        let ledger = reviewed_feature_ledger_line(name, spec);
        assert!(
            adr.contains(&ledger),
            "ADR 0004 must carry the reviewed feature selection verbatim: {ledger}"
        );
    }
}

// tools/xtask/tests/adr_gate.rs — dritte Instanz desselben Gates, keine
// Verallgemeinerung der ersten beiden: ADR 0002, 0004 und 0005 ratifizieren
// verschiedene Klassen und muessen trennbar bleiben.
const BROWSER_ADR_PATH: &str = "docs/adr/0005-browser-runtime-and-wasm-dependency-class.md";

const BROWSER_ADR_SECTIONS: [&str; 8] = [
    "## Context",
    "## Decision",
    "## Rejected alternatives",
    "## Primary-source and RustSec review",
    "## wasm-bindgen crate and CLI parity",
    "## Enumerated web-sys features",
    "## Browser provisioning",
    "## Consequences",
];

const BROWSER_ADR_LITERALS: [&str; 7] = [
    "docs/adr/0001-toolchain-and-cryptography-dependencies.md",
    "docs/adr/0004-server-runtime-and-dependency-class.md",
    "RustSec advisory database",
    "getrandom 0.4.3 selects its wasm backend through the Cargo feature `wasm_js`",
    "--cfg getrandom_backend",
    "spikes/wasm-runtime-proof/spike.sh",
    "no member of this stage consumes",
];

const BROWSER_RUNTIME_DEPENDENCIES: [&str; 5] = [
    "js-sys",
    "wasm-bindgen",
    "wasm-bindgen-futures",
    "wasm-bindgen-test",
    "web-sys",
];

#[test]
fn browser_runtime_dependency_class_is_ratified_before_use() {
    let adr = fs::read_to_string(workspace_root().join(BROWSER_ADR_PATH))
        .expect("ADR 0005 must exist before any browser dependency is pinned");
    for section in BROWSER_ADR_SECTIONS {
        assert!(adr.contains(section), "ADR 0005 is missing {section}");
    }
    for literal in BROWSER_ADR_LITERALS {
        assert!(
            adr.contains(literal),
            "ADR 0005 is missing the literal {literal}"
        );
    }
    let shared = shared_dependencies();
    for name in BROWSER_RUNTIME_DEPENDENCIES {
        let spec = shared
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be a shared workspace dependency"));
        let version = spec
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name} must carry an explicit version"));
        assert!(version.starts_with('='), "{name} must be pinned exactly");
        assert!(
            adr.lines()
                .any(|line| line.contains(&format!("`{name}`")) && line.contains(version)),
            "ADR 0005 must carry {name} and its pin {version} on one line"
        );
        let ledger = reviewed_feature_ledger_line(name, spec);
        assert!(
            adr.contains(&ledger),
            "ADR 0005 must carry the reviewed feature selection verbatim: {ledger}"
        );
    }
}
