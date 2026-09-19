//! DRK-321: Signaturmacht der Reader-Crates, nach Fähigkeit statt nach Wörtern.
//!
//! Web-Reader-Design §3: Der Reader signiert ausschließlich seine eigene,
//! jobgebundene Löschattestierung, dazu sein lokales Audit. Er signiert keinen
//! Zustandsübergang, keine Autorisierung und keinen Preflight. Dieser Zeuge
//! liest `crates/ea-reader/src` und `crates/ea-reader-wasm/src` als Text und
//! hält jeden Signieraufruf gegen eine Allowlist:
//!
//! - jeder `sign_*`-Aufruf (Methode oder `Typ::sign_*(`) braucht eine Zeile in
//!   `COSE_SIGNING_CALLS`;
//! - die Roh-`.sign(`-Aufrufe (HTTP-Nachrichtensignatur, Vault-Schlüsselbeweis)
//!   sind kein COSE-Objekt und stehen je Datei mit ihrer Anzahl in
//!   `RAW_SIGNING_CALLS`;
//! - die Bausteine eines Übergangs, einer Autorisierung oder eines Preflights
//!   kommen gar nicht vor.
//!
//! Die Prüfung ist bewusst textuell, wie `bridge_boundary.rs` in
//! `ea-reader-wasm`: ein neuer Aufruf wird rot, bis er begründet eingetragen ist.
#![cfg(not(target_arch = "wasm32"))]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// `(Datei relativ zum Crate-Paar, Methode)`: jeder zugelassene COSE-Signieraufruf.
const COSE_SIGNING_CALLS: &[(&str, &str)] = &[
    // Lokales Reader-Audit (eigene Kette des Geräts).
    ("ea-reader/src/audit.rs", "sign_local_audit"),
    // Eigene, jobgebundene Löschattestierung des Reader-Caches (§3).
    (
        "ea-reader/src/reader_attestation.rs",
        "sign_deletion_attestation_digest",
    ),
];

/// `(Datei, Anzahl)`: Roh-Ed25519-Signaturen außerhalb von COSE.
const RAW_SIGNING_CALLS: &[(&str, usize)] = &[
    // Enrollment-Nachrichtensignatur (HTTP Message Signatures).
    ("ea-reader/src/enrollment.rs", 1),
    // Sync-Anfragesignatur (HTTP Message Signatures).
    ("ea-reader/src/sync.rs", 1),
    // Schlüsselbeweis des Tresors über einen Digest.
    ("ea-reader/src/vault.rs", 1),
];

/// Bausteine, die nur ein Übergangs-, Autorisierungs- oder Preflight-Signierer
/// braucht. Heute 0 Treffer; jeder Treffer ist ein Verstoß gegen §3.
const FORBIDDEN: &[&str] = &[
    "sign_destruction_transition_digest",
    "sign_destruction_approval_digest",
    "sign_destruction_preflight_report",
    "TrustPayloadV1::destruction_transition",
    "TrustPayloadV1::destruction_authorization",
    "DestructionTransitionFieldsV1 {",
    "DestructionAuthorizationFieldsV1 {",
];

fn collect_rust_sources(directory: &Path, into: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", directory.display()))
    {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
}

/// `(relativer Pfad, Quelltext ohne Kommentarzeilen)` beider Reader-Crates.
fn reader_sources() -> Vec<(String, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory");
    let mut out = Vec::new();
    for name in ["ea-reader", "ea-reader-wasm"] {
        let mut paths = Vec::new();
        collect_rust_sources(&crates.join(name).join("src"), &mut paths);
        paths.sort();
        for path in paths {
            let text = fs::read_to_string(&path).expect("readable source");
            let code: String = text
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .map(|line| format!("{line}\n"))
                .collect();
            let relative = path
                .strip_prefix(crates)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((relative, code));
        }
    }
    assert!(
        out.iter()
            .any(|(path, _)| path.starts_with("ea-reader-wasm/")),
        "the wasm bridge sources must be scanned too"
    );
    out
}

/// Jeder Aufruf `.sign_x(` oder `::sign_x(` im Code.
fn sign_calls(code: &str) -> Vec<String> {
    let mut calls = Vec::new();
    for (index, _) in code.match_indices("sign_") {
        let before = &code[..index];
        if !(before.ends_with('.') || before.ends_with("::")) {
            continue;
        }
        let name: String = code[index..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if code[index + name.len()..].trim_start().starts_with('(') {
            calls.push(name);
        }
    }
    calls
}

/// Anzahl der Roh-Aufrufe `.sign(`.
fn raw_sign_calls(code: &str) -> usize {
    code.match_indices("sign")
        .filter(|(index, _)| {
            code[..*index].ends_with('.') && code[index + 4..].trim_start().starts_with('(')
        })
        .count()
}

#[test]
fn reader_crates_sign_only_their_own_attestation_and_audit() {
    let sources = reader_sources();
    let mut cose = Vec::new();
    let mut raw = BTreeMap::new();
    for (path, code) in &sources {
        for forbidden in FORBIDDEN {
            assert!(
                !code.contains(forbidden),
                "{path} uses `{forbidden}`: the reader signs no state transition, \
                 authorization or preflight (Web-Reader-Design §3)"
            );
        }
        for call in sign_calls(code) {
            cose.push((path.clone(), call));
        }
        let count = raw_sign_calls(code);
        if count > 0 {
            raw.insert(path.clone(), count);
        }
    }
    let unlisted: Vec<_> = cose
        .iter()
        .filter(|(path, call)| {
            !COSE_SIGNING_CALLS
                .iter()
                .any(|(p, c)| p == path && c == call)
        })
        .collect();
    assert!(
        unlisted.is_empty(),
        "new signing calls in the reader crates need a justified entry in \
         COSE_SIGNING_CALLS: {unlisted:?}"
    );
    let stale: Vec<_> = COSE_SIGNING_CALLS
        .iter()
        .filter(|(p, c)| !cose.iter().any(|(path, call)| path == p && call == c))
        .collect();
    assert!(
        stale.is_empty(),
        "COSE_SIGNING_CALLS lists calls that no longer exist: {stale:?}"
    );
    let expected: BTreeMap<String, usize> = RAW_SIGNING_CALLS
        .iter()
        .map(|(path, count)| ((*path).to_owned(), *count))
        .collect();
    assert_eq!(
        raw, expected,
        "raw `.sign(` calls in the reader crates must match RAW_SIGNING_CALLS"
    );
}

#[test]
fn the_scanner_sees_method_and_path_calls() {
    assert_eq!(
        sign_calls("a.sign_x(1); B::sign_y (2); sign_z(3); c.sign_w;"),
        ["sign_x", "sign_y"]
    );
    assert_eq!(
        raw_sign_calls("k.sign(d); k.sign (e); k.signal(f); sign(g)"),
        2
    );
}
