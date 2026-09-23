// crates/ea-reader-wasm/tests/escrow_dto.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es — aus demselben Grund wie in
// `tests/session_dto.rs`.
#![cfg(not(target_arch = "wasm32"))]

//! Die Status-DTOs der Escrow-Zeremonien (Scheibe e), Feld für Feld und
//! geparst: sie tragen ausschließlich Hex, Zahlen, feste Codes und
//! öffentliche Dateibytes — nie Schlüsselmaterial.

use ea_reader_wasm::escrow_bridge::{
    escrow_package_json, registration_request_json, transport_begin_json, transport_open_json,
};

fn parsed(rendered: &str) -> serde_json::Map<String, serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_str(rendered).expect("das DTO MUSS gueltiges JSON sein");
    value.as_object().cloned().expect("das DTO ist ein Objekt")
}

fn keys(map: &serde_json::Map<String, serde_json::Value>) -> Vec<&str> {
    map.keys().map(String::as_str).collect()
}

fn text<'a>(map: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> &'a str {
    map[key].as_str().expect("ein Textfeld")
}

#[test]
fn the_registration_dto_carries_name_bytes_and_two_fingerprints() {
    let map = parsed(&registration_request_json(
        "ab.registration.cbor",
        &[0x01, 0xfe],
        &[0x11; 32],
        &[0x22; 32],
    ));
    let mut expected = vec![
        "fileName",
        "bytesHex",
        "kemFingerprint",
        "signingFingerprint",
    ];
    expected.sort_unstable();
    assert_eq!(keys(&map), expected);
    assert_eq!(text(&map, "fileName"), "ab.registration.cbor");
    assert_eq!(text(&map, "bytesHex"), "01fe");
    assert_eq!(text(&map, "kemFingerprint"), "11".repeat(32));
    assert_eq!(text(&map, "signingFingerprint"), "22".repeat(32));
}

#[test]
fn the_package_dto_carries_the_public_hashes() {
    let map = parsed(&escrow_package_json(
        "cd.reader-key-escrow-package.cbor",
        &[0x0a],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 32],
        &[0x66; 32],
    ));
    let mut expected = vec![
        "fileName",
        "bytesHex",
        "escrowCoreHash",
        "readerCertificate",
        "recoveryCertificate",
        "kemFingerprint",
    ];
    expected.sort_unstable();
    assert_eq!(keys(&map), expected);
    assert_eq!(text(&map, "escrowCoreHash"), "33".repeat(32));
    assert_eq!(text(&map, "readerCertificate"), "44".repeat(32));
    assert_eq!(text(&map, "recoveryCertificate"), "55".repeat(32));
    assert_eq!(text(&map, "kemFingerprint"), "66".repeat(32));
}

#[test]
fn the_transport_dto_carries_the_handle_and_the_fingerprint() {
    let map = parsed(&transport_begin_json(
        7,
        &[0x77; 32],
        &[0x88; 32],
        &[0x99; 32],
        "ef.reader-key-escrow-transport.cbor",
        &[0x0b, 0x0c],
    ));
    let mut expected = vec![
        "handle",
        "transportFingerprint",
        "escrowObjectHash",
        "readerCertificate",
        "fileName",
        "bytesHex",
    ];
    expected.sort_unstable();
    assert_eq!(keys(&map), expected);
    assert_eq!(map["handle"].as_u64(), Some(7));
    assert_eq!(text(&map, "transportFingerprint"), "77".repeat(32));
    assert_eq!(text(&map, "bytesHex"), "0b0c");
}

#[test]
fn the_open_dto_carries_the_restored_fingerprint_and_the_shown_authorization() {
    let map = parsed(&transport_open_json(&[0xaa; 32], &[0xbb; 32]));
    let mut expected = vec!["restored", "kemFingerprint", "authorizationObjectHash"];
    expected.sort_unstable();
    assert_eq!(keys(&map), expected);
    assert_eq!(map["restored"].as_bool(), Some(true));
    assert_eq!(text(&map, "kemFingerprint"), "aa".repeat(32));
    assert_eq!(text(&map, "authorizationObjectHash"), "bb".repeat(32));
}
