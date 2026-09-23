//! Kanarienvögel der Escrow-Zeremonien (Scheibe e, Muster
//! `privacy_canaries_reader`): der Reader-KEM und der Signaturschlüssel
//! stehen in keiner Übergabedatei, in keinem Fehlercode und nicht im Klartext
//! des lokalen Speichers.
mod escrow_line;
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
mod fixtures;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

use ea_format::{
    ReaderKeyEscrowTransportRequestV1, decode_reader_key_escrow_transport_request,
    encode_reader_key_escrow_transport_request,
};
use ea_reader::{
    InMemoryReaderBlobStore, ReaderBlobStore, ReaderEnrollment, ReaderKeyEscrowTransportV1,
    decode_trust_anchor, reader_registration_request, seal_reader_key_escrow_package,
};
use ea_testkit::contains_canary;
use ea_types::UnixMillis;
use escrow_line::{AUDIT_SEED, LineSource, line_with_escrow, restored_kem, vault_on};
use escrow_support::{EscrowLineOptions, READER_KEM_SEED, escrow_line, subject};

fn assert_clean(label: &str, haystack: &[u8], canaries: &[[u8; 32]]) {
    for canary in canaries {
        assert!(!contains_canary(haystack, canary), "{label}");
        assert!(
            !contains_canary(haystack, hex::encode(canary).as_bytes()),
            "{label} (hex)"
        );
    }
}

#[test]
fn the_search_finds_a_canary_where_it_lies() {
    let mut haystack = b"prefix".to_vec();
    haystack.extend_from_slice(&READER_KEM_SEED);
    assert!(contains_canary(&haystack, &READER_KEM_SEED));
    assert!(contains_canary(
        hex::encode(READER_KEM_SEED).as_bytes(),
        hex::encode(READER_KEM_SEED).as_bytes()
    ));
}

#[test]
fn package_and_registration_files_carry_no_private_key() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let vault = vault_on(&escrow, READER_KEM_SEED);
    let canaries = [READER_KEM_SEED, AUDIT_SEED];
    let package = seal_reader_key_escrow_package(
        &vault,
        &LineSource::of(&escrow),
        subject(0xc1),
        UnixMillis::new(1_200),
    )
    .unwrap();
    assert_clean("package", package.exact_bytes(), &canaries);
    assert_clean("package name", package.file_name().as_bytes(), &canaries);
    let registration = reader_registration_request(&vault).unwrap();
    assert_clean("registration", registration.exact_bytes(), &canaries);

    // Ein Fehler trägt nur seinen Code.
    let foreign = vault_on(&escrow, [0x0d; 32]);
    let error = seal_reader_key_escrow_package(
        &foreign,
        &LineSource::of(&escrow),
        subject(0xc1),
        UnixMillis::new(1_200),
    )
    .err()
    .unwrap();
    assert_eq!(format!("{error:?}"), error.code());
    assert_clean("error", format!("{error:?}{error}").as_bytes(), &canaries);
}

/// Die Transportdatei ist GENAU die Codec-Kodierung ihrer drei öffentlichen
/// Felder — für den privaten Transport-Schlüssel ist darin kein Platz.
#[test]
fn the_transport_file_is_exactly_its_three_public_fields() {
    let (escrow, _) = line_with_escrow(subject(0xc1));
    let transport = ReaderKeyEscrowTransportV1::begin(
        &decode_trust_anchor(escrow.line.exact_anchor_bytes()).unwrap(),
        &LineSource::of(&escrow),
        subject(0xc1),
        UnixMillis::new(2_000),
    )
    .unwrap();
    let file = transport.transport_request().unwrap();
    let decoded = decode_reader_key_escrow_transport_request(file.exact_bytes()).unwrap();
    let reencoded =
        encode_reader_key_escrow_transport_request(&ReaderKeyEscrowTransportRequestV1 {
            organization_id: decoded.organization_id,
            escrow_object_hash: decoded.escrow_object_hash,
            target_transport_public_key: decoded.target_transport_public_key,
        })
        .unwrap();
    assert_eq!(file.exact_bytes(), reencoded.as_slice());
    assert_clean("transport", file.exact_bytes(), &[READER_KEM_SEED]);
}

/// Der wiederhergestellte KEM liegt danach nur VERSIEGELT im Speicher.
#[test]
fn the_restored_vault_stores_no_plaintext_key() {
    let (escrow, escrow_hash) = line_with_escrow(subject(0xc1));
    let restored = restored_kem(&escrow, escrow_hash, subject(0xc1));
    let mut store = InMemoryReaderBlobStore::new();
    let mut enrollment = ReaderEnrollment::begin_restored(
        &store,
        support::organization(),
        subject(0xc1),
        decode_trust_anchor(escrow.line.exact_anchor_bytes()).unwrap(),
        fixtures::bundle_fingerprint(),
        restored,
    )
    .unwrap();
    enrollment
        .register_authenticator(fixtures::attested(1))
        .unwrap();
    enrollment
        .register_authenticator(fixtures::attested(2))
        .unwrap();
    let shown = enrollment.fingerprints();
    let confirmation = enrollment
        .confirm_fingerprints(
            &shown.key_fingerprint_hex(),
            &shown.bundle_fingerprint_hex(),
        )
        .unwrap();
    let enrolled = enrollment
        .finish_restored(confirmation, &mut store)
        .unwrap();
    let audit = enrolled
        .unlock_with(&fixtures::authenticator(1))
        .unwrap()
        .audit_signing_key()
        .with_exposed(|seed| *seed);
    for key in store.keys().unwrap() {
        let bytes = store.get(&key).unwrap().unwrap();
        assert_clean(key.as_str(), &bytes, &[READER_KEM_SEED, audit]);
    }
}
