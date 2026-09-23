// crates/ea-reader-wasm/tests/escrow_restore_abort.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es — aus demselben Grund wie in
// `tests/escrow_dto.rs`.
#![cfg(not(target_arch = "wasm32"))]

//! Zeremonie B, Sperrung (Escrow-Profil §7, Controller-Ruling Fixrunde 3):
//! der Abbruch unter der Escrow-Kennung nullt den wiederhergestellten
//! Reader-KEM in JEDEM Zustand — auch nachdem `enrollmentBeginRestored` ihn
//! unter eine neue Enrollment-Kennung gelegt hat (review-e F1).
//!
//! Der Weg läuft über dieselben Tabellenhälften, die die wasm-Ausfuhren
//! rufen, und über die echte Escrow-Linie von `ea-reader`: Transport
//! beginnen, Umschlag an den öffentlichen Schlüssel der Transportdatei
//! versiegeln, öffnen, Enrollment beginnen, abbrechen.
#[path = "../../ea-reader/tests/escrow_line/mod.rs"]
mod escrow_line;
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

use ea_crypto::{HpkeRecipientPublicKey, SecretBytes, hpke_aad, hpke_info, hpke_seal};
use ea_format::{
    ReaderKeyEscrowEnvelopeV1, ReaderKeyEscrowRestoreContextV1,
    decode_reader_key_escrow_transport_request, encode_reader_key_escrow_envelope,
};
use ea_reader::{Hash32, InMemoryReaderBlobStore, decode_trust_anchor};
use ea_reader_wasm::escrow_bridge::{
    ESCROW_BRIDGE_ARGUMENT_CODE, transport_abort, transport_begin_status, transport_open_status,
};
use ea_reader_wasm::webauthn::{begin_restored_status, enrollment_fingerprints_status};
use ea_types::{KeyThumbprint, SubjectId, UnixMillis};
use escrow_line::{LineSource, line_with_escrow};
use escrow_support::{EscrowLine, READER_KEM_SEED, subject, x25519_key};

const ENROLLMENT_BRIDGE_ARGUMENT_CODE: &str = "EA-READER-ENROLLMENT-BRIDGE-ARGUMENT";

fn reader_subject() -> SubjectId {
    subject(0xc1)
}

fn field(rendered: &str, key: &str) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_str(rendered).expect("gueltiges JSON");
    value[key].clone()
}

/// Transport beginnen und den Umschlag öffnen — bis zum wiederhergestellten
/// KEM unter der Escrow-Kennung.
fn restored_under_escrow_handle(escrow: &EscrowLine, escrow_hash: ea_types::ObjectHash) -> u32 {
    let anchor = decode_trust_anchor(escrow.line.exact_anchor_bytes()).unwrap();
    let begun = transport_begin_status(
        &anchor,
        &LineSource::of(escrow),
        reader_subject(),
        UnixMillis::new(2_000),
    )
    .unwrap();
    let handle = u32::try_from(field(&begun, "handle").as_u64().unwrap()).unwrap();
    let request_bytes = hex::decode(field(&begun, "bytesHex").as_str().unwrap()).unwrap();
    let fingerprint = hex::decode(field(&begun, "transportFingerprint").as_str().unwrap()).unwrap();
    let request = decode_reader_key_escrow_transport_request(&request_bytes).unwrap();

    let context = ReaderKeyEscrowRestoreContextV1 {
        organization_id: anchor.organization_id(),
        authorization_object_hash: support::object_hash_marker(0x7a),
        escrow_object_hash: escrow_hash,
        reader_certificate_object_hash: escrow.reader.certificate,
        reader_subject_id: reader_subject(),
        target_transport_key_thumbprint: KeyThumbprint::try_from(fingerprint.as_slice()).unwrap(),
    };
    let encoded = context.encode();
    let sealed = hpke_seal(
        &HpkeRecipientPublicKey::from_bytes(request.target_transport_public_key).unwrap(),
        &SecretBytes::new(READER_KEM_SEED),
        &hpke_info(&encoded),
        &hpke_aad(&encoded),
    )
    .unwrap();
    let envelope = encode_reader_key_escrow_envelope(&ReaderKeyEscrowEnvelopeV1 {
        restore_context: context,
        encapsulated_key: *sealed.encapsulated_key(),
        sealed_reader_kem_key: *sealed.wrapped_cek(),
    })
    .unwrap();
    let opened = transport_open_status(handle, &envelope).unwrap();
    assert_eq!(
        field(&opened, "kemFingerprint").as_str().unwrap(),
        hex::encode(x25519_key(READER_KEM_SEED).thumbprint().as_bytes())
    );
    handle
}

fn bundle_fingerprint() -> Hash32 {
    Hash32::try_from([0x5b; 32].as_slice()).unwrap()
}

#[test]
fn the_abort_after_the_restored_enrollment_began_wipes_the_restored_kem() {
    let (escrow, escrow_hash) = line_with_escrow(reader_subject());
    let escrow_handle = restored_under_escrow_handle(&escrow, escrow_hash);
    let store = InMemoryReaderBlobStore::new();
    let enrollment = begin_restored_status(escrow_handle, &store, bundle_fingerprint()).unwrap();
    let enrollment = u32::try_from(field(&enrollment, "handle").as_u64().unwrap()).unwrap();

    // Vorher: der KEM liegt im Enrollment und zeigt sich am Gate.
    let shown = enrollment_fingerprints_status(enrollment).unwrap();
    assert_eq!(
        field(&shown, "keyFingerprint").as_str().unwrap(),
        hex::encode(x25519_key(READER_KEM_SEED).thumbprint().as_bytes())
    );

    // Die Oberfläche bricht mit der Kennung ab, die sie kennt: der
    // Escrow-Kennung.
    transport_abort(escrow_handle);

    // Nachher: unter keiner Kennung mehr erreichbar. `SecretBytes` nullt
    // beim Fallen des `ReaderEnrollment`.
    assert_eq!(
        enrollment_fingerprints_status(enrollment).err(),
        Some(ENROLLMENT_BRIDGE_ARGUMENT_CODE)
    );
    assert_eq!(
        begin_restored_status(escrow_handle, &store, bundle_fingerprint()).err(),
        Some(ENROLLMENT_BRIDGE_ARGUMENT_CODE)
    );
    // Idempotent.
    transport_abort(escrow_handle);
}

#[test]
fn the_abort_before_the_enrollment_wipes_the_restored_kem() {
    let (escrow, escrow_hash) = line_with_escrow(reader_subject());
    let escrow_handle = restored_under_escrow_handle(&escrow, escrow_hash);
    transport_abort(escrow_handle);
    assert_eq!(
        begin_restored_status(
            escrow_handle,
            &InMemoryReaderBlobStore::new(),
            bundle_fingerprint()
        )
        .err(),
        Some(ENROLLMENT_BRIDGE_ARGUMENT_CODE)
    );
}

#[test]
fn a_restored_enrollment_leaves_the_escrow_handle_useless_for_a_second_open_or_begin() {
    let (escrow, escrow_hash) = line_with_escrow(reader_subject());
    let escrow_handle = restored_under_escrow_handle(&escrow, escrow_hash);
    let store = InMemoryReaderBlobStore::new();
    let enrollment = begin_restored_status(escrow_handle, &store, bundle_fingerprint()).unwrap();
    let enrollment = u32::try_from(field(&enrollment, "handle").as_u64().unwrap()).unwrap();
    // Weder ein zweiter Import noch ein zweiter Enrollment-Beginn löst die
    // Verknüpfung — sonst liefe der Abbruch danach ins Leere.
    assert_eq!(
        transport_open_status(escrow_handle, &[0xa0]).err(),
        Some(ESCROW_BRIDGE_ARGUMENT_CODE)
    );
    assert_eq!(
        begin_restored_status(escrow_handle, &store, bundle_fingerprint()).err(),
        Some(ENROLLMENT_BRIDGE_ARGUMENT_CODE)
    );
    transport_abort(escrow_handle);
    assert_eq!(
        enrollment_fingerprints_status(enrollment).err(),
        Some(ENROLLMENT_BRIDGE_ARGUMENT_CODE)
    );
}
