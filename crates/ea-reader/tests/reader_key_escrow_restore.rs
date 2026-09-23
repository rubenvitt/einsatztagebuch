//! Zeremonie B im Browser: flüchtiger Transport-Schlüssel, Transportanfrage
//! und einmaliges Öffnen des Umschlags (Profil §6 Schritte 1 und 6, §7).
mod escrow_line;
#[path = "../../ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../ea-trust/tests/support/mod.rs"]
mod support;

use ea_crypto::{
    CanonicalPublicCoseKey, HpkeRecipientPublicKey, SecretBytes, hpke_aad, hpke_info, hpke_seal,
};
use ea_format::{
    ReaderKeyEscrowEnvelopeV1, ReaderKeyEscrowRestoreContextV1, ReaderKeyEscrowTransferKindV1,
    decode_reader_key_escrow_transport_request, encode_reader_key_escrow_envelope,
    reader_key_escrow_transfer_file_name,
};
use ea_reader::{
    InMemoryReaderBlobStore, ReaderBlobKey, ReaderBlobStore, ReaderKeyEscrowTransportV1,
    TrustAnchorV1, decode_trust_anchor,
};
use ea_types::{CertificateHash, KeyThumbprint, ObjectHash, SubjectId, UnixMillis};
use escrow_line::LineSource;
use escrow_support::{
    EscrowLine, EscrowLineOptions, READER_KEM_SEED, SECOND_READER_KEM_SEED, approval_core,
    escrow_core, escrow_line, publish_escrow, push_revocation, subject, x25519_key,
};

const NOW: UnixMillis = UnixMillis::new(2_000);

fn reader_subject() -> SubjectId {
    subject(0xc1)
}

/// Eine Linie mit EINEM veröffentlichten, gültigen Escrow für den Reader.
fn line_with_escrow() -> (EscrowLine, ObjectHash) {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = escrow_core(
        &escrow,
        &escrow.reader,
        READER_KEM_SEED,
        reader_subject(),
        1_200,
    );
    let tip = *escrow.line.heads().last().unwrap();
    let approval = approval_core(
        &escrow.line,
        escrow_support::Basis::of(&tip, tip.effective_from.get()),
        (1_000, 1_300),
        0xe4,
    );
    let (_, escrow_hash) = publish_escrow(&mut escrow, &core, &approval);
    (escrow, escrow_hash)
}

fn anchor(escrow: &EscrowLine) -> TrustAnchorV1 {
    decode_trust_anchor(escrow.line.exact_anchor_bytes()).unwrap()
}

fn begin(escrow: &EscrowLine) -> ReaderKeyEscrowTransportV1 {
    ReaderKeyEscrowTransportV1::begin(
        &anchor(escrow),
        &LineSource::of(escrow),
        reader_subject(),
        NOW,
    )
    .unwrap()
}

/// Die Restore-Bindung, wie der native Öffnungsdienst sie aus einer
/// geprüften Autorisierung ableitet — hier mit festem Autorisierungshash.
fn restore_context(
    escrow: &EscrowLine,
    escrow_hash: ObjectHash,
    transport: &ReaderKeyEscrowTransportV1,
) -> ReaderKeyEscrowRestoreContextV1 {
    ReaderKeyEscrowRestoreContextV1 {
        organization_id: support::organization(),
        authorization_object_hash: support::object_hash_marker(0x7a),
        escrow_object_hash: escrow_hash,
        reader_certificate_object_hash: escrow.reader.certificate,
        reader_subject_id: reader_subject(),
        target_transport_key_thumbprint: transport.fingerprint(),
    }
}

/// Der Umschlag, versiegelt an den ÖFFENTLICHEN Schlüssel aus der
/// Transportdatei — genau das, was nativ ankommt.
fn envelope(
    transport: &ReaderKeyEscrowTransportV1,
    context: &ReaderKeyEscrowRestoreContextV1,
    reader_kem_seed: [u8; 32],
) -> Vec<u8> {
    let request = decode_reader_key_escrow_transport_request(
        transport.transport_request().unwrap().exact_bytes(),
    )
    .unwrap();
    let encoded = context.encode();
    let sealed = hpke_seal(
        &HpkeRecipientPublicKey::from_bytes(request.target_transport_public_key).unwrap(),
        &SecretBytes::new(reader_kem_seed),
        &hpke_info(&encoded),
        &hpke_aad(&encoded),
    )
    .unwrap();
    encode_reader_key_escrow_envelope(&ReaderKeyEscrowEnvelopeV1 {
        restore_context: context.clone(),
        encapsulated_key: *sealed.encapsulated_key(),
        sealed_reader_kem_key: *sealed.wrapped_cek(),
    })
    .unwrap()
}

fn open_code(
    escrow: &EscrowLine,
    escrow_hash: ObjectHash,
    deviate: impl FnOnce(&mut ReaderKeyEscrowRestoreContextV1),
) -> &'static str {
    let transport = begin(escrow);
    let mut context = restore_context(escrow, escrow_hash, &transport);
    deviate(&mut context);
    let bytes = envelope(&transport, &context, READER_KEM_SEED);
    match transport.open(&bytes) {
        Ok(_) => "OK",
        Err(error) => error.code(),
    }
}

#[test]
fn the_round_trip_restores_the_escrowed_kem() {
    let (escrow, escrow_hash) = line_with_escrow();
    let transport = begin(&escrow);
    assert!(transport.escrow_object_hash() == escrow_hash);
    assert!(transport.reader_certificate_object_hash() == escrow.reader.certificate);

    // Die Transportdatei trägt Organisation, Escrow und den öffentlichen
    // Schlüssel, dessen Abdruck angezeigt wird.
    let file = transport.transport_request().unwrap();
    let request = decode_reader_key_escrow_transport_request(file.exact_bytes()).unwrap();
    assert!(request.organization_id == support::organization());
    assert!(request.escrow_object_hash == escrow_hash);
    assert!(
        CanonicalPublicCoseKey::x25519(request.target_transport_public_key)
            .unwrap()
            .thumbprint()
            == transport.fingerprint()
    );
    assert_eq!(
        file.file_name(),
        reader_key_escrow_transfer_file_name(
            ReaderKeyEscrowTransferKindV1::TransportRequest,
            file.exact_bytes()
        )
    );

    let context = restore_context(&escrow, escrow_hash, &transport);
    let bytes = envelope(&transport, &context, READER_KEM_SEED);
    let restored = transport.open(&bytes).unwrap();
    assert!(restored.kem_key_thumbprint() == x25519_key(READER_KEM_SEED).thumbprint());
    assert!(restored.authorization_object_hash() == support::object_hash_marker(0x7a));
    // Organisation, Subject und Anker des neuen Tresors reisen mit dem KEM —
    // aus dem geprüften Transport, nicht aus einem zweiten Aufruf.
    assert!(restored.organization_id() == support::organization());
    assert!(restored.subject_id() == reader_subject());
    assert_eq!(
        restored.pinned_anchor_bytes(),
        escrow.line.exact_anchor_bytes()
    );
}

#[test]
fn every_transport_draws_its_own_key() {
    let (escrow, _) = line_with_escrow();
    assert!(begin(&escrow).fingerprint() != begin(&escrow).fingerprint());
}

#[test]
fn each_deviating_binding_field_is_refused() {
    let (escrow, escrow_hash) = line_with_escrow();
    let cases: [(&str, Deviation); 5] = [
        ("organization-id", |context| {
            context.organization_id =
                ea_types::OrganizationId::try_from([0x3f; 16].as_slice()).unwrap();
        }),
        ("escrow-object-hash", |context| {
            context.escrow_object_hash = support::object_hash_marker(0x3d);
        }),
        ("reader-certificate-object-hash", |context| {
            context.reader_certificate_object_hash =
                CertificateHash::try_from([0x3e; 32].as_slice()).unwrap();
        }),
        ("reader-subject-id", |context| {
            context.reader_subject_id = subject(0xc9);
        }),
        ("target-transport-key-thumbprint", |context| {
            context.target_transport_key_thumbprint =
                KeyThumbprint::try_from([0x3c; 32].as_slice()).unwrap();
        }),
    ];
    for (label, deviate) in cases {
        assert_eq!(
            open_code(&escrow, escrow_hash, deviate),
            "EA-READER-ESCROW-RESTORE-BINDING",
            "{label}"
        );
    }
    // Positivkontrolle.
    assert_eq!(open_code(&escrow, escrow_hash, |_| {}), "OK");
}

type Deviation = fn(&mut ReaderKeyEscrowRestoreContextV1);

/// Benannte Abweichung: der Autorisierungshash hat im Browser keine
/// Referenz. Ein fremder Wert wird angenommen, angezeigt und ist über die
/// AEAD gebunden — nicht mehr.
#[test]
fn a_foreign_authorization_hash_is_bound_only_through_the_aead_and_shown() {
    let (escrow, escrow_hash) = line_with_escrow();
    let transport = begin(&escrow);
    let mut context = restore_context(&escrow, escrow_hash, &transport);
    context.authorization_object_hash = support::object_hash_marker(0x44);
    let bytes = envelope(&transport, &context, READER_KEM_SEED);
    let restored = transport.open(&bytes).unwrap();
    assert!(restored.authorization_object_hash() == support::object_hash_marker(0x44));
}

#[test]
fn another_secret_under_the_right_context_is_a_kem_mismatch() {
    let (escrow, escrow_hash) = line_with_escrow();
    let transport = begin(&escrow);
    let context = restore_context(&escrow, escrow_hash, &transport);
    let bytes = envelope(&transport, &context, SECOND_READER_KEM_SEED);
    let refused = transport.open(&bytes);
    assert_eq!(
        refused.err().map(|error| error.code()),
        Some("EA-READER-ESCROW-KEM-MISMATCH")
    );
}

#[test]
fn a_broken_envelope_is_a_format_error_and_a_foreign_one_does_not_open() {
    let (escrow, escrow_hash) = line_with_escrow();
    let transport = begin(&escrow);
    let context = restore_context(&escrow, escrow_hash, &transport);
    let mut bytes = envelope(&transport, &context, READER_KEM_SEED);
    bytes.push(0);
    assert_eq!(
        transport.open(&bytes).err().map(|error| error.code()),
        Some("EA-CBOR-TRAILING")
    );

    // Versiegelt an einen ANDEREN Transport, aber mit dem Abdruck dieses.
    let transport = begin(&escrow);
    let other = begin(&escrow);
    let context = restore_context(&escrow, escrow_hash, &transport);
    let foreign = envelope(&other, &context, READER_KEM_SEED);
    assert_eq!(
        transport.open(&foreign).err().map(|error| error.code()),
        Some("EA-CRYPTO-HPKE-OPEN")
    );
}

#[test]
fn without_a_valid_escrow_for_the_subject_there_is_no_transport() {
    let (mut escrow, _) = line_with_escrow();
    let other = ReaderKeyEscrowTransportV1::begin(
        &anchor(&escrow),
        &LineSource::of(&escrow),
        subject(0xc8),
        NOW,
    );
    assert_eq!(
        other.err().map(|error| error.code()),
        Some("EA-READER-ESCROW-NOT-FOUND")
    );
    // U2: ein widerrufenes Reader-Zertifikat ist nicht zu öffnen.
    push_revocation(&mut escrow.line, escrow.reader.certificate);
    let revoked = ReaderKeyEscrowTransportV1::begin(
        &anchor(&escrow),
        &LineSource::of(&escrow),
        reader_subject(),
        NOW,
    );
    assert_eq!(
        revoked.err().map(|error| error.code()),
        Some("EA-READER-ESCROW-NOT-FOUND")
    );
}

/// Die Laufzeithälfte zur Signaturaussage „nie persistiert": die
/// Zeremonie nimmt keinen Speicher, und ein daneben liegender Speicher ist
/// über den ganzen Lauf bytegleich.
#[test]
fn the_ceremony_leaves_a_blob_store_untouched() {
    let (escrow, escrow_hash) = line_with_escrow();
    let mut store = InMemoryReaderBlobStore::new();
    let key = ReaderBlobKey::new("vault/reader-vault-v1").unwrap();
    store.put(&key, b"sealed-vault-placeholder").unwrap();
    let before = store.get(&key).unwrap();
    let transport = begin(&escrow);
    let context = restore_context(&escrow, escrow_hash, &transport);
    let bytes = envelope(&transport, &context, READER_KEM_SEED);
    transport.open(&bytes).unwrap();
    assert_eq!(store.get(&key).unwrap(), before);
    assert_eq!(store.keys().unwrap().len(), 1);
}
