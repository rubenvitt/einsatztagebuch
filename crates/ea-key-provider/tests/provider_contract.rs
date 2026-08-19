//! Der Vertrag des Schluesselports, gegen den deterministischen
//! In-Prozess-Provider gefahren.
//!
//! Alle Zusicherungen laufen gegen die stabilen Fehlercodes von
//! [`ea_key_provider::KeyError`] und niemals gegen eine Formatierung.

use std::sync::Arc;

use ea_crypto::{ContentType, SecretBytes, parse_cose_sign1};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_types::CertificateHash;

#[test]
fn deleted_secret_cannot_be_unwrapped_or_restored() {
    let provider = InMemoryKeyProvider::new_for_test([7; 32]);
    let handle = provider
        .wrap_secret(SecretPurpose::DraftDek, SecretBytes::<32>::new([3; 32]))
        .unwrap();
    provider.delete(&handle).unwrap();
    assert!(!provider.contains(&handle).unwrap());
    // Kein `unwrap_err()`: dessen Ok-Typ muss `Debug` sein, und `SecretBytes`
    // traegt bewusst keine Formatierung (`crates/ea-crypto/src/secret.rs`).
    let Err(error) = provider.unwrap_secret(&handle) else {
        panic!("ein geloeschtes Geheimnis darf sich nicht auspacken lassen");
    };
    assert_eq!(error.code(), "EA-KEY-NOT-FOUND");
}

#[test]
fn a_handle_never_serves_a_second_purpose() {
    let provider = InMemoryKeyProvider::new_for_test([11; 32]);
    let handle = provider
        .wrap_secret(SecretPurpose::DraftDek, SecretBytes::<32>::new([4; 32]))
        .unwrap();
    let Err(error) = provider.unwrap_database_key(&handle) else {
        panic!("ein draftDEK-Handle darf keinen Datenbankschluessel liefern");
    };
    assert_eq!(error.code(), "EA-KEY-PURPOSE-MISMATCH");
}

#[test]
fn an_in_memory_provider_never_pretends_to_reach_hardware() {
    let provider = InMemoryKeyProvider::new_for_test([13; 32]);
    let error = provider
        .generate(
            SecretPurpose::WriterSigningKey,
            KeyProtectionProfileV1::HardwareNonExportable,
        )
        .unwrap_err();
    assert_eq!(error.code(), "EA-KEY-PROTECTION-PROFILE-UNREACHABLE");
}

#[test]
fn every_stage_two_unreachable_protection_profile_is_refused() {
    let provider = InMemoryKeyProvider::new_for_test([17; 32]);
    for protection in [
        KeyProtectionProfileV1::OfflineEncryptedContainer,
        KeyProtectionProfileV1::Pkcs11,
        KeyProtectionProfileV1::ServerSecretStoreOrHsm,
    ] {
        let error = provider
            .generate(SecretPurpose::LocalDatabaseKey, protection)
            .unwrap_err();
        assert_eq!(error.code(), "EA-KEY-PROTECTION-PROFILE-UNSUPPORTED");
    }
}

#[test]
fn a_keystore_entry_of_this_product_never_roams_and_is_never_backed_up() {
    let provider = InMemoryKeyProvider::new_for_test([19; 32]);
    let handle = provider
        .generate(SecretPurpose::DraftDek, KeyProtectionProfileV1::OsWrapped)
        .unwrap();
    let policy = handle.entry_policy();
    assert!(!policy.is_roaming());
    assert!(!policy.is_cloud_synchronised());
    assert!(!policy.is_included_in_ordinary_backup());
}

#[test]
fn the_port_is_object_safe_and_shareable() {
    let provider: Arc<dyn KeyProvider> = Arc::new(InMemoryKeyProvider::new_for_test([23; 32]));
    let handle = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    assert!(provider.contains(&handle).unwrap());
}

#[test]
fn a_signature_is_a_parsable_cose_sign1_over_the_given_payload() {
    let certificate_hash = CertificateHash::try_from([0x5a; 32].as_slice()).unwrap();
    let payload = [0x21; 32];

    let provider = InMemoryKeyProvider::new_for_test([29; 32]);
    let handle = provider
        .generate(
            SecretPurpose::WriterSigningKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let signed = provider
        .sign(
            &handle,
            ContentType::RecordDigest,
            certificate_hash,
            &payload,
        )
        .unwrap();

    let parsed = parse_cose_sign1(signed.as_bytes(), &[]).unwrap();
    assert_eq!(parsed.content_type(), ContentType::RecordDigest);
    assert_eq!(
        parsed.certificate_hash().map(|hash| *hash.as_bytes()),
        Some(*certificate_hash.as_bytes())
    );
    assert_eq!(parsed.payload(), payload.as_slice());

    // Derselbe Startwert ergibt denselben Schluessel und damit dieselben Bytes.
    let twin = InMemoryKeyProvider::new_for_test([29; 32]);
    let twin_handle = twin
        .generate(
            SecretPurpose::WriterSigningKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let twin_signed = twin
        .sign(
            &twin_handle,
            ContentType::RecordDigest,
            certificate_hash,
            &payload,
        )
        .unwrap();
    assert_eq!(signed.as_bytes(), twin_signed.as_bytes());
}

#[test]
fn a_payload_that_does_not_match_its_content_type_never_becomes_a_signature() {
    // Der Port dupliziert die Nutzlastpruefung der Stufe 1 NICHT: er liest die
    // fertigen Bytes gegen `parse_cose_sign1` gegen, und die prueft den
    // vollstaendigen CBOR-Kern der sechs nicht-Digest-Inhaltstypen mit.
    let provider = InMemoryKeyProvider::new_for_test([37; 32]);
    let handle = provider
        .generate(
            SecretPurpose::OperatorInstanceKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let Err(error) = provider.sign(
        &handle,
        ContentType::LocalAuditCbor,
        CertificateHash::try_from([0x11; 32].as_slice()).unwrap(),
        b"kein local-audit-event-v1",
    ) else {
        panic!("eine Nutzlast ohne gueltigen CBOR-Kern darf nicht signiert werden");
    };
    assert_eq!(error.code(), "EA-CRYPTO-INVALID-PROTOCOL-CORE");
}

#[test]
fn only_a_signing_purpose_signs() {
    let provider = InMemoryKeyProvider::new_for_test([31; 32]);
    let handle = provider
        .generate(SecretPurpose::DraftDek, KeyProtectionProfileV1::OsWrapped)
        .unwrap();
    // Kein `unwrap_err()`: dessen Ok-Typ muss `Debug` sein, und
    // `CoseSign1Bytes` traegt bewusst keine Formatierung.
    let Err(error) = provider.sign(
        &handle,
        ContentType::RecordDigest,
        CertificateHash::try_from([0x11; 32].as_slice()).unwrap(),
        &[0x21; 32],
    ) else {
        panic!("ein draftDEK-Handle darf nicht signieren");
    };
    assert_eq!(error.code(), "EA-KEY-PURPOSE-MISMATCH");
}

#[test]
fn a_second_wrap_of_the_same_purpose_replaces_the_first() {
    // Ein Schluesselspeicher adressiert ueber Dienst und Konto, und dieses
    // Produkt haelt je Kontoinstanz genau einen Eintrag je Zweck — es gibt
    // genau einen aktiven Entwurf. Ein zweites Einpacken ERSETZT deshalb, statt
    // einen zweiten Eintrag anzulegen.
    let provider = InMemoryKeyProvider::new_for_test([41; 32]);
    let first = provider
        .wrap_secret(SecretPurpose::DraftDek, SecretBytes::<32>::new([1; 32]))
        .unwrap();
    let second = provider
        .wrap_secret(SecretPurpose::DraftDek, SecretBytes::<32>::new([2; 32]))
        .unwrap();
    assert_eq!(first, second);
    assert!(provider.unwrap_secret(&first).unwrap().matches(&[2; 32]));
}
