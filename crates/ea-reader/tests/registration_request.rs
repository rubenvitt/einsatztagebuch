//! Der Registrierungsantrag des Browser-Readers (WEBREADER §6.6 Schritte 3–4,
//! Ruling Q2 der Scheibe e).
//!
//! Die Datei muss dieselben Prüfungen bestehen, die die native Admin-Inbox
//! (`crates/ea-admin/src/administration_runtime/inbox.rs`,
//! `verify_registration`) an einen `.registration.cbor` stellt: Dekodierung,
//! Rolle 1 mit KEM, Besitznachweis über den EXAKTEN Core — und der Dateiname
//! ist der Objekthash der Bytes, wie `inbox_directory.rs` ihn nachrechnet.
mod fixtures;

use ea_crypto::{CanonicalPublicCoseKey, object_hash};
use ea_reader::reader_registration_request;
use ea_sync_protocol::DeviceRegistrationRequestV1;

#[test]
fn the_registration_file_passes_the_admin_inbox_checks_and_carries_the_vault_keys() {
    let vault = fixtures::unlocked_vault();
    let file = reader_registration_request(&vault).unwrap();

    let request = DeviceRegistrationRequestV1::decode(file.exact_bytes()).unwrap();
    let core = request.core();
    assert!(core.organization_id == vault.pinned_anchor().organization_id());
    assert_eq!(core.requested_role, 1, "Rolle 1 ist Reader");
    let kem = core
        .kem_public_cose_key
        .clone()
        .expect("ein Reader trägt KEM");
    assert!(
        kem == CanonicalPublicCoseKey::x25519(*vault.kem_private_key().public_key().as_bytes())
            .unwrap()
    );
    assert!(kem.thumbprint() == vault.kem_key_thumbprint());
    assert!(file.kem_key_thumbprint() == vault.kem_key_thumbprint());
    let signing = vault.audit_signer().public_key().unwrap();
    assert!(core.signing_public_cose_key == signing);
    assert!(file.signing_key_thumbprint() == signing.thumbprint());
    assert_eq!(core.supported_format_versions, vec![1]);
    assert_eq!(
        core.supported_suite_ids,
        vec![ea_crypto::SUITE_ID.to_owned()]
    );

    // Der Besitznachweis über den exakten Core — Zeile für Zeile wie
    // `verify_registration`.
    let exact_core = ea_crypto::encode_device_registration_request_core(core).unwrap();
    let exact = file.exact_bytes();
    let mut decoder = minicbor::Decoder::new(exact);
    assert_eq!(decoder.array().unwrap(), Some(2));
    decoder.skip().unwrap();
    let start = decoder.position();
    decoder.skip().unwrap();
    ea_crypto::verify_enrollment_pop(
        &exact[start..decoder.position()],
        &core.signing_public_cose_key,
        &exact_core,
    )
    .unwrap();

    // Der Name ist eine Funktion der Bytes und sonst von nichts.
    assert_eq!(
        file.file_name(),
        format!(
            "{}.registration.cbor",
            hex::encode(object_hash(exact).as_bytes())
        )
    );
}

#[test]
fn every_request_draws_its_own_device_id() {
    let vault = fixtures::unlocked_vault();
    let first = reader_registration_request(&vault).unwrap();
    let second = reader_registration_request(&vault).unwrap();
    let first = DeviceRegistrationRequestV1::decode(first.exact_bytes()).unwrap();
    let second = DeviceRegistrationRequestV1::decode(second.exact_bytes()).unwrap();
    assert!(first.core().device_id != second.core().device_id);
    assert!(first.core().signing_public_cose_key == second.core().signing_public_cose_key);
}

#[test]
fn the_registration_file_carries_no_private_key_material() {
    let vault = fixtures::unlocked_vault();
    let file = reader_registration_request(&vault).unwrap();
    let kem_seed = fixtures::reader_kem_seed();
    let audit_seed = vault.audit_signing_key().with_exposed(|seed| *seed);
    // Positivkontrolle: die Suche findet einen Kanarienvogel, wo er liegt.
    assert!(ea_testkit::contains_canary(&kem_seed, &kem_seed));
    assert!(!ea_testkit::contains_canary(file.exact_bytes(), &kem_seed));
    assert!(!ea_testkit::contains_canary(
        file.exact_bytes(),
        &audit_seed
    ));
    assert!(!ea_testkit::contains_canary(
        file.file_name().as_bytes(),
        &kem_seed
    ));
}
