//! Runtime boundaries use the existing archive verifier and native identity ports.
#[path = "../../ea-recovery/tests/support/mod.rs"]
mod archives;
use archives::verify_support as support;
#[path = "../../ea-verify/tests/destruction_stub_support/mod.rs"]
mod stub_support;

use ea_admin::operator_runtime::{
    OperatorArchiveSnapshot, OperatorRuntimeConfig, OperatorRuntimeError,
    verify_local_signing_identity,
};
use ea_types::UnixMillis;
use serde_json::{Value, json};

fn config() -> Value {
    json!({
        "archive_directory": "archive", "database_path": "operator.sqlite",
        "device_certificate_hash": "11".repeat(32), "binding_object_hash": "22".repeat(32),
        "role": "writer", "purpose": "finalize"
    })
}

#[test]
fn public_config_accepts_only_the_closed_operator_fields() {
    let config = OperatorRuntimeConfig::from_json(&serde_json::to_vec(&config()).unwrap()).unwrap();
    assert!(!config.authority);
    assert!(config.ceremony_exchange_directory.is_none());
}

#[test]
fn config_rejects_identity_secrets_free_sequence_time_and_executable_overrides() {
    for field in [
        "display_name",
        "os_account",
        "expected_account",
        "instance_key",
        "key_seed",
        "helper",
        "sequence",
        "now",
        "trust_anchor",
    ] {
        let mut value = config();
        value[field] = json!("caller-selected-private-value");
        let error = OperatorRuntimeConfig::from_json(&serde_json::to_vec(&value).unwrap())
            .err()
            .unwrap();
        assert_eq!(error.code(), "EA-OPERATOR-CONFIG");
        assert!(!error.to_string().contains("caller-selected-private-value"));
    }
}

#[test]
fn invalid_hashes_roles_purposes_and_unpaired_admin_references_are_rejected() {
    for (field, value) in [
        ("device_certificate_hash", json!("00")),
        ("binding_object_hash", json!("zz".repeat(32))),
        ("role", json!("root")),
        ("purpose", json!("login-as")),
        ("authority", json!(true)),
        ("admin_certificate_hash", json!("33".repeat(32))),
    ] {
        let mut body = config();
        body[field] = value;
        assert!(
            OperatorRuntimeConfig::from_json(&serde_json::to_vec(&body).unwrap()).is_err(),
            "{field}"
        );
    }
    let duplicate = format!(
        "{{\"role\":\"writer\",{}",
        serde_json::to_string(&config())
            .unwrap()
            .trim_start_matches('{')
    );
    assert!(OperatorRuntimeConfig::from_json(duplicate.as_bytes()).is_err());
}

#[test]
fn offline_authority_and_exchange_require_explicit_public_configuration() {
    let mut value = config();
    value["role"] = json!("organization-admin");
    value["purpose"] = json!("admin-root-ceremony");
    value["authority"] = json!(true);
    value["target_certificate_hash"] = json!("55".repeat(32));
    value["ceremony_exchange_directory"] = json!("exchange");
    value["admin_certificate_hash"] = json!("33".repeat(32));
    value["admin_binding_object_hash"] = json!("44".repeat(32));
    let config = OperatorRuntimeConfig::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(config.authority);
    assert!(config.admin_certificate_hash.is_some());
}

/// DRK-458: die Öffnung eines Reader-Key-Escrows verlangt ihren EIGENEN
/// Wiederanmeldungszweck; die Konfiguration nennt ihn über sein Etikett.
#[test]
fn config_names_the_reader_key_escrow_recovery_purpose_by_its_label() {
    let mut value = config();
    value["role"] = json!("organization-admin");
    value["purpose"] = json!("reader-key-escrow-recovery");
    let config = OperatorRuntimeConfig::from_json(&serde_json::to_vec(&value).unwrap())
        .expect("der zwölfte Zweck ist ein bekanntes Etikett");
    assert_eq!(config.purpose.label(), "reader-key-escrow-recovery");
}

#[test]
fn offline_authority_must_pin_its_expected_requesting_device_independently() {
    let mut value = config();
    value["role"] = json!("organization-admin");
    value["authority"] = json!(true);
    assert!(OperatorRuntimeConfig::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    value["target_certificate_hash"] = json!("55".repeat(32));
    assert!(OperatorRuntimeConfig::from_json(&serde_json::to_vec(&value).unwrap()).is_ok());
}

#[test]
fn public_config_files_resolve_paths_beside_the_file_and_are_bounded() {
    let directory = archives::temp_dir("operator-runtime-config");
    let path = directory.path().join("public.json");
    let mut value = config();
    value["ceremony_exchange_directory"] = json!("exchange");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let config = OperatorRuntimeConfig::load(&path).unwrap();
    assert_eq!(config.archive_directory, directory.path().join("archive"));
    assert_eq!(
        config.database_path,
        directory.path().join("operator.sqlite")
    );
    assert_eq!(
        config.ceremony_exchange_directory.unwrap(),
        directory.path().join("exchange")
    );
    std::fs::write(&path, vec![b' '; 65_537]).unwrap();
    assert!(matches!(
        OperatorRuntimeConfig::load(&path),
        Err(OperatorRuntimeError::Config)
    ));
}

#[test]
fn native_signer_must_match_the_full_active_certificate_and_role() {
    use archives::verify_support::archive_support::trust_support::{
        self, ActionSpec, HeadOptions, RegistryLineBuilder,
    };
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(0),
            valid_through: Some(0),
            ..HeadOptions::default()
        },
    );
    let writer = line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: Some(1),
        },
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            ..HeadOptions::default()
        },
    );
    let certificate = ea_types::CertificateHash::from(writer.direct_object_hash.unwrap());
    let anchor = ea_trust::decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let now = UnixMillis::new(1_000);
    // Only this signature fixture uses an ephemeral store; the production
    // runtime and its process tests always open OperatorTrustStateStore.
    let mut store = ea_verify::EphemeralTrustStateStore::new(trust_support::state_key(), now);
    let head = loop {
        let trust = ea_trust::verify_trust(
            &anchor,
            &line.source(),
            ea_trust::load_trust_state(&mut store, trust_support::state_key()).unwrap(),
        )
        .unwrap();
        let candidate =
            ea_trust::verify_registry_candidate(&trust, ea_types::ChainSequence::new(1)).unwrap();
        let time = ea_trust::prepare_local_time(&mut store, &candidate, now, &[]).unwrap();
        match ea_trust::select_registry_head(candidate, time, None).unwrap() {
            ea_trust::RegistrySelectionOutcome::Selected(head) => break head,
            ea_trust::RegistrySelectionOutcome::Advanced(_) => {}
            _ => panic!("fixture head must be current"),
        }
    };
    let fields = head.active_certificate_fields(certificate).unwrap();
    let native_key = ea_crypto::CanonicalPublicCoseKey::from_deterministic_cbor(
        fields.signing_public_cose_key.as_ref().unwrap(),
    )
    .unwrap();
    assert!(
        verify_local_signing_identity(
            &head,
            certificate,
            ea_format::OperatorRoleV1::Writer,
            &native_key
        )
        .is_ok()
    );
    assert!(matches!(
        verify_local_signing_identity(
            &head,
            certificate,
            ea_format::OperatorRoleV1::Writer,
            &ea_crypto::CanonicalPublicCoseKey::ed25519(
                ed25519_dalek::SigningKey::from_bytes(&[0x79; 32])
                    .verifying_key()
                    .to_bytes()
            )
            .unwrap()
        ),
        Err(OperatorRuntimeError::SignerMismatch)
    ));
    assert!(matches!(
        verify_local_signing_identity(
            &head,
            certificate,
            ea_format::OperatorRoleV1::OrganizationAdmin,
            &native_key
        ),
        Err(OperatorRuntimeError::SignerMismatch)
    ));
    let unknown = ea_types::CertificateHash::try_from([0xee; 32].as_slice()).unwrap();
    assert!(
        verify_local_signing_identity(
            &head,
            unknown,
            ea_format::OperatorRoleV1::Writer,
            &native_key
        )
        .is_err()
    );
}

#[test]
fn next_sequence_comes_from_one_complete_verified_frozen_archive() {
    let directory = archives::temp_dir("operator-runtime-snapshot");
    let fixture = archives::verify_support::complete_valid_archive_with_two_entries();
    let archive = directory.path().join("archive");
    archives::materialize(&fixture.fixture, &archive);
    let anchor = directory.path().join("independent-anchor");
    std::fs::write(&anchor, &fixture.anchor_bytes).unwrap();
    let snapshot =
        OperatorArchiveSnapshot::open(&archive, &anchor, UnixMillis::new(1_000)).unwrap();
    assert_eq!(snapshot.next_sequence().get(), 2);
    let count = snapshot.inventory().entries().len();
    std::fs::remove_dir_all(&archive).unwrap();
    assert_eq!(snapshot.inventory().entries().len(), count);
    assert_eq!(snapshot.next_sequence().get(), 2);
    assert!(snapshot.report().is_fully_verified());
}

#[test]
fn historical_chain_progress_does_not_require_a_fresh_action_head() {
    let directory = archives::temp_dir("operator-runtime-bad-archive");
    let fixture = archives::verify_support::complete_valid_archive();
    let anchor = directory.path().join("anchor");
    std::fs::write(&anchor, &fixture.anchor_bytes).unwrap();
    let archive = directory.path().join("archive");
    archives::materialize(&fixture.fixture, &archive);
    let snapshot = OperatorArchiveSnapshot::open(&archive, &anchor, UnixMillis::new(100_000_000))
        .expect("historically authenticated sequence is independent of action freshness");
    assert_eq!(snapshot.next_sequence().get(), 1);
}

#[test]
fn unverified_truncated_or_empty_archives_cannot_supply_a_sequence() {
    let directory = archives::temp_dir("operator-runtime-incomplete-archive");
    let fixture = archives::verify_support::complete_valid_archive();
    let anchor = directory.path().join("anchor");
    std::fs::write(&anchor, &fixture.anchor_bytes).unwrap();
    let archive = directory.path().join("archive");
    archives::materialize(&fixture.fixture, &archive);
    std::fs::remove_dir_all(&archive).unwrap();
    std::fs::create_dir(&archive).unwrap();
    assert!(OperatorArchiveSnapshot::open(&archive, &anchor, UnixMillis::new(1_000)).is_err());
    let bad = archives::verify_support::archive_with_a_missing_middle_entry();
    archives::materialize(&bad.fixture, &archive);
    std::fs::write(&anchor, bad.anchor().exact_bytes()).unwrap();
    assert!(OperatorArchiveSnapshot::open(&archive, &anchor, UnixMillis::new(1_000)).is_err());
}

#[test]
fn recipientless_stub_can_supply_only_authenticated_public_chain_progress() {
    let directory = archives::temp_dir("operator-runtime-public-progress");
    for sequence in [1, 2] {
        let fixture = stub_support::fixture_at(true, true, sequence);
        let archive = directory.path().join(format!("archive-{sequence}"));
        archives::materialize(&fixture.source, &archive);
        let anchor = directory.path().join(format!("anchor-{sequence}"));
        std::fs::write(&anchor, fixture.original.anchor.exact_bytes()).unwrap();
        let result = OperatorArchiveSnapshot::open(&archive, &anchor, UnixMillis::new(800));
        if sequence == 1 {
            let snapshot = result.expect("authentic original manifests remain public progress");
            assert_eq!(snapshot.next_sequence().get(), 2);
            assert!(!snapshot.report().is_fully_verified());
            assert!(
                snapshot
                    .report()
                    .object_results()
                    .all(|item| { item.object_hash() != fixture.stub_hash }),
                "a public sequence does not authorize destruction completion"
            );
        } else {
            assert!(
                result.is_err(),
                "disconnected manifests supply no sequence authority"
            );
        }
    }
}

#[test]
fn an_anchor_inside_the_archive_is_not_an_independent_trust_anchor() {
    let directory = archives::temp_dir("operator-runtime-anchor");
    let fixture = archives::verify_support::complete_valid_archive();
    archives::materialize(&fixture.fixture, directory.path());
    let anchor = directory.path().join("copied-anchor.etb");
    std::fs::write(&anchor, &fixture.anchor_bytes).unwrap();
    assert!(matches!(
        OperatorArchiveSnapshot::open(directory.path(), &anchor, UnixMillis::new(1_000)),
        Err(OperatorRuntimeError::Config)
    ));
}
