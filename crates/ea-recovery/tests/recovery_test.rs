use ea_recovery::{KeyInventory, RecoveryKeyRole};
mod support;

mod recovery_fixture;
use recovery_fixture::recovery_payload;

#[test]
fn recovery_probe_opens_validates_and_preserves_the_exact_original_archive() {
    use ea_recovery::{FsArchiveSource, RecoveryArchiveProbe};
    use support::verify_support as fixture;
    let f = fixture::historical::fixture_with_payload(recovery_payload);
    let temp = support::temp_dir("t9-sample");
    support::materialize(&f.fixture, temp.path());
    let source = FsArchiveSource::open(temp.path()).unwrap();
    let probe =
        RecoveryArchiveProbe::verify(&source, &f.anchor, ea_types::UnixMillis::new(800)).unwrap();
    let grant = ea_crypto::object_hash(&f.original_bytes);
    let key = fixture::complete_recipient_private_key();
    let fields = match ea_format::decode_exact_object(&f.original_bytes).unwrap() {
        ea_format::ParsedArchiveObject::Grant(g) => g.value().grant_body().fields().clone(),
        _ => panic!(),
    };
    let inv=KeyInventory::parse(&serde_json::to_vec(&serde_json::json!({"schemaId":"ea.key-inventory/v1","inventoryId":"aa".repeat(16),"media":[{"mediumId":"recovery-a","keyRole":"recoveryRecipient","expectedKeyThumbprint":hex::encode(fields.recipient_key_thumbprint.as_bytes()),"certificateObjectHash":hex::encode(fields.recipient_certificate_hash.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"recoveryDecrypt"}]})).unwrap()).unwrap();
    let result = probe
        .test_recovery_medium(&inv.media()[0], f.entry_hash, grant, &key)
        .unwrap();
    assert!(result.full_archive_verified());
    assert_eq!(result.samples().len(), 1);
    assert_eq!(result.samples()[0].schema_id(), "ea.incident");
    assert_eq!(
        result.samples()[0].entry_hash().as_bytes(),
        f.entry_hash.as_bytes()
    );
    assert!(
        probe
            .test_recovery_medium(
                &inv.media()[0],
                f.entry_hash,
                grant,
                &fixture::other_recipient_private_key()
            )
            .is_err()
    );
    assert!(
        probe
            .test_recovery_medium(
                &inv.media()[0],
                f.entry_hash,
                ea_types::ObjectHash::from(ea_types::Hash32::ZERO),
                &key
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(temp.path().join("entries/000000000000_entry.eip")).unwrap(),
        f.entry_bytes
    );
    assert_eq!(
        std::fs::read(temp.path().join("grants/000000000000_original.eag")).unwrap(),
        f.original_bytes
    );
}

#[test]
fn aead_success_with_invalid_schema_or_operator_profile_does_not_pass_recovery() {
    use ea_recovery::{FsArchiveSource, RecoveryArchiveProbe};
    use support::verify_support as fixture;
    for payload in [
        |_: ea_types::RegistryVersion, _: ea_types::ObjectHash| {
            fixture::COMPLETE_PLAINTEXT_V1.to_vec()
        },
        |version, binding| {
            let mut bytes = recovery_payload(version, binding);
            let p = bytes
                .windows(b"Erika Beispiel".len())
                .position(|w| w == b"Erika Beispiel")
                .unwrap();
            bytes[p] = b'A';
            bytes
        },
    ] {
        let f = fixture::historical::fixture_with_payload(payload);
        let temp = support::temp_dir("t9-invalid-sample");
        support::materialize(&f.fixture, temp.path());
        let source = FsArchiveSource::open(temp.path()).unwrap();
        let probe =
            RecoveryArchiveProbe::verify(&source, &f.anchor, ea_types::UnixMillis::new(800))
                .unwrap();
        let fields = match ea_format::decode_exact_object(&f.original_bytes).unwrap() {
            ea_format::ParsedArchiveObject::Grant(g) => g.value().grant_body().fields().clone(),
            _ => panic!(),
        };
        let inv=KeyInventory::parse(&serde_json::to_vec(&serde_json::json!({"schemaId":"ea.key-inventory/v1","inventoryId":"aa".repeat(16),"media":[{"mediumId":"recovery-a","keyRole":"recoveryRecipient","expectedKeyThumbprint":hex::encode(fields.recipient_key_thumbprint.as_bytes()),"certificateObjectHash":hex::encode(fields.recipient_certificate_hash.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"recoveryDecrypt"}]})).unwrap()).unwrap();
        assert!(
            probe
                .test_recovery_medium(
                    &inv.media()[0],
                    f.entry_hash,
                    ea_crypto::object_hash(&f.original_bytes),
                    &fixture::complete_recipient_private_key()
                )
                .is_err()
        );
    }
}

#[test]
fn real_backup_challenges_are_fresh_bound_to_the_signed_certificate_and_never_productive() {
    use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, CryptoError, SecretBytes};
    use ea_recovery::{RecoverySigningBackup, verify_signing_backup};
    use support::verify_support::{self as fixture, archive_support::trust_support};
    let f = fixture::historical::fixture(fixture::COMPLETE_PLAINTEXT_V1);
    let head = f.selected(1, 800, 800);
    let cert = f.hga_certificate;
    let signing = trust_support::authorized_device_signer();
    let bytes=serde_json::to_vec(&serde_json::json!({"schemaId":"ea.key-inventory/v1","inventoryId":"aa".repeat(16),"media":[{
        "mediumId":"hga-1","keyRole":"historicalGrantAuthority","expectedKeyThumbprint":hex::encode(signing.public_key().unwrap().thumbprint().as_bytes()),"certificateObjectHash":hex::encode(cert.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"signatureChallenge"
    }]})).unwrap();
    let inventory = KeyInventory::parse(&bytes).unwrap();
    let medium = &inventory.media()[0];
    struct Recording {
        signer: CoseSigner,
        payloads: std::cell::RefCell<Vec<Vec<u8>>>,
    }
    impl RecoverySigningBackup for Recording {
        fn public_key(&self) -> Result<CanonicalPublicCoseKey, CryptoError> {
            self.signer.public_key()
        }
        fn sign_recovery_test(
            &self,
            cert: ea_types::CertificateHash,
            challenge: SecretBytes<32>,
        ) -> Result<Vec<u8>, CryptoError> {
            let bytes = self.signer.sign_recovery_test(cert, challenge)?;
            self.payloads
                .borrow_mut()
                .push(ea_crypto::parse_cose_sign1(&bytes, &[])?.payload().to_vec());
            Ok(bytes)
        }
    }
    let backup = Recording {
        signer: signing,
        payloads: Default::default(),
    };
    let one = verify_signing_backup(&head, medium, &backup).unwrap();
    let two = verify_signing_backup(&head, medium, &backup).unwrap();
    assert_eq!(
        one.key_thumbprint().as_bytes(),
        two.key_thumbprint().as_bytes()
    );
    assert_ne!(backup.payloads.borrow()[0], backup.payloads.borrow()[1]);
    let wrong = CoseSigner::from_secret(SecretBytes::new([0x77; 32]));
    assert!(verify_signing_backup(&head, medium, &wrong).is_err());
    struct ProductionSignature(CoseSigner);
    impl RecoverySigningBackup for ProductionSignature {
        fn public_key(&self) -> Result<CanonicalPublicCoseKey, CryptoError> {
            self.0.public_key()
        }
        fn sign_recovery_test(
            &self,
            cert: ea_types::CertificateHash,
            _: SecretBytes<32>,
        ) -> Result<Vec<u8>, CryptoError> {
            self.0.sign_root_trust_digest(cert, &[0; 32], None)
        }
    }
    assert!(
        verify_signing_backup(
            &head,
            medium,
            &ProductionSignature(trust_support::authorized_device_signer())
        )
        .is_err()
    );
    let mut mismatched: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    mismatched["media"][0]["keyRole"] = serde_json::json!("keyApprover");
    let inventory = KeyInventory::parse(&serde_json::to_vec(&mismatched).unwrap()).unwrap();
    assert!(verify_signing_backup(&head, &inventory.media()[0], &backup).is_err());
}

fn inventory(rows: &[(&str, &str)]) -> Vec<u8> {
    let media: Vec<_> = rows.iter().map(|(id, role)| serde_json::json!({
        "mediumId": id, "keyRole": role, "expectedKeyThumbprint": "11".repeat(32),
        "certificateObjectHash": "22".repeat(32), "protectionProfile": "offlineEncryptedContainer",
        "testKind": "signatureChallenge"
    })).collect();
    serde_json::to_vec(&serde_json::json!({"schemaId":"ea.key-inventory/v1","inventoryId":"aa".repeat(16),"media":media})).unwrap()
}

#[test]
fn inventory_parses_the_existing_nine_role_wire_without_private_source_fields() {
    let rows = [
        ("m01", "root"),
        ("m02", "organizationAdmin"),
        ("m03", "writer"),
        ("m04", "reader"),
        ("m05", "recoveryRecipient"),
        ("m06", "serverReceipt"),
        ("m07", "keyApprover"),
        ("m08", "historicalGrantAuthority"),
        ("m09", "deletionAttest"),
    ];
    let parsed = KeyInventory::parse(&inventory(&rows)).unwrap();
    assert_eq!(parsed.media().len(), 9);
    assert_eq!(parsed.media()[0].role(), RecoveryKeyRole::Root);
    assert_eq!(parsed.media()[8].role(), RecoveryKeyRole::DeletionAttest);
}

#[test]
fn inventory_rejects_ambiguous_duplicate_unsorted_and_unprofiled_inputs() {
    for rows in [
        vec![("m1", "root"), ("m1", "root")],
        vec![("m2", "root"), ("m1", "root")],
        vec![("m1", "unknownRole")],
    ] {
        assert!(KeyInventory::parse(&inventory(&rows)).is_err());
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(&inventory(&[("m1", "root")])).unwrap();
    value["media"][0]["privateKeyPath"] = serde_json::json!("/sensitive/key");
    assert!(KeyInventory::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    value["media"][0]
        .as_object_mut()
        .unwrap()
        .remove("privateKeyPath");
    value["media"][0]["expectedKeyThumbprint"] = serde_json::json!("AA".repeat(32));
    assert!(KeyInventory::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(KeyInventory::parse(br#"{"schemaId":"ea.key-inventory/v1","schemaId":"ea.key-inventory/v1","inventoryId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","media":[]}"#).is_err());
}

#[test]
fn retired_backup_possession_uses_signed_past_epoch_without_current_authority() {
    use ea_format::CertificateKindV1;
    use ea_recovery::{FsArchiveSource, RecoveryArchiveProbe};
    use ea_trust::TrustObjectSource;
    use ea_types::{CertificateHash, ChainSequence, UnixMillis};
    use support::verify_support::{
        self as fixture,
        archive_support::{ArchiveFixture, trust_support},
    };
    let mut f = fixture::historical::fixture_with_payload(recovery_payload);
    let options = |sequence| trust_support::HeadOptions {
        effective_from: Some(sequence),
        valid_through: Some(100),
        not_after: UnixMillis::new(10_000),
        ..Default::default()
    };
    let issued = f.line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::ServerReceipt,
            marker: 0x75,
            effective_from: Some(1),
        },
        options(1),
    );
    let cert = CertificateHash::from(issued.direct_object_hash.unwrap());
    f.head = f.line.push(
        trust_support::ActionSpec::Revoke {
            target_kind: 2,
            object_hash: issued.direct_object_hash.unwrap(),
        },
        options(2),
    );
    let current = f.selected(2, 800, 800);
    assert!(current.active_certificate_fields(cert).is_none());
    let mut archive = ArchiveFixture::new();
    let trust = f.line.source();
    trust
        .visit_trust_object_hashes(&mut |hash| {
            archive.push_exact_bytes(
                &format!("registry/{}.etb", hex::encode(hash.as_bytes())),
                trust.read_exact_trust_object(hash)?.unwrap().to_vec(),
            );
            Ok(())
        })
        .unwrap();
    archive.push_exact_bytes("entries/first.eip", f.entry_bytes);
    archive.push_exact_bytes("grants/first.eag", f.original_bytes);
    let temp = support::temp_dir("t9-retired-signing");
    support::materialize(&archive, temp.path());
    let source = FsArchiveSource::open_committed(temp.path()).unwrap();
    let probe = RecoveryArchiveProbe::verify(&source, &f.anchor, UnixMillis::new(800)).unwrap();
    let past = ea_verify::historical_registry_head(
        probe.inventory(),
        &f.anchor,
        issued.version,
        issued.object_hash,
        ChainSequence::new(1),
        UnixMillis::new(800),
    )
    .unwrap();
    let fields = past.active_certificate_fields(cert).unwrap();
    let inventory=KeyInventory::parse(&serde_json::to_vec(&serde_json::json!({"schemaId":"ea.key-inventory/v1","inventoryId":"aa".repeat(16),"media":[{"mediumId":"old-receipt","keyRole":"serverReceipt","expectedKeyThumbprint":hex::encode(fields.signing_key_thumbprint.unwrap().as_bytes()),"certificateObjectHash":hex::encode(cert.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"signatureChallenge"}]})).unwrap()).unwrap();
    let signer = trust_support::authorized_device_signer();
    assert!(ea_recovery::verify_signing_backup(&current, &inventory.media()[0], &signer).is_err());
    assert!(
        ea_recovery::verify_historical_signing_backup(&past, &inventory.media()[0], &signer)
            .is_ok()
    );
    assert!(
        ea_recovery::verify_historical_signing_backup(
            &past,
            &inventory.media()[0],
            &ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([79; 32]))
        )
        .is_err()
    );
}
