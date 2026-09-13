use ea_recovery::{
    RecoveryBackupKdf, RecoveryProbeBinding, RecoverySourceCore, RecoverySourceFields,
};
mod recovery_fixture;
mod support;

fn fields() -> RecoverySourceFields {
    RecoverySourceFields {
        source_id: [1; 16],
        organization_id: [2; 16],
        chain_id: [3; 16],
        anchor_hash: [4; 32],
        source_machine: [5; 32],
        source_installation: [6; 32],
        registry_version: 1,
        registry_head: [7; 32],
        proposed_sequence: 2,
        effective_now: 500,
        inventory_hash: [8; 32],
        archive_inventory_hash: [9; 32],
        tip_sequence: 1,
        tip_entry_hash: [10; 32],
        snapshot_hash: [11; 32],
        migrations_hash: [12; 32],
        kdf: RecoveryBackupKdf::fresh().unwrap(),
        probes: vec![RecoveryProbeBinding {
            medium_hash: [13; 32],
            certificate_hash: [14; 32],
            key_thumbprint: [15; 32],
            setup_entry_hash: [16; 32],
            initial_grant_hash: [17; 32],
        }],
    }
}

#[test]
fn signed_source_requires_exact_audit_scope_all_roles_and_existing_epochs() {
    signed_source_case(false, false, false, false, false);
}
#[test]
fn signed_source_and_complete_run_include_a_retired_signing_backup() {
    signed_source_case(true, false, false, false, false);
}
#[test]
fn signed_source_and_complete_run_cover_two_distinct_accepted_root_epochs() {
    signed_source_case(false, true, false, false, false);
}
#[test]
fn signed_source_and_complete_run_cover_two_distinct_recovery_kem_epochs() {
    signed_source_case(false, false, true, false, false);
}
#[test]
fn signed_source_and_complete_run_cover_distinct_writer_and_schema_epochs() {
    signed_source_case(false, false, true, true, false);
}
#[test]
#[cfg(all(feature = "pkcs11-fixture", unix))]
fn signed_source_and_complete_run_use_actual_nonexporting_token_signing_and_kem() {
    signed_source_case(false, false, false, false, true);
}
#[path = "source_manifest/epochs.rs"]
mod epochs;
#[path = "source_manifest/token.rs"]
mod token;
fn signed_source_case(
    retired: bool,
    rotated_root: bool,
    rotated_kem: bool,
    rotated_writer: bool,
    pkcs11: bool,
) {
    use ea_format::*;
    use ea_recovery::{
        FsArchiveSource, KeyInventory, RecoveryKeyRole, recovery_source_envelope,
        verify_recovery_source,
    };
    use ea_types::*;
    use support::verify_support::{
        self as fixture,
        archive_support::{ArchiveFixture, trust_support},
    };
    let mut writer_binding = None;
    let mut f = fixture::historical::fixture_with_payload(|version, binding| {
        writer_binding = Some(binding);
        recovery_fixture::recovery_payload(version, binding)
    });
    let replacement_signer =
        ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x87; 32]));
    let retired_medium = if retired {
        let before = f.selected(1, 800, 800);
        let (hash, fields) = before
            .active_certificates()
            .find(|(_, c)| c.certificate_kind == CertificateKindV1::ServerReceipt)
            .unwrap();
        let fields = fields.clone();
        let opts = || trust_support::HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            not_after: UnixMillis::new(10_000),
            ..Default::default()
        };
        f.line.push(
            trust_support::ActionSpec::Revoke {
                target_kind: 2,
                object_hash: ObjectHash::try_from(hash.as_bytes().as_slice()).unwrap(),
            },
            opts(),
        );
        f.line.push(
            trust_support::ActionSpec::Device {
                kind: CertificateKindV1::ServerReceipt,
                marker: 0x76,
                effective_from: Some(1),
            },
            trust_support::HeadOptions {
                signing_public_key_override: Some(replacement_signer.public_key().unwrap()),
                ..opts()
            },
        );
        assert!(
            fields.signing_key_thumbprint.unwrap()
                != replacement_signer.public_key().unwrap().thumbprint()
        );
        Some((hash, fields))
    } else {
        None
    };
    f.head = f.line.push(
        trust_support::ActionSpec::Device {
            kind: CertificateKindV1::DeletionAttest,
            marker: 0x73,
            effective_from: Some(1),
        },
        trust_support::HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            not_after: UnixMillis::new(10_000),
            ..Default::default()
        },
    );
    if rotated_root {
        f.head = f.line.push(
            trust_support::ActionSpec::RootRotate {
                previous_root_hash: None,
                effective_version: None,
            },
            trust_support::HeadOptions {
                effective_from: Some(1),
                valid_through: Some(100),
                not_after: UnixMillis::new(10_000),
                ..Default::default()
            },
        );
    }
    let epoch = rotated_kem
        .then(|| epochs::append_kem_epoch(&mut f, writer_binding.unwrap(), rotated_writer, None));
    let sequence = if rotated_kem { 2 } else { 1 };
    let head = f.selected(sequence, 800, 800);
    let mut archive = ArchiveFixture::new();
    use ea_trust::TrustObjectSource;
    let trust = f.line.source();
    trust
        .visit_trust_object_hashes(&mut |hash| {
            archive.push_exact_bytes(
                &format!("registry/events/{}.etb", hex::encode(hash.as_bytes())),
                trust.read_exact_trust_object(hash)?.unwrap().to_vec(),
            );
            Ok(())
        })
        .unwrap();
    archive.push_exact_bytes("entries/000000000000_entry.eip", f.entry_bytes.clone());
    archive.push_exact_bytes("grants/000000000000_original.eag", f.original_bytes.clone());
    if let Some(epoch) = &epoch {
        archive.push_exact_bytes("entries/000000000001_epoch.eip", epoch.entry_bytes.clone());
        archive.push_exact_bytes("grants/000000000001_epoch.eag", epoch.grant_bytes.clone());
    }
    let temp = support::temp_dir("source-manifest-signed");
    support::materialize(&archive, temp.path());
    let source = FsArchiveSource::open_committed(temp.path()).unwrap();
    let mut rows = Vec::new();
    for (hash, c) in head.active_certificates() {
        let role = match c.certificate_kind {
            CertificateKindV1::Writer => "writer",
            CertificateKindV1::Reader => "reader",
            CertificateKindV1::OrganizationAdmin => "organizationAdmin",
            CertificateKindV1::KeyApprover => "keyApprover",
            CertificateKindV1::RecoveryRecipient => "recoveryRecipient",
            CertificateKindV1::HistoricalGrantAuthority => "historicalGrantAuthority",
            CertificateKindV1::ServerReceipt => "serverReceipt",
            CertificateKindV1::DeletionAttest => "deletionAttest",
        };
        let recovery = c.certificate_kind == CertificateKindV1::RecoveryRecipient;
        rows.push(serde_json::json!({"mediumId":hex::encode(hash.as_bytes()),"keyRole":role,"expectedKeyThumbprint":hex::encode(if recovery {c.kem_key_thumbprint.unwrap()}else{c.signing_key_thumbprint.unwrap()}.as_bytes()),"certificateObjectHash":hex::encode(hash.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":if recovery {"recoveryDecrypt"}else{"signatureChallenge"}}));
    }
    if let Some((hash, fields)) = retired_medium {
        assert!(head.active_certificate_fields(hash).is_none());
        rows.push(serde_json::json!({"mediumId":"retired-receipt","keyRole":"serverReceipt","expectedKeyThumbprint":hex::encode(fields.signing_key_thumbprint.unwrap().as_bytes()),"certificateObjectHash":hex::encode(hash.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"signatureChallenge"}));
    }
    if let Some(epoch) = &epoch {
        rows.push(serde_json::json!({"mediumId":"old-recovery-epoch","keyRole":"recoveryRecipient","expectedKeyThumbprint":hex::encode(fixture::complete_recipient_key_thumbprint().as_bytes()),"certificateObjectHash":hex::encode(epoch.old_certificate.as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"recoveryDecrypt"}));
    }
    rows.push(serde_json::json!({"mediumId":"root","keyRole":"root","expectedKeyThumbprint":hex::encode(f.anchor.root_key_thumbprint().as_bytes()),"certificateObjectHash":hex::encode(f.anchor.root_certificate_object_hash().as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"signatureChallenge"}));
    if rotated_root {
        assert!(
            head.root_certificate_fields().root_key_thumbprint != f.anchor.root_key_thumbprint()
        );
        rows.push(serde_json::json!({"mediumId":"root-current","keyRole":"root","expectedKeyThumbprint":hex::encode(head.root_certificate_fields().root_key_thumbprint.as_bytes()),"certificateObjectHash":hex::encode(head.root_certificate_object_hash().as_bytes()),"protectionProfile":"offlineEncryptedContainer","testKind":"signatureChallenge"}));
    }
    let token = pkcs11.then(|| token::TokenMedia::open(temp.path()));
    if let Some(token) = &token {
        for row in &mut rows {
            if row["expectedKeyThumbprint"] == token.signing_thumbprint() {
                row["protectionProfile"] = serde_json::json!("pkcs11");
                row["testKind"] = serde_json::json!("providerPresence");
            }
            if row["keyRole"] == "recoveryRecipient" {
                row["protectionProfile"] = serde_json::json!("pkcs11");
            }
        }
    }
    rows.sort_by(|a, b| a["mediumId"].as_str().cmp(&b["mediumId"].as_str()));
    let inventory_bytes = |rows: &Vec<serde_json::Value>| {
        serde_json::to_vec(&serde_json::json!({"schemaId":"ea.key-inventory/v1","inventoryId":"aa".repeat(16),"media":rows})).unwrap()
    };
    let keys = KeyInventory::parse(&inventory_bytes(&rows)).unwrap();
    let make_core = |keys: &KeyInventory| {
        let mut value = fields();
        value.organization_id = *f.anchor.organization_id().as_bytes();
        value.chain_id = *f.anchor.chain_id().as_bytes();
        value.anchor_hash = *f.anchor.trust_anchor_hash().as_bytes();
        value.registry_version = head.registry_version().get();
        value.registry_head = *head.registry_head_hash().as_bytes();
        value.proposed_sequence = sequence;
        value.effective_now = 800;
        value.inventory_hash = *keys.exact_hash().as_bytes();
        value.archive_inventory_hash =
            ea_recovery::recovery_archive_inventory_hash(&source).unwrap();
        value.tip_sequence = sequence - 1;
        value.tip_entry_hash = *epoch
            .as_ref()
            .map_or(f.entry_hash, |epoch| epoch.entry_hash)
            .as_bytes();
        value.probes = keys
            .media()
            .iter()
            .filter(|m| m.role() == RecoveryKeyRole::RecoveryRecipient)
            .map(|m| RecoveryProbeBinding {
                medium_hash: *m.pseudonymous_id_hash().as_bytes(),
                certificate_hash: *m.certificate().as_bytes(),
                key_thumbprint: *m.expected_thumbprint().as_bytes(),
                setup_entry_hash: *epoch
                    .as_ref()
                    .filter(|epoch| m.certificate() == epoch.new_certificate)
                    .map_or(f.entry_hash, |epoch| epoch.entry_hash)
                    .as_bytes(),
                initial_grant_hash: *ea_crypto::object_hash(
                    epoch
                        .as_ref()
                        .filter(|epoch| m.certificate() == epoch.new_certificate)
                        .map_or(f.original_bytes.as_slice(), |epoch| {
                            epoch.grant_bytes.as_slice()
                        }),
                )
                .as_bytes(),
            })
            .collect();
        value.probes.sort_by_key(|p| p.medium_hash);
        RecoverySourceCore::new(value).unwrap()
    };
    let signed = |core: &RecoverySourceCore, outcome| {
        let cert = CertificateHash::from(f.line.second_bootstrap_admin_hash());
        let fields = LocalAuditEventCoreFieldsV1 {
            event_id: EventId::try_from([0x61; 16].as_slice()).unwrap(),
            organization_id: f.anchor.organization_id(),
            device_id: head.active_certificate_fields(cert).unwrap().device_id,
            operator_binding_object_hash: Some(f.operator_binding),
            signer_certificate_object_hash: f.line.second_bootstrap_admin_hash(),
            action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                ObjectHash::from(core.context_hash()),
            ))),
            outcome,
            effective_now: UnixMillis::new(800),
            nonce: [0x62; 32],
        };
        let exact = encode_local_audit_core(&fields).unwrap();
        let signature = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
            trust_support::second_admin_signing_secret(),
        ))
        .sign_local_audit(&exact)
        .unwrap();
        recovery_source_envelope(core, &encode_local_audit_event(&exact, &signature).unwrap())
            .unwrap()
    };
    let core = make_core(&keys);
    let envelope = signed(&core, LocalAuditOutcomeV1::Accepted);
    let verified =
        verify_recovery_source(&envelope, &source, &f.anchor, &keys, UnixMillis::new(800)).unwrap();
    assert_eq!(verified.exact_envelope(), envelope);
    if rotated_root {
        for missing in ["root", "root-current"] {
            let subset = rows
                .iter()
                .filter(|row| row["mediumId"] != missing)
                .cloned()
                .collect::<Vec<_>>();
            let subset = KeyInventory::parse(&inventory_bytes(&subset)).unwrap();
            let exact = signed(&make_core(&subset), LocalAuditOutcomeV1::Accepted);
            assert!(
                matches!(
                    verify_recovery_source(
                        &exact,
                        &source,
                        &f.anchor,
                        &subset,
                        UnixMillis::new(800)
                    ),
                    Err(ea_recovery::RecoveryTestError::Incomplete)
                ),
                "missing accepted Root epoch must be incomplete"
            );
        }
    }
    if let Some(epoch) = &epoch {
        for missing in [epoch.old_certificate, epoch.new_certificate] {
            let subset = rows
                .iter()
                .filter(|row| row["certificateObjectHash"] != hex::encode(missing.as_bytes()))
                .cloned()
                .collect::<Vec<_>>();
            let subset = KeyInventory::parse(&inventory_bytes(&subset)).unwrap();
            let exact = signed(&make_core(&subset), LocalAuditOutcomeV1::Accepted);
            assert!(
                matches!(
                    verify_recovery_source(
                        &exact,
                        &source,
                        &f.anchor,
                        &subset,
                        UnixMillis::new(800)
                    ),
                    Err(ea_recovery::RecoveryTestError::Incomplete)
                ),
                "a missing existing KEM epoch must remain incomplete"
            );
        }
    }
    let new_run = || {
        ea_recovery::RecoveryTestRun::new(
            &verified,
            &source,
            &f.anchor,
            &keys,
            &head,
            Hash32::try_from([91; 32].as_slice()).unwrap(),
        )
        .unwrap()
    };
    assert!(new_run().finish().is_err());
    let missing = new_run().finish_failed().unwrap();
    let failed_json: serde_json::Value = serde_json::from_slice(missing.exact_report()).unwrap();
    assert_eq!(failed_json["result"], "failed");
    assert_eq!(
        failed_json["media"].as_array().unwrap().len(),
        keys.media().len()
    );
    assert!(
        failed_json["media"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["result"] == "missing")
    );
    let failure_core =
        ea_recovery::RecoveryFailureCore::new(&missing, [93; 32], UnixMillis::new(800)).unwrap();
    let signed_failure = |failure_core: &ea_recovery::RecoveryFailureCore, outcome| {
        let cert = CertificateHash::from(f.line.second_bootstrap_admin_hash());
        let exact = encode_local_audit_core(&LocalAuditEventCoreFieldsV1 {
            event_id: EventId::try_from(&[0x65; 16][..]).unwrap(),
            organization_id: f.anchor.organization_id(),
            device_id: head.active_certificate_fields(cert).unwrap().device_id,
            operator_binding_object_hash: Some(f.operator_binding),
            signer_certificate_object_hash: f.line.second_bootstrap_admin_hash(),
            action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                ObjectHash::from(failure_core.context_hash()),
            ))),
            outcome,
            effective_now: UnixMillis::new(800),
            nonce: [0x66; 32],
        })
        .unwrap();
        let signature = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
            trust_support::second_admin_signing_secret(),
        ))
        .sign_local_audit(&exact)
        .unwrap();
        ea_recovery::recovery_failure_envelope(
            &failure_core,
            &encode_local_audit_event(&exact, &signature).unwrap(),
        )
        .unwrap()
    };
    let exact_failure = signed_failure(&failure_core, LocalAuditOutcomeV1::Failed);
    let checked_failure = ea_recovery::verify_failed_recovery_report(
        &exact_failure,
        &verified,
        &source,
        &f.anchor,
        &keys,
        UnixMillis::new(800),
    )
    .unwrap();
    assert_eq!(checked_failure.exact_envelope(), exact_failure);
    assert_eq!(checked_failure.public_report(), missing.exact_report());
    assert!(
        ea_recovery::verify_completed_recovery_report(
            &exact_failure,
            &verified,
            &source,
            &f.anchor,
            &keys,
            UnixMillis::new(800)
        )
        .is_err()
    );
    assert!(
        ea_recovery::verify_failed_recovery_report(
            &signed_failure(&failure_core, LocalAuditOutcomeV1::Completed),
            &verified,
            &source,
            &f.anchor,
            &keys,
            UnixMillis::new(800)
        )
        .is_err()
    );
    let mut changed = exact_failure.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(
        ea_recovery::verify_failed_recovery_report(
            &changed,
            &verified,
            &source,
            &f.anchor,
            &keys,
            UnixMillis::new(800)
        )
        .is_err()
    );
    let mut run = new_run();
    let mut failed_run = new_run();
    let root_medium = keys
        .media()
        .iter()
        .find(|m| m.role() == RecoveryKeyRole::Root)
        .unwrap();
    assert!(
        failed_run
            .test_signing(
                root_medium.pseudonymous_id_hash(),
                &trust_support::authorized_device_signer()
            )
            .is_err()
    );
    let first_admin: [u8; 32] =
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .unwrap()
            .try_into()
            .unwrap();
    let mut secrets = vec![
        trust_support::root_signing_secret(),
        trust_support::device_signing_secret(),
        trust_support::second_admin_signing_secret(),
        first_admin,
    ];
    if rotated_root {
        // Existing published test vector used by trust_support's RootRotate.
        secrets.push(
            hex::decode("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5")
                .unwrap()
                .try_into()
                .unwrap(),
        );
    }
    if retired {
        secrets.push([0x87; 32]);
    }
    if rotated_writer {
        secrets.push([0x88; 32]);
    }
    let signers = secrets
        .into_iter()
        .map(|secret| ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(secret)))
        .collect::<Vec<_>>();
    for medium in keys.media() {
        if medium.role() == RecoveryKeyRole::RecoveryRecipient {
            let key = if epoch
                .as_ref()
                .is_some_and(|epoch| epoch.new_certificate == medium.certificate())
            {
                fixture::other_recipient_private_key()
            } else {
                fixture::complete_recipient_private_key()
            };
            let key: &dyn ea_crypto::HpkeRecipient = token
                .as_ref()
                .map_or(&key as &dyn ea_crypto::HpkeRecipient, |token| {
                    &token.recovery
                });
            run.test_recovery(medium.pseudonymous_id_hash(), key)
                .unwrap();
            failed_run
                .test_recovery(medium.pseudonymous_id_hash(), key)
                .unwrap();
        } else {
            let signer = signers
                .iter()
                .find(|signer| {
                    signer.public_key().unwrap().thumbprint() == medium.expected_thumbprint()
                })
                .unwrap();
            let signer: &dyn ea_recovery::RecoverySigningBackup = token
                .as_ref()
                .filter(|token| {
                    token.signing.public_key().unwrap().thumbprint() == medium.expected_thumbprint()
                })
                .map_or(signer as &dyn ea_recovery::RecoverySigningBackup, |token| {
                    &token.signing
                });
            run.test_signing(medium.pseudonymous_id_hash(), signer)
                .unwrap();
            failed_run
                .test_signing(medium.pseudonymous_id_hash(), signer)
                .unwrap();
        }
    }
    let ea_recovery::RecoveryRunOutcome::Failed(failed) = failed_run.finish_report().unwrap()
    else {
        panic!("a failed key test cannot be erased by retrying with a good key");
    };
    let failed_json: serde_json::Value = serde_json::from_slice(failed.exact_report()).unwrap();
    assert_eq!(
        failed_json["errorCode"],
        ea_recovery::RecoveryTestError::Incomplete.code()
    );
    assert_eq!(
        failed_json["media"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["result"] == "failed")
            .count(),
        1
    );
    let wrong = failed_json["media"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["result"] == "failed")
        .unwrap();
    assert_eq!(
        wrong["mediumIdHash"],
        hex::encode(root_medium.pseudonymous_id_hash().as_bytes())
    );
    assert_eq!(
        wrong["errorCode"],
        ea_recovery::RecoveryTestError::Key.code()
    );
    assert_ne!(wrong["observedThumbprint"], wrong["expectedThumbprint"]);
    let failed_core =
        ea_recovery::RecoveryFailureCore::new(&failed, [93; 32], UnixMillis::new(800)).unwrap();
    let checked = ea_recovery::verify_failed_recovery_report(
        &signed_failure(&failed_core, LocalAuditOutcomeV1::Failed),
        &verified,
        &source,
        &f.anchor,
        &keys,
        UnixMillis::new(800),
    )
    .unwrap();
    assert_eq!(checked.public_report(), failed.exact_report());
    let ea_recovery::RecoveryRunOutcome::Completed(complete) = run.finish_report().unwrap() else {
        panic!("every actual medium and sample was complete");
    };
    let report: serde_json::Value = serde_json::from_slice(complete.exact_report()).unwrap();
    assert_eq!(report["schemaId"], "ea.recovery-test/v1");
    assert!(report.get("errorCode").is_none());
    assert_eq!(
        report["media"].as_array().unwrap().len(),
        keys.media().len()
    );
    assert_eq!(
        report["samples"].as_array().unwrap().len(),
        if rotated_kem { 2 } else { 1 }
    );
    if rotated_writer {
        let samples = report["samples"].as_array().unwrap();
        assert_ne!(
            samples[0]["writerCertificateHash"],
            samples[1]["writerCertificateHash"]
        );
        assert_ne!(samples[0]["schemaId"], samples[1]["schemaId"]);
    }
    let text = String::from_utf8(complete.exact_report().to_vec()).unwrap();
    assert!(!text.contains("Erika Beispiel"));
    assert!(!text.contains("T9 private"));
    assert!(!text.contains(&hex::encode(first_admin)));
    let completion = ea_recovery::RecoveryCompletionCore::new(
        &complete,
        [93; 32],
        UnixMillis::new(800),
        UnixMillis::new(800 + head.policy_fields().restore_test_interval_ms as i64),
    )
    .unwrap();
    let completion_audit = |outcome| {
        let exact = encode_local_audit_core(&LocalAuditEventCoreFieldsV1 {
            event_id: EventId::try_from(&[94; 16][..]).unwrap(),
            organization_id: f.anchor.organization_id(),
            device_id: head
                .active_certificate_fields(CertificateHash::from(
                    f.line.second_bootstrap_admin_hash(),
                ))
                .unwrap()
                .device_id,
            operator_binding_object_hash: Some(f.operator_binding),
            signer_certificate_object_hash: f.line.second_bootstrap_admin_hash(),
            action: LocalAuditActionV1::RecoveryTest(GenericAuditContextV1::new(Some(
                ObjectHash::from(completion.context_hash()),
            ))),
            outcome,
            effective_now: UnixMillis::new(800),
            nonce: [95; 32],
        })
        .unwrap();
        let cose = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
            trust_support::second_admin_signing_secret(),
        ))
        .sign_local_audit(&exact)
        .unwrap();
        ea_recovery::recovery_completion_envelope(
            &completion,
            &encode_local_audit_event(&exact, &cose).unwrap(),
        )
        .unwrap()
    };
    let exact_completion = completion_audit(LocalAuditOutcomeV1::Completed);
    let checked = ea_recovery::verify_completed_recovery_report(
        &exact_completion,
        &verified,
        &source,
        &f.anchor,
        &keys,
        UnixMillis::new(800),
    )
    .unwrap();
    assert_eq!(checked.restored_content_hash(), &[93; 32]);
    assert_eq!(checked.exact_envelope(), exact_completion);
    assert!(
        ea_recovery::verify_completed_recovery_report(
            &completion_audit(LocalAuditOutcomeV1::Accepted),
            &verified,
            &source,
            &f.anchor,
            &keys,
            UnixMillis::new(800)
        )
        .is_err()
    );
    for needle in [&[93; 32][..], complete.exact_report()] {
        let mut changed = exact_completion.clone();
        let at = changed
            .windows(needle.len())
            .position(|b| b == needle)
            .unwrap();
        changed[at] ^= 1;
        assert!(
            ea_recovery::verify_completed_recovery_report(
                &changed,
                &verified,
                &source,
                &f.anchor,
                &keys,
                UnixMillis::new(800)
            )
            .is_err()
        );
    }

    assert!(
        verify_recovery_source(
            &signed(&core, LocalAuditOutcomeV1::Completed),
            &source,
            &f.anchor,
            &keys,
            UnixMillis::new(800)
        )
        .is_err()
    );
    let mut tampered = envelope.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        verify_recovery_source(&tampered, &source, &f.anchor, &keys, UnixMillis::new(800)).is_err()
    );
    for needle in [
        core.fields().snapshot_hash,
        core.fields().source_machine,
        core.fields().probes[0].initial_grant_hash,
    ] {
        let mut changed = envelope.clone();
        let index = changed.windows(32).position(|w| w == needle).unwrap();
        changed[index] ^= 1;
        assert!(
            verify_recovery_source(&changed, &source, &f.anchor, &keys, UnixMillis::new(800))
                .is_err()
        );
    }
    rows.retain(|r| r["keyRole"] != "deletionAttest");
    let missing = KeyInventory::parse(&inventory_bytes(&rows)).unwrap();
    let missing_core = make_core(&missing);
    assert!(
        verify_recovery_source(
            &signed(&missing_core, LocalAuditOutcomeV1::Accepted),
            &source,
            &f.anchor,
            &missing,
            UnixMillis::new(800)
        )
        .is_err()
    );
    assert!(
        verify_recovery_source(
            &envelope,
            &source,
            &f.anchor,
            &missing,
            UnixMillis::new(800)
        )
        .is_err()
    );
}
#[test]
fn exact_source_core_binds_all_public_source_and_epoch_inputs() {
    let core = RecoverySourceCore::new(fields()).unwrap();
    let decoded = RecoverySourceCore::from_exact(core.exact_bytes()).unwrap();
    assert!(core.context_hash() == decoded.context_hash());
    assert_eq!(decoded.fields().probes[0].initial_grant_hash, [17; 32]);
    let mut changed = core.exact_bytes().to_vec();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(
        RecoverySourceCore::from_exact(&changed)
            .unwrap()
            .context_hash()
            != core.context_hash()
    );
    changed.push(0);
    assert!(RecoverySourceCore::from_exact(&changed).is_err());
    let mut duplicate = fields();
    duplicate.probes.push(duplicate.probes[0].clone());
    assert!(RecoverySourceCore::new(duplicate).is_err());
    let mut incomplete = fields();
    incomplete.probes.clear();
    assert!(RecoverySourceCore::new(incomplete).is_err());
    let mut invalid = fields();
    invalid.proposed_sequence = invalid.tip_sequence;
    assert!(RecoverySourceCore::new(invalid).is_err());
    let mut gap = fields();
    gap.proposed_sequence = gap.tip_sequence + 2;
    assert!(
        RecoverySourceCore::new(gap).is_err(),
        "a signed source cannot invent an unobserved next sequence"
    );
    let mut invalid = core.exact_bytes().to_vec();
    invalid[0] = 0x94;
    assert!(RecoverySourceCore::from_exact(&invalid).is_err());
}

#[test]
fn source_scope_preserves_staging_while_public_verification_keeps_the_committed_tip() {
    let f = support::verify_support::historical::fixture_with_payload(
        recovery_fixture::recovery_payload,
    );
    let temp = support::temp_dir("source-scope-staging");
    support::materialize(&f.fixture, temp.path());
    let before = ea_recovery::FsArchiveSource::open(temp.path()).unwrap();
    let original_hash = ea_recovery::recovery_archive_inventory_hash(&before).unwrap();
    std::fs::write(
        temp.path().join("entries/prepared.eip.staging"),
        &f.entry_bytes,
    )
    .unwrap();
    let frozen = ea_recovery::FsArchiveSource::open(temp.path()).unwrap();
    let whole_hash = ea_recovery::recovery_archive_inventory_hash(&frozen).unwrap();
    assert_ne!(whole_hash, original_hash);
    let probe = ea_recovery::RecoveryArchiveProbe::verify(
        &frozen,
        &f.anchor,
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    assert_eq!(probe.inventory().entries().len(), 1);
    std::fs::remove_file(temp.path().join("entries/prepared.eip.staging")).unwrap();
    assert_eq!(
        ea_recovery::recovery_archive_inventory_hash(&frozen).unwrap(),
        whole_hash,
        "the signed scope keeps its exact snapshot"
    );
    assert_eq!(
        ea_recovery::recovery_archive_inventory_hash(
            &ea_recovery::FsArchiveSource::open(temp.path()).unwrap()
        )
        .unwrap(),
        original_hash
    );
}
