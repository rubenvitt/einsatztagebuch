use super::*;

#[test]
fn retained_preview_cannot_hide_a_new_authenticated_time_floor() {
    time_floor_probe(true);
}
#[test]
fn without_preview_rechecks_the_new_authenticated_time_floor() {
    time_floor_probe(false);
}
fn time_floor_probe(retain_preview: bool) {
    use ea_trust::*;
    let mut installed = Installation::new();
    let config = configure_writer_expiring_at(
        &mut installed,
        UnixMillis::new(support::live_clock().get() - 1000),
    );
    let mut known = Vec::new();
    installed
        .line
        .source()
        .visit_trust_object_hashes(&mut |hash| {
            known.push(hash);
            Ok(())
        })
        .unwrap();
    let server = installed
        .line
        .push(
            ActionSpec::Device {
                kind: CertificateKindV1::ServerReceipt,
                marker: 0x7e,
                effective_from: Some(1),
            },
            HeadOptions {
                effective_from: Some(1),
                valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
                not_after: UnixMillis::new(support::live_clock().get() - 1000),
                ..Default::default()
            },
        )
        .direct_object_hash
        .unwrap();
    let source = installed.line.source();
    source
        .visit_trust_object_hashes(&mut |hash| {
            if known.contains(&hash) {
                return Ok(());
            }
            let target = installed
                .archive
                .join(format!("{}.etb", hex::encode(hash.as_bytes())));
            if !target.exists() {
                fs::write(target, source.read_exact_trust_object(hash)?.unwrap()).unwrap();
            }
            Ok(())
        })
        .unwrap();
    let native = host_with_writer(&installed, Some(config));
    native.login().unwrap();
    let state = native.desktop_state();
    state
        .drafts()
        .unwrap()
        .save_payload("must require a fresh session after signed time advances".into())
        .unwrap();
    if retain_preview {
        let _preview = state.writer().unwrap().preview(&native_incident()).unwrap();
    }
    let anchor = ea_recovery::load_trust_anchor(&installed.anchor).unwrap();
    let key = TrustStateKey {
        organization_id: anchor.organization_id(),
        device_id: device(),
    };
    let mut store = ea_admin::operator_trust_store::OperatorTrustStateStore::open(
        open_database(&installed.database),
        key,
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        support::live_clock(),
    )
    .unwrap();
    let trust = verify_trust(&anchor, &source, load_trust_state(&mut store, key).unwrap()).unwrap();
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(1)).unwrap();
    let old_pin = *trust.pinned_head().unwrap();
    let floor =
        UnixMillis::new(support::live_clock().get() + ea_operator::MAX_INACTIVITY_MS + 10_000);
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        trust_support::device_signing_secret(),
    ));
    let core = ea_format::ReceiptCoreV1::new(ea_format::ReceiptCoreFieldsV1 {
        organization_id: anchor.organization_id(),
        chain_id: anchor.chain_id(),
        chain_sequence: ChainSequence::new(1),
        entry_hash: anchor.genesis_entry_hash(),
        entry_object_hash: ObjectHash::try_from(&[0x11; 32][..]).unwrap(),
        previous_entry_hash: Some(anchor.genesis_entry_hash()),
        registry_version: old_pin.registry_version(),
        registry_head_hash: Hash32::try_from(old_pin.registry_head_hash().as_bytes().as_slice())
            .unwrap(),
        policy_object_hash: installed.line.current_policy_hash().unwrap(),
        initial_grant_plan_hash: Hash32::try_from(&[0x12; 32][..]).unwrap(),
        initial_grant_object_hashes: vec![ObjectHash::try_from(&[0x13; 32][..]).unwrap()],
        accepted_at_server: floor,
        evidence_due_at: None,
        server_key_thumbprint: signer.public_key().unwrap().thumbprint(),
        server_certificate_hash: CertificateHash::from(server),
    })
    .unwrap();
    let signature = signer.sign_receipt(core.exact_bytes()).unwrap();
    let exact =
        ea_format::encode_receipt(&ea_format::ReceiptV1::new(core, signature).unwrap()).unwrap();
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(exact.as_bytes()).unwrap()
    else {
        panic!("receipt")
    };
    let verified =
        verify_receipt_time(candidate.preexisting_authority().unwrap(), &receipt).unwrap();
    drop(prepare_local_time(&mut store, &candidate, support::live_clock(), &[verified]).unwrap());
    let durable = load_trust_state(&mut store, key).unwrap();
    assert_eq!(durable.trusted_time().floor().get(), floor.get());
    assert!(durable.pinned_head().unwrap().registry_head_hash() == old_pin.registry_head_hash());
    let disclosed = state.drafts().unwrap().load_payload();
    assert!(
        disclosed.is_err(),
        "retained preview must not validate an expired native purpose proof against an obsolete time floor; disclosed={:?}",
        disclosed
    );
}

#[test]
fn current_presence_rejects_new_signed_time() {
    presence_floor_probe(false);
}
#[test]
fn stale_presence_rejects_new_signed_time() {
    presence_floor_probe(true);
}
fn presence_floor_probe(stale: bool) {
    use ea_trust::*;
    let mut installed = Installation::new();
    let not_after = if stale {
        UnixMillis::new(support::live_clock().get() - 1000)
    } else {
        UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1)
    };
    let config = configure_writer_expiring_at(&mut installed, not_after);
    let mut known = Vec::new();
    installed
        .line
        .source()
        .visit_trust_object_hashes(&mut |hash| {
            known.push(hash);
            Ok(())
        })
        .unwrap();
    let server = installed
        .line
        .push(
            ActionSpec::Device {
                kind: CertificateKindV1::ServerReceipt,
                marker: 0x7e,
                effective_from: Some(1),
            },
            HeadOptions {
                effective_from: Some(1),
                valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
                not_after,
                ..Default::default()
            },
        )
        .direct_object_hash
        .unwrap();
    let source = installed.line.source();
    source
        .visit_trust_object_hashes(&mut |hash| {
            if known.contains(&hash) {
                return Ok(());
            }
            let target = installed
                .archive
                .join(format!("{}.etb", hex::encode(hash.as_bytes())));
            if !target.exists() {
                fs::write(target, source.read_exact_trust_object(hash)?.unwrap()).unwrap();
            }
            Ok(())
        })
        .unwrap();
    let native = host_with_writer(&installed, Some(config));
    native.login().unwrap();
    let state = native.desktop_state();
    state
        .drafts()
        .unwrap()
        .save_payload("must require a fresh session after signed time advances".into())
        .unwrap();
    let _preview = state.writer().unwrap().preview(&native_incident()).unwrap();
    let barrier = installed.directory.path().join("hold-operator-signature");
    fs::write(&barrier, b"").unwrap();
    let action_host = native.clone();
    let presence = std::thread::spawn(move || {
        action_host.reauthenticate(if stale {
            ReauthPurpose::RegistryStaleFinalize
        } else {
            ReauthPurpose::Finalize
        })
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !installed
        .directory
        .path()
        .join("operator-signature-paused")
        .exists()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "actual native signature barrier"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let anchor = ea_recovery::load_trust_anchor(&installed.anchor).unwrap();
    let key = TrustStateKey {
        organization_id: anchor.organization_id(),
        device_id: device(),
    };
    let mut store = ea_admin::operator_trust_store::OperatorTrustStateStore::open(
        open_database(&installed.database),
        key,
        anchor.chain_id(),
        anchor.trust_anchor_hash(),
        support::live_clock(),
    )
    .unwrap();
    let trust = verify_trust(&anchor, &source, load_trust_state(&mut store, key).unwrap()).unwrap();
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(1)).unwrap();
    let old_pin = *trust.pinned_head().unwrap();
    let floor =
        UnixMillis::new(support::live_clock().get() + ea_operator::MAX_INACTIVITY_MS + 10_000);
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        trust_support::device_signing_secret(),
    ));
    let core = ea_format::ReceiptCoreV1::new(ea_format::ReceiptCoreFieldsV1 {
        organization_id: anchor.organization_id(),
        chain_id: anchor.chain_id(),
        chain_sequence: ChainSequence::new(1),
        entry_hash: anchor.genesis_entry_hash(),
        entry_object_hash: ObjectHash::try_from(&[0x11; 32][..]).unwrap(),
        previous_entry_hash: Some(anchor.genesis_entry_hash()),
        registry_version: old_pin.registry_version(),
        registry_head_hash: Hash32::try_from(old_pin.registry_head_hash().as_bytes().as_slice())
            .unwrap(),
        policy_object_hash: installed.line.current_policy_hash().unwrap(),
        initial_grant_plan_hash: Hash32::try_from(&[0x12; 32][..]).unwrap(),
        initial_grant_object_hashes: vec![ObjectHash::try_from(&[0x13; 32][..]).unwrap()],
        accepted_at_server: floor,
        evidence_due_at: None,
        server_key_thumbprint: signer.public_key().unwrap().thumbprint(),
        server_certificate_hash: CertificateHash::from(server),
    })
    .unwrap();
    let signature = signer.sign_receipt(core.exact_bytes()).unwrap();
    let exact =
        ea_format::encode_receipt(&ea_format::ReceiptV1::new(core, signature).unwrap()).unwrap();
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(exact.as_bytes()).unwrap()
    else {
        panic!("receipt")
    };
    let verified =
        verify_receipt_time(candidate.preexisting_authority().unwrap(), &receipt).unwrap();
    drop(prepare_local_time(&mut store, &candidate, support::live_clock(), &[verified]).unwrap());
    let durable = load_trust_state(&mut store, key).unwrap();
    assert_eq!(durable.trusted_time().floor().get(), floor.get());
    assert!(durable.pinned_head().unwrap().registry_head_hash() == old_pin.registry_head_hash());
    fs::remove_file(barrier).unwrap();
    let result = presence.join().unwrap();
    assert!(
        result.is_err(),
        "time changed during actual native presence must reject before a successful proof; stale={stale}"
    );
    assert_eq!(native.verified_role().unwrap(), None);
    let disclosed = state.drafts().unwrap().load_payload();
    assert!(
        disclosed.is_err(),
        "retained preview must not validate an expired native purpose proof against an obsolete time floor; disclosed={:?}",
        disclosed
    );
}
