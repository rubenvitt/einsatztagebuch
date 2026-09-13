use super::*;
use ea_admin::operator_runtime::OperatorArchiveSnapshot;
use ea_admin::operator_runtime::clock_repair::ClockRepairRuntime;
use ea_trust::{
    TrustStateKey, load_trust_state, prepare_local_time, verify_receipt_time,
    verify_registry_candidate, verify_trust,
};

struct Reference {
    server: CertificateHash,
    registry: ea_types::RegistryVersion,
    head: Hash32,
    policy: ObjectHash,
}
fn persist_reference(
    installation: &AdministrationInstallation,
    store: &mut ea_admin::operator_trust_store::OperatorTrustStateStore,
    key: TrustStateKey,
    reference: &Reference,
    accepted: UnixMillis,
) {
    let now = support::live_clock();
    let snapshot = OperatorArchiveSnapshot::open(
        &installation.directory.path().join("archive"),
        &installation.anchor,
        now,
    )
    .unwrap();
    let trust = verify_trust(
        snapshot.anchor(),
        snapshot.inventory(),
        load_trust_state(store, key).unwrap(),
    )
    .unwrap();
    let candidate = verify_registry_candidate(&trust, snapshot.next_sequence()).unwrap();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        trust_support::device_signing_secret(),
    ));
    let core = ea_format::ReceiptCoreV1::new(ea_format::ReceiptCoreFieldsV1 {
        organization_id: key.organization_id,
        chain_id: snapshot.anchor().chain_id(),
        chain_sequence: snapshot.next_sequence(),
        entry_hash: snapshot.anchor().genesis_entry_hash(),
        entry_object_hash: ea_crypto::object_hash(b"clock native receipt exact entry"),
        previous_entry_hash: Some(snapshot.anchor().genesis_entry_hash()),
        registry_version: reference.registry,
        registry_head_hash: reference.head,
        policy_object_hash: reference.policy,
        initial_grant_plan_hash: Hash32::try_from(&[0x21; 32][..]).unwrap(),
        initial_grant_object_hashes: vec![ea_crypto::object_hash(b"clock native grant")],
        accepted_at_server: accepted,
        evidence_due_at: None,
        server_key_thumbprint: signer.public_key().unwrap().thumbprint(),
        server_certificate_hash: reference.server,
    })
    .unwrap();
    let signature = signer.sign_receipt(core.exact_bytes()).unwrap();
    let exact =
        ea_format::encode_receipt(&ea_format::ReceiptV1::new(core, signature).unwrap()).unwrap();
    let ea_format::ParsedArchiveObject::Receipt(receipt) =
        ea_format::decode_exact_object(exact.as_bytes()).unwrap()
    else {
        panic!()
    };
    let verified =
        verify_receipt_time(candidate.preexisting_authority().unwrap(), &receipt).unwrap();
    drop(prepare_local_time(store, &candidate, now, &[verified]).unwrap());
}
fn provider(installation: &AdministrationInstallation) -> Arc<NativeOperatorProvider> {
    NativeOperatorProvider::open_test_fixture(
        installation.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap()
}
#[test]
fn native_clock_only_restart_persists_audits_consumes_once_and_old_reference_still_blocks_normal_reopen()
 {
    let installation = AdministrationInstallation::new();
    let runtime = installation.open();
    let reference = Reference {
        server: runtime
            .head()
            .active_certificates()
            .find(|(_, fields)| {
                fields.certificate_kind == ea_format::CertificateKindV1::ServerReceipt
            })
            .unwrap()
            .0,
        registry: runtime.head().registry_version(),
        head: Hash32::try_from(runtime.head().registry_head_hash().as_bytes().as_slice()).unwrap(),
        policy: runtime.head().policy_object_hash(),
    };
    let key = TrustStateKey {
        organization_id: runtime.anchor().organization_id(),
        device_id: DeviceId::try_from(&[0x52; 16][..]).unwrap(),
    };
    let mut store = runtime.trust_store().clone();
    let config = runtime.config().clone();
    let accepted = UnixMillis::new(
        support::live_clock().get()
            - i64::try_from(runtime.head().policy_fields().max_future_clock_skew_ms).unwrap()
            - 30_000,
    );
    persist_reference(&installation, &mut store, key, &reference, accepted);
    drop(runtime);
    let ordinary = OperatorRuntime::open_with_test_native(
        config.clone(),
        &installation.anchor,
        support::live_clock(),
        false,
        provider(&installation),
    );
    assert!(matches!(ordinary,Err(ref error) if error.code()=="EA-TRUST-FUTURE-SKEW"));
    let mut repair_config = config.clone();
    repair_config.purpose = ea_operator::ReauthPurpose::ClockSkewRelease;
    let repair = ClockRepairRuntime::open_with_test_native(
        repair_config,
        &installation.anchor,
        provider(&installation),
    )
    .expect("actual restart admits only the sealed Clock repair path");
    let completed = repair
        .release(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
        .expect("native presence, durable Login/Clock audits and atomic one-use selection");
    let login = ea_format::decode_local_audit_event(completed.login().exact_bytes()).unwrap();
    assert!(matches!(
        login.action(),
        ea_format::LocalAuditActionV1::Login(_)
    ));
    assert_eq!(login.outcome(), ea_format::LocalAuditOutcomeV1::Completed);
    let audit = ea_format::decode_clock_release_audit(completed.release().exact_bytes()).unwrap();
    assert_eq!(audit.outcome(), ea_format::LocalAuditOutcomeV1::Accepted);
    let ordinary = OperatorRuntime::open_with_test_native(
        config.clone(),
        &installation.anchor,
        support::live_clock(),
        false,
        provider(&installation),
    );
    assert!(
        matches!(ordinary,Err(ref error) if error.code()=="EA-TRUST-FUTURE-SKEW"),
        "a one-use release never grants a persistent normal-reopen exception"
    );
    persist_reference(
        &installation,
        &mut store,
        key,
        &reference,
        support::live_clock(),
    );
    let recovered = OperatorRuntime::open_with_test_native(
        config,
        &installation.anchor,
        support::live_clock(),
        false,
        provider(&installation),
    )
    .expect("only a genuinely new verified signed time reference restores normal admission");
    for event in [completed.login(), completed.release()] {
        let row = recovered
            .database()
            .query_row(
                "SELECT exact_bytes FROM local_audit_event WHERE event_id=?1",
                &[StoreValue::Blob(event.id().as_bytes().to_vec())],
            )
            .unwrap()
            .unwrap();
        assert_eq!(row.blob(0).unwrap(), event.exact_bytes());
    }
}
