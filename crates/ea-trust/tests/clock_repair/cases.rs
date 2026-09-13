use super::*;
use ea_trust::verify_clock_repair_authority;

fn issuance(fixture: &FlowFixture, wall: UnixMillis) -> Result<(), ClockReleaseError> {
    let mut store = fixture.store();
    let block = prepare_local_time(&mut store, &fixture.candidate, wall, &fixture.sources).unwrap();
    let authority = verify_clock_repair_authority(
        &fixture.candidate,
        &block,
        CertificateHash::from(fixture.audit.signer_certificate_hash),
        fixture.audit.admin_binding_hash.unwrap(),
    )?;
    assert!(authority.organization_id() == fixture.key.organization_id);
    assert!(authority.device_id() == fixture.key.device_id);
    assert!(authority.registry_head_hash() == fixture.candidate.registry_head_hash());
    assert!(authority.raw_now() == wall.max(block_floor(fixture)));
    Ok(())
}
fn block_floor(fixture: &FlowFixture) -> UnixMillis {
    fixture.initial_time.floor()
}

#[test]
fn clock_repair_issuance_accepts_only_fresh_blocked_current_admin_context() {
    let fixture = successor_fixture_with(
        SignedReferenceKind::Receipt,
        AuditSigner::First,
        50,
        UnixMillis::new(700),
        UnixMillis::new(700),
        UnixMillis::new(800),
        [0x51; 32],
    );
    issuance(&fixture, UnixMillis::new(800))
        .expect("actual verified receipt, unexpired guard and target");
}

#[test]
fn clock_repair_issuance_refuses_unblocked_and_expired_registry() {
    let fixture = successor_fixture_with(
        SignedReferenceKind::Receipt,
        AuditSigner::First,
        50,
        UnixMillis::new(700),
        UnixMillis::new(700),
        UnixMillis::new(800),
        [0x52; 32],
    );
    assert!(issuance(&fixture, UnixMillis::new(749)).is_err());
    assert!(issuance(&fixture, UnixMillis::new(10_001)).is_err());
}

#[test]
fn clock_repair_issuance_never_inherits_historical_revoked_admin_permission() {
    let fixture = candidate_revokes_signing_admin_fixture();
    let (historical, _) = verify_fields_once(&fixture, &fixture.audit, fixture.signer, |_| {});
    historical.expect("existing historical verifier remains valid for the old signed release");
    assert!(
        issuance(&fixture, fixture.audit.observed_os_wall_clock).is_err(),
        "a new action cannot inherit the historical original-admin permission"
    );
}

#[test]
fn clock_repair_issuance_binds_exact_candidate_device_and_persistent_block() {
    let fixture = successor_fixture_with(
        SignedReferenceKind::Receipt,
        AuditSigner::First,
        50,
        UnixMillis::new(700),
        UnixMillis::new(700),
        UnixMillis::new(800),
        [0x53; 32],
    );
    let foreign = successor_fixture_with(
        SignedReferenceKind::Receipt,
        AuditSigner::Second,
        50,
        UnixMillis::new(700),
        UnixMillis::new(700),
        UnixMillis::new(800),
        [0x54; 32],
    );
    let mut store = fixture.store();
    let block = prepare_local_time(
        &mut store,
        &fixture.candidate,
        UnixMillis::new(800),
        &fixture.sources,
    )
    .unwrap();
    assert!(
        verify_clock_repair_authority(
            &foreign.candidate,
            &block,
            CertificateHash::from(foreign.audit.signer_certificate_hash),
            foreign.audit.admin_binding_hash.unwrap(),
        )
        .is_err()
    );
    assert!(
        verify_clock_repair_authority(
            &fixture.candidate,
            &block,
            CertificateHash::from(foreign.audit.signer_certificate_hash),
            foreign.audit.admin_binding_hash.unwrap(),
        )
        .is_err()
    );
}

#[test]
fn clock_repair_issuance_refuses_a_later_known_relevant_head() {
    let mut line = RegistryLineBuilder::new();
    for (from, through) in [(1, 9), (10, 19), (20, 39)] {
        line.push(
            policy(),
            HeadOptions {
                effective_from: Some(from),
                valid_through: Some(through),
                policy_max_future_clock_skew_ms_override: Some(50),
                ..HeadOptions::default()
            },
        );
    }
    let guard = line.current_policy_hash().unwrap();
    let candidate = line.push(
        policy(),
        HeadOptions {
            effective_from: Some(30),
            valid_through: Some(49),
            ..HeadOptions::default()
        },
    );
    let admin = line.second_bootstrap_admin_hash();
    let binding = line.second_bootstrap_admin_binding_hash();
    line.push(
        ActionSpec::AdminRevoke { object_hash: admin },
        HeadOptions {
            effective_from: Some(30),
            valid_through: Some(59),
            ..HeadOptions::default()
        },
    );
    let fixture = persisted_reference_fixture(
        &line,
        2,
        ChainSequence::new(30),
        candidate,
        guard,
        device_id(0x52),
        admin,
        binding,
        AuditSigner::Second,
        50,
    );
    let (historical, _) = verify_fields_once(&fixture, &fixture.audit, fixture.signer, |_| {});
    historical.expect("the existing historical audit verifier is unchanged");
    assert!(
        issuance(&fixture, fixture.audit.observed_os_wall_clock).is_err(),
        "a fresh issuer must not stop its authority at H4 when the exact catalogue already carries H5"
    );
}

#[test]
fn clock_repair_issuance_requires_an_independent_reference() {
    let mut fixture = successor_fixture_with(
        SignedReferenceKind::Receipt,
        AuditSigner::First,
        50,
        UnixMillis::new(700),
        UnixMillis::new(700),
        UnixMillis::new(800),
        [0x55; 32],
    );
    fixture.sources.clear();
    assert!(issuance(&fixture, UnixMillis::new(800)).is_err());
}

#[test]
fn clock_repair_context_survives_fresh_exact_reread_but_never_a_changed_floor_or_reference() {
    fn fixture(floor: i64, reference: i64, wall: i64) -> FlowFixture {
        successor_fixture_with(
            SignedReferenceKind::Receipt,
            AuditSigner::First,
            50,
            UnixMillis::new(floor),
            UnixMillis::new(reference),
            UnixMillis::new(wall),
            [0x61; 32],
        )
    }
    let original = fixture(700, 700, 800);
    let mut first_store = original.store();
    let first_block = prepare_local_time(
        &mut first_store,
        &original.candidate,
        UnixMillis::new(800),
        &original.sources,
    )
    .unwrap();
    let proof = verify_clock_repair_authority(
        &original.candidate,
        &first_block,
        CertificateHash::from(original.audit.signer_certificate_hash),
        original.audit.admin_binding_hash.unwrap(),
    )
    .unwrap();
    let digest = proof.context_hash();
    drop(first_block);
    let equal = fixture(700, 700, 800);
    let mut equal_store = equal.store();
    let equal_block = prepare_local_time(
        &mut equal_store,
        &equal.candidate,
        UnixMillis::new(800),
        &equal.sources,
    )
    .unwrap();
    let equal_proof = verify_clock_repair_authority(
        &equal.candidate,
        &equal_block,
        CertificateHash::from(equal.audit.signer_certificate_hash),
        equal.audit.admin_binding_hash.unwrap(),
    )
    .unwrap();
    assert!(digest == equal_proof.context_hash());
    proof
        .require_same_state(&equal.candidate, &equal_block)
        .unwrap();
    for (floor, reference, wall, should_allow) in [
        (700, 700, 801, true),
        (701, 700, 801, false),
        (700, 701, 801, false),
        (700, 700, 799, false),
    ] {
        let fresh = fixture(floor, reference, wall);
        let mut store = fresh.store();
        let block = prepare_local_time(
            &mut store,
            &fresh.candidate,
            UnixMillis::new(wall),
            &fresh.sources,
        )
        .unwrap();
        assert_eq!(
            proof.require_same_state(&fresh.candidate, &block).is_ok(),
            should_allow
        );
        assert!(
            proof.context_hash() == digest,
            "revalidation cannot renew or rewrite the signed challenge context"
        );
    }
}

