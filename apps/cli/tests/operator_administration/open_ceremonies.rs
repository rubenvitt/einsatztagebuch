use super::*;
use ea_admin::{
    TrustCeremonyStep,
    administration_runtime::{authorization, ceremony},
};

#[test]
fn native_open_ceremonies_reopens_exact_stored_rounds_without_renewing_authority() {
    let stations = SeparateAdministrationStations::new();
    let mut runtime = stations.source.open();
    let revoke = ceremony::begin_revoke(&mut runtime, stations.source.reader).unwrap();
    let (request, target) = actual_registration_intent(&runtime);
    let registration = ceremony::begin_registration(&mut runtime, &request, &target).unwrap();
    ceremony::confirm_registration_fingerprint(
        &mut runtime,
        registration.id(),
        ea_crypto::object_hash(&request),
    )
    .unwrap();
    let proof = runtime
        .reauthenticate_for(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    let authorized = authorization::authorize(&mut runtime, registration.id(), &proof).unwrap();
    let rows = runtime
        .database()
        .query_row("SELECT COUNT(*) FROM administration_ceremony_record", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    drop(proof);
    drop(runtime);
    let mut reopened = stations.source.open();
    let visible = ceremony::open_ceremonies(&mut reopened)
        .expect("actual stored open rounds survive restart");
    assert_eq!(visible.len(), 2);
    let approved = visible
        .iter()
        .find(|row| row.id() == registration.id())
        .unwrap();
    assert_eq!(approved.step(), TrustCeremonyStep::AdminAuthorized);
    assert_eq!(
        approved.exact_target_payload(),
        authorized.exact_target_payload()
    );
    assert_eq!(
        visible
            .iter()
            .find(|row| row.id() == revoke.id())
            .unwrap()
            .step(),
        TrustCeremonyStep::PendingRequest
    );
    assert_eq!(
        reopened
            .database()
            .query_row("SELECT COUNT(*) FROM administration_ceremony_record", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        rows,
        "reading the list cannot renew an authorization, audit or replay entry"
    );
}

#[test]
fn native_open_ceremonies_refuses_unverifiable_journal_membership_instead_of_hiding_it() {
    let stations = SeparateAdministrationStations::new();
    let mut runtime = stations.source.open();
    let revoke = ceremony::begin_revoke(&mut runtime, stations.source.reader).unwrap();
    assert_eq!(ceremony::open_ceremonies(&mut runtime).unwrap().len(), 1);
    // A row is local metadata, never proof that its claimed ID is an actual
    // authorized intention. Even a correctly scoped copied payload is insufficient.
    runtime.database().execute(
        "INSERT INTO administration_ceremony_intent SELECT ?1,organization_id,chain_id,trust_anchor_hash,admin_certificate_hash,admin_binding_hash,registry_version,registry_head_hash,proposed_sequence,target_payload,source_kind,source_bytes,ceremony_round,parent_intent_hash,created_at FROM administration_ceremony_intent WHERE intent_hash=?2",
        &[StoreValue::Blob(vec![0x6d;32]),StoreValue::Blob(revoke.id().as_bytes().to_vec())]).unwrap();
    drop(runtime);
    let mut reopened = stations.source.open();
    assert!(
        ceremony::open_ceremonies(&mut reopened).is_err(),
        "unknown or inconsistent recorded rounds are not an empty successful list"
    );
}
