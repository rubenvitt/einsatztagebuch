mod support;
use ea_destruction::*;
use ea_format::*;
use ea_types::*;
use support::{Fixture, trust};

#[test]
fn exact_attestation_binds_original_authority_replica_device_and_closed_result_semantics() {
    let f = Fixture::new(true, true, false);
    let selected = f.head();
    let trust = f.line.verified_with_record(
        trust::Pin::Exact(selected.registry_version(), selected.registry_head_hash()),
        17,
        ea_time::TrustedTimeState::initial(UnixMillis::new(support::NOW)),
        trust::state_key(),
    );
    let historical = ea_trust::verify_historical_registry_authority(
        &trust,
        selected.registry_version(),
        selected.registry_head_hash(),
        selected.proposed_sequence(),
    )
    .unwrap();
    let auth = verify_authorization(&f.authorization(), &selected).unwrap();
    let device = selected
        .active_certificate_fields(f.deletion)
        .unwrap()
        .device_id;
    let fields = DeletionAttestationFieldsV1 {
        destruction_id: auth.fields().destruction_id,
        destruction_authorization_object_hash: auth.object_hash(),
        replica_id: *device.as_bytes(),
        replica_kind: ManagedReplicaKind::Writer.code(),
        removed_object_hashes: vec![ObjectHash::try_from(&[1; 32][..]).unwrap()],
        result: 0,
        backup_expiry_at: None,
        executed_at: UnixMillis::new(1000),
    };
    let sign = |fields: DeletionAttestationFieldsV1| {
        let p = TrustPayloadV1::deletion_attestation(fields).unwrap();
        let sig = trust::authorized_device_signer()
            .sign_deletion_attestation_digest(
                f.deletion,
                p.exact_digest_input(),
                auth.exact_bytes(),
            )
            .unwrap();
        support::exact(p, vec![sig])
    };
    let exact = sign(fields.clone());
    let proof =
        verify_attestation_historical(&exact, &auth, &historical, UnixMillis::new(1000)).unwrap();
    assert_eq!(proof.exact_bytes(), exact);
    assert!(proof.certificate_hash() == f.deletion);
    assert!(proof.object_hash() == ea_crypto::object_hash(&exact));
    for mutate in [0, 1, 2, 3, 4] {
        let mut changed = fields.clone();
        match mutate {
            0 => changed.replica_id = [0; 16],
            1 => changed.replica_kind = 3,
            2 => changed.executed_at = UnixMillis::new(1001),
            3 => {
                changed.result = 1;
                changed.backup_expiry_at = None
            }
            _ => changed.backup_expiry_at = Some(UnixMillis::new(1001)),
        }
        assert!(
            verify_attestation_historical(
                &sign(changed),
                &auth,
                &historical,
                UnixMillis::new(1000)
            )
            .is_err(),
            "mutation {mutate}"
        );
    }
    let mut pending = fields.clone();
    pending.result = 1;
    pending.backup_expiry_at = Some(UnixMillis::new(2000));
    assert!(
        verify_attestation_historical(&sign(pending), &auth, &historical, UnixMillis::new(1000))
            .is_ok()
    );
    let mut expired_but_removed = fields;
    expired_but_removed.backup_expiry_at = Some(UnixMillis::new(999));
    assert!(
        verify_attestation_historical(
            &sign(expired_but_removed),
            &auth,
            &historical,
            UnixMillis::new(1000)
        )
        .is_ok()
    );
}
