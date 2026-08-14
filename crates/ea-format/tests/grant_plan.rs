use ea_format::{
    DestructionTargetV1, GrantKindV1, GrantPlanItemV1, GrantPlanV1, GrantPurposeV1,
    ParsedArchiveObject, decode_exact_object, validate_destruction_targets,
};

mod support;

#[test]
fn grant_plan_is_total_sorted_unique_and_has_exactly_one_recovery() {
    let recovery = support::grant_plan_item(0x10, 0x20, GrantPurposeV1::Recovery);
    let reader_a = support::grant_plan_item(0x30, 0x40, GrantPurposeV1::Reader);
    let reader_b = support::grant_plan_item(0x50, 0x60, GrantPurposeV1::Reader);
    let plan =
        GrantPlanV1::new(vec![reader_b.clone(), recovery.clone(), reader_a.clone()]).unwrap();

    assert_eq!(plan.items(), &[recovery, reader_a, reader_b]);
    assert_eq!(
        hex::encode(plan.hash().as_bytes()),
        "fe2064c046f7f372bd7d3d2186606ef6c4467c46f486e25c81e9f9d7278148c0"
    );
}

#[test]
fn grant_plan_rejects_every_local_duplicate_and_recovery_cardinality_error() {
    let recovery = support::grant_plan_item(0x10, 0x20, GrantPurposeV1::Recovery);
    assert_eq!(
        GrantPlanV1::new(vec![
            recovery.clone(),
            support::grant_plan_item(0x11, 0x21, GrantPurposeV1::Recovery),
        ])
        .unwrap_err()
        .code(),
        "EA-GRANT-DUPLICATE-RECOVERY"
    );
    assert_eq!(
        GrantPlanV1::new(vec![support::grant_plan_item(
            0x10,
            0x21,
            GrantPurposeV1::Reader
        )])
        .unwrap_err()
        .code(),
        "EA-GRANT-MISSING-RECOVERY"
    );
    assert_eq!(
        GrantPlanV1::new(vec![
            recovery.clone(),
            support::grant_plan_item(0x10, 0x30, GrantPurposeV1::Reader),
        ])
        .unwrap_err()
        .code(),
        "EA-GRANT-DUPLICATE-RECIPIENT-KEY"
    );
    assert_eq!(
        GrantPlanV1::new(vec![
            recovery.clone(),
            support::grant_plan_item(0x11, 0x20, GrantPurposeV1::Reader),
        ])
        .unwrap_err()
        .code(),
        "EA-GRANT-DUPLICATE-RECIPIENT-CERTIFICATE"
    );
    assert_eq!(
        GrantPlanV1::new(vec![
            recovery,
            support::grant_plan_item(0x20, 0x30, GrantPurposeV1::Reader),
            support::grant_plan_item(0x30, 0x20, GrantPurposeV1::Reader),
        ])
        .unwrap_err()
        .code(),
        "EA-GRANT-DUPLICATE-RECIPIENT-CERTIFICATE"
    );
}

#[test]
fn destruction_targets_use_entry_hash_identity_and_tuple_order() {
    let hash_a = [0x10; 32];
    let hash_b = [0x20; 32];
    let valid = [
        DestructionTargetV1::new(hash_a, 9),
        DestructionTargetV1::new(hash_b, 9),
    ];
    assert!(validate_destruction_targets(&valid).is_ok());

    assert_eq!(
        validate_destruction_targets(&[
            DestructionTargetV1::new(hash_b, 1),
            DestructionTargetV1::new(hash_a, u64::MAX),
        ])
        .unwrap_err()
        .code(),
        "EA-FORMAT-UNSORTED"
    );
    assert_eq!(
        validate_destruction_targets(&[
            DestructionTargetV1::new(hash_a, 1),
            DestructionTargetV1::new(hash_a, 2),
        ])
        .unwrap_err()
        .code(),
        "EA-FORMAT-DUPLICATE"
    );
    assert_eq!(
        validate_destruction_targets(&[
            DestructionTargetV1::new(hash_a, 1),
            DestructionTargetV1::new(hash_a, 1),
        ])
        .unwrap_err()
        .code(),
        "EA-FORMAT-DUPLICATE"
    );
}

#[test]
fn grant_plan_item_wire_tuple_contains_the_fixed_suite_and_purpose() {
    let item = support::grant_plan_item(1, 2, GrantPurposeV1::Reader);
    assert_eq!(item.grant_suite_id(), "EINSATZARCHIV-HPKE-1");
    assert_eq!(item.purpose(), GrantPurposeV1::Reader);
    let _typed_contract: GrantPlanItemV1 = item;
}

#[test]
fn initial_and_historical_grants_decode_their_exact_positional_contracts() {
    let initial = match decode_exact_object(&support::valid_initial_eag()).unwrap() {
        ParsedArchiveObject::Grant(value) => value,
        _ => unreachable!(),
    };
    assert_eq!(initial.value().kind(), GrantKindV1::Initial);
    assert_eq!(initial.value().purpose(), GrantPurposeV1::Reader);

    let historical = match decode_exact_object(&support::valid_historical_eag()).unwrap() {
        ParsedArchiveObject::Grant(value) => value,
        _ => unreachable!(),
    };
    assert_eq!(historical.value().kind(), GrantKindV1::Historical);
    assert_eq!(historical.value().purpose(), GrantPurposeV1::Reader);
}

#[test]
fn grant_kind_purpose_capability_and_authorization_fields_correlate() {
    for invalid in support::invalid_grant_correlations() {
        assert_eq!(
            decode_exact_object(&invalid).unwrap_err().code(),
            "EA-FORMAT-SHAPE"
        );
    }
}

#[test]
fn grant_hpke_lengths_suite_digest_and_protected_bindings_are_exact() {
    for (invalid, code) in support::invalid_grant_wire_cases() {
        assert_eq!(decode_exact_object(&invalid).unwrap_err().code(), code);
    }
}
