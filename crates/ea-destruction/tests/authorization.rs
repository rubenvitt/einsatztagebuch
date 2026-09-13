mod support;
use ea_destruction::verify_authorization;
use ea_types::*;
use support::Fixture;
#[test]
fn valid_two_people_bind_exact_bytes_and_hash() {
    let f = Fixture::new(true, true, false);
    let bytes = f.authorization();
    let verified = verify_authorization(&bytes, &f.head()).unwrap();
    assert_eq!(verified.exact_bytes(), bytes);
    assert!(verified.object_hash() == ea_crypto::object_hash(&bytes));
}
#[test]
fn both_signed_privacy_conditions_are_required() {
    for (enabled, document) in [(false, false), (false, true), (true, false)] {
        let f = Fixture::new(enabled, document, false);
        assert_eq!(
            verify_authorization(&f.authorization(), &f.head())
                .unwrap_err()
                .code(),
            "EA-DESTRUCTION-PRIVACY-GATE"
        );
    }
}
#[test]
fn two_certificates_of_one_person_are_not_two_approvers() {
    let f = Fixture::new(true, true, true);
    assert_eq!(
        verify_authorization(&f.authorization(), &f.head())
            .unwrap_err()
            .code(),
        "EA-DESTRUCTION-APPROVERS"
    );
}
#[test]
fn duplicated_signature_is_not_two_approvers() {
    let f = Fixture::new(true, true, false);
    let bytes = f.sign(f.fields(), vec![f.approvers[0]; 2]);
    assert_eq!(
        verify_authorization(&bytes, &f.head()).unwrap_err().code(),
        "EA-DESTRUCTION-APPROVERS"
    );
}
#[test]
fn selected_head_hash_version_organization_and_sequence_are_exact() {
    let f = Fixture::new(true, true, false);
    for change in 0..4 {
        let mut fields = f.fields();
        match change {
            0 => fields.registry_head_hash = Hash32::ZERO,
            1 => fields.registry_version = RegistryVersion::new(1),
            2 => fields.organization_id = OrganizationId::try_from(&[0xff; 16][..]).unwrap(),
            _ => fields.authorization_sequence += 1,
        }
        assert!(verify_authorization(&f.sign(fields, f.approvers.to_vec()), &f.head()).is_err());
    }
}
#[test]
fn capability_and_signature_are_verified() {
    let f = Fixture::new(true, true, false);
    assert!(
        verify_authorization(
            &f.sign(f.fields(), vec![f.approvers[0], f.deletion]),
            &f.head()
        )
        .is_err()
    );
    let mut bytes = f.authorization();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(verify_authorization(&bytes, &f.head()).is_err());
}
#[test]
fn targets_are_nonempty_hash_ordered_and_unique_even_if_sequences_differ() {
    use ea_format::{DestructionTargetV1 as T, TrustPayloadV1};
    let f = Fixture::new(true, true, false);
    for targets in [
        vec![],
        vec![T::new([2; 32], 1), T::new([1; 32], 1)],
        vec![T::new([1; 32], 1), T::new([1; 32], 1)],
        vec![T::new([1; 32], 1), T::new([1; 32], 2)],
    ] {
        let mut fields = f.fields();
        fields.targets = targets;
        assert!(TrustPayloadV1::destruction_authorization(fields).is_err());
    }
}

#[test]
fn target_crosschecks_real_writer_signature_manifest_sequence_and_hash() {
    let f = support::with_writer(Fixture::new(true, true, false));
    let entry = support::entry(&f);
    let mut fields = f.fields();
    fields.targets = vec![ea_format::DestructionTargetV1::new(
        *entry.entry_hash().as_bytes(),
        entry.manifest().fields().chain_sequence.get(),
    )];
    let bytes = f.sign(fields.clone(), f.approvers.to_vec());
    let auth = verify_authorization(&bytes, &f.head()).unwrap();
    assert!(auth.verify_target(&entry, &f.head()).is_ok());
    fields.targets[0] = ea_format::DestructionTargetV1::new(*entry.entry_hash().as_bytes(), 1);
    let bad = verify_authorization(&f.sign(fields, f.approvers.to_vec()), &f.head()).unwrap();
    assert!(bad.verify_target(&entry, &f.head()).is_err());
    let mut signature = entry.writer_signature().to_vec();
    let last = signature.len() - 1;
    signature[last] ^= 1;
    let forged = ea_format::EntryPackageV1::new(
        entry.signed_manifest().clone(),
        entry.ciphertext().to_vec(),
        signature,
    )
    .unwrap();
    assert!(auth.verify_target(&forged, &f.head()).is_err());
}

#[test]
fn revoked_approvers_are_rejected_at_current_verification() {
    let mut f = Fixture::new(true, true, false);
    let target = ObjectHash::try_from(f.approvers[0].as_bytes().as_slice()).unwrap();
    f.line.push(
        support::trust::ActionSpec::Revoke {
            target_kind: 0,
            object_hash: target,
        },
        support::options(),
    );
    assert!(verify_authorization(&f.authorization(), &f.head()).is_err());
}

#[test]
fn expired_registry_does_not_produce_the_selected_head_required_by_authorization() {
    let f = Fixture::new(true, true, false);
    let boundary = support::try_selected(&f.line, 10_000_000).unwrap();
    assert!(verify_authorization(&f.authorization(), &boundary).is_ok());
    assert_eq!(
        support::try_selected(&f.line, 10_000_001)
            .err()
            .map(|e| e.code()),
        Some("EA-TRUST-STALE")
    );
}
