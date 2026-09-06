use ea_format::{OperatorBindingFieldsV1, OperatorRoleV1, TrustPayloadV1};
use ea_types::{
    CertificateHash, ChainSequence, Hash32, ObjectHash, OperatorSubjectId, OrganizationId,
};

fn binding() -> TrustPayloadV1 {
    TrustPayloadV1::authorized_operator_binding(
        OperatorBindingFieldsV1 {
            organization_id: OrganizationId::try_from(&[1; 16][..]).unwrap(),
            operator_subject_id: OperatorSubjectId::try_from(&[2; 16][..]).unwrap(),
            device_certificate_hash: CertificateHash::try_from(&[3; 32][..]).unwrap(),
            operator_role: OperatorRoleV1::Writer,
            os_account_binding_hash: Hash32::try_from(&[4; 32][..]).unwrap(),
            operator_instance_key_thumbprint: ea_types::KeyThumbprint::try_from(&[6; 32][..])
                .unwrap(),
            operator_profile_commitment: Hash32::try_from(&[5; 32][..]).unwrap(),
            effective_from_sequence: ChainSequence::new(1),
            revoked_from_sequence: None,
        },
        ObjectHash::from(Hash32::ZERO),
    )
    .unwrap()
}

#[test]
fn exact_unsigned_input_preserves_the_canonical_constructor_bytes() {
    let input = binding();
    let parsed = TrustPayloadV1::from_exact_digest_input(input.exact_digest_input()).unwrap();
    assert_eq!(parsed.subtype(), input.subtype());
    assert_eq!(parsed.exact_payload(), input.exact_payload());
    assert_eq!(parsed.exact_digest_input(), input.exact_digest_input());
}

#[test]
fn unsigned_input_refuses_trailing_truncated_noncanonical_and_wrong_shape_bytes() {
    let input = binding();
    let valid = input.exact_digest_input();
    let mut trailing = valid.to_vec();
    trailing.push(0);
    let mut noncanonical = vec![0x98, 2];
    noncanonical.extend_from_slice(&valid[1..]);
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&valid[1..]);
    indefinite.push(0xff);
    for bytes in [
        trailing,
        valid[..valid.len() - 1].to_vec(),
        noncanonical,
        indefinite,
        vec![0x82, 0x60, 0x80],
    ] {
        assert!(TrustPayloadV1::from_exact_digest_input(&bytes).is_err());
    }
}
