mod support;
use ea_crypto::{CoseSigner, SecretBytes, object_hash};
use ea_format::{
    AdminRootContextV1, CertificateKindV1, DecodedTrustPayloadV1, LocalAuditActionV1,
    LocalAuditEventCoreFieldsV1, LocalAuditOutcomeV1, ParsedArchiveObject,
};
use ea_types::{ChainSequence, EventId, Id16, ObjectHash, UnixMillis};
use support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

const ADMIN_SECRET: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
fn options() -> HeadOptions {
    HeadOptions {
        effective_from: Some(0),
        valid_through: Some(100),
        ..Default::default()
    }
}
fn fixture() -> (RegistryLineBuilder, support::BuiltHead, support::BuiltHead) {
    let mut line = RegistryLineBuilder::new();
    let previous = line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        options(),
    );
    let target = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x44,
            effective_from: Some(0),
        },
        options(),
    );
    (line, previous, target)
}
fn audit(
    line: &RegistryLineBuilder,
    target: ObjectHash,
    change: impl FnOnce(&mut LocalAuditEventCoreFieldsV1),
) -> Vec<u8> {
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(line.exact_object_bytes(target)).unwrap()
    else {
        panic!()
    };
    let authorization = match parsed.value().decoded_payload().unwrap() {
        DecodedTrustPayloadV1::RegistryEvent(core) => core.authorization_object_hash(),
        DecodedTrustPayloadV1::AuthorizedDevice(core) => core.authorization_object_hash(),
        _ => panic!(),
    };
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(line.exact_object_bytes(line.bootstrap_admin_hash()))
            .unwrap()
    else {
        panic!()
    };
    let DecodedTrustPayloadV1::InitialAdminDevice(cert) = parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let mut fields = LocalAuditEventCoreFieldsV1 {
        event_id: EventId::from(Id16::try_from([0x7a; 16].as_slice()).unwrap()),
        organization_id: cert.organization_id,
        device_id: cert.device_id,
        operator_binding_object_hash: Some(line.bootstrap_admin_binding_hash()),
        signer_certificate_object_hash: line.bootstrap_admin_hash(),
        action: LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(
            authorization,
            target,
            0,
        )),
        outcome: LocalAuditOutcomeV1::Completed,
        effective_now: UnixMillis::new(150),
        nonce: [0x91; 32],
    };
    change(&mut fields);
    let core = ea_format::encode_local_audit_core(&fields).unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(ADMIN_SECRET))
        .sign_local_audit(&core)
        .unwrap();
    ea_format::encode_local_audit_event(&core, &signature).unwrap()
}
#[test]
fn exact_publication_audit_survives_later_admin_revocation_without_old_sequence_authority() {
    let (mut line, previous, target) = fixture();
    let exact = audit(&line, target.object_hash, |_| {});
    line.push(
        ActionSpec::AdminRevoke {
            object_hash: line.bootstrap_admin_hash(),
        },
        options(),
    );
    let trust = line.verified_with_floor(Pin::Head(2), UnixMillis::new(20_000));
    let proof =
        ea_trust::verify_registry_publication_audit(&trust, target.object_hash, &exact).unwrap();
    assert!(proof.target_hash() == target.object_hash);
    assert_eq!(proof.original_sequence().get(), 0);
    assert!(
        ea_trust::verify_historical_registry_authority(
            &trust,
            previous.version,
            previous.object_hash,
            ChainSequence::new(0)
        )
        .is_err()
    );
}
#[test]
fn only_the_exact_completed_admin_publication_claim_is_accepted() {
    let (line, _, target) = fixture();
    let trust = line.verified_with_floor(Pin::Head(1), UnixMillis::new(20_000));
    let wrong = support::object_hash_marker(0xee);
    for mutation in 0..8 {
        let exact = audit(&line, target.object_hash, |fields| match mutation {
            0 => {
                fields.action = LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(
                    wrong,
                    target.object_hash,
                    0,
                ))
            }
            1 => {
                fields.action =
                    LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(wrong, wrong, 0))
            }
            2 => {
                if let LocalAuditActionV1::AdminRootCeremony(context) = &fields.action {
                    fields.action = LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(
                        context.authorization_object_hash(),
                        target.object_hash,
                        1,
                    ));
                }
            }
            3 => fields.outcome = LocalAuditOutcomeV1::Accepted,
            4 => {
                fields.operator_binding_object_hash =
                    Some(line.second_bootstrap_admin_binding_hash())
            }
            5 => {
                fields.action = LocalAuditActionV1::Login(ea_format::GenericAuditContextV1::new(
                    Some(target.object_hash),
                ))
            }
            6 => fields.effective_now = UnixMillis::new(99),
            7 => fields.effective_now = UnixMillis::new(20_000),
            _ => unreachable!(),
        });
        assert!(
            ea_trust::verify_registry_publication_audit(&trust, target.object_hash, &exact)
                .is_err(),
            "mutation {mutation}"
        );
    }
    let exact = audit(&line, target.object_hash, |_| {});
    assert!(
        ea_trust::verify_registry_publication_audit(&trust, line.bootstrap_admin_hash(), &exact)
            .is_err()
    );
    assert!(ea_trust::verify_registry_publication_audit(&trust, wrong, &exact).is_err());
    let mut corrupted = exact.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(
        ea_trust::verify_registry_publication_audit(&trust, target.object_hash, &corrupted)
            .is_err()
    );
}
#[test]
fn corrupt_root_target_and_registry_forks_cannot_gain_a_publication_proof() {
    let (mut line, _, target) = fixture();
    let exact = audit(&line, target.object_hash, |_| {});
    let mut corrupted = line.exact_object_bytes(target.object_hash).to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    line.remove_object(target.object_hash);
    let corrupt_hash = object_hash(&corrupted);
    line.add_object(corrupted);
    let trust = line.verified_with_floor(Pin::None, UnixMillis::new(800));
    assert!(ea_trust::verify_registry_publication_audit(&trust, corrupt_hash, &exact).is_err());
    let (mut line, _, target) = fixture();
    let exact = audit(&line, target.object_hash, |_| {});
    line.add_branch(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: 0x55,
            effective_from: Some(0),
        },
        HeadOptions {
            registry_version: Some(2),
            previous_hash: support::PreviousHash::Value(
                ea_types::Hash32::try_from(line.heads()[0].object_hash.as_bytes().as_slice())
                    .unwrap(),
            ),
            ..options()
        },
    );
    let trust = line.verified_with_floor(Pin::None, UnixMillis::new(800));
    assert!(
        ea_trust::verify_registry_publication_audit(&trust, target.object_hash, &exact).is_err()
    );
}

#[test]
fn direct_publication_is_exact_history_without_reopening_old_sequence_authority() {
    let (mut line, previous, activation) = fixture();
    let target = activation.direct_object_hash.unwrap();
    let exact = audit(&line, target, |_| {});
    line.push(
        ActionSpec::AdminRevoke {
            object_hash: line.bootstrap_admin_hash(),
        },
        options(),
    );
    let trust = line.verified_with_floor(Pin::Head(2), UnixMillis::new(20_000));
    let proof = ea_trust::verify_direct_target_publication_audit(&trust, target, &exact).unwrap();
    assert!(proof.target_hash() == target);
    assert_eq!(proof.original_sequence().get(), 0);
    assert!(
        ea_trust::verify_historical_registry_authority(
            &trust,
            previous.version,
            previous.object_hash,
            ChainSequence::new(0)
        )
        .is_err()
    );
    for mutation in 0..9 {
        let wrong = support::object_hash_marker(0xff);
        let changed =
            audit(&line, target, |fields| match mutation {
                0 => {
                    fields.action = LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(
                        wrong, target, 0,
                    ))
                }
                1 => {
                    if let LocalAuditActionV1::AdminRootCeremony(c) = &fields.action {
                        fields.action = LocalAuditActionV1::AdminRootCeremony(
                            AdminRootContextV1::new(c.authorization_object_hash(), wrong, 0),
                        );
                    }
                }
                2 => {
                    if let LocalAuditActionV1::AdminRootCeremony(c) = &fields.action {
                        fields.action = LocalAuditActionV1::AdminRootCeremony(
                            AdminRootContextV1::new(c.authorization_object_hash(), target, 2),
                        );
                    }
                }
                3 => fields.outcome = LocalAuditOutcomeV1::Accepted,
                4 => {
                    fields.operator_binding_object_hash =
                        Some(line.second_bootstrap_admin_binding_hash())
                }
                5 => fields.signer_certificate_object_hash = line.second_bootstrap_admin_hash(),
                6 => fields.effective_now = UnixMillis::new(99),
                7 => fields.effective_now = UnixMillis::new(20_000),
                8 => {
                    fields.action = LocalAuditActionV1::Login(
                        ea_format::GenericAuditContextV1::new(Some(target)),
                    )
                }
                _ => unreachable!(),
            });
        assert!(
            ea_trust::verify_direct_target_publication_audit(&trust, target, &changed).is_err(),
            "mutation {mutation}"
        );
    }
    assert!(
        ea_trust::verify_direct_target_publication_audit(&trust, activation.object_hash, &exact)
            .is_err()
    );
    assert!(
        ea_trust::verify_direct_target_publication_audit(
            &trust,
            line.bootstrap_admin_hash(),
            &exact
        )
        .is_err()
    );
    let mut damaged = exact.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(ea_trust::verify_direct_target_publication_audit(&trust, target, &damaged).is_err());
}
