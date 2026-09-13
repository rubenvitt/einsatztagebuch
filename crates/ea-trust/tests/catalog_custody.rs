#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;
use ea_trust::*;
use ea_types::*;
use support::{ActionSpec, HeadOptions, RegistryLineBuilder};
#[test]
fn catalog_custody_keeps_future_and_later_revoked_servers_without_current_authority() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            valid_through: Some(1000),
            ..Default::default()
        },
    );
    let server = line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::ServerReceipt,
            marker: 0x71,
            effective_from: Some(400),
        },
        HeadOptions {
            effective_from: Some(400),
            valid_through: Some(1000),
            ..Default::default()
        },
    );
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let key = state::verification_state_key(anchor.organization_id());
    let mut store = state::EphemeralTrustStateStore::new(key, UnixMillis::new(800));
    let trust = verify_trust(
        &anchor,
        &line.source(),
        load_trust_state(&mut store, key).unwrap(),
    )
    .unwrap();
    let complete = verify_catalog_custody_authority(&trust).unwrap();
    assert!(complete.registry_head_hash() == server.object_hash);
    assert!(
        complete
            .known_certificate_fields()
            .any(|(hash, _)| hash.as_bytes() == server.direct_object_hash.unwrap().as_bytes())
    );
    let revoked = line.push(
        ActionSpec::Revoke {
            target_kind: 2,
            object_hash: server.direct_object_hash.unwrap(),
        },
        HeadOptions {
            effective_from: Some(500),
            valid_through: Some(1000),
            ..Default::default()
        },
    );
    let trust = verify_trust(
        &anchor,
        &line.source(),
        load_trust_state(&mut store, key).unwrap(),
    )
    .unwrap();
    let complete = verify_catalog_custody_authority(&trust).unwrap();
    assert!(complete.registry_head_hash() == revoked.object_hash);
    assert!(
        complete
            .known_certificate_fields()
            .any(|(hash, _)| hash.as_bytes() == server.direct_object_hash.unwrap().as_bytes()),
        "revocation cannot shrink custody"
    );
}

#[test]
fn complete_catalog_refuses_empty_gapped_forked_or_invalid_signed_history() {
    for fault in 0..4 {
        let mut line = RegistryLineBuilder::new();
        if fault != 0 {
            line.push(
                ActionSpec::Policy {
                    policy_version: None,
                    previous_policy_hash: None,
                    effective_from: None,
                },
                HeadOptions {
                    valid_through: Some(1000),
                    ..Default::default()
                },
            );
            line.push(
                ActionSpec::Device {
                    kind: ea_format::CertificateKindV1::Reader,
                    marker: 0x72,
                    effective_from: Some(201),
                },
                HeadOptions {
                    registry_version: Some(if fault == 1 {
                        3
                    } else if fault == 2 {
                        1
                    } else {
                        2
                    }),
                    effective_from: Some(201),
                    valid_through: Some(1000),
                    corrupt_direct_authorization_signature: fault == 3,
                    ..Default::default()
                },
            );
        }
        let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
        let key = state::verification_state_key(anchor.organization_id());
        let mut store = state::EphemeralTrustStateStore::new(key, UnixMillis::new(800));
        let trust = verify_trust(
            &anchor,
            &line.source(),
            load_trust_state(&mut store, key).unwrap(),
        )
        .unwrap();
        assert!(
            verify_catalog_custody_authority(&trust).is_err(),
            "fault {fault}"
        );
    }
}
