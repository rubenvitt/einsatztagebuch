#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;
use ea_trust::*;
use ea_types::*;
use support::{ActionSpec, HeadOptions, RegistryLineBuilder};

#[test]
fn a_known_signed_successor_exclusively_limits_the_old_historical_sequence() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let old = line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::HistoricalGrantAuthority,
            marker: 0x75,
            effective_from: None,
        },
        HeadOptions {
            valid_through: Some(1000),
            ..Default::default()
        },
    );
    let revoked = line.push(
        ActionSpec::Revoke {
            target_kind: 0,
            object_hash: old.direct_object_hash.unwrap(),
        },
        HeadOptions {
            effective_from: Some(201),
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
    let certificate = CertificateHash::from(old.direct_object_hash.unwrap());
    for sequence in [old.effective_from, ChainSequence::new(200)] {
        let historical =
            verify_historical_registry_authority(&trust, old.version, old.object_hash, sequence)
                .unwrap();
        assert!(historical.active_certificate_fields(certificate).is_some());
    }
    let current = verify_historical_registry_authority(
        &trust,
        revoked.version,
        revoked.object_hash,
        revoked.effective_from,
    )
    .unwrap();
    assert!(current.active_certificate_fields(certificate).is_none());
    assert!(
        matches!(
            verify_historical_registry_authority(
                &trust,
                old.version,
                old.object_hash,
                revoked.effective_from
            ),
            Err(RegistryError::SequenceLease)
        ),
        "the exact old hash cannot bypass a successor effective at this sequence"
    );
}

#[test]
fn expired_historical_authority_preserves_then_active_roles_without_authorizing_current_actions() {
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            not_after: UnixMillis::new(500),
            ..Default::default()
        },
    );
    let old = line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::HistoricalGrantAuthority,
            marker: 0x75,
            effective_from: None,
        },
        HeadOptions {
            not_after: UnixMillis::new(500),
            ..Default::default()
        },
    );
    let cert = CertificateHash::from(old.direct_object_hash.unwrap());
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let key = state::verification_state_key(anchor.organization_id());
    let mut store = state::EphemeralTrustStateStore::new(key, UnixMillis::new(800));
    let mut stale = false;
    for _ in 0..=line.heads().len() + 1 {
        let trust = verify_trust(
            &anchor,
            &line.source(),
            load_trust_state(&mut store, key).unwrap(),
        )
        .unwrap();
        let candidate = verify_registry_candidate(&trust, old.effective_from).unwrap();
        let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(800), &[]).unwrap();
        match select_registry_head(candidate, time, None) {
            Err(RegistryError::Stale) => {
                stale = true;
                break;
            }
            Ok(RegistrySelectionOutcome::Advanced(_)) => {}
            _ => panic!("expired head cannot become current action authority"),
        }
    }
    assert!(stale);
    let revoked = line.push(
        ActionSpec::Revoke {
            target_kind: 0,
            object_hash: old.direct_object_hash.unwrap(),
        },
        HeadOptions::default(),
    );
    let trust = verify_trust(
        &anchor,
        &line.source(),
        load_trust_state(&mut store, key).unwrap(),
    )
    .unwrap();
    let historical = verify_historical_registry_authority(
        &trust,
        old.version,
        old.object_hash,
        old.effective_from,
    )
    .unwrap();
    assert!(
        historical.active_certificate_fields(cert).is_some(),
        "a later revocation does not erase prior authority"
    );
    let current = verify_historical_registry_authority(
        &trust,
        revoked.version,
        revoked.object_hash,
        revoked.effective_from,
    )
    .unwrap();
    assert!(
        current.active_certificate_fields(cert).is_none(),
        "revocation effective at the bound sequence is enforced"
    );
    assert!(
        verify_historical_registry_authority(
            &trust,
            old.version,
            ObjectHash::from(Hash32::ZERO),
            old.effective_from
        )
        .is_err()
    );
    assert!(
        verify_historical_registry_authority(
            &trust,
            old.version,
            old.object_hash,
            ChainSequence::new(u64::MAX)
        )
        .is_err()
    );
}
