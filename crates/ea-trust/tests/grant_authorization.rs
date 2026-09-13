#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;
use ea_crypto::{CoseSigner, SecretBytes};
use ea_format::{
    CertificateKindV1, GrantAuthorizationFieldsV1, TrustObjectV1, TrustPayloadV1, encode_trust,
};
use ea_trust::*;
use ea_types::*;
use support::{ActionSpec, HeadOptions, RegistryLineBuilder};

fn fixture(same_person: bool) -> (Vec<u8>, SelectedRegistryHead) {
    fixture_with_capability(same_person, false, false)
}
fn fixture_with_capability(
    same_person: bool,
    missing_capability: bool,
    revoked: bool,
) -> (Vec<u8>, SelectedRegistryHead) {
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let mut certs = Vec::new();
    for marker in [0x71, 0x72] {
        let head = line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::KeyApprover,
                marker,
                effective_from: None,
            },
            HeadOptions {
                certificate_capabilities_override: missing_capability.then(Vec::new),
                authority_subject_id_override: same_person
                    .then(|| SubjectId::try_from(&[0x71; 16][..]).unwrap()),
                ..HeadOptions::default()
            },
        );
        certs.push(
            CertificateHash::try_from(head.direct_object_hash.unwrap().as_bytes().as_slice())
                .unwrap(),
        );
    }
    if revoked {
        line.push(
            ActionSpec::Revoke {
                target_kind: 0,
                object_hash: ObjectHash::try_from(certs[0].as_bytes().as_slice()).unwrap(),
            },
            HeadOptions::default(),
        );
    }
    let last = *line.heads().last().unwrap();
    let sequence = last.effective_from;
    let anchor = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let key = state::verification_state_key(anchor.organization_id());
    let mut store = state::EphemeralTrustStateStore::new(key, UnixMillis::new(800));
    let selected = loop {
        let snapshot = load_trust_state(&mut store, key).unwrap();
        let trust = verify_trust(&anchor, &line.source(), snapshot).unwrap();
        let candidate = verify_registry_candidate(&trust, sequence).unwrap();
        let time = prepare_local_time(&mut store, &candidate, UnixMillis::new(800), &[]).unwrap();
        match select_registry_head(candidate, time, None).unwrap() {
            RegistrySelectionOutcome::Selected(head) => break head,
            RegistrySelectionOutcome::Advanced(_) => {}
            RegistrySelectionOutcome::PendingFuture(_) => panic!("unexpected future"),
        }
    };
    let payload = TrustPayloadV1::grant_authorization(GrantAuthorizationFieldsV1 {
        authorization_id: AuthorizationId::try_from(&[0x81; 16][..]).unwrap(),
        organization_id: anchor.organization_id(),
        registry_version: selected.registry_version(),
        registry_head_hash: Hash32::try_from(selected.registry_head_hash().as_bytes().as_slice())
            .unwrap(),
        authorization_sequence: sequence.get(),
        entry_hashes: vec![EntryHash::from(support::hash32(0x82))],
        recipient_key_thumbprint: KeyThumbprint::from(support::hash32(0x83)),
        recipient_certificate_hash: CertificateHash::from(support::object_hash_marker(0x84)),
        expires_at: UnixMillis::new(800),
    })
    .unwrap();
    let signer = CoseSigner::from_secret(SecretBytes::new(support::device_signing_secret()));
    let signatures = certs
        .into_iter()
        .map(|cert| {
            signer
                .sign_historical_grant_approval_digest(cert, payload.exact_digest_input())
                .unwrap()
        })
        .collect();
    let bytes = encode_trust(&TrustObjectV1::new(payload, signatures).unwrap())
        .unwrap()
        .as_bytes()
        .to_vec();
    (bytes, selected)
}
#[test]
fn distinct_active_subjects_authorize_at_exact_expiry_boundary() {
    let (bytes, head) = fixture(false);
    assert!(
        verify_grant_authorization(&bytes, &head).is_ok(),
        "valid current authorization at expiresAt must verify"
    );
}
#[test]
fn rotations_of_one_person_cannot_supply_two_approvals() {
    let (bytes, head) = fixture(true);
    assert!(matches!(
        verify_grant_authorization(&bytes, &head),
        Err(GrantAuthorizationError::Insufficient)
    ));
}

#[test]
fn every_approver_needs_the_historical_grant_capability() {
    let (bytes, head) = fixture_with_capability(false, true, false);
    assert!(matches!(
        verify_grant_authorization(&bytes, &head),
        Err(GrantAuthorizationError::Unverifiable)
    ));
}
#[test]
fn one_approver_signature_cannot_be_removed_or_replaced() {
    let (bytes, head) = fixture(false);
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&bytes).unwrap()
    else {
        panic!()
    };
    let signatures = parsed.value().signatures();
    let payload = match parsed.value().decoded_payload().unwrap() {
        ea_format::DecodedTrustPayloadV1::GrantAuthorization(f) => {
            TrustPayloadV1::grant_authorization(f).unwrap()
        }
        _ => panic!(),
    };
    assert!(TrustObjectV1::new(payload.clone(), vec![signatures[0].clone()]).is_err());
    let duplicate = encode_trust(
        &TrustObjectV1::new(payload, vec![signatures[0].clone(), signatures[0].clone()]).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify_grant_authorization(duplicate.as_bytes(), &head),
        Err(GrantAuthorizationError::Insufficient)
    ));
}

#[test]
fn a_revoked_approver_cannot_authorize_with_a_still_valid_signature() {
    let (bytes, head) = fixture_with_capability(false, false, true);
    assert!(matches!(
        verify_grant_authorization(&bytes, &head),
        Err(GrantAuthorizationError::Unverifiable)
    ));
}
