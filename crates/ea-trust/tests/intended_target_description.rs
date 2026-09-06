mod support;

use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, TrustPayloadV1, decode_exact_object};
use ea_trust::describe_intended_trust_target;
use ea_types::{ChainSequence, Hash32, ObjectHash};
use support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

#[test]
fn description_matches_the_actual_signed_authorization_and_ignores_its_reference() {
    let mut line = RegistryLineBuilder::new();
    let (hash, target) = line.prepare_unsigned(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let trust = line.verified(Pin::None);
    let ParsedArchiveObject::Trust(auth) =
        decode_exact_object(line.exact_object_bytes(hash)).unwrap()
    else {
        panic!("authorization");
    };
    let DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) =
        auth.value().decoded_payload().unwrap()
    else {
        panic!("admin authorization");
    };
    let description =
        describe_intended_trust_target(&trust, None, &target, ChainSequence::new(1)).unwrap();
    assert_eq!(description.action_code(), fields.action_code);
    assert!(description.organization_id() == fields.organization_id);
    assert!(description.authorized_core_hash() == fields.authorized_trust_core_hash);
    let DecodedTrustPayloadV1::Policy(policy) = target.decoded_payload().unwrap() else {
        panic!("policy");
    };
    let changed_reference =
        TrustPayloadV1::policy(policy.fields().clone(), ObjectHash::from(Hash32::ZERO)).unwrap();
    assert!(
        describe_intended_trust_target(&trust, None, &changed_reference, ChainSequence::new(1))
            .unwrap()
            .authorized_core_hash()
            == fields.authorized_trust_core_hash
    );
    let mut changed = policy.fields().clone();
    changed.policy_version += 1;
    let changed = TrustPayloadV1::policy(changed, hash).unwrap();
    assert!(
        describe_intended_trust_target(&trust, None, &changed, ChainSequence::new(1))
            .unwrap()
            .authorized_core_hash()
            != fields.authorized_trust_core_hash
    );
}

#[test]
fn an_authorization_is_not_itself_an_authorizable_target() {
    let mut line = RegistryLineBuilder::new();
    let (hash, _) = line.prepare_unsigned(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions::default(),
    );
    let trust = line.verified(Pin::None);
    let ParsedArchiveObject::Trust(auth) =
        decode_exact_object(line.exact_object_bytes(hash)).unwrap()
    else {
        panic!("authorization");
    };
    let payload =
        TrustPayloadV1::from_exact_digest_input(auth.value().exact_digest_input()).unwrap();
    assert!(describe_intended_trust_target(&trust, None, &payload, ChainSequence::new(1)).is_err());
}
