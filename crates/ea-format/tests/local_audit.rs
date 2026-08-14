use ea_crypto::{ContentType, CoseSigner, ProtectedHeader, SecretBytes};
use ea_format::{
    ClockReleaseJustificationV1, IndependentTimeKindV1, LocalAuditOutcomeV1,
    decode_clock_release_audit,
};
use ea_types::{
    CertificateHash, DeviceId, EventId, KeyThumbprint, ObjectHash, OrganizationId, RegistryVersion,
    UnixMillis,
};
use minicbor::{Decoder, Encoder, data::Tag};

#[derive(Clone, Copy)]
enum ContextShape {
    ExactTen,
    LegacySix,
    WrongNine,
}

#[derive(Clone)]
struct Fixture {
    action: u8,
    outcome: u8,
    independent_reference_tag: u8,
    justification: u8,
    issued_at: i64,
    expires_at: i64,
    binding_present: bool,
    empty_extensions: bool,
    context_shape: ContextShape,
}

impl Fixture {
    fn valid() -> Self {
        Self {
            action: 6,
            outcome: 1,
            independent_reference_tag: 0,
            justification: 0,
            issued_at: 1_000,
            expires_at: 1_200,
            binding_present: true,
            empty_extensions: true,
            context_shape: ContextShape::ExactTen,
        }
    }
}

fn signer() -> CoseSigner {
    CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)))
}

fn core(fixture: &Fixture) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(12)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[0x00; 16])
        .unwrap()
        .bytes(&[0x10; 16])
        .unwrap()
        .bytes(&[0x20; 16])
        .unwrap();
    if fixture.binding_present {
        encoder.bytes(&[0x30; 32]).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder
        .bytes(&[0x40; 32])
        .unwrap()
        .u8(fixture.action)
        .unwrap()
        .u8(fixture.outcome)
        .unwrap()
        .i64(1_100)
        .unwrap()
        .array(2)
        .unwrap();
    if fixture.action == 5 {
        encoder
            .u8(3)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&[0x50; 32])
            .unwrap()
            .u64(0)
            .unwrap();
    } else {
        encoder.u8(2).unwrap();
        match fixture.context_shape {
            ContextShape::ExactTen => {
                encoder
                    .array(10)
                    .unwrap()
                    .i64(1_000)
                    .unwrap()
                    .i64(1_100)
                    .unwrap()
                    .u64(100)
                    .unwrap()
                    .u64(7)
                    .unwrap()
                    .bytes(&[0xa0; 32])
                    .unwrap()
                    .bytes(&[0xb0; 32])
                    .unwrap()
                    .array(3)
                    .unwrap()
                    .u8(fixture.independent_reference_tag)
                    .unwrap()
                    .bytes(&[0xc0; 32])
                    .unwrap()
                    .i64(900)
                    .unwrap()
                    .u8(fixture.justification)
                    .unwrap()
                    .i64(fixture.issued_at)
                    .unwrap()
                    .i64(fixture.expires_at)
                    .unwrap();
            }
            ContextShape::LegacySix => {
                encoder
                    .array(6)
                    .unwrap()
                    .i64(1_000)
                    .unwrap()
                    .i64(1_100)
                    .unwrap()
                    .u64(100)
                    .unwrap()
                    .u8(fixture.justification)
                    .unwrap()
                    .i64(fixture.issued_at)
                    .unwrap()
                    .i64(fixture.expires_at)
                    .unwrap();
            }
            ContextShape::WrongNine => {
                encoder
                    .array(9)
                    .unwrap()
                    .i64(1_000)
                    .unwrap()
                    .i64(1_100)
                    .unwrap()
                    .u64(100)
                    .unwrap()
                    .u64(7)
                    .unwrap()
                    .bytes(&[0xa0; 32])
                    .unwrap()
                    .bytes(&[0xb0; 32])
                    .unwrap()
                    .array(3)
                    .unwrap()
                    .u8(fixture.independent_reference_tag)
                    .unwrap()
                    .bytes(&[0xc0; 32])
                    .unwrap()
                    .i64(900)
                    .unwrap()
                    .u8(fixture.justification)
                    .unwrap()
                    .i64(fixture.issued_at)
                    .unwrap();
            }
        }
    }
    encoder
        .bytes(&[0xd0; 32])
        .unwrap()
        .array(if fixture.empty_extensions { 0 } else { 1 })
        .unwrap();
    if !fixture.empty_extensions {
        encoder.u8(0).unwrap();
    }
    bytes
}

fn wrapper(exact_core: &[u8], exact_cose: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes).array(2).unwrap();
    bytes.extend_from_slice(exact_core);
    bytes.extend_from_slice(exact_cose);
    bytes
}

fn signed_wrapper(fixture: &Fixture) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let exact_core = core(fixture);
    let exact_cose = signer().sign_local_audit(&exact_core).unwrap();
    let exact_wrapper = wrapper(&exact_core, &exact_cose);
    (exact_wrapper, exact_core, exact_cose)
}

fn cose_with_matching_payload(template: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut decoder = Decoder::new(template);
    assert_eq!(decoder.tag().unwrap().as_u64(), 18);
    assert_eq!(decoder.array().unwrap(), Some(4));
    let protected = decoder.bytes().unwrap().to_vec();
    decoder.skip().unwrap();
    decoder.bytes().unwrap();
    let signature = decoder.bytes().unwrap().to_vec();

    let mut exact = Vec::new();
    Encoder::new(&mut exact)
        .tag(Tag::new(18))
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&protected)
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(&signature)
        .unwrap();
    exact
}

fn structural_cose(protected: &[u8], payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut exact = Vec::new();
    Encoder::new(&mut exact)
        .tag(Tag::new(18))
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(protected)
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(signature)
        .unwrap();
    exact
}

fn wrapper_with_matching_opaque_cose(core: &[u8], template_cose: &[u8]) -> Vec<u8> {
    wrapper(core, &cose_with_matching_payload(template_cose, core))
}

fn exact_signature(exact_cose: &[u8]) -> [u8; 64] {
    let mut decoder = Decoder::new(exact_cose);
    assert_eq!(decoder.tag().unwrap().as_u64(), 18);
    assert_eq!(decoder.array().unwrap(), Some(4));
    decoder.bytes().unwrap();
    decoder.skip().unwrap();
    decoder.bytes().unwrap();
    decoder.bytes().unwrap().try_into().unwrap()
}

fn typed_id<T: TryFrom<&'static [u8]>>(bytes: &'static [u8]) -> T
where
    T::Error: core::fmt::Debug,
{
    T::try_from(bytes).unwrap()
}

#[test]
fn clock_release_view_exposes_every_field_and_all_exact_byte_regions() {
    let (bytes, exact_core, exact_cose) = signed_wrapper(&Fixture::valid());
    let audit = decode_clock_release_audit(&bytes).unwrap();

    assert!(audit.event_id() == typed_id::<EventId>(&[0x00; 16]));
    assert!(audit.organization_id() == typed_id::<OrganizationId>(&[0x10; 16]));
    assert!(audit.target_device_id() == typed_id::<DeviceId>(&[0x20; 16]));
    assert!(audit.admin_operator_binding_object_hash() == typed_id::<ObjectHash>(&[0x30; 32]));
    assert!(audit.signer_certificate_object_hash() == typed_id::<ObjectHash>(&[0x40; 32]));
    assert_eq!(audit.outcome(), LocalAuditOutcomeV1::Accepted);
    assert!(audit.effective_now() == UnixMillis::new(1_100));
    assert_eq!(audit.nonce(), &[0xd0; 32]);
    assert_eq!(audit.exact_core(), exact_core);
    assert_eq!(audit.exact_cose(), exact_cose);
    assert_eq!(audit.signature_bytes(), &exact_signature(&exact_cose));

    let context = audit.context();
    assert!(context.trusted_time_floor() == UnixMillis::new(1_000));
    assert!(context.observed_os_wall_clock() == UnixMillis::new(1_100));
    assert_eq!(context.max_future_clock_skew_ms(), 100);
    assert!(context.registry_version() == RegistryVersion::new(7));
    assert!(context.registry_head_hash() == typed_id::<ObjectHash>(&[0xa0; 32]));
    assert!(context.guard_policy_object_hash() == typed_id::<ObjectHash>(&[0xb0; 32]));
    assert_eq!(
        context.justification(),
        ClockReleaseJustificationV1::OperatorVerifiedWallClock
    );
    assert!(context.issued_at() == UnixMillis::new(1_000));
    assert!(context.expires_at() == UnixMillis::new(1_200));

    let reference = context.independent_reference();
    assert_eq!(reference.kind(), IndependentTimeKindV1::Receipt);
    assert!(reference.object_hash() == typed_id::<ObjectHash>(&[0xc0; 32]));
    assert!(reference.verified_time() == UnixMillis::new(900));
}

#[test]
fn clock_release_format_accepts_all_closed_outcomes_references_and_justifications() {
    let outcomes = [
        LocalAuditOutcomeV1::Failed,
        LocalAuditOutcomeV1::Accepted,
        LocalAuditOutcomeV1::Completed,
    ];
    let kinds = [
        IndependentTimeKindV1::Receipt,
        IndependentTimeKindV1::Checkpoint,
        IndependentTimeKindV1::Tsa,
    ];
    let justifications = [
        ClockReleaseJustificationV1::OperatorVerifiedWallClock,
        ClockReleaseJustificationV1::PlatformTimeSourceRecovery,
        ClockReleaseJustificationV1::HardwareClockMaintenance,
    ];

    for wire_value in 0_u8..=2 {
        let mut fixture = Fixture::valid();
        fixture.outcome = wire_value;
        fixture.independent_reference_tag = wire_value;
        fixture.justification = wire_value;
        let (bytes, _, _) = signed_wrapper(&fixture);
        let audit = decode_clock_release_audit(&bytes).unwrap();
        assert_eq!(audit.outcome(), outcomes[usize::from(wire_value)]);
        assert_eq!(
            audit.context().independent_reference().kind(),
            kinds[usize::from(wire_value)]
        );
        assert_eq!(
            audit.context().justification(),
            justifications[usize::from(wire_value)]
        );
    }
}

#[test]
fn corrupt_opaque_signature_and_expired_at_effective_now_remain_structurally_decodable() {
    let mut fixture = Fixture::valid();
    fixture.expires_at = 1_001;
    let exact_core = core(&fixture);
    let mut exact_cose = signer().sign_local_audit(&exact_core).unwrap();
    *exact_cose.last_mut().unwrap() ^= 0xff;
    let bytes = wrapper(&exact_core, &exact_cose);

    let audit = decode_clock_release_audit(&bytes).unwrap();
    assert!(audit.effective_now() == UnixMillis::new(1_100));
    assert!(audit.context().expires_at() == UnixMillis::new(1_001));
    assert_eq!(audit.signature_bytes(), &exact_signature(&exact_cose));
}

#[test]
fn clock_release_decoder_rejects_non_clock_wrapper_shapes_and_trailing_items() {
    let valid = Fixture::valid();
    let (valid_wrapper, valid_core, valid_cose) = signed_wrapper(&valid);

    let mut wrong_action = valid.clone();
    wrong_action.action = 5;
    let mut null_binding = valid.clone();
    null_binding.binding_present = false;
    let mut nonempty_extensions = valid;
    nonempty_extensions.empty_extensions = false;
    let mut trailing = valid_wrapper.clone();
    trailing.push(0);
    let mut nonminimal_outer_array = vec![0x98, 0x02];
    nonminimal_outer_array.extend_from_slice(&valid_wrapper[1..]);

    let (_, wrong_action_core, wrong_action_cose) = signed_wrapper(&wrong_action);
    let (_, null_binding_core, null_binding_cose) = signed_wrapper(&null_binding);
    let nonempty_extensions_core = core(&nonempty_extensions);
    let nonempty_extensions_wrapper =
        wrapper_with_matching_opaque_cose(&nonempty_extensions_core, &valid_cose);

    let mut wrong_arity = Vec::new();
    Encoder::new(&mut wrong_arity).array(3).unwrap();
    wrong_arity.extend_from_slice(&valid_core);
    wrong_arity.extend_from_slice(&valid_cose);
    Encoder::new(&mut wrong_arity).null().unwrap();

    for invalid in [
        wrapper(&wrong_action_core, &wrong_action_cose),
        wrapper(&null_binding_core, &null_binding_cose),
        nonempty_extensions_wrapper,
        trailing,
        nonminimal_outer_array,
        wrong_arity,
        wrapper(&valid_core, &[]),
    ] {
        assert!(decode_clock_release_audit(&invalid).is_err());
    }
}

#[test]
fn clock_release_decoder_rejects_open_tags_outcomes_and_wrong_context_lengths() {
    let valid = Fixture::valid();
    let (_, _, template_cose) = signed_wrapper(&valid);

    let mut outcome = valid.clone();
    outcome.outcome = 3;
    let mut reference = valid.clone();
    reference.independent_reference_tag = 3;
    let mut justification = valid.clone();
    justification.justification = 3;
    let mut legacy = valid.clone();
    legacy.context_shape = ContextShape::LegacySix;
    let mut wrong_nine = valid;
    wrong_nine.context_shape = ContextShape::WrongNine;

    for invalid_core in [
        core(&outcome),
        core(&reference),
        core(&justification),
        core(&legacy),
        core(&wrong_nine),
    ] {
        let invalid = wrapper_with_matching_opaque_cose(&invalid_core, &template_cose);
        assert!(decode_clock_release_audit(&invalid).is_err());
    }
}

#[test]
fn clock_release_decoder_rejects_cose_content_payload_and_certificate_mismatches() {
    let valid = Fixture::valid();
    let (_, valid_core, valid_cose) = signed_wrapper(&valid);

    let mut other_valid = valid;
    other_valid.outcome = 2;
    let other_valid_core = core(&other_valid);
    let payload_mismatch = wrapper(&other_valid_core, &valid_cose);

    let key_thumbprint = typed_id::<KeyThumbprint>(&[0x42; 32]);
    let wrong_certificate = typed_id::<CertificateHash>(&[0x41; 32]);
    let certificate_mismatch_protected = ProtectedHeader::normal(
        ContentType::LocalAuditCbor,
        key_thumbprint,
        wrong_certificate,
    )
    .to_deterministic_cbor();
    let certificate_mismatch = wrapper(
        &valid_core,
        &structural_cose(&certificate_mismatch_protected, &valid_core, &[0x77; 64]),
    );

    let matching_certificate = typed_id::<CertificateHash>(&[0x40; 32]);
    let content_mismatch_protected = ProtectedHeader::normal(
        ContentType::CheckpointCbor,
        key_thumbprint,
        matching_certificate,
    )
    .to_deterministic_cbor();
    let content_mismatch = wrapper(
        &valid_core,
        &structural_cose(&content_mismatch_protected, &valid_core, &[0x78; 64]),
    );

    for invalid in [payload_mismatch, certificate_mismatch, content_mismatch] {
        assert!(decode_clock_release_audit(&invalid).is_err());
    }
}
