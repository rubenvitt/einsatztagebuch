mod support;
use ea_crypto::{VerificationContext, object_hash, parse_cose_sign1, verify_cose_sign1};
use support::*;

fn core(
    f: &Fixture,
    domain: &str,
    version: u64,
    report: &[u8],
    hash: &[u8],
    extra: bool,
) -> Vec<u8> {
    let head = f.head();
    let fields = f.fields();
    let mut bytes = Vec::new();
    let mut e = minicbor::Encoder::new(&mut bytes);
    e.array(if extra { 17 } else { 16 }).unwrap();
    e.str(domain).unwrap().u64(version).unwrap();
    e.bytes(fields.organization_id.as_bytes()).unwrap();
    e.bytes(head.chain_id().as_bytes()).unwrap();
    e.bytes(fields.destruction_id.as_bytes()).unwrap();
    e.bytes(object_hash(&f.authorization()).as_bytes()).unwrap();
    e.bytes(&[0x72; 32])
        .unwrap()
        .bytes(hash)
        .unwrap()
        .bytes(report)
        .unwrap();
    e.u64(head.registry_version().get())
        .unwrap()
        .bytes(head.registry_head_hash().as_bytes())
        .unwrap();
    e.u64(head.proposed_sequence().get()).unwrap();
    e.u64(head.registry_version().get())
        .unwrap()
        .bytes(head.registry_head_hash().as_bytes())
        .unwrap();
    e.u64(head.proposed_sequence().get())
        .unwrap()
        .i64(NOW)
        .unwrap();
    if extra {
        e.null().unwrap();
    }
    bytes
}
const DOMAIN: &str = "EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v1";

#[test]
fn shared_read_only_parser_preserves_every_execution_and_authorization_binding() {
    let f = Fixture::new(true, true, false);
    let bytes = core(&f, DOMAIN, 1, b"{}", object_hash(b"{}").as_bytes(), false);
    let parsed = ea_crypto::decode_destruction_preflight_core(&bytes).unwrap();
    assert_eq!(
        parsed.organization_id,
        *f.fields().organization_id.as_bytes()
    );
    assert_eq!(parsed.chain_id, *f.head().chain_id().as_bytes());
    assert_eq!(parsed.destruction_id, *f.fields().destruction_id.as_bytes());
    assert_eq!(
        parsed.authorization_hash,
        *object_hash(&f.authorization()).as_bytes()
    );
    assert_eq!(parsed.inventory_hash, [0x72; 32]);
    assert_eq!(parsed.report_hash, *object_hash(b"{}").as_bytes());
    assert_eq!(parsed.report_json, b"{}");
    assert_eq!(
        parsed.authorization_registry,
        f.head().registry_version().get()
    );
    assert_eq!(
        parsed.authorization_head,
        *f.head().registry_head_hash().as_bytes()
    );
    assert_eq!(
        parsed.authorization_sequence,
        f.head().proposed_sequence().get()
    );
    assert_eq!(parsed.execution_registry, f.head().registry_version().get());
    assert_eq!(
        parsed.execution_head,
        *f.head().registry_head_hash().as_bytes()
    );
    assert_eq!(
        parsed.execution_sequence,
        f.head().proposed_sequence().get()
    );
    assert_eq!(parsed.observed_effective_now, NOW);
}

#[test]
fn internal_preflight_signature_binds_exact_report_and_current_deletion_authority() {
    let f = Fixture::new(true, true, false);
    let bytes = core(&f, DOMAIN, 1, b"{}", object_hash(b"{}").as_bytes(), false);
    let signature = trust::authorized_device_signer()
        .sign_destruction_preflight_report(f.deletion, &bytes)
        .unwrap();
    let context = VerificationContext::destruction_preflight_report(&bytes, f.deletion).unwrap();
    assert_eq!(
        parse_cose_sign1(&signature, &[])
            .unwrap()
            .content_type()
            .as_str(),
        "application/vnd.einsatzarchiv.destruction-preflight-digest"
    );
    verify_cose_sign1(&signature, &f.head(), &context).unwrap();
    let changed = core(
        &f,
        DOMAIN,
        1,
        b"{\"changed\":true}",
        object_hash(b"{\"changed\":true}").as_bytes(),
        false,
    );
    assert!(
        verify_cose_sign1(
            &signature,
            &f.head(),
            &VerificationContext::destruction_preflight_report(&changed, f.deletion).unwrap()
        )
        .is_err()
    );
    let approver_signature = trust::authorized_device_signer()
        .sign_destruction_preflight_report(f.approvers[0], &bytes)
        .unwrap();
    assert!(
        verify_cose_sign1(
            &approver_signature,
            &f.head(),
            &VerificationContext::destruction_preflight_report(&bytes, f.approvers[0]).unwrap()
        )
        .is_err()
    );
}

#[test]
fn internal_preflight_profile_rejects_wrong_domain_version_arity_hash_and_trailing_bytes() {
    let f = Fixture::new(true, true, false);
    let hash = object_hash(b"{}");
    let mut cases = vec![
        core(
            &f,
            "EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v2",
            1,
            b"{}",
            hash.as_bytes(),
            false,
        ),
        core(&f, DOMAIN, 2, b"{}", hash.as_bytes(), false),
        core(&f, DOMAIN, 1, b"{}", hash.as_bytes(), true),
        core(&f, DOMAIN, 1, b"{}", &[0x12; 32], false),
    ];
    let mut trailing = core(&f, DOMAIN, 1, b"{}", hash.as_bytes(), false);
    trailing.push(0);
    cases.push(trailing);
    for bytes in cases {
        assert!(
            trust::authorized_device_signer()
                .sign_destruction_preflight_report(f.deletion, &bytes)
                .is_err()
        );
        assert!(VerificationContext::destruction_preflight_report(&bytes, f.deletion).is_err());
    }
}
