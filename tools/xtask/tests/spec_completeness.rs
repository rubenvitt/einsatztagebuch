#[test]
fn cddl_registers_every_v1_wire_type() {
    let archive = include_str!("../../../schemas/archive/v1/archive.cddl");
    let trust = include_str!("../../../schemas/archive/v1/trust.cddl");
    let evidence = include_str!("../../../schemas/archive/v1/evidence.cddl");
    for name in ["eip-v1", "eag-v1", "esr-v1", "ecp-v1", "etb-v1", "eds-v1"] {
        assert!(archive.contains(name), "missing {name}");
    }
    for subtype in [
        "root-certificate-core-v1",
        "device-certificate-core-v1",
        "operator-binding-core-v1",
        "organization-admin-authorization-v1",
        "registry-event-core-v1",
        "policy-core-v1",
        "writer-transition-core-v1",
        "grant-authorization-core-v1",
        "destruction-authorization-core-v1",
        "destruction-transition-core-v1",
        "deletion-attestation-core-v1",
    ] {
        assert!(trust.contains(subtype), "missing {subtype}");
    }
    for name in [
        "checkpoint-core-v1",
        "timestamp-evidence-v1",
        "renewal-core-v1",
    ] {
        assert!(evidence.contains(name), "missing {name}");
    }
    let audit = include_str!("../../../schemas/reports/v1/local-audit.cddl");
    for name in [
        "local-audit-event-v1",
        "stale-registry-context-v1",
        "clock-release-context-v1",
    ] {
        assert!(audit.contains(name), "missing {name}");
    }
}

#[test]
fn cddl_parser_accepts_the_complete_archive_and_audit_grammars() {
    let archive_bundle = [
        include_str!("../../../schemas/archive/v1/archive.cddl"),
        include_str!("../../../schemas/archive/v1/trust.cddl"),
        include_str!("../../../schemas/archive/v1/evidence.cddl"),
    ]
    .join("\n");
    cddl::pest_bridge::cddl_from_pest_str_checked(&archive_bundle)
        .expect("archive CDDL must parse with all references resolved");
    cddl::pest_bridge::cddl_from_pest_str_checked(include_str!(
        "../../../schemas/reports/v1/local-audit.cddl"
    ))
    .expect("local audit CDDL must parse with all references resolved");
}

fn validate_cbor(root: &str, cddl: &str, cbor: &[u8]) -> bool {
    let normalized = cddl.replace("#6.18(COSE-Sign1)", "COSE-Sign1");
    let fixture_grammar = if normalized.contains("COSE-Sign1 =") {
        normalized
    } else {
        format!("COSE-Sign1 = any\n{normalized}")
    };
    cddl_cat::validate_cbor_bytes(root, &fixture_grammar, cbor).is_ok()
}

fn archive_cddl() -> String {
    [
        include_str!("../../../schemas/archive/v1/archive.cddl"),
        include_str!("../../../schemas/archive/v1/trust.cddl"),
        include_str!("../../../schemas/archive/v1/evidence.cddl"),
    ]
    .join("\n")
}

fn checkpoint_core(include_domain: bool) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(if include_domain { 11 } else { 10 }).unwrap();
    encoder.u8(1).unwrap();
    if include_domain {
        encoder.str("EINSATZARCHIV-CHECKPOINT-v1").unwrap();
    }
    encoder.bytes(&[0; 16]).unwrap();
    encoder.bytes(&[1; 16]).unwrap();
    encoder.u8(1).unwrap();
    encoder.u8(2).unwrap();
    encoder.bytes(&[2; 32]).unwrap();
    encoder.bytes(&[3; 32]).unwrap();
    encoder.i64(4).unwrap();
    encoder.null().unwrap();
    encoder.array(0).unwrap();
    encoder.into_writer()
}

fn renewal_core(include_domain: bool) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(if include_domain { 8 } else { 7 }).unwrap();
    encoder.u8(1).unwrap();
    if include_domain {
        encoder.str("EINSATZARCHIV-EVIDENCE-RENEWAL-v1").unwrap();
    }
    encoder.bytes(&[0; 16]).unwrap();
    encoder.bytes(&[1; 16]).unwrap();
    encoder.bytes(&[2; 32]).unwrap();
    encoder.null().unwrap();
    encoder.array(1).unwrap();
    encoder.bytes(&[3; 32]).unwrap();
    encoder.array(0).unwrap();
    encoder.into_writer()
}

#[test]
fn evidence_cores_require_the_fixed_domain_at_position_one() {
    let evidence = include_str!("../../../schemas/archive/v1/evidence.cddl");

    assert!(validate_cbor(
        "checkpoint-core-v1",
        evidence,
        &checkpoint_core(true)
    ));
    assert!(!validate_cbor(
        "checkpoint-core-v1",
        evidence,
        &checkpoint_core(false)
    ));
    assert!(validate_cbor(
        "renewal-core-v1",
        evidence,
        &renewal_core(true)
    ));
    assert!(!validate_cbor(
        "renewal-core-v1",
        evidence,
        &renewal_core(false)
    ));
}

#[derive(Clone, Copy)]
enum TrustPayload {
    DirectRoot { has_previous: bool },
    AuthorizedRoot { has_previous: bool },
    Device { certificate_kind: u8 },
    GrantAuthorization,
    DestructionAuthorization,
}

fn encode_trust_payload(encoder: &mut minicbor::Encoder<Vec<u8>>, payload: TrustPayload) {
    match payload {
        TrustPayload::DirectRoot { has_previous } => {
            encode_root_certificate_core(encoder, has_previous);
        }
        TrustPayload::AuthorizedRoot { has_previous } => {
            encoder.array(2).unwrap();
            encode_root_certificate_core(encoder, has_previous);
            encoder.bytes(&[9; 32]).unwrap();
        }
        TrustPayload::Device { certificate_kind } => {
            encoder.array(13).unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[0; 16]).unwrap();
            encoder.bytes(&[1; 16]).unwrap();
            encoder.u8(certificate_kind).unwrap();
            encoder.bytes(&[2]).unwrap();
            encoder.null().unwrap();
            encoder.bytes(&[3; 32]).unwrap();
            encoder.null().unwrap();
            encoder.array(1).unwrap();
            encoder.str("organizationAdminApprove").unwrap();
            encoder.u8(0).unwrap();
            encoder.u8(0).unwrap();
            encoder.null().unwrap();
            encoder.array(0).unwrap();
        }
        TrustPayload::GrantAuthorization => {
            encoder.array(12).unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[0; 16]).unwrap();
            encoder.bytes(&[1; 16]).unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[2; 32]).unwrap();
            encoder.u8(1).unwrap();
            encoder.array(1).unwrap();
            encoder.bytes(&[3; 32]).unwrap();
            encoder.bytes(&[4; 32]).unwrap();
            encoder.bytes(&[5; 32]).unwrap();
            encoder.u8(1).unwrap();
            encoder.i64(10).unwrap();
            encoder.array(0).unwrap();
        }
        TrustPayload::DestructionAuthorization => {
            encoder.array(10).unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[0; 16]).unwrap();
            encoder.bytes(&[1; 16]).unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[2; 32]).unwrap();
            encoder.u8(1).unwrap();
            encoder.array(1).unwrap();
            encoder.array(2).unwrap();
            encoder.bytes(&[3; 32]).unwrap();
            encoder.u8(1).unwrap();
            encoder.u8(0).unwrap();
            encoder.u8(0).unwrap();
            encoder.array(0).unwrap();
        }
    }
}

fn encode_root_certificate_core(encoder: &mut minicbor::Encoder<Vec<u8>>, has_previous: bool) {
    encoder.array(7).unwrap();
    encoder.u8(1).unwrap();
    encoder.bytes(&[0; 16]).unwrap();
    encoder.bytes(&[1]).unwrap();
    encoder.bytes(&[2; 32]).unwrap();
    if has_previous {
        encoder.bytes(&[3; 32]).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder.u8(0).unwrap();
    encoder.array(0).unwrap();
}

fn etb_fixture(subtype: &str, payload: TrustPayload, signature_count: u64) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(5).unwrap();
    encoder.bytes(b"EA1\0").unwrap();
    encoder.u8(5).unwrap();
    encoder.u8(1).unwrap();
    encoder.array(0).unwrap();
    encoder.array(3).unwrap();
    encoder.str(subtype).unwrap();
    encode_trust_payload(&mut encoder, payload);
    encoder.array(signature_count).unwrap();
    for _ in 0..signature_count {
        encoder.null().unwrap();
    }
    encoder.into_writer()
}

#[test]
fn etb_cddl_correlates_subtype_payload_and_signature_cardinality() {
    let cddl = archive_cddl();

    assert!(validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "rootCertificate",
            TrustPayload::DirectRoot {
                has_previous: false
            },
            1
        )
    ));
    assert!(validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "deviceCertificate",
            TrustPayload::Device {
                certificate_kind: 2
            },
            1
        )
    ));
    assert!(!validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "deviceCertificate",
            TrustPayload::Device {
                certificate_kind: 0
            },
            1
        )
    ));
    assert!(validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture("grantAuthorization", TrustPayload::GrantAuthorization, 2)
    ));
    assert!(!validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture("grantAuthorization", TrustPayload::GrantAuthorization, 1)
    ));
    assert!(validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "destructionAuthorization",
            TrustPayload::DestructionAuthorization,
            2
        )
    ));
    assert!(!validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "destructionAuthorization",
            TrustPayload::DestructionAuthorization,
            1
        )
    ));
    assert!(!validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "grantAuthorization",
            TrustPayload::DestructionAuthorization,
            2
        )
    ));
}

#[test]
fn root_certificate_cddl_separates_bootstrap_from_authorized_rotation() {
    let cddl = archive_cddl();

    assert!(validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "rootCertificate",
            TrustPayload::DirectRoot {
                has_previous: false
            },
            1
        )
    ));
    assert!(!validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "rootCertificate",
            TrustPayload::DirectRoot { has_previous: true },
            1
        )
    ));
    assert!(validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "rootCertificate",
            TrustPayload::AuthorizedRoot { has_previous: true },
            1
        )
    ));
    assert!(!validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "rootCertificate",
            TrustPayload::AuthorizedRoot {
                has_previous: false
            },
            1
        )
    ));
    assert!(!validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "rootCertificate",
            TrustPayload::DirectRoot {
                has_previous: false
            },
            2
        )
    ));
}

#[derive(Clone, Copy)]
enum AuditContext {
    Generic,
    Export,
    Destruction,
}

fn audit_fixture(action: u8, context: AuditContext) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).unwrap();
    encoder.array(12).unwrap();
    encoder.u8(1).unwrap();
    encoder.bytes(&[0; 16]).unwrap();
    encoder.bytes(&[1; 16]).unwrap();
    encoder.bytes(&[2; 16]).unwrap();
    encoder.null().unwrap();
    encoder.bytes(&[3; 32]).unwrap();
    encoder.u8(action).unwrap();
    encoder.u8(2).unwrap();
    encoder.i64(4).unwrap();
    match context {
        AuditContext::Generic => {
            encoder.array(2).unwrap();
            encoder.u8(0).unwrap();
            encoder.null().unwrap();
        }
        AuditContext::Export => {
            encoder.array(2).unwrap();
            encoder.u8(3).unwrap();
            encoder.array(2).unwrap();
            encoder.bytes(&[4; 32]).unwrap();
            encoder.u8(1).unwrap();
        }
        AuditContext::Destruction => {
            encoder.array(2).unwrap();
            encoder.u8(7).unwrap();
            encoder.array(2).unwrap();
            encoder.bytes(&[4; 32]).unwrap();
            encoder.bytes(&[5; 32]).unwrap();
        }
    }
    encoder.bytes(&[6; 32]).unwrap();
    encoder.array(0).unwrap();
    encoder.null().unwrap();
    encoder.into_writer()
}

#[test]
fn local_audit_cddl_correlates_action_and_context_tag() {
    let cddl = include_str!("../../../schemas/reports/v1/local-audit.cddl");

    assert!(validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(0, AuditContext::Generic)
    ));
    assert!(!validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(0, AuditContext::Destruction)
    ));
    assert!(validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(5, AuditContext::Export)
    ));
    assert!(!validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(5, AuditContext::Generic)
    ));
}

#[test]
fn report_schemas_compile_and_reject_unknown_properties() {
    let verification_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/reports/v1/verification-report.schema.json"
    ))
    .unwrap();
    jsonschema::meta::validate(&verification_schema).unwrap();
    let verification = jsonschema::validator_for(&verification_schema).unwrap();
    let valid_report = serde_json::json!({
        "schemaId": "ea.verification-report/v1",
        "archiveObjectCount": 0,
        "entryPackageCount": 0,
        "destroyedEntryCount": 0,
        "chainHead": {
            "chainId": "00000000000000000000000000000000",
            "sequence": 0,
            "entryHash": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        "registryVersions": [],
        "objectResults": [],
        "authorizedDestructions": [],
        "gaps": [],
        "signatureErrors": [],
        "evidenceErrors": [],
        "decryptionErrors": [],
        "publicKeyThumbprints": [],
        "reportHash": "0000000000000000000000000000000000000000000000000000000000000000"
    });
    assert!(verification.is_valid(&valid_report));
    let mut unknown_root = valid_report.clone();
    unknown_root["unknown"] = serde_json::json!(true);
    assert!(!verification.is_valid(&unknown_root));
    let mut unknown_nested = valid_report;
    unknown_nested["chainHead"]["hostPath"] = serde_json::json!("/tmp/archive");
    assert!(!verification.is_valid(&unknown_nested));

    let inventory_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/reports/v1/key-inventory.schema.json"
    ))
    .unwrap();
    jsonschema::meta::validate(&inventory_schema).unwrap();
    let inventory = jsonschema::validator_for(&inventory_schema).unwrap();
    let valid_inventory = serde_json::json!({
        "schemaId": "ea.key-inventory/v1",
        "inventoryId": "00000000000000000000000000000000",
        "media": [{
            "mediumId": "recovery-medium-1",
            "keyRole": "recoveryRecipient",
            "expectedKeyThumbprint": "0000000000000000000000000000000000000000000000000000000000000000",
            "certificateObjectHash": "0000000000000000000000000000000000000000000000000000000000000000",
            "protectionProfile": "offlineEncryptedContainer",
            "testKind": "recoveryDecrypt"
        }]
    });
    assert!(inventory.is_valid(&valid_inventory));
    let mut unknown_medium_property = valid_inventory;
    unknown_medium_property["media"][0]["path"] = serde_json::json!("/Volumes/key");
    assert!(!inventory.is_valid(&unknown_medium_property));
}
