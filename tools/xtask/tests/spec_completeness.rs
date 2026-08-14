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
    let protocol = protocol_cddl();
    for name in [
        "challenge-response-core-v1",
        "challenge-response-v1",
        "device-registration-request-core-v1",
        "device-registration-request-v1",
        "reader-ack-core-v1",
        "reader-ack-v1",
    ] {
        assert!(protocol.contains(name), "missing {name}");
    }
    let identity = identity_cddl();
    for name in ["canonical-os-account-id-v1", "os-account-context-v1"] {
        assert!(identity.contains(name), "missing {name}");
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

fn assert_contains_all(name: &str, source: &str, required: &[&str]) {
    for marker in required {
        assert!(source.contains(marker), "{name} is missing `{marker}`");
    }
}

fn normalized_prose(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn stage_one_plan() -> &'static str {
    include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    )
}

fn stage_one_task_six() -> &'static str {
    let (_, after_heading) = stage_one_plan()
        .split_once("### Task 6: Exact Archive Objects, Grants, Receipts, and Parser Limits")
        .expect("Stage-1 plan must retain Task 6");
    after_heading
        .split_once("### Task 7: Versioned Payload Schemas and Compatibility Registry")
        .expect("Stage-1 plan must retain Task 7 after Task 6")
        .0
}

fn assert_markers_in_order(name: &str, source: &str, markers: &[&str]) {
    let mut after = 0;
    for marker in markers {
        let relative = source[after..]
            .find(marker)
            .unwrap_or_else(|| panic!("{name} is missing ordered marker `{marker}`"));
        after += relative + marker.len();
    }
}

fn encoded_archive_prefix(object_type: u8) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(5).unwrap();
    encoder.bytes(b"EA1\0").unwrap();
    encoder.u8(object_type).unwrap();
    encoder.u8(1).unwrap();
    encoder.array(0).unwrap();
    encoder.into_writer()
}

#[test]
fn stage_one_overview_rejects_the_stale_one_mib_cbor_limit() {
    let overview = stage_one_plan()
        .split_once("### Task 1: Reproducible Monorepo and Dependency Decision Record")
        .expect("Stage-1 plan must retain Task 1")
        .0;

    assert!(
        !overview.contains("1 MiB per text/byte string"),
        "Stage-1 overview retained the stale CBOR item limit"
    );
    assert_contains_all(
        "Stage-1 overview",
        overview,
        &[
            "MAX_PLAINTEXT_BYTES_V1 = 1_048_576",
            "MAX_CBOR_TEXT_OR_BYTES_V1 = 1_048_592",
            "MAX_CIPHERTEXT_BYTES_V1 = 1_048_592",
            "MAX_CONTAINER_ITEMS_V1 = 10_000",
            "MAX_TOTAL_ITEMS_V1 = 10_000",
            "per top-level item",
        ],
    );
}

#[test]
fn task_six_requires_semantic_ciphertext_length_equality() {
    let task = &normalized_prose(stage_one_task_six());
    assert_contains_all(
        "Stage-1 Task 6",
        task,
        &[
            "MANIFEST_CIPHERTEXT_LENGTH_RULE_V1 = ACTUAL_EXACT_CIPHERTEXT_BSTR_LENGTH",
            "encoders MUST derive `manifestCore.ciphertext-length` from the exact ciphertext `bstr` bytes",
            "declared shorter than actual",
            "declared longer than actual",
            "both lengths remain within 16..1_048_592",
            "CDDL range checks do not establish this cross-field equality",
        ],
    );
}

#[test]
fn task_six_pins_exact_prefixes_caps_and_preflight_order() {
    let expected_prefixes = [
        [0x85, 0x44, 0x45, 0x41, 0x31, 0x00, 0x01, 0x01, 0x80],
        [0x85, 0x44, 0x45, 0x41, 0x31, 0x00, 0x02, 0x01, 0x80],
        [0x85, 0x44, 0x45, 0x41, 0x31, 0x00, 0x03, 0x01, 0x80],
        [0x85, 0x44, 0x45, 0x41, 0x31, 0x00, 0x04, 0x01, 0x80],
        [0x85, 0x44, 0x45, 0x41, 0x31, 0x00, 0x05, 0x01, 0x80],
        [0x85, 0x44, 0x45, 0x41, 0x31, 0x00, 0x06, 0x01, 0x80],
    ];
    for (object_type, expected) in (1_u8..=6).zip(expected_prefixes) {
        assert_eq!(encoded_archive_prefix(object_type), expected);
    }

    let task = stage_one_task_six();
    assert_markers_in_order(
        "Stage-1 Task-6 preflight",
        task,
        &[
            "PREFLIGHT_STAGE_1_GLOBAL_RAW_CAP",
            "PREFLIGHT_STAGE_2_EXACT_PREFIX",
            "PREFLIGHT_STAGE_3_FAMILY_RAW_CAP",
            "PREFLIGHT_STAGE_4_FULL_CBOR_AND_BODY",
        ],
    );
    let normalized_task = normalized_prose(task);
    assert_contains_all(
        "Stage-1 Task 6",
        &normalized_task,
        &[
            "EIP_PREFIX_V1 = 85 44 45 41 31 00 01 01 80",
            "EAG_PREFIX_V1 = 85 44 45 41 31 00 02 01 80",
            "ESR_PREFIX_V1 = 85 44 45 41 31 00 03 01 80",
            "ECP_PREFIX_V1 = 85 44 45 41 31 00 04 01 80",
            "ETB_PREFIX_V1 = 85 44 45 41 31 00 05 01 80",
            "EDS_PREFIX_V1 = 85 44 45 41 31 00 06 01 80",
            "(.eip, 2_097_152, 2_097_153)",
            "(.eag, 65_536, 65_537)",
            "(.esr, 65_536, 65_537)",
            "(.ecp, 4_194_304, 4_194_305)",
            "(.etb, 4_194_304, 4_194_305)",
            "(.eds, 262_144, 262_145)",
            "malformed oversized body MUST return the family raw-limit error before any full-CBOR/body error",
            "before any input-sized allocation",
        ],
    );
}

fn encode_manifest_core(encoder: &mut minicbor::Encoder<Vec<u8>>, ciphertext_length: u64) {
    encoder.array(16).unwrap();
    encoder.u8(1).unwrap();
    encoder.u8(1).unwrap();
    encoder.u8(1).unwrap();
    encoder.bytes(&[0; 16]).unwrap();
    encoder.bytes(&[1; 16]).unwrap();
    encoder.u8(0).unwrap();
    encoder.null().unwrap();
    encoder.bytes(&[2; 32]).unwrap();
    encoder.null().unwrap();
    encoder.u8(0).unwrap();
    encoder.bytes(&[3; 32]).unwrap();
    encoder.bytes(&[4; 32]).unwrap();
    encoder.str("EINSATZARCHIV-SUITE-1").unwrap();
    encoder.bytes(&[5; 12]).unwrap();
    encoder.u64(ciphertext_length).unwrap();
    encoder.array(0).unwrap();
}

fn eip_fixture(ciphertext_length: usize, declared_length: u64) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(5).unwrap();
    encoder.bytes(b"EA1\0").unwrap();
    encoder.u8(1).unwrap();
    encoder.u8(1).unwrap();
    encoder.array(0).unwrap();
    encoder.array(3).unwrap();
    encoder.array(2).unwrap();
    encode_manifest_core(&mut encoder, declared_length);
    encoder.bytes(&[6; 32]).unwrap();
    encoder.bytes(&vec![0; ciphertext_length]).unwrap();
    encoder.null().unwrap();
    encoder.into_writer()
}

#[test]
fn eip_cddl_enforces_the_exact_suite_v1_ciphertext_boundaries() {
    let cddl = archive_cddl();

    assert!(validate_cbor("eip-v1", &cddl, &eip_fixture(16, 16)));
    assert!(validate_cbor(
        "eip-v1",
        &cddl,
        &eip_fixture(1_048_592, 1_048_592)
    ));
    assert!(!validate_cbor("eip-v1", &cddl, &eip_fixture(15, 15)));
    assert!(!validate_cbor(
        "eip-v1",
        &cddl,
        &eip_fixture(1_048_593, 1_048_593)
    ));
}

#[test]
fn normative_sources_keep_plaintext_ciphertext_and_cbor_limits_distinct() {
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let addendum = include_str!(
        "../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md"
    );
    let required = [
        "MAX_PLAINTEXT_BYTES_V1 = 1_048_576",
        "AEAD_TAG_BYTES_V1 = 16",
        "MAX_CIPHERTEXT_BYTES_V1 = 1_048_592",
        "MAX_CBOR_TEXT_OR_BYTES_V1 = 1_048_592",
    ];
    assert_contains_all("design", design, &required);
    assert_contains_all("wire-format addendum", addendum, &required);

    let archive = include_str!("../../../schemas/archive/v1/archive.cddl");
    assert_contains_all(
        "archive CDDL",
        archive,
        &[
            "ciphertext-length-v1 = 16..1048592",
            "ciphertext-v1 = bstr .size (16..1048592)",
        ],
    );
}

#[test]
fn v1_archive_preflight_and_family_limits_are_non_relaxable() {
    let umbrella = include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md");
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let preflight = [
        "MAX_ARCHIVE_OBJECT_BYTES_V1 = 4_194_304",
        "FIXED_PREFIX_V1 = 85 44 45 41 31 00 TT 01 80",
        "TT = 01..06",
        "EIP_MAX_RAW_BYTES_V1 = 2_097_152",
        "EAG_MAX_RAW_BYTES_V1 = 65_536",
        "ESR_MAX_RAW_BYTES_V1 = 65_536",
        "ECP_MAX_RAW_BYTES_V1 = 4_194_304",
        "ETB_MAX_RAW_BYTES_V1 = 4_194_304",
        "EDS_MAX_RAW_BYTES_V1 = 262_144",
    ];
    assert_contains_all("umbrella plan", umbrella, &preflight);
    assert_contains_all("Stage-1 plan", stage_one, &preflight);
    assert_contains_all("design", design, &preflight);

    let public_seam = "pub fn decode_exact_object(bytes: &[u8])";
    assert_contains_all("umbrella plan", umbrella, &[public_seam]);
    assert_contains_all("Stage-1 plan", stage_one, &[public_seam]);
    assert!(!umbrella.contains("decode_exact_object(bytes: &[u8], limits:"));
    assert!(!stage_one.contains("decode_exact_object(bytes: &[u8], limits:"));
}

#[test]
fn destruction_target_order_and_entry_hash_identity_are_normative_everywhere() {
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let addendum = include_str!(
        "../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md"
    );
    let trust = include_str!("../../../schemas/archive/v1/trust.cddl");
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    let stage_five = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md"
    );
    let required = [
        "(entryHash bytes, chainSequence numeric)",
        "Target identity is entryHash",
        "repeated entryHash",
        "Equal chainSequence values with different entryHash values are not duplicates",
    ];
    for (name, source) in [
        ("design", design),
        ("wire-format addendum", addendum),
        ("Trust CDDL", trust),
        ("Stage-1 plan", stage_one),
        ("Stage-5 plan", stage_five),
    ] {
        let normalized = normalized_prose(source);
        assert_contains_all(name, &normalized, &required);
    }
}

#[test]
fn normative_sources_define_the_total_token_budget_and_counting_rule() {
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let addendum = include_str!(
        "../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md"
    );
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    let required = [
        "MAX_TOTAL_ITEMS_V1 = 10_000",
        "top-level item",
        "every map key and value separately",
        "every tag and tagged value",
        "tstr/bstr payload byte length does not add tokens",
        "container and total budgets are cumulative",
    ];
    assert_contains_all("design", &normalized_prose(design), &required);
    assert_contains_all(
        "wire-format addendum",
        &normalized_prose(addendum),
        &required,
    );
    assert_contains_all("Stage-1 plan", &normalized_prose(stage_one), &required);
    assert!(stage_one.contains("max_total_items: 10_000"));
}

fn protocol_cddl() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/protocol/v1/signed-protocol.cddl"),
    )
    .expect("normative signed-protocol CDDL must exist")
}

fn identity_cddl() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/identity/v1/os-account.cddl"),
    )
    .expect("normative OS-account CDDL must exist")
}

fn signed_protocol_fixture(kind: &str, wrap: bool) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    if wrap {
        encoder.array(2).unwrap();
    }
    match kind {
        "challenge" => {
            encoder.array(7).unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[0; 16]).unwrap();
            encoder.bytes(&[1; 32]).unwrap();
            encoder.i64(2).unwrap();
            encoder.i64(3).unwrap();
            encoder.bytes(&[4; 32]).unwrap();
            encoder.array(0).unwrap();
        }
        "enrollment" => {
            encoder.array(9).unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[0; 16]).unwrap();
            encoder.bytes(&[1; 16]).unwrap();
            encoder.u8(0).unwrap();
            encoder.bytes(&[2]).unwrap();
            encoder.null().unwrap();
            encoder.array(1).unwrap();
            encoder.u8(1).unwrap();
            encoder.array(1).unwrap();
            encoder.str("EINSATZARCHIV-SUITE-1").unwrap();
            encoder.array(0).unwrap();
        }
        "reader-ack" => {
            encoder.array(8).unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[0; 16]).unwrap();
            encoder.bytes(&[1; 16]).unwrap();
            encoder.bytes(&[2; 32]).unwrap();
            encoder.u8(3).unwrap();
            encoder.bytes(&[4; 32]).unwrap();
            encoder.i64(5).unwrap();
            encoder.array(0).unwrap();
        }
        _ => unreachable!(),
    }
    if wrap {
        encoder.null().unwrap();
    }
    encoder.into_writer()
}

#[test]
fn signed_protocol_cddl_validates_unsigned_cores_and_non_recursive_wrappers() {
    let cddl = protocol_cddl();
    cddl::pest_bridge::cddl_from_pest_str_checked(&cddl)
        .expect("signed protocol CDDL must parse with all references resolved");

    for (core_root, wrapper_root, kind) in [
        (
            "challenge-response-core-v1",
            "challenge-response-v1",
            "challenge",
        ),
        (
            "device-registration-request-core-v1",
            "device-registration-request-v1",
            "enrollment",
        ),
        ("reader-ack-core-v1", "reader-ack-v1", "reader-ack"),
    ] {
        let core = signed_protocol_fixture(kind, false);
        let wrapper = signed_protocol_fixture(kind, true);
        assert!(validate_cbor(core_root, &cddl, &core));
        assert!(!validate_cbor(core_root, &cddl, &wrapper));
        assert!(validate_cbor(wrapper_root, &cddl, &wrapper));
        assert!(!validate_cbor(wrapper_root, &cddl, &core));
    }
}

fn os_account_context_fixture(platform: u8, text_identifier: bool) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).unwrap();
    encoder.bytes(&[0; 16]).unwrap();
    encoder.bytes(&[1; 16]).unwrap();
    match platform {
        0 => {
            encoder.array(3).unwrap();
            encoder.u8(1).unwrap();
            encoder.u8(0).unwrap();
            encoder
                .bytes(&[
                    1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 232,
                    3, 0, 0,
                ])
                .unwrap();
        }
        1 | 2 => {
            encoder.array(4).unwrap();
            encoder.u8(1).unwrap();
            encoder.u8(platform).unwrap();
            if text_identifier {
                encoder.str("00000000-0000-0000-0000-000000000000").unwrap();
            } else {
                encoder.bytes(&[platform; 16]).unwrap();
            }
            encoder.u16(if platform == 1 { 501 } else { 1000 }).unwrap();
        }
        _ => unreachable!(),
    }
    encoder.into_writer()
}

#[test]
fn os_account_context_cddl_accepts_only_closed_binary_platform_forms() {
    let cddl = identity_cddl();
    for platform in 0..=2 {
        assert!(validate_cbor(
            "os-account-context-v1",
            &cddl,
            &os_account_context_fixture(platform, false)
        ));
    }
    assert!(!validate_cbor(
        "os-account-context-v1",
        &cddl,
        &os_account_context_fixture(1, true)
    ));
    assert!(!validate_cbor(
        "os-account-context-v1",
        &cddl,
        &os_account_context_fixture(2, true)
    ));
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
