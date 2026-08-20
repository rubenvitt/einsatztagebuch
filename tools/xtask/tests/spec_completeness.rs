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
        "archive-profile-migration-context-v1",
    ] {
        assert!(audit.contains(name), "missing {name}");
    }
    // Das eigenstaendige Dokument des Archivprofils. `validate_schemas` ist
    // eine harte Pfadliste; ein nicht registrierter Wurzelname waere hier
    // unsichtbar, und genau deshalb steht er hier.
    let archive_profile = archive_profile_cddl();
    for name in [
        "archive-backend-profile-core-v1",
        "archive-inventory-entry-v1",
        "archive-inventory-list-v1",
        "active-profile-pointer-core-v1",
    ] {
        assert!(archive_profile.contains(name), "missing {name}");
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

fn validate_payload_cbor(root: &str, cddl: &str, cbor: &[u8]) -> bool {
    validate_cbor(root, cddl, cbor) && ea_cbor::validate(cbor, ea_cbor::ParserLimits::V1).is_ok()
}

fn archive_cddl() -> String {
    [
        include_str!("../../../schemas/archive/v1/archive.cddl"),
        include_str!("../../../schemas/archive/v1/trust.cddl"),
        include_str!("../../../schemas/archive/v1/evidence.cddl"),
    ]
    .join("\n")
}

/// Die eigenstaendige Grammatik des Archivprofils.
///
/// Getrennt von [`archive_cddl`], weil das Dokument sich selbst genuegt und
/// nichts ausserhalb seiner selbst referenziert.
fn archive_profile_cddl() -> String {
    include_str!("../../../schemas/archive/v1/archive-profile.cddl").to_owned()
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

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_required(relative: &str) -> String {
    std::fs::read_to_string(workspace_root().join(relative))
        .unwrap_or_else(|error| panic!("required artifact {relative} is unreadable: {error}"))
}

fn decode_lower_hex_fixture(relative: &str) -> Vec<u8> {
    let source = read_required(relative);
    let hex = source
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("{relative} must end in exactly one newline"));
    assert!(!hex.is_empty(), "{relative} must not be empty");
    assert_eq!(
        hex.len() % 2,
        0,
        "{relative} must contain complete hexadecimal octets"
    );
    assert!(
        hex.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{relative} must contain lowercase hexadecimal only"
    );
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

fn encode_payload_header(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    record_type: &str,
    record_id: [u8; 16],
    schema_id: &str,
    finalized_at_device: i64,
    timezone: &str,
) {
    encoder.array(11).unwrap();
    encoder.str(record_type).unwrap();
    encoder.bytes(&record_id).unwrap();
    encoder.str(schema_id).unwrap();
    encoder.u8(1).unwrap();
    encoder.i64(finalized_at_device).unwrap();
    encoder.str(timezone).unwrap();
    encoder.array(6).unwrap();
    encoder.bytes(&[0x10; 16]).unwrap();
    encoder.bytes(&[0x20; 16]).unwrap();
    encoder.str("Erika Beispiel").unwrap();
    encoder.str("Einsatzleitung").unwrap();
    encoder.bytes(&[0x30; 32]).unwrap();
    encoder.bytes(&[0x40; 32]).unwrap();
    encoder.array(4).unwrap();
    encoder.u8(0).unwrap();
    encoder.str("writer-native").unwrap();
    encoder.u8(1).unwrap();
    encoder.null().unwrap();
    encoder.u8(7).unwrap();
    encoder.array(0).unwrap();
}

fn payload_fixture(record_type: &str) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match record_type {
        "genesis" => {
            encode_payload_header(
                &mut encoder,
                "genesis",
                [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x70, 0x08, 0x80, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10,
                ],
                "ea.genesis",
                1_700_000_000_000,
                "Europe/Berlin",
            );
            encoder.array(6).unwrap();
            encoder.bytes(&[0x10; 16]).unwrap();
            encoder.bytes(&[0x50; 16]).unwrap();
            encoder.bytes(&[0x60; 32]).unwrap();
            encoder.u8(1).unwrap();
            encoder.str("EINSATZARCHIV-SUITE-1").unwrap();
            encoder.bytes(&[0x70; 32]).unwrap();
        }
        "incident" => {
            encode_payload_header(
                &mut encoder,
                "incident",
                [
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x70, 0x18, 0x80, 0x1a, 0x1b, 0x1c, 0x1d,
                    0x1e, 0x1f, 0x20,
                ],
                "ea.incident",
                1_798_763_400_000,
                "America/New_York",
            );
            encoder.array(12).unwrap();
            encoder.str("2026-0001").unwrap();
            encoder.array(2).unwrap();
            encoder.i64(1_798_763_400_000).unwrap();
            encoder.i64(1_798_767_000_000).unwrap();
            encoder.array(3).unwrap();
            encoder.u8(1).unwrap();
            encoder.str("brand").unwrap();
            encoder.str("Brand groß").unwrap();
            encoder.array(3).unwrap();
            encoder.u8(1).unwrap();
            encoder.array(6).unwrap();
            for value in ["Hauptstraße", "7a", "10115", "Berlin", "BE", "DE"] {
                encoder.str(value).unwrap();
            }
            encoder.array(2).unwrap();
            encoder.i32(525_200_000).unwrap();
            encoder.i32(134_050_000).unwrap();
            encoder.array(2).unwrap();
            encoder.array(6).unwrap();
            encoder.u8(0).unwrap();
            encoder.str("person-42").unwrap();
            encoder.str("Zulu Zugführer").unwrap();
            encoder.str("Zugführer").unwrap();
            encoder.array(2).unwrap();
            encoder.u8(0).unwrap();
            encoder.u8(3).unwrap();
            encoder.null().unwrap();
            encoder.array(3).unwrap();
            encoder.u8(1).unwrap();
            encoder.str("Alpha Unterstützung").unwrap();
            encoder.null().unwrap();
            encoder.null().unwrap();
            encoder.array(1).unwrap();
            encoder.array(7).unwrap();
            encoder.u8(0).unwrap();
            encoder.str("vehicle-7").unwrap();
            encoder.str("LF 20").unwrap();
            encoder.str("Florian 1/46-1").unwrap();
            encoder.str("B-DR 112").unwrap();
            encoder.array(2).unwrap();
            encoder.u8(1).unwrap();
            encoder.i64(1_700_000_000_000).unwrap();
            encoder.array(3).unwrap();
            encoder.str("csv-vehicles").unwrap();
            encoder.u8(1).unwrap();
            encoder.bytes(&[0x81; 32]).unwrap();
            encoder.null().unwrap();
            encoder.u8(1).unwrap();
            encoder.u8(0).unwrap();
            encoder.str("Keine Patientendaten.").unwrap();
            encoder.array(2).unwrap();
            encoder.array(2).unwrap();
            encoder.str("z-org").unwrap();
            encoder.str("Zulu Klinik").unwrap();
            encoder.array(2).unwrap();
            encoder.null().unwrap();
            encoder.str("Alpha Behörde").unwrap();
        }
        "amendment" => {
            encode_payload_header(
                &mut encoder,
                "amendment",
                [
                    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x70, 0x28, 0x80, 0x2a, 0x2b, 0x2c, 0x2d,
                    0x2e, 0x2f, 0x30,
                ],
                "ea.amendment",
                1_798_768_000_000,
                "Europe/Berlin",
            );
            encoder.array(6).unwrap();
            encoder.str("2026-0001").unwrap();
            encoder
                .bytes(&[
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x70, 0x18, 0x80, 0x1a, 0x1b, 0x1c, 0x1d,
                    0x1e, 0x1f, 0x20,
                ])
                .unwrap();
            encoder.bytes(&[0x90; 32]).unwrap();
            encoder.u8(42).unwrap();
            encoder.str("Lage präzisiert").unwrap();
            encoder.array(2).unwrap();
            encoder.array(2).unwrap();
            encoder.str("location").unwrap();
            encoder.str("Hausnummer 7a ergänzt").unwrap();
            encoder.array(2).unwrap();
            encoder.str("notes").unwrap();
            encoder.str("Sachverhalt klargestellt").unwrap();
        }
        "keyTransition" => {
            encode_payload_header(
                &mut encoder,
                "keyTransition",
                [
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x70, 0x38, 0x80, 0x3a, 0x3b, 0x3c, 0x3d,
                    0x3e, 0x3f, 0x40,
                ],
                "ea.key-transition",
                1_798_769_000_000,
                "Europe/Berlin",
            );
            encoder.array(2).unwrap();
            encoder.bytes(&[0xa0; 32]).unwrap();
            encoder.str("Geplanter Writer-Wechsel").unwrap();
        }
        "destructionEvidence" => {
            encode_payload_header(
                &mut encoder,
                "destructionEvidence",
                [
                    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x70, 0x48, 0x80, 0x4a, 0x4b, 0x4c, 0x4d,
                    0x4e, 0x4f, 0x50,
                ],
                "ea.destruction-evidence",
                1_798_770_000_000,
                "Europe/Berlin",
            );
            encoder.array(7).unwrap();
            encoder.bytes(&[0xb0; 16]).unwrap();
            encoder.bytes(&[0xb1; 32]).unwrap();
            encoder.u8(1).unwrap();
            encoder.array(2).unwrap();
            for (hash, sequence) in [(0x01, 7), (0x02, 9)] {
                encoder.array(2).unwrap();
                encoder.bytes(&[hash; 32]).unwrap();
                encoder.u8(sequence).unwrap();
            }
            encoder.array(2).unwrap();
            for (hash, confirmed, code) in [(0x01, true, 0), (0x02, false, 2)] {
                encoder.array(3).unwrap();
                encoder.bytes(&[hash; 32]).unwrap();
                encoder.bool(confirmed).unwrap();
                encoder.u8(code).unwrap();
            }
            encoder.array(2).unwrap();
            for (hash, stub) in [(0x01, 0xc1), (0x02, 0xc2)] {
                encoder.array(2).unwrap();
                encoder.bytes(&[hash; 32]).unwrap();
                encoder.bytes(&[stub; 32]).unwrap();
            }
            encoder.array(3).unwrap();
            encoder.array(3).unwrap();
            encoder.bytes(&[0x01; 16]).unwrap();
            encoder.u8(0).unwrap();
            encoder.bytes(&[0xd1; 32]).unwrap();
            encoder.array(3).unwrap();
            encoder.bytes(&[0x02; 16]).unwrap();
            encoder.u8(1).unwrap();
            encoder.null().unwrap();
            encoder.array(3).unwrap();
            encoder.bytes(&[0x03; 16]).unwrap();
            encoder.u8(2).unwrap();
            encoder.null().unwrap();
        }
        _ => unreachable!(),
    }
    encoder.into_writer()
}

const GENESIS_PAYLOAD_HEX: &str = "8b6767656e65736973500102030405067008800a0b0c0d0e0f106a65612e67656e65736973011b0000018bcfe568006d4575726f70652f4265726c696e86501010101010101010101010101010101050202020202020202020202020202020206e4572696b6120426569737069656c6e45696e7361747a6c656974756e67582030303030303030303030303030303030303030303030303030303030303030305820404040404040404040404040404040404040404040404040404040404040404084006d7772697465722d6e617469766501f60780865010101010101010101010101010101010505050505050505050505050505050505058206060606060606060606060606060606060606060606060606060606060606060017545494e5341545a4152434849562d53554954452d3158207070707070707070707070707070707070707070707070707070707070707070";
const INCIDENT_PAYLOAD_HEX: &str = "8b68696e636964656e74501112131415167018801a1b1c1d1e1f206b65612e696e636964656e74011b000001a2cea74b4070416d65726963612f4e65775f596f726b86501010101010101010101010101010101050202020202020202020202020202020206e4572696b6120426569737069656c6e45696e7361747a6c656974756e67582030303030303030303030303030303030303030303030303030303030303030305820404040404040404040404040404040404040404040404040404040404040404084006d7772697465722d6e617469766501f607808c69323032362d30303031821b000001a2cea74b401b000001a2cede39c08301656272616e646b4272616e642067726fc39f8301866c486175707473747261c39f65623761653130313135664265726c696e624245624445821a1f4dea801a07fd70d082860069706572736f6e2d34326f5a756c75205a756766c3bc687265726a5a756766c3bc68726572820003f6830174416c70686120556e7465727374c3bc747a756e67f6f68187006976656869636c652d37654c462032306e466c6f7269616e20312f34362d3168422d44522031313282011b0000018bcfe56800836c6373762d76656869636c65730158208181818181818181818181818181818181818181818181818181818181818181f60100754b65696e652050617469656e74656e646174656e2e8282657a2d6f72676b5a756c75204b6c696e696b82f66e416c70686120426568c3b6726465";
const AMENDMENT_PAYLOAD_HEX: &str = "8b69616d656e646d656e74502122232425267028802a2b2c2d2e2f306c65612e616d656e646d656e74011b000001a2ceed7c006d4575726f70652f4265726c696e86501010101010101010101010101010101050202020202020202020202020202020206e4572696b6120426569737069656c6e45696e7361747a6c656974756e67582030303030303030303030303030303030303030303030303030303030303030305820404040404040404040404040404040404040404040404040404040404040404084006d7772697465722d6e617469766501f607808669323032362d30303031501112131415167018801a1b1c1d1e1f2058209090909090909090909090909090909090909090909090909090909090909090182a704c616765207072c3a47a6973696572748282686c6f636174696f6e76486175736e756d6d657220376120657267c3a46e7a7482656e6f74657378185361636876657268616c74206b6c617267657374656c6c74";
const KEY_TRANSITION_PAYLOAD_HEX: &str = "8b6d6b65795472616e736974696f6e503132333435367038803a3b3c3d3e3f407165612e6b65792d7472616e736974696f6e011b000001a2cefcbe406d4575726f70652f4265726c696e86501010101010101010101010101010101050202020202020202020202020202020206e4572696b6120426569737069656c6e45696e7361747a6c656974756e67582030303030303030303030303030303030303030303030303030303030303030305820404040404040404040404040404040404040404040404040404040404040404084006d7772697465722d6e617469766501f60780825820a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a078184765706c616e746572205772697465722d5765636873656c";
const DESTRUCTION_EVIDENCE_PAYLOAD_HEX: &str = "8b736465737472756374696f6e45766964656e6365504142434445467048804a4b4c4d4e4f507765612e6465737472756374696f6e2d65766964656e6365011b000001a2cf0c00806d4575726f70652f4265726c696e86501010101010101010101010101010101050202020202020202020202020202020206e4572696b6120426569737069656c6e45696e7361747a6c656974756e67582030303030303030303030303030303030303030303030303030303030303030305820404040404040404040404040404040404040404040404040404040404040404084006d7772697465722d6e617469766501f607808750b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b05820b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b10182825820010101010101010101010101010101010101010101010101010101010101010107825820020202020202020202020202020202020202020202020202020202020202020209828358200101010101010101010101010101010101010101010101010101010101010101f5008358200202020202020202020202020202020202020202020202020202020202020202f4028282582001010101010101010101010101010101010101010101010101010101010101015820c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c182582002020202020202020202020202020202020202020202020202020202020202025820c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c283835001010101010101010101010101010101005820d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d183500202020202020202020202020202020201f683500303030303030303030303030303030302f6";

#[test]
fn payload_cddl_closes_the_five_exact_eleven_position_wire_families() {
    let cddl = read_required("schemas/payload/v1/payload.cddl");
    cddl::pest_bridge::cddl_from_pest_str_checked(&cddl)
        .expect("payload CDDL must parse with all references resolved");
    assert_contains_all(
        "payload CDDL",
        &normalized_prose(&cddl),
        &[
            "payload-v1 = genesis-payload-v1 / incident-payload-v1 / amendment-payload-v1 / key-transition-payload-v1 / destruction-evidence-payload-v1",
            "record-id-v7 = bstr .size 16",
            "epoch-millis-i64-v1 supported bound = -9223372036854775808..9223372036854775807",
            "operator-snapshot-v1",
            "source-v1",
            "registry-version: uint",
            "extension-data: []",
            "MAX_PLAINTEXT_BYTES_V1 = 1_048_576",
        ],
    );
    for (root, record_type, schema_id) in [
        ("genesis-payload-v1", "genesis", "ea.genesis"),
        ("incident-payload-v1", "incident", "ea.incident"),
        ("amendment-payload-v1", "amendment", "ea.amendment"),
        (
            "key-transition-payload-v1",
            "keyTransition",
            "ea.key-transition",
        ),
        (
            "destruction-evidence-payload-v1",
            "destructionEvidence",
            "ea.destruction-evidence",
        ),
    ] {
        assert!(cddl.contains(root), "payload CDDL is missing {root}");
        assert!(
            cddl.contains(&format!("\"{record_type}\"")),
            "payload CDDL is missing recordType {record_type}"
        );
        assert!(
            cddl.contains(&format!("\"{schema_id}\"")),
            "payload CDDL is missing schemaId {schema_id}"
        );
    }
}

#[test]
fn immutable_payload_vectors_are_complete_canonical_family_items() {
    let cddl = read_required("schemas/payload/v1/payload.cddl");
    let vectors = [
        (
            "genesis.hex",
            "genesis-payload-v1",
            "genesis",
            "ea.genesis",
            GENESIS_PAYLOAD_HEX,
        ),
        (
            "incident.hex",
            "incident-payload-v1",
            "incident",
            "ea.incident",
            INCIDENT_PAYLOAD_HEX,
        ),
        (
            "amendment.hex",
            "amendment-payload-v1",
            "amendment",
            "ea.amendment",
            AMENDMENT_PAYLOAD_HEX,
        ),
        (
            "key-transition.hex",
            "key-transition-payload-v1",
            "keyTransition",
            "ea.key-transition",
            KEY_TRANSITION_PAYLOAD_HEX,
        ),
        (
            "destruction-evidence.hex",
            "destruction-evidence-payload-v1",
            "destructionEvidence",
            "ea.destruction-evidence",
            DESTRUCTION_EVIDENCE_PAYLOAD_HEX,
        ),
    ];

    for (file, root, expected_record_type, expected_schema_id, expected_hex) in vectors {
        let relative = format!("vectors/format/payload-v1/{file}");
        assert_eq!(
            read_required(&relative),
            format!("{expected_hex}\n"),
            "{relative} full immutable hex changed"
        );
        let bytes = decode_lower_hex_fixture(&relative);
        assert_eq!(bytes, payload_fixture(expected_record_type), "{relative}");
        cddl_cat::validate_cbor_bytes(root, &cddl, &bytes)
            .unwrap_or_else(|error| panic!("{relative} must validate against {root}: {error:?}"));

        let mut decoder = minicbor::Decoder::new(&bytes);
        assert_eq!(decoder.array().unwrap(), Some(11), "{relative}");
        assert_eq!(decoder.str().unwrap(), expected_record_type, "{relative}");
        let record_id = decoder.bytes().unwrap();
        assert_eq!(record_id.len(), 16, "{relative}");
        assert_eq!(record_id[6] >> 4, 7, "{relative} must use UUIDv7");
        assert_eq!(
            record_id[8] >> 6,
            2,
            "{relative} must use the RFC UUID variant"
        );
        assert_eq!(decoder.str().unwrap(), expected_schema_id, "{relative}");
        assert_eq!(decoder.u64().unwrap(), 1, "{relative}");
        decoder.i64().unwrap();
        assert!(!decoder.str().unwrap().is_empty(), "{relative}");
        decoder.skip().unwrap();
        decoder.skip().unwrap();
        decoder.u64().unwrap();
        assert_eq!(decoder.array().unwrap(), Some(0), "{relative}");
        decoder.skip().unwrap();
        assert_eq!(decoder.position(), bytes.len(), "{relative}");
    }
}

#[test]
fn payload_vectors_fail_closed_on_trailing_truncated_and_header_mutations() {
    let cddl = read_required("schemas/payload/v1/payload.cddl");
    for (file, root) in [
        ("genesis.hex", "genesis-payload-v1"),
        ("incident.hex", "incident-payload-v1"),
        ("amendment.hex", "amendment-payload-v1"),
        ("key-transition.hex", "key-transition-payload-v1"),
        (
            "destruction-evidence.hex",
            "destruction-evidence-payload-v1",
        ),
    ] {
        let relative = format!("vectors/format/payload-v1/{file}");
        let bytes = decode_lower_hex_fixture(&relative);
        let mut appended = bytes.clone();
        appended.push(0);
        assert!(!validate_payload_cbor(root, &cddl, &appended), "{relative}");
        assert!(
            !validate_payload_cbor(root, &cddl, &bytes[..bytes.len() - 1]),
            "{relative}"
        );
    }

    let genesis = decode_lower_hex_fixture("vectors/format/payload-v1/genesis.hex");
    let mut family = genesis.clone();
    family[2] = b'x';
    assert!(!validate_payload_cbor("payload-v1", &cddl, &family));

    let schema_offset = genesis
        .windows(b"ea.genesis".len())
        .position(|window| window == b"ea.genesis")
        .unwrap();
    let mut schema = genesis.clone();
    schema[schema_offset + b"ea.genesis".len() - 1] = b'x';
    assert!(!validate_payload_cbor("payload-v1", &cddl, &schema));

    let mut decoder = minicbor::Decoder::new(&genesis);
    decoder.array().unwrap();
    decoder.skip().unwrap();
    decoder.skip().unwrap();
    decoder.skip().unwrap();
    let version_offset = decoder.position();
    assert_eq!(genesis[version_offset], 1);
    let mut version = genesis;
    version[version_offset] = 2;
    assert!(!validate_payload_cbor("payload-v1", &cddl, &version));
}

#[test]
fn incident_authoring_order_is_preserved_and_float_coordinates_fail_closed() {
    let cddl = read_required("schemas/payload/v1/payload.cddl");
    let incident = decode_lower_hex_fixture("vectors/format/payload-v1/incident.hex");
    assert!(validate_cbor("incident-payload-v1", &cddl, &incident));

    let mut decoder = minicbor::Decoder::new(&incident);
    assert_eq!(decoder.array().unwrap(), Some(11));
    for _ in 0..10 {
        decoder.skip().unwrap();
    }
    assert_eq!(decoder.array().unwrap(), Some(12));
    for _ in 0..4 {
        decoder.skip().unwrap();
    }
    assert_eq!(decoder.array().unwrap(), Some(2));
    assert_eq!(decoder.array().unwrap(), Some(6));
    assert_eq!(decoder.u8().unwrap(), 0);
    decoder.str().unwrap();
    let first_display = decoder.str().unwrap();
    for _ in 0..3 {
        decoder.skip().unwrap();
    }
    assert_eq!(decoder.array().unwrap(), Some(3));
    assert_eq!(decoder.u8().unwrap(), 1);
    let second_display = decoder.str().unwrap();
    assert_eq!(
        (first_display, second_display),
        ("Zulu Zugführer", "Alpha Unterstützung")
    );

    let integer_latitude = [0x1a, 0x1f, 0x4d, 0xea, 0x80];
    let latitude_offset = incident
        .windows(integer_latitude.len())
        .position(|window| window == integer_latitude)
        .unwrap();
    let mut float_coordinate = incident.clone();
    let mut encoded_float = vec![0xfb];
    encoded_float.extend_from_slice(&52.52_f64.to_bits().to_be_bytes());
    float_coordinate.splice(
        latitude_offset..latitude_offset + integer_latitude.len(),
        encoded_float,
    );
    assert!(!validate_cbor(
        "incident-payload-v1",
        &cddl,
        &float_coordinate
    ));
    assert_eq!(
        ea_cbor::validate(&float_coordinate, ea_cbor::ParserLimits::V1)
            .unwrap_err()
            .code(),
        "EA-CBOR-FLOAT"
    );
}

#[test]
fn every_payload_vector_is_canonical_under_ea_cbor() {
    for file in [
        "genesis.hex",
        "incident.hex",
        "amendment.hex",
        "key-transition.hex",
        "destruction-evidence.hex",
    ] {
        let relative = format!("vectors/format/payload-v1/{file}");
        let bytes = decode_lower_hex_fixture(&relative);
        assert!(
            bytes.len() <= 1_048_576,
            "{relative} exceeds the plaintext cap"
        );
        ea_cbor::validate(&bytes, ea_cbor::ParserLimits::V1)
            .unwrap_or_else(|error| panic!("{relative} is not canonical: {error}"));
        assert_eq!(
            ea_cbor::canonical_reencode(&bytes, ea_cbor::ParserLimits::V1).unwrap(),
            bytes,
            "{relative} changed under canonical re-encoding"
        );
    }
}

#[test]
fn timezone_and_incident_year_contracts_are_exact_and_reproducible() {
    let manifest: toml::Value = read_required("Cargo.toml").parse().unwrap();
    let dependencies = manifest["workspace"]["dependencies"].as_table().unwrap();
    assert_eq!(dependencies["jiff"]["version"].as_str(), Some("=0.2.35"));
    assert_eq!(
        dependencies["jiff"]["default-features"].as_bool(),
        Some(false)
    );
    assert_eq!(
        dependencies["jiff"]["features"].as_array().unwrap(),
        &[
            toml::Value::String("std".into()),
            toml::Value::String("tzdb-bundle-always".into())
        ]
    );
    assert_eq!(dependencies["jiff-tzdb"].as_str(), Some("=0.1.8"));

    let addendum = read_required(
        "docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md",
    );
    assert_contains_all(
        "payload wire addendum",
        &normalized_prose(&addendum),
        &[
            "jiff = 0.2.35",
            "jiff-tzdb = 0.1.8",
            "IANA tzdb 2026c",
            "TimeZoneDatabase::bundled()",
            "jiff_tzdb::get",
            "canonical name",
            "Etc/Unknown",
            "1798763400000 in America/New_York -> 2026",
            "1798759800000 in Europe/Berlin -> 2027",
            "operatorSnapshot.organizationId",
            "NFC UTF-8 bytes of humanIncidentNumber",
            "abgeleitete lokale Jahreskomponente",
        ],
    );
}

#[test]
fn incident_number_key_separates_local_year_inputs_from_exact_number_bytes() {
    for (name, relative) in [
        (
            "payload wire addendum",
            "docs/superpowers/specs/2026-08-14-einsatzarchiv-v0-1-payload-wire-addendum.md",
        ),
        (
            "design",
            "docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md",
        ),
    ] {
        let source = normalized_prose(&read_required(relative));
        assert_contains_all(
            name,
            &source,
            &[
                "`finalizedAtDevice`, das UTC-Jahr und ein UI-artiges `YYYY-`-Präfix bestimmen die abgeleitete lokale Jahreskomponente nicht",
                "Präfix-Stripping, Case-Folding und Locale-Folding finden nicht statt",
                "Jede Änderung der NFC-UTF-8-Bytes von `humanIncidentNumber` ändert Tupelkomponente 3",
            ],
        );
    }
}

#[test]
fn xtask_declares_distinct_report_and_payload_projection_profiles() {
    let xtask = read_required("tools/xtask/src/main.rs");
    assert_contains_all(
        "xtask schema profiles",
        &xtask,
        &[
            "enum JsonSchemaProfile",
            "DeterministicReport",
            "PayloadProjection",
        ],
    );
    let task = stage_one_plan()
        .split_once("### Task 7: Versioned Payload Schemas and Compatibility Registry")
        .unwrap()
        .1
        .split_once("### Task 8: Trust/Time v1 Closure, then Runtime Verification")
        .unwrap()
        .0;
    assert_contains_all(
        "Stage-1 Task 7",
        &normalized_prose(task),
        &[
            "JsonSchemaProfile::DeterministicReport",
            "JsonSchemaProfile::PayloadProjection",
            "ordered authoring arrays",
            "x-ea-sort-key",
        ],
    );
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

#[test]
fn task8_trust_time_closure_is_consistent_across_normative_sources() {
    let closure = include_str!(
        "../../../docs/superpowers/specs/2026-08-14-einsatzarchiv-task-8-trust-time-closure-design.md"
    );
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let addendum = include_str!(
        "../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md"
    );
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    let trust = include_str!("../../../schemas/archive/v1/trust.cddl");
    let audit = include_str!("../../../schemas/reports/v1/local-audit.cddl");

    assert_contains_all(
        "approved Task-8 closure",
        &normalized_prose(closure),
        &[
            "authorization.registryVersion = previousHead.registryVersion",
            "event.registryVersion = checked_add(authorization.registryVersion, 1)",
            "| 4 `operatorBinding`",
            "Change 4",
            "| 6 `rootRotation`",
            "Change 6",
            "authoritySubjectId",
            "independent-time-reference-v1",
            "registry-head-hash",
            "guard-policy-object-hash",
        ],
    );

    for (name, source) in [
        ("main design", design),
        ("wire-format addendum", addendum),
        ("Stage-1 plan", stage_one),
    ] {
        assert_contains_all(
            name,
            &normalized_prose(source),
            &[
                "authorization.registryVersion = previousHead.registryVersion",
                "event.registryVersion = checked_add(authorization.registryVersion, 1)",
                "authoritySubjectId",
                "independent-time-reference-v1",
                "registry-head-hash",
                "guard-policy-object-hash",
            ],
        );
    }

    assert_contains_all(
        "Trust CDDL",
        trust,
        &[
            "device-certificate-core-for-v1<KIND, AUTHORITY_SUBJECT_ID>",
            "authority-subject-id",
        ],
    );
    assert_contains_all(
        "local-audit CDDL",
        audit,
        &[
            "independent-time-reference-v1",
            "registry-head-hash",
            "guard-policy-object-hash",
        ],
    );
    assert_contains_all(
        "Stage-1 old-shape rejection",
        stage_one,
        &[
            "device-certificate-core-v1 length 13 is invalid",
            "clock-release-context-v1 length 6 is invalid",
        ],
    );
}

#[test]
fn task8_bootstrap_policy_is_closed_across_normative_sources() {
    for (name, source) in [
        (
            "main design",
            include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md"),
        ),
        (
            "wire-format addendum",
            include_str!(
                "../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md"
            ),
        ),
        ("Stage-1 plan", stage_one_plan()),
    ] {
        assert_contains_all(
            name,
            &normalized_prose(source),
            &[
                "initialPolicy.policyVersion = 1",
                "initialPolicy.previousPolicyObjectHash = null",
                "initialPolicy.effectiveFromSequence = head1.effectiveFromSequence",
            ],
        );
    }
}

#[test]
fn task8_clock_release_interval_is_closed_across_normative_sources() {
    for (name, source) in [
        (
            "main design",
            include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md"),
        ),
        (
            "wire-format addendum",
            include_str!(
                "../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md"
            ),
        ),
        ("Stage-1 plan", stage_one_plan()),
    ] {
        assert_contains_all(
            name,
            &normalized_prose(source),
            &["clockRelease.issuedAt <= EffectiveNow <= clockRelease.expiresAt"],
        );
    }
}

#[test]
fn task8_runtime_seams_are_authoritative_and_not_duplicated() {
    let runtime = include_str!(
        "../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md"
    );
    let umbrella = include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-v0-1.md");
    let stage_one = stage_one_plan();
    let required = [
        "source: &dyn TrustObjectSource",
        "snapshot: TrustStateSnapshot",
        "local_time: &mut LocalTimeBlock<'_>",
        "RegistrySelectionOutcome",
        "Advanced(AdvancedRegistryHead)",
        "PendingFuture(PendingFutureSuccessor)",
    ];

    assert_contains_all("Task-8 Runtime Phase B plan", runtime, &required);
    assert_contains_all("umbrella plan Task-8 seam", umbrella, &required);
    assert!(
        umbrella.contains("2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md"),
        "umbrella plan must link the authoritative Task-8 runtime plan"
    );
    assert!(
        !umbrella.contains(
            "verify_trust(anchor: &TrustAnchorV1, objects: &ArchiveInventory, now: EffectiveNow)"
        ),
        "umbrella plan retains the obsolete ArchiveInventory/EffectiveNow trust seam"
    );
    assert!(
        stage_one.contains("2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md"),
        "Stage-1 plan must link the authoritative Task-8 runtime plan"
    );
    assert!(
        !stage_one.contains("pub fn verify_registry_candidate(")
            && !stage_one.contains("pub fn verify_clock_release(")
            && !stage_one.contains("pub fn select_registry_head("),
        "Stage-1 plan must not duplicate the authoritative runtime API seam"
    );
}

#[test]
fn task8_registry_candidate_contract_closes_target_kinds_errors_and_phase_boundary() {
    let main =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let wire = include_str!(
        "../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-wire-format-addendum.md"
    );
    let closure = include_str!(
        "../../../docs/superpowers/specs/2026-08-14-einsatzarchiv-task-8-trust-time-closure-design.md"
    );
    let stage_one = stage_one_plan();
    let trust_cddl = include_str!("../../../schemas/archive/v1/trust.cddl");
    let target_kind_markers = [
        "target-kind 0 = deviceCertificate with CertificateKind Writer, Reader, KeyApprover, RecoveryRecipient, or HistoricalGrantAuthority",
        "target-kind 1 = operatorBinding",
        "target-kind 2 = deviceCertificate with CertificateKind ServerReceipt or DeletionAttest",
        "OrganizationAdmin is invalid under Change 1",
    ];

    for (name, source) in [
        ("main design", main),
        ("wire-format addendum", wire),
        ("Task-8 closure", closure),
        ("Stage-1 plan", stage_one),
        ("Trust CDDL", trust_cddl),
    ] {
        assert_contains_all(name, source, &target_kind_markers);
    }

    for (name, source) in [
        ("main design", main),
        ("wire-format addendum", wire),
        ("Task-8 closure", closure),
        ("Stage-1 plan", stage_one),
    ] {
        assert_contains_all(
            name,
            source,
            &["preTransitionSequence = head1.effectiveFromSequence"],
        );
    }

    let runtime = include_str!(
        "../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md"
    );
    let task_seven = runtime
        .split_once(
            "### Task 7: Build the complete historical Registry candidate without candidate time",
        )
        .expect("runtime plan must contain Task 7")
        .1
        .split_once("### Task 8: Add candidate-independent verified Receipt/Checkpoint time")
        .expect("runtime plan must contain Task 8 after Task 7")
        .0;
    assert_contains_all(
        "Task-7 runtime slice",
        task_seven,
        &[
            "Modify: `crates/ea-trust/src/error.rs`",
            "RegistryError preserves every lower-layer TrustError code losslessly",
            "Advanced, PendingFuture, and Selected outcomes remain Task 11-only",
            "intermediate successor is returned only as a non-operation RegistryCandidate",
            "preTransitionSequence = head1.effectiveFromSequence",
            "topology-only lookahead may read only organization, registryVersion, previousRegistryHash, and objectHash",
        ],
    );
    assert!(
        !task_seven.contains("expired intermediate H2 -> Advanced only -> reload -> fresh lease-covering H3 -> Selected"),
        "Task 7 must not require Task-11 selection outcome types"
    );
}

#[test]
fn task8_trust_source_limits_are_normative_and_bounded_before_retention() {
    let closure = include_str!(
        "../../../docs/superpowers/specs/2026-08-14-einsatzarchiv-task-8-trust-time-closure-design.md"
    );
    let runtime = include_str!(
        "../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md"
    );
    let stage_one = stage_one_plan();
    let required = [
        "MAX_TRUST_OBJECTS_V1 = 65_536",
        "MAX_TOTAL_TRUST_OBJECT_BYTES_V1 = 268_435_456",
        "EA-TRUST-SOURCE-COUNT-LIMIT",
        "EA-TRUST-SOURCE-BYTE-LIMIT",
        "visit_trust_object_hashes",
        "checked_add",
        "before retention",
    ];

    assert_contains_all(
        "Task-8 closure Trust-source limits",
        &normalized_prose(closure),
        &required,
    );
    assert_contains_all(
        "Task-8 runtime Trust-source limits",
        &normalized_prose(runtime),
        &required,
    );
    assert_contains_all(
        "Stage-1 inventory Trust-source limits",
        &normalized_prose(stage_one),
        &required,
    );
}

#[test]
fn task8_initial_admin_crypto_seam_is_explicit_and_wrapper_free() {
    let closure = include_str!(
        "../../../docs/superpowers/specs/2026-08-14-einsatzarchiv-task-8-trust-time-closure-design.md"
    );
    let runtime = include_str!(
        "../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md"
    );
    let required = [
        "CoseSigner::sign_initial_admin_trust_digest",
        "VerificationContext::initial_admin_trust_digest",
        "initial_admin_trust_bindings",
        "direct initial Admin Device Certificate or Operator Binding",
        "RegistryVersion::new(0)",
        "without an organizationAdminAuthorization wrapper",
    ];

    assert_contains_all(
        "Task-8 closure initial-Admin crypto seam",
        &normalized_prose(closure),
        &required,
    );
    assert_contains_all(
        "Task-8 runtime initial-Admin crypto seam",
        &normalized_prose(runtime),
        &required,
    );
}

#[test]
fn task8_bootstrap_admin_pairs_require_independent_people_and_keys() {
    let closure = include_str!(
        "../../../docs/superpowers/specs/2026-08-14-einsatzarchiv-task-8-trust-time-closure-design.md"
    );
    let runtime = include_str!(
        "../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md"
    );
    let required = [
        "pairwise distinct Admin certificate signing-key thumbprints",
        "pairwise distinct OS-account binding hashes",
        "pairwise distinct operator-instance-key thumbprints",
        "operator-instance-key thumbprint differs from its own Admin certificate signing-key thumbprint",
        "deviceId values need not be distinct",
    ];

    assert_contains_all(
        "Task-8 closure bootstrap Admin independence",
        &normalized_prose(closure),
        &required,
    );
    assert_contains_all(
        "Task-8 runtime bootstrap Admin independence",
        &normalized_prose(runtime),
        &required,
    );
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
struct DeviceCertificateFixture {
    certificate_kind: u8,
    authority_subject_id: Option<[u8; 16]>,
}

fn encode_device_certificate_core(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    fixture: DeviceCertificateFixture,
    include_authority_subject_id: bool,
) {
    encoder
        .array(if include_authority_subject_id { 14 } else { 13 })
        .unwrap();
    encoder.u8(1).unwrap();
    encoder.bytes(&[0; 16]).unwrap();
    encoder.bytes(&[1; 16]).unwrap();
    encoder.u8(fixture.certificate_kind).unwrap();
    encoder.bytes(&[2]).unwrap();
    encoder.null().unwrap();
    encoder.bytes(&[3; 32]).unwrap();
    encoder.null().unwrap();
    encoder.array(1).unwrap();
    encoder.str("organizationAdminApprove").unwrap();
    encoder.u8(0).unwrap();
    encoder.u8(0).unwrap();
    encoder.null().unwrap();
    if include_authority_subject_id {
        if let Some(authority_subject_id) = fixture.authority_subject_id {
            encoder.bytes(&authority_subject_id).unwrap();
        } else {
            encoder.null().unwrap();
        }
    }
    encoder.array(0).unwrap();
}

fn device_certificate_core_fixture(fixture: DeviceCertificateFixture) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_device_certificate_core(&mut encoder, fixture, true);
    encoder.into_writer()
}

#[derive(Clone, Copy)]
enum TrustPayload {
    DirectRoot { has_previous: bool },
    AuthorizedRoot { has_previous: bool },
    Device(DeviceCertificateFixture),
    LegacyDevice { certificate_kind: u8 },
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
        TrustPayload::Device(fixture) => encode_device_certificate_core(encoder, fixture, true),
        TrustPayload::LegacyDevice { certificate_kind } => {
            encode_device_certificate_core(
                encoder,
                DeviceCertificateFixture {
                    certificate_kind,
                    authority_subject_id: None,
                },
                false,
            );
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
            TrustPayload::Device(DeviceCertificateFixture {
                certificate_kind: 2,
                authority_subject_id: Some([7; 16]),
            }),
            1
        )
    ));
    assert!(!validate_cbor(
        "etb-v1",
        &cddl,
        &etb_fixture(
            "deviceCertificate",
            TrustPayload::LegacyDevice {
                certificate_kind: 2,
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
fn device_certificate_cddl_authority_subject_id_matrix_is_closed() {
    let cddl = archive_cddl();

    for certificate_kind in 0..=7 {
        let authority_subject_id = matches!(certificate_kind, 2 | 3).then_some([7; 16]);
        assert!(
            validate_cbor(
                "device-certificate-core-v1",
                &cddl,
                &device_certificate_core_fixture(DeviceCertificateFixture {
                    certificate_kind,
                    authority_subject_id,
                }),
            ),
            "closed positive kind {certificate_kind}"
        );
    }

    for certificate_kind in [2, 3] {
        assert!(
            !validate_cbor(
                "device-certificate-core-v1",
                &cddl,
                &device_certificate_core_fixture(DeviceCertificateFixture {
                    certificate_kind,
                    authority_subject_id: None,
                }),
            ),
            "kind {certificate_kind} must require authoritySubjectId"
        );
    }

    for certificate_kind in [0, 1, 4, 5, 6, 7] {
        assert!(
            !validate_cbor(
                "device-certificate-core-v1",
                &cddl,
                &device_certificate_core_fixture(DeviceCertificateFixture {
                    certificate_kind,
                    authority_subject_id: Some([7; 16]),
                }),
            ),
            "kind {certificate_kind} must reject authoritySubjectId"
        );
    }
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
enum AuditContextFixture {
    Generic,
    Export,
    Destruction,
    ClockRelease {
        registry_version: u64,
        registry_head_hash: [u8; 32],
        guard_policy_object_hash: [u8; 32],
        independent_reference: (u8, [u8; 32], i64),
    },
    LegacyClockRelease,
}

fn audit_fixture(action: u8, context: AuditContextFixture) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).unwrap();
    encoder.array(12).unwrap();
    encoder.u8(1).unwrap();
    encoder.bytes(&[0; 16]).unwrap();
    encoder.bytes(&[1; 16]).unwrap();
    encoder.bytes(&[2; 16]).unwrap();
    if matches!(
        context,
        AuditContextFixture::ClockRelease { .. } | AuditContextFixture::LegacyClockRelease
    ) {
        encoder.bytes(&[7; 32]).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder.bytes(&[3; 32]).unwrap();
    encoder.u8(action).unwrap();
    encoder
        .u8(
            if matches!(
                context,
                AuditContextFixture::ClockRelease { .. } | AuditContextFixture::LegacyClockRelease
            ) {
                1
            } else {
                2
            },
        )
        .unwrap();
    encoder
        .i64(
            if matches!(
                context,
                AuditContextFixture::ClockRelease { .. } | AuditContextFixture::LegacyClockRelease
            ) {
                1_000
            } else {
                4
            },
        )
        .unwrap();
    match context {
        AuditContextFixture::Generic => {
            encoder.array(2).unwrap();
            encoder.u8(0).unwrap();
            encoder.null().unwrap();
        }
        AuditContextFixture::Export => {
            encoder.array(2).unwrap();
            encoder.u8(3).unwrap();
            encoder.array(2).unwrap();
            encoder.bytes(&[4; 32]).unwrap();
            encoder.u8(1).unwrap();
        }
        AuditContextFixture::Destruction => {
            encoder.array(2).unwrap();
            encoder.u8(7).unwrap();
            encoder.array(2).unwrap();
            encoder.bytes(&[4; 32]).unwrap();
            encoder.bytes(&[5; 32]).unwrap();
        }
        AuditContextFixture::ClockRelease {
            registry_version,
            registry_head_hash,
            guard_policy_object_hash,
            independent_reference,
        } => {
            encoder.array(2).unwrap();
            encoder.u8(2).unwrap();
            encoder.array(10).unwrap();
            encoder.i64(900).unwrap();
            encoder.i64(1_000).unwrap();
            encoder.u64(100).unwrap();
            encoder.u64(registry_version).unwrap();
            encoder.bytes(&registry_head_hash).unwrap();
            encoder.bytes(&guard_policy_object_hash).unwrap();
            encoder.array(3).unwrap();
            encoder.u8(independent_reference.0).unwrap();
            encoder.bytes(&independent_reference.1).unwrap();
            encoder.i64(independent_reference.2).unwrap();
            encoder.u8(0).unwrap();
            encoder.i64(900).unwrap();
            encoder.i64(1_200).unwrap();
        }
        AuditContextFixture::LegacyClockRelease => {
            encoder.array(2).unwrap();
            encoder.u8(2).unwrap();
            encoder.array(6).unwrap();
            encoder.i64(900).unwrap();
            encoder.i64(1_000).unwrap();
            encoder.u64(100).unwrap();
            encoder.u8(0).unwrap();
            encoder.i64(900).unwrap();
            encoder.i64(1_200).unwrap();
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
        &audit_fixture(0, AuditContextFixture::Generic)
    ));
    assert!(!validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(0, AuditContextFixture::Destruction)
    ));
    assert!(validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(5, AuditContextFixture::Export)
    ));
    assert!(!validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(5, AuditContextFixture::Generic)
    ));
    assert!(validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(
            6,
            AuditContextFixture::ClockRelease {
                registry_version: 7,
                registry_head_hash: [8; 32],
                guard_policy_object_hash: [9; 32],
                independent_reference: (0, [10; 32], 900),
            },
        )
    ));
    assert!(!validate_cbor(
        "local-audit-event-v1",
        cddl,
        &audit_fixture(6, AuditContextFixture::LegacyClockRelease)
    ));
}

/// Eine eingefrorene Datei der Familie `local-audit/v1`.
struct LocalAuditVectorFile {
    /// Der Name relativ zur Familienwurzel, etwa `event/accepted-login.bin`.
    name: String,
    /// Die eingefrorenen Bytes, unveraendert von der Platte.
    bytes: Vec<u8>,
}

/// Die Zahl der eingefrorenen Dateien der Familie.
///
/// Ohne diese Schranke waeren beide Schleifen unten LEER gruen, sobald das
/// Verzeichnis fehlt oder ausgeduennt wird — genau der stille Durchlauf, den
/// `EXPECTED_ENTRY_COUNT` in `conformance_golden_vectors.rs` verhindert.
const LOCAL_AUDIT_VECTOR_FILE_COUNT: usize = 17;

/// Alle eingefrorenen Dateien der Familie, lexikografisch.
fn local_audit_vector_files() -> Vec<LocalAuditVectorFile> {
    let directory = workspace_root().join("vectors/local-audit/v1/event");
    let mut files = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| {
            panic!(
                "the frozen local audit vectors are unreadable at {}: {error}",
                directory.display()
            )
        })
        .map(|child| {
            let path = child.expect("a readable directory entry").path();
            let name = format!(
                "event/{}",
                path.file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .expect("a vector file name is valid UTF-8")
            );
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("{name} is unreadable: {error}"));
            LocalAuditVectorFile { name, bytes }
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
        files.len(),
        LOCAL_AUDIT_VECTOR_FILE_COUNT,
        "the frozen local audit family must carry exactly \
         {LOCAL_AUDIT_VECTOR_FILE_COUNT} files"
    );
    files
}

/// Die zwoelf Kerne des Kodierers, einer je Aktion.
///
/// Sie kommen aus den EINGEFRORENEN Bytes und nicht aus einer zweiten,
/// handgeschriebenen Fixture: `ea_testkit::local_audit_v1_manifest` erzeugt die
/// Familie mit `encode_local_audit_core`, und
/// `the_committed_local_audit_family_matches_its_generator` haelt fest, dass die
/// eingecheckten Bytes genau diese Ausgabe sind. Der Kern wird hier durch
/// `decode_local_audit_event` gezogen, damit die zwoelf Aktionscodes mitgemessen
/// werden statt geraten.
fn local_audit_cores_for_every_action() -> Vec<Vec<u8>> {
    let mut codes = std::collections::BTreeSet::new();
    let mut cores = Vec::new();
    for file in local_audit_vector_files() {
        if !file.name.starts_with("event/accepted-") {
            continue;
        }
        let event = ea_format::decode_local_audit_event(&file.bytes)
            .unwrap_or_else(|error| panic!("{} must decode: {error}", file.name));
        assert!(
            codes.insert(event.action().code()),
            "{} repeats an action code",
            file.name
        );
        cores.push(event.exact_core().to_vec());
    }
    assert_eq!(
        codes,
        (0..12).collect::<std::collections::BTreeSet<u8>>(),
        "the accepted vectors must cover every one of the twelve actions"
    );
    cores
}

/// Der Kern eines signierten Ereignisses, neu umschlossen als `[core, null]`.
///
/// `cddl_cat` kann eine COSE-getaggte Struktur nicht durchlaufen — gemessen:
/// `[core, #6.18([...])]` scheitert mit `can't handle hidden cbor Value`,
/// waehrend `[core, null]` besteht. Genau deshalb setzt schon die vorhandene
/// Fixture `audit_fixture` ein `null` an die Signaturstelle. Die Aussage bleibt
/// dieselbe: `#6.18(COSE-Sign1)` normalisiert `validate_cbor` zu `any`, und
/// `any` nimmt `null` an.
fn local_audit_grammar_fixture(signed: &[u8]) -> Vec<u8> {
    let mut decoder = minicbor::Decoder::new(signed);
    assert_eq!(
        decoder.array().expect("a signed event is an array"),
        Some(2),
        "a signed event is the pair of core and signature"
    );
    let start = decoder.position();
    decoder.skip().expect("the core is a complete item");
    let core = &signed[start..decoder.position()];

    let mut fixture = Vec::with_capacity(core.len() + 2);
    minicbor::Encoder::new(&mut fixture).array(2).unwrap();
    fixture.extend_from_slice(core);
    minicbor::Encoder::new(&mut fixture).null().unwrap();
    fixture
}

#[test]
fn every_encoded_local_audit_core_satisfies_the_frozen_grammar() {
    let cddl = include_str!("../../../schemas/reports/v1/local-audit.cddl");
    for core in local_audit_cores_for_every_action() {
        assert!(validate_cbor("local-audit-event-core-v1", cddl, &core));
    }
}

/// Die vier Vektoren, deren Ablehnung GRAMMATISCH ist. Jeder andere Vektor der
/// Familie — auch `rejected-flipped-nonce-byte` — ist von der CDDL akzeptiert
/// und wird erst vom Decoder abgelehnt.
const GRAMMATICALLY_REJECTED: [&str; 4] = [
    "event/rejected-flipped-action-code.bin",
    "event/rejected-flipped-context-tag.bin",
    "event/rejected-flipped-outcome.bin",
    "event/rejected-unknown-action-code-200.bin",
];

#[test]
fn the_frozen_local_audit_vectors_match_the_grammar() {
    let cddl = include_str!("../../../schemas/reports/v1/local-audit.cddl");
    for file in local_audit_vector_files() {
        let expected = !GRAMMATICALLY_REJECTED.contains(&file.name.as_str());
        assert_eq!(
            validate_cbor(
                "local-audit-event-v1",
                cddl,
                &local_audit_grammar_fixture(&file.bytes)
            ),
            expected,
            "{} must be {} by local-audit-event-v1",
            file.name,
            if expected { "accepted" } else { "rejected" }
        );
    }
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
        "objectResults": [{
            "objectHash": "1111111111111111111111111111111111111111111111111111111111111111",
            "objectType": 1,
            "result": "valid",
            "serverConfirmation": "notServerConfirmed"
        }],
        "authorizedDestructions": [],
        "gaps": [],
        "formatErrors": [{
            "objectHash": "2222222222222222222222222222222222222222222222222222222222222222",
            "code": "EA-FORMAT-UNKNOWN-VERSION"
        }],
        "quarantinedObjects": [{
            "objectHash": "3333333333333333333333333333333333333333333333333333333333333333",
            "reason": "conflicting"
        }],
        "nonObjectFileCount": 3,
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
    let mut unknown_nested = valid_report.clone();
    unknown_nested["chainHead"]["hostPath"] = serde_json::json!("/tmp/archive");
    assert!(!verification.is_valid(&unknown_nested));

    // Die Server-Bestaetigung ist Pflicht: sie darf nicht still entfallen.
    let mut missing_confirmation = valid_report.clone();
    missing_confirmation["objectResults"][0]
        .as_object_mut()
        .unwrap()
        .remove("serverConfirmation");
    assert!(!verification.is_valid(&missing_confirmation));

    // Sie ist orthogonal: kein dritter result-Wert.
    let mut folded_confirmation = valid_report.clone();
    folded_confirmation["objectResults"][0]["result"] = serde_json::json!("notServerConfirmed");
    assert!(!verification.is_valid(&folded_confirmation));

    // Quarantaene traegt einen Grund aus der geschlossenen Menge, keinen Freitext.
    let mut free_text_reason = valid_report;
    free_text_reason["quarantinedObjects"][0]["reason"] = serde_json::json!("weird bytes");
    assert!(!verification.is_valid(&free_text_reason));

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

#[test]
fn web_reader_stage_one_scope_is_closed_across_normative_sources() {
    let web_reader = include_str!(
        "../../../docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md"
    );
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );

    // Der Selbstwiderspruch des Specs ist aufgeloest.
    assert!(
        !web_reader.contains("Sie ändert keine Wireformate, keine Objektfamilien"),
        "spec §1 still denies the object-family change introduced in §11.5/11.6"
    );
    assert!(
        web_reader.contains("v1.1-Erweiterung außerhalb Stage 1"),
        "spec must classify webBundleRelease and readerKeyEscrow as v1.1 outside stage 1"
    );

    // getrandom 0.4.3 braucht kein --cfg getrandom_backend. Positiv geprueft, nicht
    // per Abwesenheit: der korrigierte Text MUSS den entfallenen Mechanismus benennen
    // und enthaelt das Literal daher zwangslaeufig.
    assert!(
        web_reader.contains("ist für 0.4.3 **nicht** erforderlich"),
        "spec §10 must record that getrandom 0.4.3 needs no cfg flag"
    );
    assert!(
        !web_reader.contains("und `--cfg getrandom_backend=\"wasm_js\"`"),
        "spec §10 still demands the getrandom 0.3 cfg flag as a requirement"
    );

    // Design: Browser-Zone ergaenzt, Reader aus der Desktopzone entfernt.
    assert!(
        design.contains("Browser-Zone"),
        "design §5.3 must carry the fifth trust zone from spec §3"
    );
    assert!(
        !design.contains("**Desktop-/Archivzone:** Writer, Reader, Admin"),
        "design §5.3 zone 2 must no longer list the Reader"
    );

    // Design: der neue Verifikationsstatus aus spec §5.4.
    assert!(
        design.contains("nicht server-bestätigt"),
        "design §17.4 must carry the status term required by spec §5.4"
    );

    // Design: die weiteren durch den Spec widerlegten Fundstellen.
    for marker in ["web-reader-design", "apps/web"] {
        assert!(design.contains(marker), "design must reference {marker}");
    }
    assert!(
        !design.contains("gemeinsame Binär- und UI-Basis für Writer, Reader und Administration"),
        "design §5.1 must split desktop (Writer, Administration) from the web reader"
    );

    // Stage-1-Plan: die zwei kollidierenden Global-Constraint-Zeilen.
    assert!(
        stage_one.contains("Reader läuft im Browser"),
        "stage 1 global constraints must exempt the Reader from the desktop platform list"
    );
    assert!(
        stage_one.contains("Ant Design 6") && stage_one.contains("Writer und Administration"),
        "stage 1 global constraints must scope the Ant Design chain to Writer and Administration"
    );
}

#[test]
fn verify_quick_block_in_stage_one_plan_matches_the_gate() {
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    for command in [
        r#"("cargo", vec!["fmt", "--all", "--check"])"#,
        r#""clippy", "--workspace", "--all-targets", "--all-features", "--locked""#,
        r#"("cargo", vec!["test", "--workspace", "--all-targets", "--locked"])"#,
        r#""check", "--target", "wasm32-unknown-unknown", "--locked""#,
    ] {
        assert!(
            stage_one.contains(command),
            "stage 1 plan verify-quick block is missing {command}"
        );
    }
    assert!(
        stage_one.contains("cargo check --target wasm32-unknown-unknown --locked -p ea-types"),
        "stage 1 gate command list must run the wasm32 check"
    );
}

#[test]
fn stage_one_vector_hygiene_reserves_out_of_band_negative_literals() {
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );

    // Jeder Block, der einen kuenftigen Subtype-Namen nennen darf, ist markiert.
    // Die Abwesenheitspruefung entfernt ALLE markierten Bloecke, sonst schluege sie
    // an der eigenen Verbotsklausel bzw. an den Blockadetexten fehl.
    fn extract<'a>(text: &'a str, open: &str, close: &str) -> (&'a str, usize, usize) {
        let start = text.find(open).unwrap_or_else(|| panic!("missing {open}"));
        let end = text
            .find(close)
            .unwrap_or_else(|| panic!("unterminated {open}"));
        assert!(start < end, "markers out of order: {open}");
        (&text[start..end], start, end + close.len())
    }

    let (rule, hygiene_start, hygiene_end) = extract(
        stage_one,
        "<!-- vector-hygiene-rule -->",
        "<!-- /vector-hygiene-rule -->",
    );
    for literal in ["200", "xxUnknownxx"] {
        assert!(rule.contains(literal), "hygiene rule must pin {literal}");
    }

    let (_, blockers_start, blockers_end) = extract(
        stage_one,
        "<!-- web-reader-blockers -->",
        "<!-- /web-reader-blockers -->",
    );

    let mut regions = [(hygiene_start, hygiene_end), (blockers_start, blockers_end)];
    regions.sort_unstable();
    let mut stripped = String::with_capacity(stage_one.len());
    let mut cursor = 0usize;
    for (start, end) in regions {
        assert!(cursor <= start, "marked regions must not overlap");
        stripped.push_str(&stage_one[cursor..start]);
        cursor = end;
    }
    stripped.push_str(&stage_one[cursor..]);

    for candidate in ["webBundleRelease", "readerKeyEscrow"] {
        assert!(
            !stripped.contains(candidate),
            "{candidate} must only appear inside a marked block"
        );
    }

    for marker in [
        "ENTSCHIEDEN — Formentscheidung nach `web-reader-design.md` §7.5",
        "ENTSCHIEDEN — Zuordnung der Policy-Frist nach `web-reader-design.md` §4.2",
        "ENTSCHIEDEN — Traceability der Web-Reader-Anforderungen",
        "**wasm32-Pflicht.**",
    ] {
        assert!(
            stage_one.contains(marker),
            "stage 1 plan is missing: {marker}"
        );
    }

    // `parse_fuzz_args` (tools/xtask/src/main.rs) kennt kein freistehendes `--`;
    // die Restargumente gehen unveraendert an `run_fuzz`.
    assert!(
        stage_one.contains("pnpm test:fuzz --smoke-seconds 60"),
        "stage 1 plan must invoke the fuzz smoke gate without a bare `--` separator"
    );
    assert!(
        !stage_one.contains("pnpm test:fuzz -- --smoke-seconds"),
        "stage 1 plan must not pass a bare `--` through pnpm to test:fuzz"
    );

    // Stufenuebergreifende Schnittstelle: stage-4/5/6 deklarieren
    // `Produces: xtask stage-gate N`. Die Kommandozeile bleibt stehen.
    assert!(
        stage_one.contains("cargo run --locked -p xtask -- stage-gate 1"),
        "stage 1 plan must keep the cross-stage stage-gate command line"
    );
}

#[test]
fn later_stage_plans_reference_the_web_reader_spec() {
    for (name, plan) in [
        (
            "stage-2",
            include_str!(
                "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-2-offline-writer.md"
            ),
        ),
        (
            "stage-3",
            include_str!(
                "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-3-blind-sync.md"
            ),
        ),
        (
            "stage-4",
            include_str!(
                "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md"
            ),
        ),
        (
            "stage-5",
            include_str!(
                "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md"
            ),
        ),
        (
            "stage-6",
            include_str!(
                "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-6-evidence-grade.md"
            ),
        ),
        (
            "stage-7",
            include_str!(
                "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md"
            ),
        ),
    ] {
        assert!(
            plan.contains("2026-08-15-einsatzarchiv-web-reader-design.md"),
            "{name} plan must carry a marker for the web reader spec"
        );
    }

    let stage_four =
        include_str!("../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md");
    assert!(
        stage_four.contains("BLOCKIERT — Laufzeitnachweis nach `web-reader-design.md` §14.1"),
        "stage 4 must be blocked on the runtime spike"
    );

    // Ausfuehrbare Anweisungen zeigen auf existierende Pfade. Historische
    // Tatsachenbehauptungen ueber Worktrees bleiben unangetastet.
    for (name, plan) in [
        (
            "task-8-normative-correction",
            include_str!(
                "../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-normative-correction.md"
            ),
        ),
        (
            "task-8-implementation",
            include_str!(
                "../../../docs/superpowers/plans/2026-08-14-einsatzarchiv-task-8-trust-time-implementation.md"
            ),
        ),
    ] {
        assert!(
            !plan.contains("/Users/rubeen/.codex/"),
            "{name} still points at the stale RTK path"
        );
        assert!(
            plan.contains("Historisch:"),
            "{name} must mark its worktree line as a historical record"
        );
    }
}

#[test]
fn verification_report_expresses_quarantine_and_server_confirmation() {
    let raw = include_str!("../../../schemas/reports/v1/verification-report.schema.json");
    let schema: serde_json::Value = serde_json::from_str(raw).unwrap();
    jsonschema::meta::validate(&schema).unwrap();

    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    for field in ["formatErrors", "quarantinedObjects", "nonObjectFileCount"] {
        assert!(
            required.contains(&field),
            "verification report must require {field}"
        );
    }
    // Nicht-Objekt-Bytes sind eine eigene Klasse: sie sind KEINE Quarantaene und
    // sie sind KEINE Archivobjekte, aber sie bleiben sichtbar. Ohne diese Klasse
    // quarantaenisiert jedes normkonforme Archiv sein eigenes README-FORMAT.txt.
    assert_eq!(
        schema["properties"]["nonObjectFileCount"]["type"].as_str(),
        Some("integer")
    );

    // Server-Bestaetigung ist eine eigene Dimension, KEIN dritter result-Wert.
    let object_result = &schema["$defs"]["objectResult"];
    let result_values: Vec<&str> = object_result["properties"]["result"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        result_values,
        ["valid", "authorizedDestroyed"],
        "server confirmation must not be folded into the verification result"
    );
    let confirmation: Vec<&str> = object_result["properties"]["serverConfirmation"]["enum"]
        .as_array()
        .expect("objectResult must carry the server confirmation dimension")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(confirmation, ["serverConfirmed", "notServerConfirmed"]);
    assert!(
        object_result["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("serverConfirmation")),
        "serverConfirmation must be mandatory so it cannot be silently omitted"
    );

    // Das code-Muster MUSS JEDEN real erzeugbaren Fehlercode akzeptieren. FormatError
    // delegiert an CborError und traegt eigene EA-GRANT-Codes; ein auf EA-FORMAT-
    // verengtes Muster machte diese Faelle unberichtbar. Die Codes werden aus den
    // Quellen extrahiert, damit der Test auch kuenftige Codes erfasst.
    let format_error = jsonschema::validator_for(&serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": "#/$defs/formatError"
    }))
    .unwrap();
    let mut codes = Vec::new();
    for source in [
        include_str!("../../../crates/ea-format/src/object.rs"),
        include_str!("../../../crates/ea-cbor/src/lib.rs"),
    ] {
        for line in source.lines() {
            let Some((_, rest)) = line.split_once("=> \"EA-") else {
                continue;
            };
            let Some((code, _)) = rest.split_once('"') else {
                continue;
            };
            codes.push(format!("EA-{code}"));
        }
    }
    assert!(
        codes.len() >= 30,
        "expected to extract every error code, found {}",
        codes.len()
    );
    for code in codes {
        let candidate = serde_json::json!({
            "objectHash": "4444444444444444444444444444444444444444444444444444444444444444",
            "code": code
        });
        assert!(
            format_error.is_valid(&candidate),
            "formatError.code must accept the real error code {code}"
        );
    }

    // Quarantaene ist fail-closed: das Schema erzwingt einen Grund je Objekt.
    let quarantined = &schema["$defs"]["quarantinedObject"];
    for field in ["objectHash", "reason"] {
        assert!(
            quarantined["required"]
                .as_array()
                .expect("quarantinedObject definition must exist")
                .iter()
                .any(|value| value.as_str() == Some(field)),
            "quarantinedObject must require {field}"
        );
    }
}

#[test]
fn gate_order_event_vocabulary_is_pinned_across_design_and_plan() {
    const GATE_EVENTS: [&str; 9] = [
        "format",
        "trust",
        "registry",
        "manifest-signature",
        "chain-position",
        "grant-plan",
        "receipt",
        "evidence",
        "recipient-grant",
    ];
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let stage_one = include_str!(
        "../../../docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md"
    );
    for event in GATE_EVENTS {
        assert!(
            design.contains(&format!("`{event}`")),
            "design §14.1 must name the gate event {event}"
        );
        assert!(
            stage_one.contains(&format!("\"{event}\"")),
            "stage 1 task 9 must pin the gate event {event}"
        );
    }
    // Die Entkapselung liegt hinter dem letzten Gate und ist selbst kein Gate.
    assert!(
        design.contains("`hpke-open`"),
        "design must name the decapsulation step that follows the nine gates"
    );

    // `GATE_ORDER_V1` ist die einzige Quelle der neun Bezeichner im Code. Der
    // Vergleich ist GEORDNET, nicht mengenwertig: die Reihenfolge IST der
    // Contract aus §14.1.
    let gates = include_str!("../../../crates/ea-verify/src/gates.rs");
    let pinned = const_array_string_literals(gates, "GATE_ORDER_V1");
    assert_eq!(
        pinned,
        GATE_EVENTS.to_vec(),
        "crates/ea-verify/src/gates.rs must carry the nine gate events of design §14.1 in order"
    );

    // Die Entkapselung steht ausserhalb des Arrays: sie ist kein Gate. Ein
    // dateiweites `!gates.contains("hpke-open")` waere falsch — die Konstante
    // DECAPSULATION_EVENT_V1 traegt genau dieses Literal.
    assert!(
        !pinned.contains(&"hpke-open"),
        "hpke-open must not be part of GATE_ORDER_V1"
    );
    assert!(
        gates.contains("pub const DECAPSULATION_EVENT_V1: &str = \"hpke-open\";"),
        "gates.rs must name the decapsulation event outside the gate array"
    );
}

/// Liest die Zeichenkettenliterale aus dem Arrayrumpf von `pub const NAME`.
///
/// Rustfmt bricht die neun Bezeichner auf je eine Zeile um, weshalb hier nicht
/// zeilenweise, sondern ueber den ausgeschnittenen Rumpf gelesen wird. Der
/// Rumpf enthaelt weder maskierte Anfuehrungszeichen noch Rohzeichenketten,
/// das Alternieren an `"` ist daher exakt. Die Reihenfolge bleibt erhalten.
fn const_array_string_literals<'a>(source: &'a str, name: &str) -> Vec<&'a str> {
    let needle = format!("pub const {name}");
    let at = source
        .find(&needle)
        .unwrap_or_else(|| panic!("gates.rs must declare {name}"));
    let tail = &source[at..];
    let body_at = tail
        .find("= [")
        .unwrap_or_else(|| panic!("{name} must be initialised with an array literal"));
    let body_end = body_at
        + tail[body_at..]
            .find("];")
            .unwrap_or_else(|| panic!("{name} must be terminated with `];`"));
    tail[body_at..body_end]
        .split('"')
        .skip(1)
        .step_by(2)
        .collect()
}

/// Die neunzehn Layoutpfade aus `design.md` §11.4 sind der einzige Bestand von
/// `crates/ea-archive/src/layout.rs` — in beide Richtungen.
///
/// Analog zu `GATE_ORDER_V1` gegen §14.1 wird die Uebereinstimmung ausfuehrbar
/// gepinnt statt kommentiert: jeder feste Pfad des Codeblocks in §11.4 muss als
/// `pub const … : &str` in `layout.rs` stehen, und `layout.rs` darf keinen Pfad
/// einfuehren, den §11.4 nicht nennt. Verglichen werden MENGEN, nicht
/// Teilzeichenketten — sonst erfuellte `"trust/organization.etb"` die Forderung
/// nach `"trust/"` stillschweigend mit.
#[test]
fn archive_layout_paths_match_design_section_11_4() {
    let design =
        include_str!("../../../docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md");
    let layout = include_str!("../../../crates/ea-archive/src/layout.rs");

    let expected = design_layout_paths(design);
    assert_eq!(
        expected.len(),
        19,
        "design §11.4 must name exactly the nineteen fixed layout paths"
    );

    let declared = layout_string_constants(layout);
    let declared_paths = declared
        .values()
        .map(|path| (*path).to_owned())
        .collect::<std::collections::BTreeSet<String>>();
    assert_eq!(
        declared_paths, expected,
        "crates/ea-archive/src/layout.rs and design §11.4 must name the same paths"
    );
    assert_eq!(
        declared.len(),
        expected.len(),
        "no two layout constants may carry the same path"
    );

    // Die Sammelkonstante nennt die Konstanten beim NAMEN; ein Literalvergleich
    // wuerde eine zu kurze Liste nicht bemerken.
    let collected = layout_paths_array_identifiers(layout);
    assert_eq!(
        collected,
        declared
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        "LAYOUT_PATHS_V1 must collect exactly the declared &str layout constants"
    );

    // Pfade sind Hinweise, nie Klassifikationsgrundlage — §11.4 sagt das, und
    // der Doc-Kommentar an LAYOUT_PATHS_V1 muss es woertlich wiederholen.
    assert_contains_all(
        "design §11.4",
        &normalized_prose(design),
        &[
            "Dateinamen sind Hinweise, keine Vertrauensquelle.",
            "Die Klassifikation entscheidet ausschließlich das Präfix, nie der Dateiname oder das Verzeichnis.",
        ],
    );
    assert_contains_all(
        "the LAYOUT_PATHS_V1 doc comment",
        &normalized_prose(layout),
        &["Diese Pfade sind Hinweise fuer Erzeuger, niemals Klassifikationsgrundlage."],
    );

    // Die Schranken des breiten Ports duerfen den Trust-Teilbestand nicht
    // enger fassen als ea-trust ihn selbst zulaesst.
    let blobs = layout_usize_constant(layout, "MAX_ARCHIVE_BLOBS_V1");
    let bytes = layout_usize_constant(layout, "MAX_TOTAL_ARCHIVE_BYTES_V1");
    assert!(
        blobs >= 65_536,
        "MAX_ARCHIVE_BLOBS_V1 must not undercut ea_trust::MAX_TRUST_OBJECTS_V1"
    );
    assert!(
        bytes >= 268_435_456,
        "MAX_TOTAL_ARCHIVE_BYTES_V1 must not undercut ea_trust::MAX_TOTAL_TRUST_OBJECT_BYTES_V1"
    );

    // Nach oben begrenzt der wasm32-Gate-Zielbau: dort ist `usize` 32 Bit
    // breit. Ein groesserer Wert uebersetzt auf wasm32 gar nicht erst
    // ("literal out of range for `usize`"), und zwar erst im Gate, lange nach
    // dem gruenen Host-Testlauf. Die Haelfte des u32-Bereichs bleibt frei,
    // damit das Aufsummieren nicht vor dem Erreichen der Schranke ueberlaeuft.
    assert!(
        bytes <= 2_147_483_648,
        "MAX_TOTAL_ARCHIVE_BYTES_V1 must fit a 32-bit usize with headroom to spare, \
         because wasm32-unknown-unknown is a gate target"
    );
    assert!(
        blobs <= 2_147_483_648,
        "MAX_ARCHIVE_BLOBS_V1 must fit a 32-bit usize with headroom to spare, \
         because wasm32-unknown-unknown is a gate target"
    );
}

/// Liest die festen Pfade aus dem `text`-Codeblock von `design.md` §11.4.
///
/// Die Einrueckung traegt die Verschachtelung (zwei Leerzeichen je Ebene). Ein
/// Blatt, dessen eigenes Segment einen Platzhalter `<…>` enthaelt, ist ein
/// Dateinamensmuster und kein fester Pfad. Liegt ein Platzhalter im Pfad eines
/// festen Segments, ist nur der Teil ab dem letzten Platzhalter fest — daher
/// `events/` und `attestations/` statt `destructions/<destruction-id>/events/`.
fn design_layout_paths(design: &str) -> std::collections::BTreeSet<String> {
    let section_at = design
        .find("### 11.4 Verzeichnisstruktur")
        .expect("design must carry section 11.4");
    let tail = &design[section_at..];
    let block_at = tail.find("```text").expect("§11.4 must carry a text block") + "```text".len();
    let block_end = block_at
        + tail[block_at..]
            .find("```")
            .expect("the §11.4 text block must be closed");
    let block = &tail[block_at..block_end];

    let mut stack: Vec<&str> = Vec::new();
    let mut paths = std::collections::BTreeSet::new();
    for line in block.lines() {
        let segment = line.trim_end();
        if segment.trim().is_empty() {
            continue;
        }
        let indent = segment.len() - segment.trim_start().len();
        assert!(
            indent.is_multiple_of(2),
            "the §11.4 tree must indent by two spaces per level: {segment}"
        );
        let depth = indent / 2;
        let segment = segment.trim_start();
        stack.truncate(depth);
        assert_eq!(stack.len(), depth, "the §11.4 tree must not skip a level");
        stack.push(segment);
        if depth == 0 {
            // Die Archivwurzel selbst ist kein Layoutpfad.
            continue;
        }
        if segment.contains('<') {
            continue;
        }
        let components = &stack[1..];
        let start = components
            .iter()
            .rposition(|component| component.contains('<'))
            .map_or(0, |placeholder| placeholder + 1);
        paths.insert(components[start..].concat());
    }
    paths
}

/// Sammelt `pub const NAME: &str = "VALUE";` aus `layout.rs`.
///
/// Der `&str`-Filter schliesst die beiden `usize`-Schranken zwingend aus.
fn layout_string_constants(layout: &str) -> std::collections::BTreeMap<&str, &str> {
    let mut declared = std::collections::BTreeMap::new();
    for line in layout.lines() {
        let Some(rest) = line.trim().strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        let Some(value) = tail.trim().strip_prefix("&str = ") else {
            continue;
        };
        let value = value
            .trim()
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix("\";"))
            .unwrap_or_else(|| panic!("{name} must be a plain string literal"));
        assert!(
            declared.insert(name.trim(), value).is_none(),
            "{name} is declared twice"
        );
    }
    assert!(
        !declared.is_empty(),
        "layout.rs must declare the §11.4 paths as string constants"
    );
    declared
}

/// Liest die Bezeichner aus dem Arrayrumpf von `LAYOUT_PATHS_V1`.
fn layout_paths_array_identifiers(layout: &str) -> std::collections::BTreeSet<&str> {
    let at = layout
        .find("pub const LAYOUT_PATHS_V1")
        .expect("layout.rs must declare LAYOUT_PATHS_V1");
    let tail = &layout[at..];
    let body_at = tail
        .find("= [")
        .expect("LAYOUT_PATHS_V1 must be initialised with an array literal");
    let body_end = body_at
        + tail[body_at..]
            .find("];")
            .expect("LAYOUT_PATHS_V1 must be terminated with `];`");
    tail[body_at..body_end]
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| token.ends_with("_V1") && *token != "LAYOUT_PATHS_V1")
        .collect()
}

/// Liest den Zahlenwert einer `pub const NAME: usize = …;`-Schranke.
fn layout_usize_constant(layout: &str, name: &str) -> usize {
    let needle = format!("pub const {name}: usize = ");
    let at = layout
        .find(&needle)
        .unwrap_or_else(|| panic!("layout.rs must declare {name}"));
    let tail = &layout[at + needle.len()..];
    let end = tail
        .find(';')
        .unwrap_or_else(|| panic!("{name} must be terminated with `;`"));
    tail[..end]
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|error| panic!("{name} must be a decimal literal: {error}"))
}

// ---------------------------------------------------------------------------
// `import-report-v1` — das normative Urbild des `importProtocolHash`.
// ---------------------------------------------------------------------------

/// Die zwoelf Positionen von `import-report-v1`, in Dokumentreihenfolge.
///
/// Die Reihenfolge IST der Vertrag: `importProtocolHash` ist ein Hash ueber
/// genau diese Bytefolge, und eine vertauschte Position ergaebe einen anderen
/// Hash bei unveraendertem Inhalt.
const IMPORT_REPORT_POSITIONS_V1: [&str; 12] = [
    "1,",
    "source-kind:",
    "source-id:",
    "source-format-version:",
    "input-file-hash:",
    "header-line:",
    "imported-at:",
    "row-count-total:",
    "row-count-accepted:",
    "row-count-rejected:",
    "warnings:",
    "errors:",
];

fn import_report_cddl() -> String {
    read_required("schemas/reports/v1/import-report.cddl")
}

/// Der Rumpf von `import-report-v1` OHNE die erlaeuternde Prosa davor.
///
/// Die Positionspruefung laeuft ausschliesslich auf diesem Ausschnitt: die
/// Kopfkommentare nennen jeden Codenamen ebenfalls, und eine Suche ueber das
/// ganze Dokument fiele auf die Prosa statt auf die Grammatik.
fn import_report_body(cddl: &str) -> String {
    let at = cddl
        .find("import-report-v1 = [")
        .expect("die Grammatik muss import-report-v1 deklarieren");
    let tail = &cddl[at..];
    let end = tail
        .find("\n]")
        .expect("import-report-v1 muss mit `]` schliessen");
    tail[..end].to_owned()
}

/// Ein `import-report-v1`-Wert mit frei waehlbarer Positionszahl und Codeliste.
fn import_report_cbor(positions: u64, codes: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);
    let mut encoder = minicbor::Encoder::new(&mut bytes);
    encoder
        .array(positions)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.str("csv-persons"))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x91; 32]))
        .and_then(|encoder| encoder.str("id,display_name,role,active"))
        .and_then(|encoder| encoder.i64(1_760_000_000_000))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.array(codes.len() as u64))
        .expect("das Kodieren in einen Vec kann nicht fehlschlagen");
    for code in codes {
        encoder
            .array(3)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.str("display_name"))
            .and_then(|encoder| encoder.u64(*code))
            .expect("das Kodieren in einen Vec kann nicht fehlschlagen");
    }
    if positions > 12 {
        encoder
            .u8(0)
            .expect("das Kodieren in einen Vec kann nicht fehlschlagen");
    }
    bytes
}

#[test]
fn import_report_cddl_carries_its_twelve_positions_in_order() {
    let cddl = import_report_cddl();
    cddl::pest_bridge::cddl_from_pest_str_checked(&cddl)
        .expect("die Importberichtsgrammatik muss vollstaendig parsen");
    let body = import_report_body(&cddl);
    let mut previous = 0;
    for position in IMPORT_REPORT_POSITIONS_V1 {
        let at = body
            .find(position)
            .unwrap_or_else(|| panic!("import-report-v1 nennt die Position {position} nicht"));
        assert!(
            at >= previous,
            "die Position {position} steht nicht in der festgelegten Reihenfolge"
        );
        previous = at;
    }
    for name in ["import-issue-v1", "import-issue-code-v1 = 0..12"] {
        assert!(cddl.contains(name), "die Grammatik nennt {name} nicht");
    }
    // Jeder gepinnte Code der Rust-Seite steht NAMENTLICH mit seiner
    // Diskriminante in der normativen Grammatik. Ohne diese Zusicherung koennte
    // ein Code umbenannt oder umnummeriert werden, ohne dass das Dokument, das
    // ihn schliesst, davon erfaehrt.
    for code in ea_format::ImportIssueCodeV1::ALL {
        let named = format!("{} {}", code.code(), code.name());
        assert!(
            cddl.contains(&named),
            "die Grammatik nennt den Code {named} nicht"
        );
    }
    assert_eq!(
        ea_format::ImportIssueCodeV1::ALL.len(),
        13,
        "der Codebereich 0..12 hat dreizehn Mitglieder"
    );
}

#[test]
fn import_report_cddl_rejects_a_thirteenth_position_and_an_unpinned_code() {
    let cddl = import_report_cddl();
    let twelve = import_report_cbor(12, &[6, 9]);
    assert!(
        cddl_cat::validate_cbor_bytes("import-report-v1", &cddl, &twelve).is_ok(),
        "die zwoelfstellige Gestalt muss angenommen werden"
    );
    assert!(
        ea_cbor::validate(&twelve, ea_cbor::ParserLimits::V1).is_ok(),
        "die zwoelfstellige Gestalt muss kanonisch sein"
    );
    let thirteen = import_report_cbor(13, &[6, 9]);
    assert!(
        cddl_cat::validate_cbor_bytes("import-report-v1", &cddl, &thirteen).is_err(),
        "eine dreizehnte Position muss abgelehnt werden"
    );
    let unpinned = import_report_cbor(12, &[13]);
    assert!(
        cddl_cat::validate_cbor_bytes("import-report-v1", &cddl, &unpinned).is_err(),
        "ein Code jenseits von 0..12 muss abgelehnt werden"
    );
    // Und die dateiweite Gestalt — `null`-Spalte — bleibt gueltig.
    let mut bytes = Vec::with_capacity(64);
    let mut encoder = minicbor::Encoder::new(&mut bytes);
    encoder
        .array(3)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.null())
        .and_then(|encoder| encoder.u8(0))
        .expect("das Kodieren in einen Vec kann nicht fehlschlagen");
    assert!(
        cddl_cat::validate_cbor_bytes("import-issue-v1", &cddl, &bytes).is_ok(),
        "eine dateiweite Zeile mit null-Spalte muss angenommen werden"
    );
}

/// Die Gestalt, in der ein `archive-backend-profile-core-v1`-Fixture kodiert
/// wird.
///
/// Dasselbe Muster wie [`PolicyCoreShapeV1`]: der Kern wird auf der Rustseite
/// POSITIONSWEISE gelesen und geschrieben, und ohne diese Zusicherung pinnt
/// nichts die Laenge gegen die NORMATIVE Seite. Das Urbild traegt einen
/// signierten Auditkontext (`archive-profile-migration-context-v1`), also
/// entscheidet die Arity darueber, ob zwei Werkzeuge denselben
/// `archiveProfileHash` errechnen.
///
/// # Was das faengt, und was nicht
///
/// Das positive Fixture schreibt an jeder Position einen KONKRETEN Typ. Eine
/// Loeschung, eine Einfuegung, eine Umsortierung und eine Typ-VERENGUNG fallen
/// damit auf. Eine Typ-ERWEITERUNG nicht: aus `uint` ein `any` zu machen laesst
/// jedes Fixture hier gueltig. Deshalb steht die Positionsnamenszusicherung
/// daneben — eine Umbenennung ist so laut wie eine Loeschung.
enum ArchiveProfileCoreShapeV1 {
    /// Alle 15 Positionen der Norm, in der Reihenfolge der Norm.
    Exact,
    /// OHNE `resume-max-attempts` — 14 Positionen.
    WithoutResumeMaxAttempts,
    /// Eine Position zu viel hinter der Erweiterungsliste — 16.
    WithExtraPosition,
}

fn archive_profile_core_fixture(shape: &ArchiveProfileCoreShapeV1) -> Vec<u8> {
    let positions = match shape {
        ArchiveProfileCoreShapeV1::Exact => 15,
        ArchiveProfileCoreShapeV1::WithoutResumeMaxAttempts => 14,
        ArchiveProfileCoreShapeV1::WithExtraPosition => 16,
    };
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(positions).unwrap();
    encoder.u8(1).unwrap(); //  1 Strukturversion
    encoder.u8(1).unwrap(); //  2 profile-kind
    encoder.str("smb-3-1-1-windows-server-2022").unwrap(); //  3 filesystem-row-id
    encoder.str("smb-3.1.1").unwrap(); //  4 protocol-id
    encoder.str("windows-server").unwrap(); //  5 server-product
    encoder.str("2022").unwrap(); //  6 server-version
    encoder.array(1).unwrap(); //  7 mount-options
    encoder.str("sync").unwrap();
    encoder.str("failover-single-node").unwrap(); //  8 failover-config-id
    encoder.str("cap-v1-smb").unwrap(); //  9 capability-test-vector-id
    encoder.u32(4096).unwrap(); // 10 queue-max-objects
    encoder.u32(1_073_741_824).unwrap(); // 11 queue-max-bytes
    encoder.u32(250).unwrap(); // 12 resume-backoff-initial-ms
    encoder.u32(60_000).unwrap(); // 13 resume-backoff-max-ms
    if !matches!(shape, ArchiveProfileCoreShapeV1::WithoutResumeMaxAttempts) {
        encoder.u32(12).unwrap(); // 14 resume-max-attempts
    }
    encoder.array(0).unwrap(); // 15 kritische Erweiterungen
    if matches!(shape, ArchiveProfileCoreShapeV1::WithExtraPosition) {
        encoder.u8(0).unwrap(); // 16 — eine zu viel
    }
    encoder.into_writer()
}

#[test]
fn archive_profile_cddl_enforces_the_exact_fifteen_positions_of_the_profile_core() {
    let cddl = archive_profile_cddl();

    assert!(
        validate_cbor(
            "archive-backend-profile-core-v1",
            &cddl,
            &archive_profile_core_fixture(&ArchiveProfileCoreShapeV1::Exact)
        ),
        "die 15 Positionen, die der Workspace kodiert, MUESSEN gegen die Grammatik gelten"
    );
    assert!(
        !validate_cbor(
            "archive-backend-profile-core-v1",
            &cddl,
            &archive_profile_core_fixture(&ArchiveProfileCoreShapeV1::WithoutResumeMaxAttempts)
        ),
        "14 Positionen MUESSEN abgelehnt werden"
    );
    assert!(
        !validate_cbor(
            "archive-backend-profile-core-v1",
            &cddl,
            &archive_profile_core_fixture(&ArchiveProfileCoreShapeV1::WithExtraPosition)
        ),
        "16 Positionen MUESSEN abgelehnt werden"
    );

    // Die Positionen beim Namen, damit eine Umbenennung so laut ist wie eine
    // Loeschung.
    assert_contains_all(
        "archive profile CDDL",
        &cddl,
        &[
            "profile-kind: 0..1",
            "filesystem-row-id: tstr",
            "protocol-id: tstr",
            "server-product: tstr",
            "server-version: tstr",
            "mount-options: [* tstr]",
            "failover-config-id: tstr",
            "capability-test-vector-id: tstr",
            "queue-max-objects: uint",
            "queue-max-bytes: uint",
            "resume-backoff-initial-ms: uint",
            "resume-backoff-max-ms: uint",
            "resume-max-attempts: uint",
            "active-profile-hash: bstr .size 32",
            "generation: uint",
        ],
    );
}
