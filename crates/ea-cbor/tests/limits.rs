use ea_cbor::{BoundedDecoder, ParserLimits, validate};

fn code(input: &[u8]) -> &'static str {
    validate(input, ParserLimits::V1).unwrap_err().code()
}

#[test]
fn oversized_and_indefinite_values_fail_before_allocation() {
    let limits = ea_cbor::ParserLimits::V1;
    assert_eq!(
        ea_cbor::validate(&[0x5f, 0xff], limits).unwrap_err().code(),
        "EA-CBOR-INDEFINITE"
    );
    let header_for_2_mib = [0x5a, 0x00, 0x20, 0x00, 0x01];
    assert_eq!(
        ea_cbor::validate(&header_for_2_mib, limits)
            .unwrap_err()
            .code(),
        "EA-CBOR-ITEM-LIMIT"
    );
}

#[test]
fn nonminimal_integer_length_and_tag_encodings_are_rejected() {
    for bytes in [
        &[0x18, 0x17][..],
        &[0x38, 0x00],
        &[0x58, 0x00],
        &[0xd8, 0x00],
        &[0x19, 0x00, 0xff],
        &[0x3a, 0x00, 0x00, 0xff, 0xff],
    ] {
        assert_eq!(code(bytes), "EA-CBOR-NONMINIMAL", "fixture {bytes:02x?}");
    }
}

#[test]
fn floats_invalid_utf8_and_non_nfc_text_are_rejected() {
    for float in [
        &[0xf9, 0x3e, 0x00][..],
        &[0xfa, 0x3f, 0xc0, 0x00, 0x00],
        &[0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ] {
        assert_eq!(code(float), "EA-CBOR-FLOAT");
    }
    assert_eq!(code(&[0x61, 0xff]), "EA-CBOR-UTF8");
    assert_eq!(code(&[0x63, b'e', 0xcc, 0x81]), "EA-CBOR-NON-NFC");
}

#[test]
fn maps_require_canonical_order_and_unique_complex_keys() {
    assert_eq!(
        code(&[0xa2, 0x62, b'a', b'a', 0x01, 0x61, b'b', 0x02]),
        "EA-CBOR-MAP-ORDER"
    );
    assert_eq!(
        code(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]),
        "EA-CBOR-DUPLICATE-KEY"
    );
    assert_eq!(
        code(&[0xa2, 0x81, 0x00, 0x01, 0x81, 0x00, 0x02]),
        "EA-CBOR-DUPLICATE-KEY"
    );
    validate(
        &[0xa2, 0x81, 0x00, 0x01, 0x82, 0x00, 0x00, 0x02],
        ParserLimits::V1,
    )
    .unwrap();
}

#[test]
fn one_top_level_item_is_required_without_trailing_bytes() {
    assert_eq!(code(&[]), "EA-CBOR-INVALID");
    assert_eq!(code(&[0x00, 0x00]), "EA-CBOR-TRAILING");
    assert_eq!(code(&[0x58, 0x18]), "EA-CBOR-INVALID");

    let mut decoder = BoundedDecoder::new(&[0x82, 0x01, 0x02], ParserLimits::V1);
    decoder.validate_one().unwrap();
    assert!(decoder.is_eof());
}

#[test]
fn all_indefinite_major_types_are_rejected() {
    for initial in [0x5f, 0x7f, 0x9f, 0xbf, 0xff] {
        assert_eq!(code(&[initial]), "EA-CBOR-INDEFINITE");
    }
}

#[test]
fn reserved_simple_values_and_additional_information_are_invalid() {
    for bytes in [&[0xf8, 0x18][..], &[0xf8, 0x1f], &[0xfc], &[0xfd], &[0xfe]] {
        assert_eq!(code(bytes), "EA-CBOR-INVALID");
    }
}

#[test]
fn minimal_multibyte_integer_length_and_tag_encodings_are_accepted() {
    for bytes in [
        &[0x18, 0x18][..],
        &[0x38, 0x18],
        &[
            0x58, 0x18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        &[0xd8, 0x18, 0x00],
    ] {
        validate(bytes, ParserLimits::V1).unwrap();
    }
}

#[test]
fn every_nonminimal_width_is_rejected_for_uint_negative_length_and_tag() {
    for bytes in [
        &[0x1a, 0x00, 0x00, 0xff, 0xff][..],
        &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        &[0x39, 0x00, 0xff],
        &[0x59, 0x00, 0x18],
        &[0xda, 0x00, 0x00, 0xff, 0xff, 0x00],
    ] {
        assert_eq!(code(bytes), "EA-CBOR-NONMINIMAL");
    }
}

#[test]
fn nesting_limit_accepts_exact_boundary_and_rejects_one_over() {
    let mut exact = vec![0x81; 16];
    exact.push(0xf6);
    validate(&exact, ParserLimits::V1).unwrap();

    let mut over = vec![0x81; 17];
    over.push(0xf6);
    assert_eq!(code(&over), "EA-CBOR-DEPTH-LIMIT");
}

#[test]
fn tag_nesting_is_included_in_the_depth_limit() {
    let mut exact = vec![0xc0; 16];
    exact.push(0xf6);
    validate(&exact, ParserLimits::V1).unwrap();

    let mut over = vec![0xc0; 17];
    over.push(0xf6);
    assert_eq!(code(&over), "EA-CBOR-DEPTH-LIMIT");
}

#[test]
fn v1_text_and_byte_limit_preserves_the_full_aead_ciphertext_boundary() {
    let mut exact = vec![0x5a, 0x00, 0x10, 0x00, 0x10];
    exact.resize(5 + 1_048_592, 0);
    validate(&exact, ParserLimits::V1).unwrap();

    for major_header in [0x5a, 0x7a] {
        let over = [major_header, 0x00, 0x10, 0x00, 0x11];
        assert_eq!(code(&over), "EA-CBOR-ITEM-LIMIT");
    }
}

#[test]
fn per_container_and_total_item_budgets_enforce_exact_boundaries() {
    let relaxed_total = ParserLimits {
        max_total_items: 20_002,
        ..ParserLimits::V1
    };
    let mut exact_container = vec![0x99, 0x27, 0x10];
    exact_container.resize(3 + 10_000, 0xf6);
    validate(&exact_container, relaxed_total).unwrap();
    assert_eq!(
        validate(&[0x99, 0x27, 0x11], relaxed_total)
            .unwrap_err()
            .code(),
        "EA-CBOR-CONTAINER-LIMIT"
    );

    let mut exact_total = vec![0x99, 0x27, 0x0f];
    exact_total.resize(3 + 9_999, 0xf6);
    validate(&exact_total, ParserLimits::V1).unwrap();
    let mut over_total = vec![0x99, 0x27, 0x10];
    over_total.resize(3 + 10_000, 0xf6);
    assert_eq!(code(&over_total), "EA-CBOR-TOKEN-LIMIT");
}

#[test]
fn nested_arrays_maps_tags_and_scalars_each_consume_one_total_token() {
    // [{ 0: 0(null) }, h'01020304'] consumes six tokens: the root array,
    // map, key, tag, tagged null, and bstr. The four bstr payload bytes consume
    // no additional tokens.
    let nested = [0x82, 0xa1, 0x00, 0xc0, 0xf6, 0x44, 1, 2, 3, 4];
    let exact = ParserLimits {
        max_container_items: 2,
        max_total_items: 6,
        max_text_or_bytes: 4,
        ..ParserLimits::V1
    };
    validate(&nested, exact).unwrap();

    let over = ParserLimits {
        max_total_items: 5,
        ..exact
    };
    assert_eq!(
        validate(&nested, over).unwrap_err().code(),
        "EA-CBOR-TOKEN-LIMIT"
    );
}

#[test]
fn errors_map_to_the_shared_format_class_without_echoing_input() {
    let error = validate(&[0x61, 0xff], ParserLimits::V1).unwrap_err();
    assert_eq!(
        error.technical_code(),
        ea_types::TechnicalErrorCode::InvalidObject
    );
    assert_eq!(format!("{error}"), "EA-CBOR-UTF8");
    assert_eq!(format!("{error:?}"), "EA-CBOR-UTF8");
}

#[test]
fn zero_security_budgets_fail_closed_in_validation_and_reencoding() {
    for limits in [
        ParserLimits {
            max_depth: 0,
            ..ParserLimits::V1
        },
        ParserLimits {
            max_container_items: 0,
            ..ParserLimits::V1
        },
        ParserLimits {
            max_total_items: 0,
            ..ParserLimits::V1
        },
    ] {
        assert_eq!(
            validate(&[0x00], limits).unwrap_err().code(),
            "EA-CBOR-INVALID"
        );
        assert_eq!(
            ea_cbor::canonical_reencode(&[0x00], limits)
                .unwrap_err()
                .code(),
            "EA-CBOR-INVALID"
        );
    }
}

#[test]
fn canonical_reencode_enforces_every_parser_budget() {
    let cases = [
        (
            &[0x82, 0x00, 0x00][..],
            ParserLimits {
                max_container_items: 1,
                ..ParserLimits::V1
            },
            "EA-CBOR-CONTAINER-LIMIT",
        ),
        (
            &[0x81, 0x00],
            ParserLimits {
                max_total_items: 1,
                ..ParserLimits::V1
            },
            "EA-CBOR-TOKEN-LIMIT",
        ),
        (
            &[0x81, 0x81, 0x00],
            ParserLimits {
                max_depth: 1,
                ..ParserLimits::V1
            },
            "EA-CBOR-DEPTH-LIMIT",
        ),
        (
            &[0x62, b'a', b'b'],
            ParserLimits {
                max_text_or_bytes: 1,
                ..ParserLimits::V1
            },
            "EA-CBOR-ITEM-LIMIT",
        ),
    ];

    for (input, limits, expected) in cases {
        assert_eq!(
            ea_cbor::canonical_reencode(input, limits)
                .unwrap_err()
                .code(),
            expected
        );
    }
}
