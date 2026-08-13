use std::collections::BTreeMap;

#[test]
fn maps_encode_in_rfc_8949_deterministic_order() {
    let map = std::collections::BTreeMap::from([("aa", 1_u64), ("b", 2_u64)]);
    let bytes = ea_cbor::to_deterministic_vec(&map).unwrap();
    assert_eq!(hex::encode(bytes), "a261620262616101");
}

#[test]
fn complex_map_keys_use_complete_encoding_bytewise_order() {
    let map = BTreeMap::from([(("aa", 0_u8), 1_u8), (("b", 0_u8), 2_u8)]);
    let bytes = ea_cbor::to_deterministic_vec(&map).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "a28261620002826261610001",
        "the first differing byte in the complete encoded array key decides"
    );
}

#[derive(Clone, Copy)]
struct DuplicateKeys;

impl<C> minicbor::Encode<C> for DuplicateKeys {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.map(2)?.str("same")?.u8(1)?.str("same")?.u8(2)?;
        Ok(())
    }
}

struct FailingEncoder;

impl<C> minicbor::Encode<C> for FailingEncoder {
    fn encode<W: minicbor::encode::Write>(
        &self,
        _encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        Err(minicbor::encode::Error::message("CANARY-CLEARTEXT"))
    }
}

#[test]
fn upstream_encode_failures_are_redacted_to_a_stable_code() {
    let error = ea_cbor::to_deterministic_vec(&FailingEncoder).unwrap_err();
    assert_eq!(error.code(), "EA-CBOR-ENCODE");
    assert_eq!(format!("{error:?}"), "EA-CBOR-ENCODE");
}

#[test]
fn duplicate_canonical_key_encodings_are_rejected() {
    let error = ea_cbor::to_deterministic_vec(&DuplicateKeys).unwrap_err();
    assert_eq!(error.code(), "EA-CBOR-DUPLICATE-KEY");
}

#[test]
fn unsupported_float_and_decomposed_text_encodings_are_rejected() {
    assert_eq!(
        ea_cbor::to_deterministic_vec(&1.5_f64).unwrap_err().code(),
        "EA-CBOR-FLOAT"
    );
    assert_eq!(
        ea_cbor::to_deterministic_vec(&"e\u{301}")
            .unwrap_err()
            .code(),
        "EA-CBOR-NON-NFC"
    );
}

#[test]
fn deterministic_encoding_is_stable_and_valid_across_generated_cases() {
    for seed in 0_u16..256 {
        let mut map = BTreeMap::new();
        for offset in 0_u16..8 {
            let key = format!("k{:03}", (seed.wrapping_mul(73) + offset * 29) % 257);
            map.insert(key, u64::from(seed) * 8 + u64::from(offset));
        }
        let first = ea_cbor::to_deterministic_vec(&map).unwrap();
        let second = ea_cbor::to_deterministic_vec(&map).unwrap();
        assert_eq!(first, second);
        ea_cbor::validate(&first, ea_cbor::ParserLimits::V1).unwrap();
    }
}

#[test]
fn canonical_inputs_are_idempotent_under_decode_validation() {
    let fixtures: &[&[u8]] = &[
        &[0x00],
        &[0x20],
        &[0x82, 0x01, 0x02],
        &[0xa2, 0x61, b'a', 0x01, 0x61, b'b', 0x02],
        &[0xc1, 0x00],
    ];
    for fixture in fixtures {
        ea_cbor::validate(fixture, ea_cbor::ParserLimits::V1).unwrap();
        ea_cbor::validate(fixture, ea_cbor::ParserLimits::V1).unwrap();
    }
}

#[test]
fn equal_length_map_keys_are_sorted_bytewise() {
    let map = BTreeMap::from([("z", 1_u8), ("a", 2_u8)]);
    assert_eq!(
        hex::encode(ea_cbor::to_deterministic_vec(&map).unwrap()),
        "a2616102617a01"
    );
}

#[test]
fn canonical_reencode_normalizes_map_order_and_is_idempotent() {
    let out_of_order = [0xa2, 0x62, b'a', b'a', 0x01, 0x61, b'b', 0x02];
    let canonical = ea_cbor::canonical_reencode(&out_of_order, ea_cbor::ParserLimits::V1).unwrap();
    assert_eq!(hex::encode(&canonical), "a261620262616101");
    assert_eq!(
        ea_cbor::canonical_reencode(&canonical, ea_cbor::ParserLimits::V1).unwrap(),
        canonical
    );
}

#[test]
fn rfc_8949_core_accepts_integer_24_before_empty_text_key() {
    let core_order = [0xa2, 0x18, 0x18, 0x01, 0x60, 0x02];
    ea_cbor::validate(&core_order, ea_cbor::ParserLimits::V1).unwrap();
}

#[test]
fn rfc_8949_core_rejects_length_first_heterogeneous_key_order() {
    let length_first_order = [0xa2, 0x60, 0x02, 0x18, 0x18, 0x01];
    assert_eq!(
        ea_cbor::validate(&length_first_order, ea_cbor::ParserLimits::V1)
            .unwrap_err()
            .code(),
        "EA-CBOR-MAP-ORDER"
    );
    assert_eq!(
        ea_cbor::canonical_reencode(&length_first_order, ea_cbor::ParserLimits::V1).unwrap(),
        [0xa2, 0x18, 0x18, 0x01, 0x60, 0x02]
    );
}

#[test]
fn rfc_8949_core_orders_complex_keys_by_complete_encoding_bytes() {
    let core_order = [
        0xa4, 0x18, 0x18, 0x01, 0x60, 0x02, 0x81, 0x00, 0x03, 0xc0, 0x80, 0x04,
    ];
    ea_cbor::validate(&core_order, ea_cbor::ParserLimits::V1).unwrap();

    let length_first_order = [
        0xa4, 0x60, 0x02, 0x18, 0x18, 0x01, 0x81, 0x00, 0x03, 0xc0, 0x80, 0x04,
    ];
    assert_eq!(
        ea_cbor::validate(&length_first_order, ea_cbor::ParserLimits::V1)
            .unwrap_err()
            .code(),
        "EA-CBOR-MAP-ORDER"
    );
}
