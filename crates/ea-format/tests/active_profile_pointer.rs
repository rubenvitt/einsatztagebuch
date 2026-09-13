use ea_format::{
    ActiveProfilePointerCoreV1, decode_active_profile_pointer_core,
    encode_active_profile_pointer_core,
};

fn pointer(generation: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x83, 0x01, 0x58, 0x20];
    bytes.extend_from_slice(&[0x5a; 32]);
    bytes.extend_from_slice(generation);
    bytes
}

#[test]
fn canonical_generation_boundaries_preserve_the_existing_exact_bytes() {
    for (generation, encoded) in [
        (0, vec![0]),
        (23, vec![23]),
        (24, vec![0x18, 24]),
        (255, vec![0x18, 255]),
        (256, vec![0x19, 1, 0]),
        (65_536, vec![0x1a, 0, 1, 0, 0]),
        (u64::MAX, vec![0x1b, 255, 255, 255, 255, 255, 255, 255, 255]),
    ] {
        let exact = pointer(&encoded);
        let decoded = decode_active_profile_pointer_core(&exact).unwrap();
        assert_eq!(decoded.active_profile_hash().as_bytes(), &[0x5a; 32]);
        assert_eq!(decoded.generation(), generation);
        assert_eq!(encode_active_profile_pointer_core(&decoded).unwrap(), exact);
    }
    assert!(decode_active_profile_pointer_core(&pointer(&[0x1b; 10])).is_err());
    assert_eq!(
        pointer(&[0x1b, 255, 255, 255, 255, 255, 255, 255, 255]).len(),
        ActiveProfilePointerCoreV1::MAX_ENCODED_BYTES
    );
}

#[test]
fn rejects_wrong_shape_version_hash_length_and_trailing_input() {
    let valid = pointer(&[0]);
    for length in 0..valid.len() {
        assert!(decode_active_profile_pointer_core(&valid[..length]).is_err());
    }
    let mut cases = vec![
        vec![],
        vec![0xff],
        pointer(&[0x20]),
        pointer(&[0xf6]),
        pointer(&[0xf9, 0, 0]),
    ];
    for (position, value) in [
        (0, 0x82),
        (0, 0x84),
        (0, 0x9f),
        (1, 0),
        (1, 2),
        (2, 0x78),
        (3, 31),
        (3, 33),
    ] {
        let mut changed = valid.clone();
        changed[position] = value;
        cases.push(changed);
    }
    let mut trailing = valid;
    trailing.push(0);
    cases.push(trailing);
    for bytes in cases {
        assert!(
            decode_active_profile_pointer_core(&bytes).is_err(),
            "accepted {bytes:02x?}"
        );
    }
}

#[test]
fn rejects_nonminimal_cbor_even_when_it_decodes_to_the_same_pointer() {
    let valid = pointer(&[0]);
    let mut nonminimal_array = vec![0x98, 3];
    nonminimal_array.extend_from_slice(&valid[1..]);
    let mut nonminimal_version = vec![0x83, 0x18, 1];
    nonminimal_version.extend_from_slice(&valid[2..]);
    let mut nonminimal_hash_length = vec![0x83, 1, 0x59, 0, 32];
    nonminimal_hash_length.extend_from_slice(&valid[4..]);
    let mut indefinite_hash = vec![0x83, 1, 0x5f, 0x58, 32];
    indefinite_hash.extend_from_slice(&[0x5a; 32]);
    indefinite_hash.extend_from_slice(&[0xff, 0]);
    for bytes in [
        nonminimal_array,
        nonminimal_version,
        nonminimal_hash_length,
        indefinite_hash,
        pointer(&[0x18, 0]),
        pointer(&[0x19, 0, 24]),
    ] {
        assert!(
            decode_active_profile_pointer_core(&bytes).is_err(),
            "accepted {bytes:02x?}"
        );
    }
}
