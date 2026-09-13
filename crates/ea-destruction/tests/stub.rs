mod support;
use ea_destruction::{build_stub, verify_authorization, verify_stub_against_original};
use ea_format::{
    DestructionTargetV1, ParsedArchiveObject, decode_exact_object, encode_entry_package,
};
use support::*;

#[test]
fn authorized_stub_preserves_exact_original_identity_and_contains_no_ciphertext() {
    let f = with_writer(Fixture::new(true, true, false));
    let original = entry(&f);
    let encoded = encode_entry_package(&original).unwrap();
    let ParsedArchiveObject::Entry(parsed) = decode_exact_object(encoded.as_bytes()).unwrap()
    else {
        panic!()
    };
    let mut fields = f.fields();
    fields.targets = vec![DestructionTargetV1::new(
        *original.entry_hash().as_bytes(),
        original.manifest().fields().chain_sequence.get(),
    )];
    let exact = f.sign(fields, f.approvers.to_vec());
    let auth = verify_authorization(&exact, &f.head()).unwrap();
    let target = auth.verify_target(&original, &f.head()).unwrap();
    let stub = build_stub(&parsed, &auth, &target).unwrap();
    let ParsedArchiveObject::Destroyed(parsed_stub) = decode_exact_object(stub.as_bytes()).unwrap()
    else {
        panic!()
    };
    let body = parsed_stub.value();
    assert_eq!(
        body.signed_manifest().exact_bytes(),
        original.signed_manifest().exact_bytes()
    );
    assert_eq!(body.writer_signature(), original.writer_signature());
    assert!(body.entry_hash() == original.entry_hash());
    assert!(body.ciphertext_hash() == original.signed_manifest().ciphertext_hash());
    assert!(body.original_eip_object_hash() == parsed.object_hash());
    assert!(body.destruction_id() == auth.fields().destruction_id);
    assert!(body.destruction_authorization_object_hash() == auth.object_hash());
    assert!(
        !stub
            .as_bytes()
            .windows(original.ciphertext().len())
            .any(|w| w == original.ciphertext())
    );
    verify_stub_against_original(stub.as_bytes(), &parsed, &auth, &target).unwrap();
    let mut corrupt = stub.as_bytes().to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(verify_stub_against_original(&corrupt, &parsed, &auth, &target).is_err());
}

#[test]
fn another_operation_cannot_reuse_a_verified_target_to_create_a_stub() {
    let f = with_writer(Fixture::new(true, true, false));
    let original = entry(&f);
    let encoded = encode_entry_package(&original).unwrap();
    let ParsedArchiveObject::Entry(parsed) = decode_exact_object(encoded.as_bytes()).unwrap()
    else {
        panic!()
    };
    let mut fields = f.fields();
    fields.targets = vec![DestructionTargetV1::new(
        *original.entry_hash().as_bytes(),
        original.manifest().fields().chain_sequence.get(),
    )];
    let first =
        verify_authorization(&f.sign(fields.clone(), f.approvers.to_vec()), &f.head()).unwrap();
    let target = first.verify_target(&original, &f.head()).unwrap();
    fields.destruction_id = ea_types::DestructionId::try_from(&[0x82; 16][..]).unwrap();
    let other = verify_authorization(&f.sign(fields, f.approvers.to_vec()), &f.head()).unwrap();
    assert!(build_stub(&parsed, &other, &target).is_err());
}
