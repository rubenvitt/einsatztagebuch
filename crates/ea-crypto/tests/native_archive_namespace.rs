use ea_crypto::native_archive_component_namespace;
use ea_types::Hash32;
#[test]
fn native_namespace_pins_domain_nul_and_exact_anchor_profile_order() {
    let anchor = Hash32::try_from([0x11; 32].as_slice()).unwrap();
    let profile = Hash32::try_from([0x22; 32].as_slice()).unwrap();
    // Independently computed with Python hashlib.sha256 over the brief bytes.
    let expected =
        hex::decode("98dfa0d03db8a913d179f7b21123fc1fe342308784a6c538babbd86b425b5db5").unwrap();
    let actual = native_archive_component_namespace(anchor, profile);
    assert_eq!(actual.as_bytes().as_slice(), expected);
    assert!(actual != native_archive_component_namespace(profile, anchor));
}
