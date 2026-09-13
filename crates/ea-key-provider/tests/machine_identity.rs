#[test]
fn native_machine_identity_is_stable_and_not_an_account_or_caller_supplied_label() {
    let first=ea_key_provider::measure_native_machine_identity().unwrap();
    let second=ea_key_provider::measure_native_machine_identity().unwrap();
    assert_eq!(first.fingerprint().as_bytes(),second.fingerprint().as_bytes());
    assert_ne!(first.fingerprint().as_bytes(),&[0;32]);
}
