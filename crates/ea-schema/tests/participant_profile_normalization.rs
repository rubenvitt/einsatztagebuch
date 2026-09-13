use ea_schema::OperatorSnapshotV1;

#[test]
fn participant_profile_texts_reuse_nfc_without_a_binding_placeholder() {
    let (name, function) =
        OperatorSnapshotV1::normalize_profile_texts("A\u{308}nne", "Fu\u{308}hrung");
    assert_eq!(name.as_str(), "Änne");
    assert_eq!(function.as_str(), "Führung");
    assert!(!format!("{name:?} {function:?}").contains("Änne"));
}
