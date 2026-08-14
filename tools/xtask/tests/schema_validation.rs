use std::process::Command;

#[test]
fn validate_schemas_checks_payload_cddl_and_all_five_literal_vectors() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("validate-schemas")
        .output()
        .expect("xtask validate-schemas must start");
    assert!(
        output.status.success(),
        "validate-schemas failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "validated 7 CDDL, 7 JSON schemas, 5 payload vectors, and compatibility matrix\n"
    );
}
