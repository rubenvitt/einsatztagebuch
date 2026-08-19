//! Das Einsatznummernregister und die NUR LESENDE Profilzeile.

mod support;

use support::DraftHarness;

#[test]
fn the_register_rejects_a_second_claim_of_the_same_key_and_accepts_another_year() {
    let harness = DraftHarness::new();
    let register = harness.incident_number_register();
    register
        .claim(harness.organization_id(), 2026, "2026-0001")
        .unwrap();
    assert_eq!(
        register
            .claim(harness.organization_id(), 2026, "2026-0001")
            .unwrap_err()
            .code(),
        "EA-DRAFT-INCIDENT-NUMBER-TAKEN"
    );
    register
        .claim(harness.organization_id(), 2027, "2026-0001")
        .unwrap();
    assert!(
        register
            .contains(harness.organization_id(), 2026, "2026-0001")
            .unwrap()
    );
}

#[test]
fn the_operator_profile_row_is_readable_and_has_no_write_path() {
    let harness = DraftHarness::with_seeded_operator_profile();
    let profile = harness.operator_profile_repo().load().unwrap().unwrap();
    assert_eq!(profile.display_name(), "Ada Lovelace");
    // Byteweise verglichen und nicht ueber den Newtype: `ObjectHash` traegt in
    // diesem Bauwerk bewusst KEINE Formatierung, und `assert_eq!` verlangt
    // `Debug` fuer seine Fehlermeldung. Die Aussage ist dieselbe — dreissig
    // zwei Bytes gegen dreissig zwei Bytes desselben Typs.
    assert_eq!(
        profile.operator_binding_object_hash().as_bytes(),
        harness.bound_operator_binding_object_hash().as_bytes()
    );
}
