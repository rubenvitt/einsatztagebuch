//! Original-object comparison before Genesis, without final trust authority.

use super::*;
use ea_trust::verify_pre_anchor_bootstrap_objects;

#[test]
fn exact_bootstrap_originals_verify_against_only_the_pre_anchor() {
    let fixture = build_pre_fixture(&BootstrapSpec::valid());
    let before = fixture.anchor.exact_bytes().to_vec();
    let result: Result<(), TrustError> =
        verify_pre_anchor_bootstrap_objects(&fixture.anchor, &fixture.source);
    result.unwrap();
    assert_eq!(fixture.anchor.exact_bytes(), before);
    assert_eq!(fixture.source.visits.get(), 1);
    assert_eq!(fixture.source.total_reads(), fixture.source.objects.len());
    assert!(
        fixture
            .source
            .reads
            .borrow()
            .values()
            .all(|reads| *reads == 1)
    );
}

#[test]
fn initial_root_pins_and_pop_fail_closed_before_genesis() {
    let mut wrong_pin = BootstrapSpec::valid();
    wrong_pin.root_pin = RootPin::FirstAdminCertificate;
    let mut corrupt_pop = BootstrapSpec::valid();
    corrupt_pop.mutate_root_signature = true;
    let mut missing_root = BootstrapSpec::valid();
    missing_root.include_root = false;
    let mut extra_root = BootstrapSpec::valid();
    extra_root.extra_root = true;
    for (spec, code) in [
        (wrong_pin, "EA-TRUST-ANCHOR-PIN"),
        (corrupt_pop, "EA-TRUST-SIGNATURE"),
        (missing_root, "EA-TRUST-ANCHOR-PIN"),
        (extra_root, "EA-TRUST-ANCHOR-PIN"),
    ] {
        let fixture = build_pre_fixture(&spec);
        assert_static_error(
            "PreAnchor Root",
            verify_pre_anchor_bootstrap_objects(&fixture.anchor, &fixture.source).unwrap_err(),
            code,
        );
    }
}

#[test]
fn validly_signed_bindings_must_pair_by_exact_certificate_and_subject() {
    let mut wrong_pair = BootstrapSpec::valid();
    wrong_pair.bindings[0].certificate_index = 1;
    let mut wrong_subject = BootstrapSpec::valid();
    wrong_subject.bindings[0].operator_subject = operator_subject_id(0x49);
    for (spec, code) in [
        (wrong_pair, "EA-TRUST-BOOTSTRAP-PAIR"),
        (wrong_subject, "EA-TRUST-SUBJECT-MISMATCH"),
    ] {
        let fixture = build_pre_fixture(&spec);
        assert_static_error(
            "PreAnchor Pair",
            verify_pre_anchor_bootstrap_objects(&fixture.anchor, &fixture.source).unwrap_err(),
            code,
        );
    }
}

#[test]
fn pre_anchor_keeps_existing_initial_admin_signature_and_capability_rules() {
    let mut wrong_root_hash = BootstrapSpec::valid();
    wrong_root_hash.bindings[0].signature_mode = SignatureMode::WrongCertificateHash;
    let mut changed_signature = BootstrapSpec::valid();
    changed_signature.certificates[0].signature_mode = SignatureMode::Mutated;
    let mut missing_capability = BootstrapSpec::valid();
    missing_capability.certificates[0].capabilities.clear();
    let mut missing_binding = BootstrapSpec::valid();
    missing_binding.omit_bindings.push(1);
    for (spec, code) in [
        (wrong_root_hash, "EA-TRUST-SIGNATURE"),
        (changed_signature, "EA-TRUST-SIGNATURE"),
        (missing_capability, "EA-TRUST-BOOTSTRAP-PAIR"),
        (missing_binding, "EA-TRUST-ANCHOR-PIN"),
    ] {
        let fixture = build_pre_fixture(&spec);
        assert_static_error(
            "PreAnchor Admin",
            verify_pre_anchor_bootstrap_objects(&fixture.anchor, &fixture.source).unwrap_err(),
            code,
        );
    }
}
