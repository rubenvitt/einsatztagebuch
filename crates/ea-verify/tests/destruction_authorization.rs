#[path = "support/mod.rs"]
mod support;
use ea_types::UnixMillis;
use ea_verify::{DestructionStateV1, VerifyOptions, verify_archive};

#[test]
fn original_pre_state_is_fully_verified_before_any_stub_replacement() {
    let f = support::destruction_v12::OriginalFixture::new(support::COMPLETE_PLAINTEXT_V1);
    let report = verify_archive(&f.source(), &f.anchor, VerifyOptions::new(UnixMillis::new(800))).unwrap();
    assert!(report.is_fully_verified(), "actual original entry and grant plan must verify");
    assert_eq!(report.object_results().count(), 1);
}

#[test]
fn deletion_attest_does_not_replace_two_distinct_approvers_or_privacy_approval() {
    for (same_subject, privacy) in [(true, true), (false, false)] {
        let f = support::destruction_v12::fixture(same_subject, 10_000, privacy);
        let report = verify_archive(&f.source, &f.anchor, VerifyOptions::new(UnixMillis::new(800))).unwrap();
        assert_eq!(report.authorized_destructions().len(), 0, "component signature cannot grant approval authority");
        assert!(!report.is_fully_verified());
    }
}

#[test]
fn valid_original_approval_and_events_survive_their_registry_wall_clock_lease() {
    let f = support::destruction_v12::fixture(false, 500, true);
    let report = verify_archive(&f.source, &f.anchor, VerifyOptions::new(UnixMillis::new(800))).unwrap();
    assert_eq!(report.authorized_destructions().len(), 1);
    assert_eq!(report.authorized_destructions().next().unwrap().state(), DestructionStateV1::InProgress);
    assert_eq!(report.signature_errors().len(), 0);
    assert!(report.is_fully_verified());
}
