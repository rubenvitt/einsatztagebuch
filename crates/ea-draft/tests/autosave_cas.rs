//! Zwei ueberlappende Autospeicherungen holen alten Inhalt nicht zurueck.

mod support;

use support::{DraftHarness, DraftRepository as _};

#[test]
fn overlapping_autosaves_never_resurrect_old_content() {
    let harness = DraftHarness::new();
    let first = harness.repo.load_or_create().unwrap();
    let second = harness.repo.load_or_create().unwrap();
    let winner = harness.repo.save(first.with_notes("NEU")).unwrap();
    assert_eq!(
        harness
            .repo
            .save(second.with_notes("ALT"))
            .unwrap_err()
            .code(),
        "EA-DRAFT-REVISION-CONFLICT"
    );
    let reread = harness.repo.load_or_create().unwrap();
    assert_eq!(reread.notes(), "NEU");
    assert_eq!(reread.revision(), winner.revision());
    assert_eq!(harness.active_draft_row_count(), 1);
}
