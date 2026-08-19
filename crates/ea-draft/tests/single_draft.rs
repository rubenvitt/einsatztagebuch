//! Genau EIN verschluesselter Entwurf ueberlebt den Neustart.

mod support;

use support::{DraftHarness, DraftRepository as _};

#[test]
fn exactly_one_encrypted_draft_is_restored_after_restart() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    harness.repo.save(draft.with_notes("CANARY-DRAFT")).unwrap();
    let mut harness = harness.close_repo();
    let reopened = harness.reopen().repo.load_or_create().unwrap();
    assert_eq!(reopened.notes(), "CANARY-DRAFT");
    assert_eq!(harness.active_draft_row_count(), 1);
    assert!(!ea_testkit::contains_canary(
        harness.raw_database_bytes(),
        b"CANARY-DRAFT"
    ));

    // Die Zusicherung des Briefs darueber misst AUSSCHLIESSLICH SQLCipher —
    // GEMESSEN: mit umgangener AEAD in beide Richtungen blieb sie bestehen,
    // weil die Datei als Ganzes verschluesselt ist und den Klartext in der
    // Spalte mit verdeckt. Die ZWEITE Schicht braucht deshalb ihre eigene
    // Zusicherung, und die liest die Spalte DURCH SQLCipher hindurch: liegt der
    // Entwurf dort im Klartext, faellt genau diese Zeile.
    assert!(!ea_testkit::contains_canary(
        &harness.stored_payload_ciphertext(),
        b"CANARY-DRAFT"
    ));
}
