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

/// `replace_with_blank` laesst genau EINEN leeren Entwurf zurueck.
///
/// Der Arm war ungetestet, und in seinem Rumpf sitzt die Raeumung des
/// Uebergangsplatzes. Der Raeumungszweig selbst ist HIER nicht messbar:
/// `draft_transition` entsteht erst mit `0002_discard.sql`, also ueberspringt
/// der Arm ihn in diesem Task — gemessen wird, was hier ausfuehrbar ist, und
/// der Nachweis der Raeumung gehoert dem Task, der die Tabelle anlegt.
#[test]
fn replacing_the_draft_with_a_blank_leaves_exactly_one_empty_draft() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let saved = harness.repo.save(draft.with_notes("CANARY-DRAFT")).unwrap();

    let blank = harness.repo.replace_with_blank().unwrap();

    assert_eq!(blank.revision(), 0);
    // `Id16` traegt bewusst kein `Debug`, deshalb der Vergleich ueber die
    // Bytes — dieselbe Begruendung wie in `register_and_profile.rs`.
    assert_ne!(blank.draft_id().as_bytes(), saved.draft_id().as_bytes());
    assert_eq!(harness.active_draft_row_count(), 1);
    assert_eq!(harness.repo.load_or_create().unwrap().notes(), "");
}

/// Der ENTWURFSKLARTEXT wird beim Fallenlassen genullt.
///
/// Ein Compile-Zeuge, und das ist die einzige ehrliche Bauart: nach einem
/// `drop` ist der Speicher freigegeben, und ihn in sicherem Rust noch einmal zu
/// lesen ginge nicht. Was sich BELEGEN laesst, ist die Zusage des Typs — und
/// sie ist keine Formalie, sondern genau das, was `design.md`:456 fuer Schritt 9
/// verlangt („fachlichen UI-Zustand leeren"): [`ea_draft::Draft`] haelt den
/// einzigen Entwurfsklartext dieses Bauwerks, und Schritt 9 der Finalisierung
/// reicht ihn an `save` weiter, das ihn am Ende seines Rumpfes fallen laesst.
///
/// Die Zusicherung ist FALSIFIZIERBAR: verschwindet `ZeroizeOnDrop` von
/// [`ea_draft::Draft`], uebersetzt diese Datei nicht mehr.
#[test]
fn the_draft_plaintext_zeroizes_itself_when_it_is_dropped() {
    const fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    requires_zeroize_on_drop::<ea_draft::Draft>();

    // Und der Ersatztext laesst den alten Puffer nicht stehen: `with_notes`
    // nullt ihn, bevor es ihn ersetzt. Messbar ist davon der ERHALT der
    // uebrigen Felder — der Zeuge fuer das Nullen selbst ist die Zeile
    // darueber.
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let draft_id = draft.draft_id().as_bytes().to_vec();
    let revision = draft.revision();
    let replaced = draft.with_notes("CANARY-DRAFT-REPLACED");
    assert_eq!(replaced.notes(), "CANARY-DRAFT-REPLACED");
    assert_eq!(replaced.draft_id().as_bytes().to_vec(), draft_id);
    assert_eq!(replaced.revision(), revision);
}
