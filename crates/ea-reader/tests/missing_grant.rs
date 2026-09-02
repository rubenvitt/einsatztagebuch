//! Die Zustandssprache aus `design.md` §17.4: fuenf Begriffe, fuenf Bestaende,
//! und eine Luecke, die gar keine Zeile hat.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{ChainSequence, EntryStatus, VerificationStatus};

use verify_fixtures::{fixtures, verify_support};

#[test]
fn a_valid_entry_without_an_own_grant_is_exactly_missing_grant() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::entry_without_own_grant();
    let classification = fixtures::classify(source, &vault);
    let entry_hash = fixtures::entry_hash(source);
    let state = classification
        .state_of(entry_hash)
        .expect("der Eintrag bleibt sichtbar");
    assert_eq!(state.verification(), VerificationStatus::MissingGrant);
    assert_eq!(state.entry_state(), EntryStatus::Present);
    // GEMESSEN, nicht gewaehlt: `archive_without_the_own_grant()` ruft
    // `complete_archive_for(.., 1)` auf der Linie mit
    // COMPLETE_GENESIS_SEQUENCE_V1 == 0. Der Bestand hat GENAU EINEN Eintrag.
    assert_eq!(
        state.sequence(),
        ChainSequence::new(verify_support::COMPLETE_GENESIS_SEQUENCE_V1),
    );
    // Kein Befund: fehlender Grant ist KEINE Beschaedigung.
    assert_eq!(state.detail_code(), None);
    assert_eq!(classification.report().decryption_errors().len(), 0);
    assert_eq!(classification.report().gaps().len(), 0);
    assert!(classification.report().is_fully_verified());
    // Und kein Zeuge, also ist die Entschluesselung nicht formulierbar.
    assert!(classification.verified_grant(entry_hash).is_none());
}

// Die Zustaende, die `design.md` §17.4 auseinanderhaelt, an je einem Bestand.
//
// `UnsupportedSchema` fehlt in dieser Tabelle, und das ist gemessen: er
// entsteht erst, wenn ein Klartext vorliegt und keine der fuenf
// Schemabestimmungen ihn traegt — `classify` entschluesselt aber nichts. Sein
// Zeuge steht in `historical_expiry.rs` am Rueckgabecode von
// `decrypt_verified`.
#[test]
fn missing_grant_gap_unknown_key_and_invalid_never_collapse() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let cases = fixtures::the_measured_states();
    // ANTI-LEERLAUF: eine leere Tabelle liefe gruen durch.
    assert!(cases.len() >= 5);
    for case in cases {
        let classification = fixtures::classify(case.source, &vault);
        let state = classification.state_of(case.key).expect(case.label);
        assert_eq!(state.verification(), case.expected, "{}", case.label);
        assert_eq!(state.detail_code(), case.expected_code, "{}", case.label);
        // DAS ZEUGENPAAR GIBT ES GENAU FUER `verifiziert`. Jede andere Zeile —
        // auch `unbekannter Schluessel`, dessen Eintrag sein `objectResult`
        // behaelt — bekommt keins: `decrypt_verified` darf fuer sie gar nicht
        // erst formulierbar sein (`web-reader-design.md` §9).
        let witnessed = case.expected == VerificationStatus::Verified;
        assert_eq!(
            classification.verified_entry(case.key).is_some(),
            witnessed,
            "{}",
            case.label
        );
        assert_eq!(
            classification.verified_grant(case.key).is_some(),
            witnessed,
            "{}",
            case.label
        );
    }
}

// Eine Luecke OHNE Traeger ist KEINE Zustandszeile, sondern eine
// SEQUENZadressierte Zeile. `archive_with_a_missing_middle_entry()` laesst
// MISSING_MIDDLE_SEQUENCE_V1 aus; zu dieser Sequenz existiert per Definition
// kein Objekt und damit weder EntryHash noch ObjectHash.
//
// ZWEI Luecken und nicht eine, und das ist gemessen: die Kettenfamilie dieses
// Fixture-Moduls beginnt auf FIRST_ENTRY_SEQUENCE_V1 == 1, die Sequenz NULL
// fehlt ihr also ohnehin (siehe GENESIS_GAP_SEQUENCE_V1). Der fruehere
// Plantext erwartete genau eine Zeile und irrte darin.
#[test]
fn a_gap_without_a_stub_is_reported_by_sequence_and_never_as_an_entry_row() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::archive_with_a_gap_without_a_stub();
    let classification = fixtures::classify(source, &vault);
    let sequences: Vec<ChainSequence> = classification
        .gaps()
        .map(|gap| {
            assert_eq!(
                gap.from_sequence(),
                gap.through_sequence(),
                "die Luecken dieses Bestands sind je eine einzelne Sequenz"
            );
            gap.from_sequence()
        })
        .collect();
    assert_eq!(
        sequences,
        vec![
            ChainSequence::new(verify_support::GENESIS_GAP_SEQUENCE_V1),
            ChainSequence::new(verify_support::MISSING_MIDDLE_SEQUENCE_V1),
        ],
    );
    // Und KEINE der beiden Sequenzen traegt eine Zustandszeile: ohne Objekt
    // gibt es weder EntryHash noch ObjectHash, und `ReaderEntryStateV1::new`
    // verlangt beide.
    for state in classification.states() {
        assert!(
            !sequences.contains(&state.sequence()),
            "eine traegerlose Luecke darf keine Zustandszeile bekommen"
        );
    }
}
