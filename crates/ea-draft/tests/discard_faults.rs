//! Verwerfen ist unwiderruflich und fortsetzbar.
//!
//! Jeder Unterbrechungspunkt der Reihenfolge fuehrt nach einem Neustart auf
//! GENAU zwei Zustaende: der alte Entwurf steht unveraendert, oder es steht ein
//! DAUERHAFT leerer Entwurf. Ein dritter Zustand — ein halb verworfener
//! Entwurf, ein wiederauferstandener Inhalt, ein liegengebliebener Schluessel —
//! existiert nicht, und diese Datei ist der Beleg dafuer.

mod support;

use ea_draft::{DiscardFaultPoint, DiscardPhase, RestartState};
use ea_operator::ReauthPurpose;
use support::DraftHarness;

#[test]
fn every_discard_fault_yields_old_draft_or_permanent_blank_draft() {
    for point in DiscardFaultPoint::ALL.iter().copied() {
        let mut h = DraftHarness::with_nonempty_draft();
        let _ = h.discard_with_fault(point);
        let first = h.restart_and_resume().unwrap();
        assert!(
            matches!(
                first,
                RestartState::OriginalDraftUnchanged | RestartState::NewBlankDraft
            ),
            "{point:?}"
        );
        let second = h.restart_and_resume().unwrap();
        assert_eq!(second, first, "ein zweites resume ist ein no-op: {point:?}");
        let restored = h.restore_captured_backup().unwrap();
        assert!(
            matches!(
                restored,
                RestartState::OriginalDraftUnchanged | RestartState::NewBlankDraft
            ),
            "{point:?}"
        );
        // Die TRAGENDE Aussage der Rueckspielung. Die Zusicherung oben laesst
        // beide Zustaende zu und kann deshalb nicht messen, dass eine
        // zurueckgelegte Sicherung keinen LESBAREN verworfenen Entwurf ergibt:
        // der `draftDEK` liegt in einem geraetegebundenen
        // Schluesselspeichereintrag, den die gewoehnliche Sicherung ausnimmt
        // (`design.md`:428, :1491). Ist er fort, MUSS die Rueckspielung im
        // leeren Entwurf enden und nicht im alten.
        if !h.draft_dek_is_present() {
            assert_eq!(
                restored,
                RestartState::NewBlankDraft,
                "eine Sicherung ohne draftDEK ergibt keinen lesbaren Entwurf: {point:?}"
            );
        }
    }
}

#[test]
fn every_discard_phase_has_its_own_restart_outcome() {
    for phase in DiscardPhase::ALL.iter().copied() {
        let mut h = DraftHarness::with_nonempty_draft();
        h.discard_up_to(phase).unwrap();
        // Der dauerhafte Schritt, der die ganze Zusage traegt, und die EINZIGE
        // Stelle, an der er sichtbar ist. Nach `KeyAbsent` — und nur dort —
        // steht kein Eintrag mehr an der Adresse des `draftDEK`. Danach legt
        // `create_blank` einen frischen an dieselbe Adresse, und ab da waere
        // „die alten Bytes sind nicht mehr zu oeffnen" auch OHNE ein Loeschen
        // wahr, blosss durch das Ueberschreiben. Eine Zusicherung, die erst
        // nach dem leeren Entwurf messen wuerde, koennte das Loeschen also
        // ueberhaupt nicht mehr sehen.
        assert_eq!(
            h.draft_dek_entry_is_absent(),
            phase == DiscardPhase::KeyAbsent,
            "{phase:?}"
        );
        let state = h.restart_and_resume().unwrap();
        let expected = match phase {
            DiscardPhase::Editable => RestartState::OriginalDraftUnchanged,
            DiscardPhase::IntentDurable | DiscardPhase::KeyAbsent | DiscardPhase::DraftRemoved => {
                RestartState::NewBlankDraft
            }
        };
        assert_eq!(state, expected, "{phase:?}");
        assert!(!h.draft_dek_is_present() || phase == DiscardPhase::Editable);
    }
}

#[test]
fn discard_without_a_fresh_proof_is_rejected() {
    let h = DraftHarness::with_nonempty_draft();
    assert_eq!(
        h.discard_service()
            .begin_discard(h.expired_proof())
            .unwrap_err()
            .code(),
        "EA-DRAFT-REAUTH-REQUIRED"
    );
    assert_eq!(
        h.restart_and_resume().unwrap(),
        RestartState::OriginalDraftUnchanged
    );
}

#[test]
fn a_proof_of_another_purpose_never_authorizes_a_discard() {
    let h = DraftHarness::with_nonempty_draft();
    assert_eq!(
        h.discard_service()
            .begin_discard(h.proof_for(ReauthPurpose::Finalize))
            .unwrap_err()
            .code(),
        "EA-DRAFT-REAUTH-PURPOSE-MISMATCH"
    );
    // Nichts ist dauerhaft geworden: der Entwurf ist noch da.
    assert_eq!(
        h.restart_and_resume().unwrap(),
        RestartState::OriginalDraftUnchanged
    );
}

#[test]
fn a_prepared_finalization_takes_precedence_over_resume_discard() {
    let mut h = DraftHarness::with_nonempty_draft();
    h.set_prepared_finalization_marker();
    assert_eq!(
        h.discard_service()
            .begin_discard(h.proof_for(ReauthPurpose::DiscardDraft))
            .unwrap_err()
            .code(),
        "EA-DRAFT-PREPARED-FINALIZATION-PRESENT"
    );
    assert_eq!(
        h.restart_and_resume().unwrap(),
        RestartState::PreparedFinalizationPending
    );
    assert!(h.pending_discard_is_absent());
}

#[test]
fn a_keystore_that_reports_a_deletion_without_deleting_stops_the_discard() {
    let h = DraftHarness::with_nonempty_draft();
    // Fail-closed: `delete` meldet `Ok`, der Eintrag liegt weiter, und der
    // Dienst sieht NACH und bricht ab, statt der Meldung des Providers zu
    // glauben.
    assert_eq!(
        h.discard_service_with_deaf_keystore()
            .begin_discard(h.proof_for(ReauthPurpose::DiscardDraft))
            .unwrap_err()
            .code(),
        "EA-DRAFT-KEY-DELETION-NOT-CONFIRMED"
    );
    // Und der Abbruch verklemmt nichts: die Absicht ist gebucht, also loest der
    // Neustart mit einem wahrhaftigen Schluesselspeicher sie auf.
    assert_eq!(h.restart_and_resume().unwrap(), RestartState::NewBlankDraft);
}

#[test]
fn a_prepared_finalization_marker_displaces_a_booked_discard_intent() {
    let mut h = DraftHarness::with_nonempty_draft();
    h.discard_up_to(DiscardPhase::IntentDurable).unwrap();
    assert!(
        !h.pending_discard_is_absent(),
        "die Absicht muss gebucht sein, sonst messen die Zeilen darunter nichts"
    );
    h.set_prepared_finalization_marker();
    // `draft_transition` ist EIN Platz mit einer `kind`-Spalte. Die
    // Abschlussmarke verdraengt die gebuchte Verwerfensabsicht deshalb
    // STRUKTURELL — `PRIMARY KEY CHECK (singleton = 0)` in
    // `0002_discard.sql` —, und nicht durch Programmdisziplin. Lagen die zwei
    // Arten in zwei Zeilen, ueberlebte die Absicht hier.
    assert!(h.pending_discard_is_absent());
    assert_eq!(
        h.restart_and_resume().unwrap(),
        RestartState::PreparedFinalizationPending
    );
}

#[test]
fn resume_discard_finishes_a_booked_intent_and_refuses_without_one() {
    let mut h = DraftHarness::with_nonempty_draft();
    // Ohne gebuchte Absicht gibt es nichts fortzusetzen. Fail-closed, und
    // ausdruecklich KEIN stilles `Ok`, das ein Verwerfen von vorn begaenne.
    assert_eq!(
        h.discard_service()
            .resume_discard(&h.proof_for(ReauthPurpose::DiscardDraft))
            .unwrap_err()
            .code(),
        "EA-DRAFT-NO-PENDING-DISCARD"
    );
    h.discard_up_to(DiscardPhase::IntentDurable).unwrap();
    let outcome = h
        .discard_service()
        .resume_discard(&h.proof_for(ReauthPurpose::DiscardDraft))
        .unwrap();
    // Der leere Entwurf traegt eine FRISCHE Kennung; `Id16` traegt bewusst kein
    // `Debug`, also wird byteweise verglichen.
    assert_ne!(
        outcome.blank().draft_id().as_bytes(),
        outcome.discarded_draft_id().as_bytes()
    );
    assert_eq!(outcome.blank().revision(), 0);
    assert!(h.pending_discard_is_absent());
    assert!(!h.draft_dek_is_present());
}

#[test]
fn a_restart_never_continues_a_discard_without_a_fresh_proof() {
    let mut h = DraftHarness::with_nonempty_draft();
    h.discard_up_to(DiscardPhase::IntentDurable).unwrap();
    // Der Neustartpfad kann den UNWIDERRUFLICHEN Schritt ausfuehren, also
    // verlangt er dieselbe frische Wiederanmeldung wie der Eingang — und zwar
    // BEVOR er ueberhaupt nachsieht, was zu tun waere.
    assert_eq!(
        h.restart_and_resume_with(&h.expired_proof())
            .unwrap_err()
            .code(),
        "EA-DRAFT-REAUTH-REQUIRED"
    );
    // Und er hat nichts fortgesetzt: Absicht gebucht, Schluessel unberuehrt.
    assert!(!h.pending_discard_is_absent());
    assert!(h.draft_dek_is_present());
    // Mit einem frischen Nachweis loest derselbe Pfad sie auf.
    assert_eq!(h.restart_and_resume().unwrap(), RestartState::NewBlankDraft);
}

/// Der Nachweis, den Task 6 AUSDRUECKLICH diesem Task uebergeben hat.
///
/// Task 6s Fix-Bericht sagt zur Raeumung von `draft_transition` in
/// `replace_with_blank`: „Nicht gemessen und hier auch nicht messbar. Ohne
/// `0002_discard.sql` gibt es keine `draft_transition`-Tabelle … Der Nachweis
/// gehoert dem Task, der die Tabelle anlegt (Task 7)." Dieser Task legt sie an,
/// also ist er hier faellig — und `resume_after_restart` erbringt ihn NICHT:
/// dort laeuft `replace_with_blank` nur auf dem Zweig, auf dem Marke und
/// Absicht schon beide fort sind, die Raeumung also leerlaeuft.
#[test]
fn replacing_the_draft_with_a_blank_clears_a_booked_discard_intent() {
    let mut h = DraftHarness::with_nonempty_draft();
    h.discard_up_to(DiscardPhase::IntentDurable).unwrap();
    assert!(!h.pending_discard_is_absent());
    h.replace_with_blank().unwrap();
    // Ohne die Raeumung meldete `pending_discard` dauerhaft eine `draft_id`,
    // die es nicht mehr gibt, und
    // `remove_ciphertext_and_intent_create_blank` wiese sie mit `NoDraft` ab:
    // ein Zustand, den kein Arm des gegateten Traits mehr verlassen kann.
    assert!(h.pending_discard_is_absent());
    assert_eq!(h.draft_row_count(), 1);
    assert_eq!(h.restart_and_resume().unwrap(), RestartState::NewBlankDraft);
}
