//! Die vier Waechter der Entwurfsablage, die keine Zusicherung trug.
//!
//! Sie stehen in EINER Datei, weil sie dieselbe Grenze bewachen: den Zugang zu
//! der EINEN Entwurfszeile. Die Sperre traegt Produktinvariante 1 („es
//! existiert genau ein aktiver Entwurf", `design.md`:426) — ohne sie sind zwei
//! Writer-Instanzen auf demselben Konto zwei Bearbeiter desselben Entwurfs.

mod support;

use ea_draft::DraftRepository as _;

use self::support::DraftHarness;

/// Die AUSSCHLIESSLICHE Entwurfssperre laesst genau einen Bewerber durch.
///
/// `create_new` ist auf allen drei Plattformen atomar (`crates/ea-draft/src/lock.rs`),
/// und daran haengt die prozessuebergreifende Fassung von Invariante 1: eine
/// zweite Writer-Instanz auf demselben Konto ist der Fall, gegen den die Sperre
/// steht. Waere das Anlegen ein gewoehnliches `create`, gelaenge es beiden.
#[test]
fn the_exclusive_draft_lock_admits_exactly_one_holder() {
    let harness = DraftHarness::new();

    let held = harness.repo.acquire_draft_lock().unwrap();
    assert_eq!(
        harness.repo.acquire_draft_lock().unwrap_err().code(),
        "EA-DRAFT-LOCK-HELD"
    );

    // Und sie ist WIRKLICH ein Waechter und keine dauerhafte Blockade: sein
    // `Drop` gibt sie frei, sonst waere nach dem ersten Verwerfen kein Eingang
    // mehr passierbar.
    drop(held);
    let _next = harness.repo.acquire_draft_lock().unwrap();
}

/// Ein Griff auf einen Entwurf, den es nicht mehr gibt, bekommt KEINEN
/// Schluessel.
///
/// `draft_dek_handle` vergleicht die Kennung der gelesenen Zeile mit der des
/// uebergebenen Belegs (`crates/ea-draft/src/autosave.rs`:205). Ohne diesen
/// Vergleich gaebe die Ablage den `draftDEK` des AKTUELLEN Entwurfs an einen
/// Beleg heraus, der einen laengst ersetzten nennt — und der Aufrufer
/// entschluesselte damit fremden Inhalt oder loeschte den falschen Schluessel.
#[test]
fn a_stale_saved_draft_never_yields_the_current_draft_dek() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let stale = harness.repo.save(draft.with_notes("ALT")).unwrap();
    // Der Beleg ist gueltig, solange sein Entwurf steht.
    harness.repo.draft_dek_handle(&stale).unwrap();

    let blank = harness.repo.replace_with_blank().unwrap();

    assert_eq!(
        harness.repo.draft_dek_handle(&stale).unwrap_err().code(),
        "EA-DRAFT-NOT-FOUND"
    );
    // Der Beleg des NEUEN Entwurfs geht durch: sonst koennte die Ablehnung
    // oben von etwas anderem als dem Kennungsvergleich kommen.
    harness.repo.draft_dek_handle(&blank).unwrap();
}

/// Die SCHREIBENDEN Uebergangsarme lehnen NAMENTLICH ab, solange
/// `0002_discard.sql` nicht registriert ist — die lesenden melden Abwesenheit.
///
/// „Die Tabelle gibt es noch nicht" ist eine andere Aussage als „die Datenbank
/// ist beschaedigt", und nur die erste darf ein spaeterer Task aufloesen
/// (`crates/ea-draft/src/model.rs`:33-38). Ohne die POSITIVE Abfrage der
/// Registratur fiele hier ein roher SQL-Fehlschlag an — `EA-STORE-DATABASE` —
/// und der Unterschied waere fort. GEMESSEN: mit entferntem Waechter meldet
/// `commit_discard_intent` genau diesen Code.
///
/// Der dritte schreibende Arm, `remove_ciphertext_and_intent_create_blank`,
/// ist in diesem Zustand nicht erreichbar und steht deshalb hier nicht: sein
/// Argument ist ein `DiscardIntent`, und der entsteht ausschliesslich aus
/// `commit_discard_intent` oder `pending_discard` — der eine lehnt hier ab, der
/// andere meldet Abwesenheit. Ein Aufrufer kann ihn nicht herstellen.
#[test]
fn the_transition_arms_name_the_missing_migration_instead_of_failing_raw() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let saved = harness.repo.save(draft).unwrap();

    // Danach wird NICHT wieder geoeffnet: die Migrationskette laeuft bei jedem
    // Oeffnen und legte die Tabelle sofort wieder an.
    harness.unregister_discard_migration();

    assert_eq!(
        harness
            .repo
            .commit_discard_intent(&saved)
            .unwrap_err()
            .code(),
        "EA-DRAFT-TRANSITION-UNAVAILABLE"
    );
    assert_eq!(
        harness
            .repo
            .replace_prepared_finalization_marker(None)
            .unwrap_err()
            .code(),
        "EA-DRAFT-TRANSITION-UNAVAILABLE"
    );
    // Die LESENDEN Arme melden dagegen Abwesenheit und keinen Fehler: ohne die
    // Tabelle KANN es weder Absicht noch Marke geben, und das ist eine wahre
    // Aussage und kein Fehlschlag.
    assert!(harness.repo.pending_discard().unwrap().is_none());
    assert!(
        harness
            .repo
            .prepared_finalization_marker()
            .unwrap()
            .is_none()
    );
    // Und die Ablehnung hat nichts geschrieben: der Entwurf steht unveraendert
    // und ist weiter lesbar.
    assert_eq!(harness.active_draft_row_count(), 1);
    assert_eq!(
        harness.repo.load_or_create().unwrap().revision(),
        saved.revision()
    );
}

/// Eine entschluesselte Nutzlast, die keine Entwurfsgestalt hat, wird
/// ABGELEHNT und nicht zurechtgebogen.
///
/// Das Chiffrat ist gueltig — dieselbe Nonce, dieselben Zusatzdaten, derselbe
/// `draftDEK` —, also geht die AEAD auf und erst die Pruefung dahinter faellt.
/// Ein `from_utf8_lossy` an dieser Stelle gaebe dem Bediener einen Entwurf mit
/// Ersatzzeichen zurueck, und die naechste Autospeicherung schriebe diesen
/// verstuemmelten Text als seinen eigenen fest.
#[test]
fn a_payload_that_is_not_a_draft_is_refused_instead_of_repaired() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let saved = harness.repo.save(draft.with_notes("ORIGINAL")).unwrap();

    harness.overwrite_payload_with_non_utf8(&saved);

    assert_eq!(
        harness.repo.load_or_create().unwrap_err().code(),
        "EA-DRAFT-PAYLOAD"
    );
    // Und die Ablehnung ist keine Reparatur: die Zeile steht unveraendert, es
    // ist KEIN zweiter Entwurf entstanden, der die Invariante brechen wuerde.
    assert_eq!(harness.active_draft_row_count(), 1);
}
