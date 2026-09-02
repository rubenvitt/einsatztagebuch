//! Der `.eds`-Stummel: zwei Ausgaenge, zwei Dimensionen, und in keinem der
//! beiden ein Weg an den HPKE-Entkapseler.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    ChainSequence, DECAPSULATION_EVENT_V1, EntryStatus, ReaderMode, ReaderVerifier,
    RecordingObserver, VerificationStatus,
};

use verify_fixtures::{fixtures, verify_support};

// GEMESSEN und gegen den frueheren Plantext korrigiert: dieser Bestand
// ERREICHT die Entkapselung. Vier seiner Eintraege tragen einen eigenen Grant
// auf den Abdruck des Tresors, `claim_own_grants` oeffnet sie, und das
// archivweite Protokoll enthaelt `hpke-open`. Eine Zusicherung auf die
// ABWESENHEIT des Ereignisses waere hier also rot gewesen — und ueber einem
// Bestand ohne eigene Grants waere sie gruen gewesen, ohne etwas zu messen.
//
// Was der Stummel wirklich zusagt, ist enger und staerker: er wird nie ein
// Kettenknoten, bekommt kein `objectResult`, kein Grant nennt seinen
// `entryHash`, und `claim_own_grants` laeuft ausschliesslich ueber platzierte
// Eintraege MIT `objectResult`. Der Typzusage nach heisst das: fuer einen
// Stummel ist `decrypt_verified` gar nicht erst formulierbar.
#[test]
fn a_stub_reaches_no_decapsulation_in_either_outcome() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    for (label, source, entry_state) in [
        (
            "autorisiert vernichtet",
            fixtures::stub_with_resolvable_authorization(),
            EntryStatus::AuthorizedDestroyed,
        ),
        (
            "ungeklaerte Luecke",
            fixtures::stub_without_resolvable_authorization(),
            EntryStatus::UnexplainedGap,
        ),
    ] {
        let mut observer = RecordingObserver::new();
        let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
            .classify(source, &vault, &mut observer)
            .expect("der Berichtsbestand muss klassifizieren");
        let key = fixtures::stub_entry_hash(source);

        // ANTI-LEERLAUF: der Lauf FAEHRT durch die Entkapselung.
        assert!(
            observer.events().contains(&DECAPSULATION_EVENT_V1),
            "{label}"
        );

        let stub_object_hash = classification.inventory().destroyed()[0].object_hash();
        assert!(
            classification
                .report()
                .object_results()
                .all(|result| result.object_hash() != stub_object_hash),
            "{label}: ein `.eds` bekommt kein objectResult"
        );
        assert!(
            classification.inventory().grants().iter().all(|grant| grant
                .value()
                .grant_body()
                .fields()
                .entry_hash
                != key),
            "{label}: kein Grant nennt den entryHash des Stummels"
        );
        assert!(classification.verified_entry(key).is_none(), "{label}");
        assert!(classification.verified_grant(key).is_none(), "{label}");

        let state = classification
            .state_of(key)
            .expect("der Stummel traegt entryHash und Sequenz selbst");
        assert_eq!(state.entry_state(), entry_state, "{label}");
        // BEIDE Dimensionen bleiben getrennt (design.md §17.4): auch der
        // autorisiert vernichtete Stummel hat KEIN objectResult und steht in
        // einem gaps-Intervall, ist in der Verifikationsdimension also `Gap`.
        assert_eq!(state.verification(), VerificationStatus::Gap, "{label}");
        assert_eq!(
            state.sequence(),
            ChainSequence::new(verify_support::REPORT_DESTROYED_STUB_SEQUENCE_V1),
            "{label}"
        );
    }
}

// Der Join, aus dem `autorisiert vernichtet` ueberhaupt erst entsteht.
//
// `ObjectResultKindV1::AuthorizedDestroyed` ist ein TOTER Zweig —
// `confirm_entries` ist der einzige Erzeuger von `objectResults` und setzt
// ausnahmslos `Valid`. Der Zustand kommt deshalb aus
// `DestroyedEntryStubV1::destruction_id()` gegen
// `VerificationReportV1::authorized_destructions()`. Dieser Zeuge haelt fest,
// dass BEIDE Bestaende denselben Vorgang fuehren und sich AUSSCHLIESSLICH in
// der Kennung unterscheiden, die der Stummel nennt.
#[test]
fn the_authorized_destruction_is_reached_through_the_destruction_id_and_nothing_else() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let resolvable = fixtures::classify(fixtures::stub_with_resolvable_authorization(), &vault);
    let unresolvable =
        fixtures::classify(fixtures::stub_without_resolvable_authorization(), &vault);

    // Derselbe Vorgang, in beiden Bestaenden, unter derselben Kennung.
    assert_eq!(resolvable.report().authorized_destructions().len(), 1);
    assert_eq!(unresolvable.report().authorized_destructions().len(), 1);
    let authorized = resolvable
        .report()
        .authorized_destructions()
        .next()
        .expect("der Vorgang liegt im Bestand")
        .destruction_id();
    assert!(
        authorized
            == unresolvable
                .report()
                .authorized_destructions()
                .next()
                .expect("der Vorgang liegt auch dort")
                .destruction_id()
    );

    // Der Unterschied ist AUSSCHLIESSLICH die Kennung, die der Stummel nennt.
    assert!(
        resolvable.inventory().destroyed()[0]
            .value()
            .destruction_id()
            == authorized
    );
    assert!(
        unresolvable.inventory().destroyed()[0]
            .value()
            .destruction_id()
            != authorized
    );
}
