//! Die Reihenfolge der neun Gates, die Entkapselung dahinter und der
//! Modusparameter, der an beidem nichts aendert.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    DECAPSULATION_EVENT_V1, GATE_ORDER_V1, ReaderMode, ReaderVerifier, RecordingObserver,
};

use verify_fixtures::fixtures;

#[test]
fn the_protocol_is_a_prefix_of_the_nine_gates_and_then_at_most_one_decapsulation() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let mut observer = RecordingObserver::new();
    let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(fixtures::complete_archive(), &vault, &mut observer)
        .expect("ein vollstaendiger Bestand muss klassifizieren");
    let events = observer.events();
    let split = events
        .iter()
        .position(|event| *event == DECAPSULATION_EVENT_V1)
        .unwrap_or(events.len());
    assert_eq!(events[..split], GATE_ORDER_V1[..split]);
    // MISST DIE FORM DES PROTOKOLLS, NICHT DIE ZAHL DER ENTKAPSELUNGEN:
    // `protocol.decapsulated()` laeuft je Lauf hoechstens einmal, unabhaengig
    // davon, wie viele Eintraege geoeffnet wurden. Die Zusicherung ist damit
    // trivial wahr und steht nur da, damit ein spaeteres zehntes Ereignis
    // hinter dem neunten Gate auffaellt.
    assert!(events[split..].len() <= 1);
    // ANTI-LEERLAUF: waere das Protokoll leer, waeren beide Zusicherungen
    // darueber gruen, ohne etwas gesehen zu haben.
    assert_eq!(split, GATE_ORDER_V1.len());
    assert!(classification.report().is_fully_verified());
}

#[test]
fn no_decapsulation_event_precedes_any_public_gate_failure() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let failures = fixtures::each_public_verification_failure();
    // ANTI-LEERLAUF fuer die `Option`: drei der neun Bestaende bemaengeln gar
    // keinen EINTRAG — eine traegerlose Luecke, ein verwaister Grant und
    // unlesbare Bytes. Verkaeme die Spalte still zu lauter `None`, liefe die
    // Schleife ueber neun Bestaende, ohne eine einzige Adresse zu pruefen.
    assert_eq!(
        failures
            .iter()
            .filter(|failure| failure.invalid_entry_hash.is_some())
            .count(),
        fixtures::PUBLIC_FAILURES_WITH_AN_INVALID_ENTRY_V1,
    );
    for broken in failures {
        let mut observer = RecordingObserver::new();
        let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
            .classify(broken.source, &vault, &mut observer)
            .expect("ein Befund ueber ein einzelnes Objekt ist nie ein Err");
        assert!(
            !observer.events().contains(&DECAPSULATION_EVENT_V1),
            "{}",
            broken.label
        );
        if let Some(entry_hash) = broken.invalid_entry_hash {
            assert!(
                classification.verified_entry(entry_hash).is_none(),
                "{}",
                broken.label
            );
            assert!(
                classification.verified_grant(entry_hash).is_none(),
                "{}",
                broken.label
            );
        }
    }
}

// Der Modusparameter aendert an der Reihenfolge NICHTS: web-reader-design.md
// §5.4 sagt „wortgleich in beiden Modi". `classify` LIEST den Modus gar nicht;
// dieser Zeuge pinnt genau diese Nicht-Abhaengigkeit und schuetzt gegen ein
// spaeteres Einfalten des Modus in die Pipeline.
#[test]
fn both_reader_modes_produce_the_same_gate_protocol_over_the_same_bytes() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive();
    let mut server = RecordingObserver::new();
    let mut file = RecordingObserver::new();
    ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(source, &vault, &mut server)
        .expect("der Server-Modus muss klassifizieren");
    ReaderVerifier::new(ReaderMode::File, fixtures::EFFECTIVE_NOW)
        .classify(source, &vault, &mut file)
        .expect("der Datei-Modus muss klassifizieren");
    assert_eq!(server.events(), file.events());
}
