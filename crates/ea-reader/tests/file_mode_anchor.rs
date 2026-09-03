//! Der EINSTIEGSPUNKT des Datei-Modus oeffnet keinen zweiten Weg zu einem
//! Anker.
//!
//! Die Ankerbindung selbst gehoert der Aufgabe davor und wird hier NICHT
//! wiederholt: `PinnedTrustAnchor::from_vault` ist ihr einziger Konstruktor,
//! und `ReaderVerifier::classify` traegt ihren eigenen Zeugen. Was dieses Ziel
//! misst, ist die Signaturseite — keiner der vier Eingaenge von
//! `ReaderFileMode` nimmt einen `TrustAnchorV1` oder einen
//! `PinnedTrustAnchor`, also kann ein Aufrufer gar keinen zweiten anbieten, und
//! Trust-Objekte, die IN der geoeffneten Datei liegen, begruenden von sich aus
//! kein Vertrauen (`web-reader-design.md` §5.3).

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

/// Die Nachbarkulisse, NUR wegen ihres FREMDEN Ankers.
///
/// Sie steht hier und nicht in `verify_fixtures/mod.rs`, weil
/// `crates/ea-reader-wasm` dieselbe `#[path]`-Kette benutzt und die Kanten
/// dieses Moduls (`ea-testkit`, `ea-sync-protocol`) dort nicht liegen —
/// dieselbe Aufteilung und dieselbe Begruendung wie in
/// `crates/ea-reader/tests/pinned_anchor.rs`.
///
/// INVERTIERT gebaut: nicht der Bestand ist fremd, sondern der TRESOR.
/// `trust_support::RegistryLineBuilder` haelt `ROOT_SECRET`, `organization()`
/// und `chain_id()` als Konstanten; ein zweiter eigenstaendiger Anker ist aus
/// der geteilten Fixturekette nicht zu bekommen. Der Anker der Nachbarkulisse
/// steht auf dem Wurzelseed `[0x11; 32]` und traegt seinen eigenen
/// Bootstrap-Hash — er ist also vollstaendig GUELTIG und nur nicht der Anker
/// dieses Bestands. Ein Anker, der schon an `decode_trust_anchor` scheiterte,
/// fiele zu frueh und maesse etwas anderes.
#[path = "fixtures/mod.rs"]
mod reader_fixtures;

use ea_reader::{
    ChainSequence, GATE_ORDER_V1, PinnedTrustAnchor, ReaderFileMode, RecordingObserver,
};

use verify_fixtures::fixtures;

/// Ein untergeschobenes Archiv mit vollstaendiger EIGENER Vertrauenskette.
///
/// ADVERSARISCH GEPAART, und die Positivkontrolle steht ZUERST: DASSELBE
/// Byte-fuer-Byte gleiche Buendel traegt gegen SEINEN eigenen gepinnten Anker
/// vollstaendig. Ohne sie waere der Fehlschlag darunter von einer kaputten
/// Kulisse nicht zu unterscheiden — ein leeres Buendel faellt an derselben
/// Stelle.
#[test]
fn a_substituted_archive_says_nothing_about_any_entry_in_file_mode() {
    let bundle = fixtures::exported_bundle_bytes(fixtures::complete_archive());

    let own_vault = fixtures::unlocked_vault_with_pinned_anchor();
    let own = ReaderFileMode::open_bundle(bundle.clone(), &own_vault, fixtures::EFFECTIVE_NOW)
        .expect("der eigene Bestand muss oeffnen");
    assert!(own.report().is_fully_verified());

    // Und gegen einen FREMDEN gepinnten Anker faellt es.
    let foreign_vault = fixtures::vault_pinning(reader_fixtures::pinned_anchor_exact_bytes());
    let mut observer = RecordingObserver::new();
    let opened = ReaderFileMode::open_bundle_observed(
        bundle,
        &foreign_vault,
        fixtures::EFFECTIVE_NOW,
        &mut observer,
    )
    .expect("ein Befund ueber die Vertrauenskette ist nie ein Err");
    let report = opened.report();

    // KEIN `unwrap`: `PinnedTrustAnchor::from_vault` ist infallibel.
    let anchor = PinnedTrustAnchor::from_vault(&foreign_vault);
    assert_eq!(observer.events(), &GATE_ORDER_V1[..2]);
    assert!(!report.is_fully_verified());
    assert_eq!(report.object_results().len(), 0);
    assert_eq!(report.public_key_thumbprints().len(), 0);
    // GEMESSEN: alle sechs Mangelfelder bleiben LEER — der Lauf steigt nach
    // `protocol.enter(Gate::Trust)` mit `return report.seal()` aus. Eine
    // Zusicherung auf ein NICHT leeres Fehlerfeld waere rot.
    assert_eq!(report.gaps().len(), 0);
    assert_eq!(report.signature_errors().len(), 0);
    // Der Kopf ist das Sentinel aus `ChainHeadV1::sentinel(anchor.chain_id())`
    // (`crates/ea-verify/src/archive.rs`): Sequenz null, Nullhash, und die
    // Kettenkennung des GEPINNTEN Ankers.
    assert_eq!(report.chain_head().sequence(), ChainSequence::new(0));
    // `assert!` und nicht `assert_ne!`: `EntryHash` leitet kein `Debug` ab.
    assert!(report.chain_head().entry_hash() != anchor.as_trust_anchor().genesis_entry_hash());
    assert!(report.chain_head().chain_id() == anchor.as_trust_anchor().chain_id());
}
