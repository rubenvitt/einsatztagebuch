//! Der Anker kommt aus dem Tresor und nie aus der geoeffneten Datei.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

/// Die Nachbarkulisse, NUR wegen ihres FREMDEN Ankers.
///
/// Sie steht hier und nicht in `verify_fixtures/mod.rs`, weil
/// `crates/ea-reader-wasm` dieselbe `#[path]`-Kette benutzt und die Kanten
/// dieses Moduls (`ea-testkit`, `ea-sync-protocol`) dort nicht liegen.
///
/// Ihr Anker ist auf dem Wurzelseed `[0x11; 32]` und der Organisation
/// `[0x12; 16]` gebaut und traegt seinen eigenen Bootstrap-Hash — er ist also
/// vollstaendig GUELTIG und nur nicht der Anker dieses Bestands. Genau das ist
/// die Fremdheit, die dieser Zeuge braucht: ein Anker, der schon an
/// `decode_trust_anchor` scheiterte, faellt zu frueh und maesse etwas anderes.
///
/// INVERTIERT gebaut: nicht der Bestand ist fremd, sondern der TRESOR.
/// `trust_support::RegistryLineBuilder` haelt `ROOT_SECRET`, `organization()`
/// und `chain_id()` als Konstanten; ein zweiter eigenstaendiger Anker ist aus
/// der geteilten Fixturekette nicht zu bekommen, auch nicht ueber
/// `ActionSpec::RootRotate` — `exact_anchor_bytes()` bleibt davon unberuehrt.
#[path = "fixtures/mod.rs"]
mod reader_fixtures;

use ea_reader::PinnedTrustAnchor;

use verify_fixtures::fixtures;

#[test]
fn a_substituted_archive_with_its_own_complete_trust_chain_fails_here() {
    // Der Bestand ist in sich vollstaendig: eigener Root, eigene Registry,
    // eigene Writer-Zertifikate, eigene Signaturen. Er ist nur nicht UNSERER.
    let vault = fixtures::vault_pinning(reader_fixtures::pinned_anchor_exact_bytes());
    let classification = fixtures::classify(fixtures::complete_archive(), &vault);
    assert!(!classification.report().is_fully_verified());
    assert_eq!(classification.report().object_results().len(), 0);
    assert!(classification.states().is_empty());
    // ACHTUNG, GEMESSEN: alle sechs Mangelfelder sind LEER. Der Lauf steigt
    // nach `protocol.enter(Gate::Trust)` mit `return report.seal()` aus, das
    // Protokoll ist exakt ["format", "trust"], und `pipeline_completed` ist
    // falsch. Eine Zusicherung auf ein NICHT leeres Fehlerfeld waere rot.
    assert_eq!(classification.report().signature_errors().len(), 0);
    assert_eq!(classification.report().format_errors().len(), 0);
    assert_eq!(classification.report().quarantined_objects().len(), 0);
    assert_eq!(classification.report().evidence_errors().len(), 0);
    assert_eq!(classification.report().decryption_errors().len(), 0);
    assert_eq!(classification.report().gaps().len(), 0);
    // Und der Bestand ist WIRKLICH vollstaendig: derselbe Bestand gegen den
    // richtigen Anker ist `is_fully_verified()`. Ohne diese Gegenprobe waere
    // der Zeuge auch ueber einem leeren Verzeichnis gruen.
    let own = fixtures::unlocked_vault_with_pinned_anchor();
    assert!(
        fixtures::classify(fixtures::complete_archive(), &own)
            .report()
            .is_fully_verified()
    );
}

#[test]
fn the_anchor_used_is_the_vault_anchor_and_not_the_one_in_the_archive() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let anchor = PinnedTrustAnchor::from_vault(&vault);
    assert!(anchor.as_trust_anchor().trust_anchor_hash() == fixtures::pinned_anchor_hash());
    assert!(reader_fixtures::pinned_anchor().trust_anchor_hash() != fixtures::pinned_anchor_hash());
}
