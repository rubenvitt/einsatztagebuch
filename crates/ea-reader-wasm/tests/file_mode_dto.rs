// crates/ea-reader-wasm/tests/file_mode_dto.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es — aus demselben Grund wie in
// `tests/bridge_boundary.rs`: ohne ihn uebergaebe der Browserlauf ein Ziel
// ohne einen einzigen `#[wasm_bindgen_test]` an den Laeufer.
#![cfg(not(target_arch = "wasm32"))]

//! Die ABBILDUNG des Berichts auf `FileModeArchiveView`, Feld fuer Feld.
//!
//! # Warum dieses Ziel ueberhaupt steht
//!
//! `file_mode_archive_json` ist die EINZIGE Strecke, auf der ein Befund der
//! neun Gates in die Oberflaeche gelangt: beide oeffnenden Brueckenausfuhren
//! enden mit ihr, und `apps/web` liest danach nur noch das DTO. Die zwei
//! Zeugen unter [`ea_reader_wasm::file_access`] messen die FALTUNGSREGEL
//! (`ConfirmationTally::over`) und fassen den Bauer nicht an; die Zeugen in
//! `crates/ea-reader/tests/file_mode.rs` messen den BERICHT und kennen kein
//! DTO. Dazwischen lag bis hierher nichts — eine vertauschte Zuordnung waere
//! auf beiden Seiten gruen geblieben.
//!
//! # Wogegen geprueft wird
//!
//! Jedes Zahlenfeld gegen die Berichtsmethode, aus der es kommen MUSS, und
//! nicht gegen eine hier hingeschriebene Zahl: ein zweiter Satz Zahlen fuer
//! dieselbe Tatsache waere beim naechsten Zug an der Kulisse falsch, ohne dass
//! er etwas ueber die Abbildung sagte. Die zwei Bestaetigungsfelder gegen die
//! GEMESSENE Eigenschaft der jeweiligen Kulisselinie: der lueckenlose Bestand
//! traegt keine einzige `.esr`, die Quittungslinie traegt sie fuer jeden
//! Eintrag (`ReceiptArchiveSpec::with_receipts` ist Alles-oder-nichts).
//!
//! # Der Bestand wird NICHT nachgebaut
//!
//! Er kommt ueber dieselbe `#[path]`-Kette wie `tests/verify_browser.rs` und
//! die Wirtszeugen in `crates/ea-reader/tests/`.

#[path = "../../ea-reader/tests/verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{OpenedArchiveV1, ReaderFileMode, ServerConfirmationV1};
use ea_reader_wasm::file_access::file_mode_archive_json;

use verify_fixtures::fixtures;

/// Die sieben Felder von `FileModeArchiveView`, in der Ordnung der Emission.
///
/// Sie stehen hier als Liste und nicht als sieben lose Zusicherungen, damit
/// ein ACHTES Feld auffaellt: ein DTO, das mehr traegt als der Vertrag, geht
/// ungeprueft in die Oberflaeche.
const VIEW_FIELDS_V1: [&str; 7] = [
    "archiveObjectCount",
    "entryPackageCount",
    "fullyVerified",
    "gapCount",
    "serverConfirmedCount",
    "notServerConfirmedCount",
    "serverConfirmation",
];

/// Oeffnet einen Kulissenbestand als EINE Datei — der universelle Weg.
fn opened(bundle: Vec<u8>) -> OpenedArchiveV1 {
    ReaderFileMode::open_bundle(
        bundle,
        &fixtures::unlocked_vault_with_pinned_anchor(),
        fixtures::EFFECTIVE_NOW,
    )
    .expect("der Bestand der Kulisse muss oeffnen")
}

/// Das DTO als geparste Karte.
///
/// Geparst und nicht als Text verglichen: „das DTO ist gueltiges JSON" kann
/// nur ein echter Parser belegen — dieselbe Begruendung, die die
/// `serde_json`-Kante in `Cargo.toml` traegt.
fn view_of(opened: &OpenedArchiveV1) -> serde_json::Map<String, serde_json::Value> {
    let rendered = file_mode_archive_json(opened);
    let parsed: serde_json::Value =
        serde_json::from_str(&rendered).expect("das Status-DTO MUSS gueltiges JSON sein");
    let view = parsed
        .as_object()
        .expect("das Status-DTO ist ein Objekt")
        .clone();
    let names: Vec<&str> = view.keys().map(String::as_str).collect();
    let mut expected = VIEW_FIELDS_V1;
    expected.sort_unstable();
    assert_eq!(
        names, expected,
        "das DTO traegt genau den Vertrag: {rendered}"
    );
    view
}

/// Jedes Feld liest die Quelle, aus der es kommen MUSS.
///
/// Der Bestand ist der lueckenlose OHNE Quittungen — der Regelfall des
/// Datei-Modus nach `web-reader-design.md` §5.4. Die zwei Anti-Leerlaufzeilen
/// unten sind der Grund, aus dem dieser Zeuge ueberhaupt etwas misst: waeren
/// Objekt- und Eintragszahl gleich, bliebe eine Vertauschung der zwei Felder
/// unsichtbar, und ohne ein einziges Objektergebnis waere jede Zusage ueber
/// die Bestaetigungsspalten leer.
#[test]
fn every_field_of_the_view_is_read_from_the_report_and_none_is_recomputed() {
    let opened = opened(fixtures::exported_bundle_bytes(fixtures::complete_archive()));
    let report = opened.report();
    let results = report.object_results().len();
    assert!(results > 0);
    assert!(
        report.archive_object_count() != report.entry_package_count(),
        "sonst faellt eine Vertauschung der zwei Zaehlfelder durch"
    );

    let view = view_of(&opened);
    assert_eq!(view["archiveObjectCount"], report.archive_object_count());
    assert_eq!(view["entryPackageCount"], report.entry_package_count());
    assert_eq!(view["fullyVerified"], report.is_fully_verified());
    assert_eq!(view["gapCount"], report.gaps().len());
    // Diese Linie traegt KEINE `.esr`, also gehoert jedes Ergebnis in die
    // zweite Spalte — und die erste ist leer.
    assert_eq!(view["serverConfirmedCount"], 0);
    assert_eq!(view["notServerConfirmedCount"], results);
    assert_eq!(
        view["serverConfirmation"],
        ServerConfirmationV1::NotServerConfirmed.label()
    );
}

/// Die zwei Dimensionen von §17.4 bewegen sich UNABHAENGIG voneinander.
///
/// Das ist die Zusicherung, die eine Ableitung der Bestaetigungsspalte aus dem
/// Verifikationsstand — in beide Richtungen — unmoeglich macht, und sie ist
/// ueber genau zwei Kulissenlinien formulierbar, weil die eine sie
/// gegenlaeufig belegt: der lueckenlose Bestand ist vollstaendig verifiziert
/// und NICHT server-bestaetigt, die Quittungslinie ist server-bestaetigt und
/// wegen ihrer Vorlauf-Luecke NICHT vollstaendig verifiziert. Wer eine der
/// beiden Spalten aus der anderen faltete, faerbte diesen Zeugen an einem der
/// zwei Bestaende rot.
#[test]
fn the_confirmation_column_is_not_a_reading_of_the_verification_state() {
    let without = view_of(&opened(fixtures::exported_bundle_bytes(
        fixtures::complete_archive(),
    )));
    assert_eq!(without["fullyVerified"], true);
    assert_eq!(
        without["serverConfirmation"],
        ServerConfirmationV1::NotServerConfirmed.label()
    );

    let with_receipts = view_of(&opened(fixtures::exported_bundle_bytes(
        fixtures::archive_with_receipts(),
    )));
    assert_eq!(with_receipts["fullyVerified"], false);
    assert_eq!(
        with_receipts["serverConfirmation"],
        ServerConfirmationV1::ServerConfirmed.label()
    );
    // Und die Zaehlspalten stehen auf der anderen Seite als oben, sonst waere
    // ihre Zuordnung ueber beide Bestaende hinweg vertauschbar.
    assert_eq!(with_receipts["notServerConfirmedCount"], 0);
    assert_eq!(
        with_receipts["serverConfirmedCount"],
        with_receipts["entryPackageCount"]
    );
}
