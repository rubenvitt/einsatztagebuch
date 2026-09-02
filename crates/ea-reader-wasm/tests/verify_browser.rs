#![cfg(target_arch = "wasm32")]

//! Die neun Gates gegen eine ECHTE COSE-Kette in Headless-Chromium.
//!
//! Die Kopfzeile `#![cfg(target_arch = "wasm32")]` steht in der ERSTEN Zeile:
//! ohne sie zoege `cargo test --workspace --all-targets --locked` dieses Ziel
//! auf dem Wirt mit und faende dort keinen Testlaeufer; die Regel dafuer steht
//! in `tests/opfs_browser.rs` und gilt fuer jedes `*_browser.rs` dieser Crate.
//!
//! # Welche Grenze des Spikes hier faellt — und welche nicht
//!
//! Der wasm-Laufzeitnachweis nannte fuenf Grenzen. Dieser Zeuge loest GENAU
//! EINE davon ein, die vierte: dort war `verify_ed25519_strict` auf einem
//! rohen RFC-8032-Vektor geprueft, nicht `parse_cose_sign1` gegen ein echtes
//! Archiv. Hier laeuft `ea_verify::verify_archive_observed` — und mit ihm
//! `parse_cose_sign1` in jedem `.eip`-, `.eag`- und Trust-Objekt der
//! Fixturelinie — zum ersten Mal im Browser ueber einen Bestand, dessen Root,
//! Registry, Schreiberzertifikat und Signaturen alle aus derselben Linie
//! stammen. Grenze 2 (kein `--release`, kein `wasm-opt`) und Grenze 5 (keine
//! RNG-Statistik) bleiben ausdruecklich offen und werden hier nicht behauptet.
//!
//! # IM BROWSER und nicht in Node
//!
//! `wasm_bindgen_test_configure!(run_in_browser)`: ohne diese Zeile faehrt
//! der Laeufer in Node, und die Grenze bliebe offen, obwohl der Test gruen
//! waere. Kein `run_in_dedicated_worker` — kein OPFS im Spiel, und das
//! Hauptfenster ist genau die Umgebung, in der `apps/web` spaeter
//! klassifiziert.
//!
//! # Der Bestand wird NICHT nachgebaut
//!
//! Er kommt ueber dieselbe `#[path]`-Kette wie die fuenf Wirtszeugen in
//! `crates/ea-reader/tests/`, und `ArchiveFixture` implementiert
//! `ArchiveSource` selbst. Die Kette signiert echt (Ed25519 nach RFC 8032)
//! und kapselt echt (`hpke_seal` zieht seinen ephemeren Schluessel aus
//! `getrandom`, das workspaceweit `wasm_js` traegt) — beides laeuft damit
//! ebenfalls im Browser, bevor ein einziges Gate misst. `ReaderVault::seal`
//! und `::unlock` sind reines Rust.

#[path = "../../ea-reader/tests/verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    DECAPSULATION_EVENT_V1, EntryStatus, GATE_ORDER_V1, ReaderMode, ReaderVerifier,
    RecordingObserver, SchemaRegistry, VerificationStatus, decrypt_verified,
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

// `ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1` kommt aus der KULISSE und stand frueher
// als eigenes Literal in dieser Datei. Es ist eine Tatsache ueber
// `complete_valid_archive` — genau EIN Eintrag, und nur so sagt das archivweite
// Protokoll etwas ueber IHN aus — und nicht ueber diesen Zeugen; seit
// `crates/ea-reader/tests/file_mode.rs` sie ebenfalls braucht, waere ein
// zweites Literal daneben der zweite Satz Zahlen fuer dieselbe Tatsache.
use verify_fixtures::fixtures::{self, ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1};

wasm_bindgen_test_configure!(run_in_browser);

/// Grenze 4: die vollstaendige Kette, alle neun Gates, im Browser.
///
/// Das Protokoll ist wortgleich das des Wirtszeugen
/// `the_protocol_is_a_prefix_of_the_nine_gates_and_then_at_most_one_decapsulation`
/// in `crates/ea-reader/tests/verification_order.rs`: `GATE_ORDER_V1` in
/// voller Laenge, dann GENAU EIN `hpke-open`. Die Zusicherung ueber die volle
/// Laenge ist der Anti-Leerlauf — ein Lauf, der an Gate `trust` ausstiege,
/// haette ein Protokoll aus zwei Eintraegen und waere ueber einem Praefixtest
/// gruen.
#[wasm_bindgen_test]
fn the_nine_gates_verify_a_real_cose_chain_in_the_browser() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive();
    let mut observer = RecordingObserver::new();
    let classification = ReaderVerifier::new(ReaderMode::Server, fixtures::EFFECTIVE_NOW)
        .classify(source, &vault, &mut observer)
        .expect("ein vollstaendiger Bestand muss auch im Browser klassifizieren");

    let expected: Vec<&str> = GATE_ORDER_V1
        .iter()
        .copied()
        .chain(core::iter::once(DECAPSULATION_EVENT_V1))
        .collect();
    assert_eq!(observer.events(), expected.as_slice());
    assert!(classification.report().is_fully_verified());

    // Und die Uebersetzung in die Zustandssprache aus `design.md` §17.4 ist
    // dieselbe wie auf dem Wirt: ein Eintrag, `Verified`, `Present`, ohne
    // Detailgrund, mit beiden Zeugen.
    assert_eq!(
        classification.states().len(),
        ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1
    );
    let entry_hash = fixtures::entry_hash(source);
    let state = classification
        .state_of(entry_hash)
        .expect("der eine Eintrag traegt eine Zustandszeile");
    assert_eq!(state.verification(), VerificationStatus::Verified);
    assert_eq!(state.entry_state(), EntryStatus::Present);
    assert_eq!(state.detail_code(), None);
    assert!(classification.verified_entry(entry_hash).is_some());
    assert!(classification.verified_grant(entry_hash).is_some());
}

/// Die Rechnung HINTER den Gates, ebenfalls im Browser.
///
/// Derselbe begrenzte Erfolgspfad wie
/// `the_hpke_and_aead_computation_runs_in_full_before_the_schema_is_determined`
/// in `crates/ea-reader/tests/historical_expiry.rs`: `decrypt_verified`
/// faehrt vollstaendig durch die HPKE-Entkapselung mit dem X25519-Schluessel
/// der Sitzung und die AEAD-Oeffnung und endet an der Schemabestimmung, weil
/// der Fixture-Klartext keine Schemakennung traegt. GENAU DIESER Ausgang
/// belegt die Rechnung — waere sie im wasm-Bau falsch, fiele der Lauf FRUEHER
/// mit `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED` oder
/// `EA-VERIFY-DECRYPT-PAYLOAD-OPEN-FAILED`.
#[wasm_bindgen_test]
fn the_session_key_decapsulates_in_the_browser_only_behind_the_nine_gates() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let source = fixtures::complete_archive();
    let classification = fixtures::classify(source, &vault);
    let entry_hash = fixtures::entry_hash(source);
    let entry = classification
        .verified_entry(entry_hash)
        .expect("der Bestand traegt einen Zeugen");
    let grant = classification
        .verified_grant(entry_hash)
        .expect("und einen eigenen Grant");

    let mut observer = RecordingObserver::new();
    let refused = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        fixtures::EFFECTIVE_NOW,
        &mut observer,
    )
    .expect_err("der Fixture-Klartext traegt keine Schemakennung");
    assert_eq!(refused.code(), "EA-READER-SCHEMA-UNSUPPORTED");
    // Ein FRISCHER Beobachter sieht genau ein Ereignis und kein Gate-Praefix:
    // die Entkapselung des Readers ist kein zehntes Gate.
    assert_eq!(observer.events(), [DECAPSULATION_EVENT_V1]);
}
