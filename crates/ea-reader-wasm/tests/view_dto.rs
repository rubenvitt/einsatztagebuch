// crates/ea-reader-wasm/tests/view_dto.rs
//
// WIRTSZEUGE, und der cfg-Kopf sagt es — aus demselben Grund wie in
// `tests/bridge_boundary.rs`: ohne ihn uebergaebe der Browserlauf ein Ziel
// ohne einen einzigen `#[wasm_bindgen_test]` an den Laeufer.
#![cfg(not(target_arch = "wasm32"))]

//! Die ABBILDUNG eines geoeffneten Bestands auf die Reader-Ansichten.
//!
//! # Warum dieses Ziel ueberhaupt steht
//!
//! `view.rs` ist der EINZIGE Ort, an dem ein `ReaderEntryStateV1`, ein
//! `VerifiedDecryptedRecord` und ein `ReaderEntryThread` in die generierten
//! DTOs fallen; `apps/web` liest danach nur noch JSON. Die Zeugen in
//! `crates/ea-reader/tests/` messen Klassifikation, Entschluesselung und Faden
//! und kennen kein DTO — dazwischen laege ohne dieses Ziel nichts.
//!
//! # Die Kulisse
//!
//! Der Nachtragsbestand aus `crates/ea-reader/tests/amendment_fixtures/` ist
//! die einzige Kulisse mit Original UND Nachtraegen; sein Modulkommentar sagt,
//! dass er teuer ist und einem Ziel gehoert. Er wird hier trotzdem eingebunden
//! — ohne ihn gaebe es fuer `ReaderAmendmentThreadView` keinen Zeugen —, und
//! die Zahl der Faelle bleibt bewusst klein. Fehlender Grant, Signaturfehler
//! und der lueckenlose Einzelbestand kommen aus `verify_fixtures`, das der
//! Nachtragsbestand ohnehin mitbringt.
//!
//! # Geparst, nicht als Text verglichen
//!
//! „Das DTO ist gueltiges JSON" kann nur ein echter Parser belegen — dieselbe
//! Begruendung, die die `serde_json`-Kante in `Cargo.toml` traegt.

#[path = "../../ea-reader/tests/amendment_fixtures/mod.rs"]
mod amendment_fixtures;

use ea_reader::{
    EntryHash, GATE_ORDER_V1, OpenedArchiveV1, ReaderFileMode, ReaderQueryV1, RecordingObserver,
    ServerConfirmationV1, UnixMillis, UnlockedVault, VerificationStatus,
};
use ea_reader_wasm::view::{
    self, EA_READER_VIEW_NO_THREAD, EA_READER_VIEW_UNKNOWN_ENTRY, ReaderStand,
};
use serde_json::Value;

use amendment_fixtures::fixtures as amendments;
use amendment_fixtures::verify_fixtures::fixtures as verify;
use amendment_fixtures::verify_fixtures::verify_support::archive_support::ArchiveFixture;

/// Oeffnet einen Kulissenbestand als EINE Datei und baut den Bestand darueber.
///
/// Der Bestand wird UNTER dem Beobachter geoeffnet, weil die Leiste aus
/// dessen Protokoll entsteht — dieselbe Bauform, die die zwei
/// Oeffnungsausfuhren in `file_access.rs` fahren.
fn stand_over(fixture: &ArchiveFixture, vault: &UnlockedVault) -> ReaderStand {
    let mut observer = RecordingObserver::new();
    let opened: OpenedArchiveV1 = ReaderFileMode::open_bundle_observed(
        verify::exported_bundle_bytes(fixture),
        vault,
        verify::EFFECTIVE_NOW,
        &mut observer,
    )
    .expect("der Bestand der Kulisse muss oeffnen");
    view::build_stand(opened, vault, verify::EFFECTIVE_NOW, observer.events())
}

fn parsed(rendered: &str) -> Value {
    serde_json::from_str(rendered).expect("jedes Ansichts-DTO MUSS gueltiges JSON sein")
}

fn hex_of(entry_hash: EntryHash) -> String {
    hex::encode(entry_hash.as_bytes())
}

fn entry_in(stand_view: &Value, entry_hash: EntryHash) -> &Value {
    let wanted = hex_of(entry_hash);
    stand_view["entries"]
        .as_array()
        .expect("entries ist ein Array")
        .iter()
        .find(|entry| entry["state"]["entryHash"] == wanted)
        .expect("der gesuchte Eintrag steht in entries")
}

fn sequences_of(views: &Value) -> Vec<u64> {
    views
        .as_array()
        .expect("ein Array von Ansichten")
        .iter()
        .map(|item| {
            item.get("sequence")
                .or_else(|| item.pointer("/state/sequence"))
                .and_then(Value::as_u64)
                .expect("jede Ansicht traegt eine Sequenz")
        })
        .collect()
}

/// Der vollstaendig verifizierte Nachtragsbestand: jede nicht-ungueltige
/// Zustandszeile steht in `entries`, das Original traegt seinen Einsatz, und
/// der Faden nennt genau die zwei gueltigen Nachtraege und die vier
/// abgewiesenen — ueber den Hash des Originals UND ueber den eines Nachtrags.
#[test]
fn a_fully_verified_amendment_stand_lists_every_state_and_threads_the_original() {
    let vault = verify::unlocked_vault_with_pinned_anchor();
    let stand = stand_over(amendments::amendment_archive(), &vault);
    let states = stand.opened().classification().states();
    let not_invalid = states
        .iter()
        .filter(|state| state.verification() != VerificationStatus::Invalid)
        .count();
    assert_eq!(not_invalid, amendments::ENTRIES_IN_THE_AMENDMENT_ARCHIVE_V1);

    let stand_view = parsed(&view::stand_json(&stand));
    assert_eq!(stand_view["fullyVerified"], true);
    assert_eq!(
        stand_view["entries"].as_array().map(Vec::len),
        Some(not_invalid)
    );
    assert_eq!(stand_view["problems"].as_array().map(Vec::len), Some(0));
    // Die zwei Eintraege der Sequenzen zwei und drei tragen einen Klartext
    // ohne Schemabestimmung: der sechste Begriff aus §17.4, den erst die
    // Entschluesselung sagen kann — kein Pruefproblem, kein Einsatz.
    let unsupported: Vec<&Value> = stand_view["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|entry| {
            entry["state"]["verification"] == VerificationStatus::UnsupportedSchema.label()
        })
        .collect();
    assert_eq!(unsupported.len(), 2);
    for entry in unsupported {
        assert_eq!(entry["incident"], Value::Null);
        assert_eq!(entry["state"]["detailCode"], "EA-READER-SCHEMA-UNSUPPORTED");
    }
    // `EntryHash` traegt kein `Debug`; verglichen werden die Bytes.
    assert_eq!(
        view::parse_entry_hash(&hex_of(amendments::original_entry_hash()))
            .map(|entry_hash| *entry_hash.as_bytes()),
        Some(*amendments::original_entry_hash().as_bytes())
    );
    assert!(view::parse_entry_hash("abcd").is_none());

    let original = entry_in(&stand_view, amendments::original_entry_hash());
    assert_eq!(
        original["incident"]["incidentNumber"],
        amendments::ORIGINAL_INCIDENT_NUMBER_V1
    );
    assert_eq!(
        original["state"]["verification"],
        VerificationStatus::Verified.label()
    );
    assert_eq!(
        original["state"]["sequence"],
        amendments::ORIGINAL_SEQUENCE_V1
    );

    let thread = view::thread_json(&stand, amendments::original_entry_hash())
        .expect("das Original traegt einen Faden");
    let thread_view = parsed(&thread);
    assert_eq!(
        thread_view["original"]["state"]["entryHash"],
        hex_of(amendments::original_entry_hash())
    );
    assert_eq!(
        sequences_of(&thread_view["amendments"]),
        vec![
            amendments::AMENDMENT_A_SEQUENCE_V1,
            amendments::AMENDMENT_B_SEQUENCE_V1
        ]
    );
    let mut rejected = sequences_of(&thread_view["rejected"]);
    rejected.sort_unstable();
    assert_eq!(
        rejected,
        vec![
            amendments::FOREIGN_RECORD_ID_SEQUENCE_V1,
            amendments::FLIPPED_ENTRY_HASH_SEQUENCE_V1,
            amendments::WRONG_SEQUENCE_SEQUENCE_V1,
            amendments::OTHER_INCIDENT_NUMBER_SEQUENCE_V1,
        ]
    );
    for item in thread_view["rejected"]
        .as_array()
        .expect("rejected ist ein Array")
    {
        assert!(
            item["reason"]
                .as_str()
                .is_some_and(|reason| reason.starts_with("EA-")),
            "ein abgewiesener Nachtrag nennt seinen Grund als stabilen Code"
        );
    }

    // Derselbe Faden ueber den Hash des ersten Nachtrags.
    let amendment_a = amendments::amendment_a().entry_hash();
    assert_eq!(
        view::thread_json(&stand, amendment_a).expect("ein Nachtrag fuehrt zu seinem Faden"),
        thread
    );
    // Ein Einsatz OHNE Nachtraege ist ein Faden ohne Nachtraege — der fremde
    // Einsatz auf Sequenz eins. Genesis ist kein Einsatz und traegt keinen.
    let foreign = verify::entry_hash_at(
        amendments::amendment_archive(),
        amendments::FOREIGN_INCIDENT_SEQUENCE_V1,
    );
    let foreign_thread = parsed(&view::thread_json(&stand, foreign).expect("ein Einsatz"));
    assert_eq!(
        foreign_thread["amendments"].as_array().map(Vec::len),
        Some(0)
    );
    let genesis = verify::entry_hash_at(
        amendments::amendment_archive(),
        amendments::GENESIS_SEQUENCE_V1,
    );
    assert_eq!(
        view::thread_json(&stand, genesis).err(),
        Some(EA_READER_VIEW_NO_THREAD)
    );
    assert_eq!(
        view::thread_json(&stand, EntryHash::try_from(&[0xee_u8; 32][..]).unwrap()).err(),
        Some(EA_READER_VIEW_UNKNOWN_ENTRY)
    );
}

/// Die Einsatzfelder erscheinen AUSSCHLIESSLICH aus einem entschluesselten
/// Einsatz: Genesis und Nachtrag sind entschluesselt und tragen trotzdem
/// `incident: null` — und in ihrem JSON steht die Einsatznummer nirgends.
#[test]
fn a_decrypted_record_without_an_incident_payload_renders_a_null_incident() {
    let vault = verify::unlocked_vault_with_pinned_anchor();
    let stand = stand_over(amendments::amendment_archive(), &vault);
    for sequence in [
        amendments::GENESIS_SEQUENCE_V1,
        amendments::AMENDMENT_A_SEQUENCE_V1,
    ] {
        let entry_hash = verify::entry_hash_at(amendments::amendment_archive(), sequence);
        let rendered = view::entry_json(&stand, entry_hash).expect("der Eintrag ist bekannt");
        let entry = parsed(&rendered);
        assert_eq!(entry["incident"], Value::Null, "{rendered}");
        assert_eq!(
            entry["state"]["verification"],
            VerificationStatus::Verified.label()
        );
        assert!(
            !rendered.contains(amendments::ORIGINAL_INCIDENT_NUMBER_V1),
            "die Einsatznummer darf ohne Einsatz nirgends im JSON stehen: {rendered}"
        );
    }
}

/// Fehlender eigener Grant: die Zeile bleibt in `entries`, `incident` ist
/// `null`, und der Wortlaut ist GENAU `fehlender Grant` — nie eine Luecke,
/// nie ungueltig, nie ein leerer Einsatz.
#[test]
fn a_missing_grant_stays_in_entries_with_a_null_incident() {
    let vault = verify::unlocked_vault_with_pinned_anchor();
    let stand = stand_over(verify::entry_without_own_grant(), &vault);
    let stand_view = parsed(&view::stand_json(&stand));
    let entry_hash = verify::entry_hash(verify::entry_without_own_grant());
    let entry = entry_in(&stand_view, entry_hash);
    assert_eq!(entry["incident"], Value::Null);
    assert_eq!(
        entry["state"]["verification"],
        VerificationStatus::MissingGrant.label()
    );
    assert_eq!(stand_view["problems"].as_array().map(Vec::len), Some(0));
    // Kein Mangel: der Bestand bleibt vollstaendig verifiziert, und die Leiste
    // traegt alle neun Tore.
    assert_eq!(stand_view["fullyVerified"], true);
    assert_eq!(stand_view["chain"].as_array().map(Vec::len), Some(9));
}

/// Ein ungueltiges Objekt lebt AUSSCHLIESSLICH in `problems` — mit seinem
/// Code — und die Leiste bricht am Tor `manifest-signature` ab.
#[test]
fn an_invalid_object_lives_in_problems_and_the_rail_stops_at_manifest_signature() {
    let vault = verify::unlocked_vault_with_pinned_anchor();
    let fixture = verify::entry_with_a_flipped_manifest_byte();
    let stand = stand_over(fixture, &vault);
    let report = stand.opened().report();
    let signature_error = report
        .signature_errors()
        .next()
        .expect("die Kulisse traegt einen Signaturbefund");
    let object_hash = hex::encode(signature_error.object_hash().as_bytes());

    let stand_view = parsed(&view::stand_json(&stand));
    assert_eq!(stand_view["fullyVerified"], false);
    let problems = stand_view["problems"]
        .as_array()
        .expect("problems ist ein Array");
    let problem = problems
        .iter()
        .find(|problem| problem["objectHash"] == object_hash)
        .expect("das bemaengelte Objekt steht in problems");
    assert_eq!(problem["verification"], VerificationStatus::Invalid.label());
    assert_eq!(problem["detailCode"], signature_error.code());
    assert!(
        stand_view["entries"]
            .as_array()
            .expect("entries ist ein Array")
            .iter()
            .all(|entry| entry["state"]["objectHash"] != object_hash),
        "ein ungueltiges Objekt steht nie in entries"
    );

    let chain = stand_view["chain"].as_array().expect("chain ist ein Array");
    let last = chain
        .last()
        .expect("die Leiste traegt mindestens einen Knoten");
    assert_eq!(last["label"], "manifest-signature");
    assert_eq!(last["verified"], false);
    assert_eq!(last["detail"], signature_error.code());
    assert_eq!(
        chain.len(),
        GATE_ORDER_V1
            .iter()
            .position(|gate| *gate == "manifest-signature")
            .expect("das Tor steht in der Reihenfolge")
            + 1,
        "hinter dem fehlgeschlagenen Tor steht KEIN Knoten"
    );
    for node in &chain[..chain.len() - 1] {
        assert_eq!(node["verified"], true);
        assert_eq!(node["detail"], Value::Null);
    }
}

/// Der vollstaendig verifizierte Bestand traegt alle neun Tore, in der
/// Reihenfolge von `GATE_ORDER_V1` und mit ihren Namen.
#[test]
fn a_fully_verified_stand_carries_all_nine_gates_as_true() {
    let vault = verify::unlocked_vault_with_pinned_anchor();
    let stand = stand_over(verify::complete_archive(), &vault);
    let stand_view = parsed(&view::stand_json(&stand));
    let chain = stand_view["chain"].as_array().expect("chain ist ein Array");
    let labels: Vec<&str> = chain
        .iter()
        .map(|node| node["label"].as_str().expect("label"))
        .collect();
    assert_eq!(labels, GATE_ORDER_V1.to_vec());
    assert!(chain.iter().all(|node| node["verified"] == true));
    assert_eq!(
        stand_view["serverConfirmation"],
        ServerConfirmationV1::NotServerConfirmed.label()
    );
}

/// Die technische Ansicht liest Feld fuer Feld aus dem Manifest des
/// verifizierten Eintrags; ein unbekannter Hash ist ein Aufruffehler.
#[test]
fn the_technical_view_reads_the_manifest_of_the_verified_entry() {
    let vault = verify::unlocked_vault_with_pinned_anchor();
    let stand = stand_over(amendments::amendment_archive(), &vault);
    let original = amendments::original_entry_hash();
    let technical =
        parsed(&view::technical_json(&stand, original).expect("das Original traegt ein Manifest"));
    assert_eq!(technical["sequence"], amendments::ORIGINAL_SEQUENCE_V1);
    assert_eq!(technical["entryHash"], hex_of(original));
    assert!(technical["previousEntryHash"].as_str().is_some());
    assert!(
        technical["ciphertextHash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    assert!(
        technical["writerCertificateHash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    assert!(
        technical["registryHeadHash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    assert!(technical["registryVersion"].is_number());
    assert_eq!(
        technical["serverConfirmation"],
        ServerConfirmationV1::NotServerConfirmed.label()
    );
    assert_eq!(technical["evidenceDetailCode"], Value::Null);

    let genesis = verify::entry_hash_at(
        amendments::amendment_archive(),
        amendments::GENESIS_SEQUENCE_V1,
    );
    let genesis_view = parsed(&view::technical_json(&stand, genesis).expect("Genesis"));
    assert_eq!(genesis_view["previousEntryHash"], Value::Null);

    assert_eq!(
        view::technical_json(&stand, EntryHash::try_from(&[0xee_u8; 32][..]).unwrap()).err(),
        Some(EA_READER_VIEW_UNKNOWN_ENTRY)
    );
}

/// Die vier Filter laufen unveraendert an `ReaderSearch::search`: das
/// Stichwort des Originals trifft es, ein Zeitraum, der alles ausschliesst,
/// trifft nichts, und ohne Filter kommt jeder indizierte Treffer.
#[test]
fn the_search_hands_the_filters_to_the_index_and_renders_every_hit() {
    let vault = verify::unlocked_vault_with_pinned_anchor();
    let stand = stand_over(amendments::amendment_archive(), &vault);
    let original = hex_of(amendments::original_entry_hash());

    let by_keyword =
        parsed(&view::search_json(&stand, &ReaderQueryV1::keyword("Brand")).expect("Suche"));
    assert!(
        by_keyword
            .as_array()
            .expect("ein Array von Treffern")
            .iter()
            .any(|hit| hit["entryHash"] == original),
        "das Stichwort des Originals trifft das Original"
    );
    let hit = by_keyword
        .as_array()
        .expect("Treffer")
        .iter()
        .find(|hit| hit["entryHash"] == original)
        .expect("das Original");
    assert_eq!(
        hit["incidentNumber"],
        amendments::ORIGINAL_INCIDENT_NUMBER_V1
    );
    assert_eq!(hit["sequence"], amendments::ORIGINAL_SEQUENCE_V1);
    assert!(hit["occurredAtStartMs"].is_number());

    let none = parsed(
        &view::search_json(
            &stand,
            &ReaderQueryV1::period(UnixMillis::new(0), UnixMillis::new(1)),
        )
        .expect("Suche"),
    );
    assert_eq!(none, Value::Array(vec![]));

    let all = parsed(&view::search_json(&stand, &ReaderQueryV1::default()).expect("Suche"));
    let stand_view = parsed(&view::stand_json(&stand));
    let with_incident = stand_view["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|entry| !entry["incident"].is_null())
        .count();
    assert!(with_incident > 1, "sonst misst die Zaehlung nichts");
    assert_eq!(all.as_array().map(Vec::len), Some(with_incident));
    let sequences = sequences_of(&all);
    let mut sorted = sequences.clone();
    sorted.sort_unstable();
    assert_eq!(sequences, sorted, "Treffer stehen in Sequenzordnung");
}

/// Der EINE Bestand des Fadens: installieren, ersetzen, fallen lassen.
#[test]
fn installing_replaces_the_current_stand_and_closing_drops_it() {
    let vault = verify::unlocked_vault_with_pinned_anchor();
    assert_eq!(view::current_stand_json(), "null");

    view::install_stand(stand_over(amendments::amendment_archive(), &vault));
    let first = parsed(&view::current_stand_json());
    assert_eq!(
        first["entries"].as_array().map(Vec::len),
        Some(amendments::ENTRIES_IN_THE_AMENDMENT_ARCHIVE_V1)
    );

    view::install_stand(stand_over(verify::complete_archive(), &vault));
    let second = parsed(&view::current_stand_json());
    assert_eq!(
        second["entries"].as_array().map(Vec::len),
        Some(verify::ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1)
    );

    view::close_stand();
    assert_eq!(view::current_stand_json(), "null");
    assert_eq!(
        view::with_current_stand(|stand| view::entry_json(
            stand,
            amendments::original_entry_hash()
        )),
        None
    );
}
