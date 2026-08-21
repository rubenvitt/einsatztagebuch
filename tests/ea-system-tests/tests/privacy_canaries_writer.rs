//! Die Kanarienvoegel des Writers: kein fachliches Zeichen ueberlebt den
//! Abschluss irgendwo auf der Platte.
//!
//! Je fachliches Feld GENAU EIN eigener Marker. Ein gemeinsamer Marker fuer
//! zwei Felder liesse offen, welches von beiden geleckt hat. Gesucht wird mit
//! `ea_testkit::contains_canary`; ein blosses `contains_subslice` gibt es auf
//! `&[u8]` nicht.
//!
//! # Warum ZWEI Auspraegungen
//!
//! `ea-schema` weist eine nichtleere Liste MIT Leergrund ab
//! (`EA-SCHEMA-LIST-REASON`). Ein einziger Einsatz kann deshalb nicht
//! gleichzeitig Personal- und Fahrzeugzeilen UND die beiden Leergruende tragen.
//! [`CanaryVariantV1::ALL`] saet beides in zwei Laeufen, und
//! `every_named_field_is_seeded_by_some_variant` belegt, dass ihre Vereinigung
//! kein Feld auslaesst.
//!
//! # Die Positivkontrollen
//!
//! Ohne sie waere die ganze Datei gruen, wenn die Marker nie in das System
//! gelangt waeren:
//!
//! 1. Der Entwurfsfreitext traegt seinen Marker VOR dem Abschluss — gelesen aus
//!    der Ablage, nicht behauptet.
//! 2. Die Einsatznummer des Kanarieneinsatzes ist NACH dem Abschluss verbraucht
//!    — der Beleg, dass genau diese Eingabe finalisiert wurde und nicht eine
//!    andere.
//! 3. Ein Marker, der in KEINER Auspraegung gesaet wird, faellt beim
//!    Vollstaendigkeitstest auf und nicht still durch die Suche.

mod support;

use std::collections::BTreeSet;

use ea_types::EntryHash;

use support::{CANARY_MARKERS, CanaryHarness, CanaryVariantV1, canary, draft_support};

#[test]
fn no_fachliche_canary_survives_finalization_anywhere_on_disk() {
    for variant in CanaryVariantV1::ALL {
        let mut harness = CanaryHarness::with_one_canary_per_field(variant);

        // Positivkontrolle 1: der Marker ist WIRKLICH im System.
        assert_eq!(
            harness.draft_notes().as_deref(),
            Some(canary("notes")),
            "{variant:?}: die Fixture MUSS den Freitextmarker in den Entwurf gelegt haben"
        );

        let entry_hash = harness.finalize().unwrap_or_else(|error| {
            panic!("{variant:?}: die Finalisierung muss gelingen: {error}")
        });

        // Positivkontrolle 2: GENAU dieser Einsatz wurde abgeschlossen.
        assert!(
            harness.incident_number_is_taken(),
            "{variant:?}: die Einsatznummer des Kanarieneinsatzes MUSS verbraucht sein"
        );
        assert!(
            harness.writer_keys_cannot_decrypt(entry_hash),
            "{variant:?}: kein Geheimnis dieses Writers darf den committed Eintrag oeffnen"
        );

        let streams = harness.every_observable_byte_stream();
        assert!(
            streams.len() >= 4,
            "{variant:?}: die Suche MUSS Datenbank, Bestand, Namen und Debug-Ausgabe umfassen: {}",
            streams.len()
        );
        for marker in harness.canaries() {
            for (place, bytes) in &streams {
                assert!(
                    !ea_testkit::contains_canary(bytes, marker),
                    "{variant:?}: {:?} steht in {place}",
                    String::from_utf8_lossy(marker)
                );
            }
        }
    }
}

#[test]
fn the_search_finds_a_marker_that_really_lies_on_disk() {
    // Die GEGENKONTROLLE der ganzen Datei: liegt ein Marker wirklich auf der
    // Platte, MUSS die Suche ihn finden. Ohne sie waere jede
    // Abwesenheitszusicherung auch dann gruen, wenn die Stromsammlung leer
    // liefe oder `contains_canary` nichts taete.
    let harness = CanaryHarness::with_one_canary_per_field(CanaryVariantV1::PopulatedLists);
    let marker = canary("notes");
    assert!(
        !harness
            .every_observable_byte_stream()
            .iter()
            .any(|(_, bytes)| ea_testkit::contains_canary(bytes, marker.as_bytes())),
        "vor der Probe darf der Marker nirgends stehen"
    );
    harness.plant_marker_for_test(marker);
    assert!(
        harness
            .every_observable_byte_stream()
            .iter()
            .any(|(_, bytes)| ea_testkit::contains_canary(bytes, marker.as_bytes())),
        "die Suche MUSS einen Marker finden, der wirklich auf der Platte liegt"
    );
}

#[test]
fn every_named_field_is_seeded_by_some_variant() {
    // Die Vollstaendigkeit der Markermenge ist selbst eine Zusage: zwei Felder
    // mit demselben Marker liessen offen, welches geleckt hat; ein leerer
    // Marker liesse `contains_canary` immer `false` melden; und ein Feld, das
    // keine Auspraegung saet, liefe ungemessen mit.
    let markers: BTreeSet<&str> = CANARY_MARKERS.iter().map(|(_, marker)| *marker).collect();
    assert_eq!(
        markers.len(),
        CANARY_MARKERS.len(),
        "jeder Marker MUSS genau einem Feld gehoeren"
    );
    let fields: BTreeSet<&str> = CANARY_MARKERS.iter().map(|(field, _)| *field).collect();
    assert_eq!(fields.len(), CANARY_MARKERS.len());
    for (field, marker) in CANARY_MARKERS {
        assert!(
            !marker.is_empty(),
            "{field} traegt einen leeren Marker, und `contains_canary` meldet fuer einen leeren \
             Marker immer false"
        );
    }
    let seeded: BTreeSet<&str> = CanaryVariantV1::ALL
        .iter()
        .flat_map(|variant| variant.seeded_fields().iter().copied())
        .collect();
    assert_eq!(
        seeded, fields,
        "die Vereinigung der Auspraegungen MUSS jedes benannte Feld saeen"
    );
}

#[test]
fn a_restored_backup_never_returns_a_finalized_or_discarded_key() {
    // Die FINALISIERTE Seite.
    let mut harness = CanaryHarness::with_one_canary_per_field(CanaryVariantV1::PopulatedLists);
    let entry_hash: EntryHash = harness.finalize().expect("die Finalisierung muss gelingen");
    // Der Zustand NACH dem Abschluss — die Datenbankdatei, die eine
    // gewoehnliche Anwendungssicherung jetzt mitnehmen wuerde.
    // Zwei Aussagen und keine Disjunktion: die Nachbedingung von Schritt 13
    // (der Entwurf ist leer) und die ZUSAGE (kein Geheimnis dieses Writers
    // oeffnet den Eintrag). Als `draft_is_blank() || !draft_dek_is_present()`
    // war die erste Haelfte immer wahr und sagte nichts ueber die zweite.
    assert!(harness.draft_is_blank());
    assert!(harness.writer_keys_cannot_decrypt(entry_hash));
    // Und die Sicherung von VOR dem Abschluss, zurueckgespielt: die
    // Datenbankdateien kehren zurueck, der geraetegebundene
    // Schluesselspeichereintrag nicht.
    harness.restore_pre_finalization_backup();
    assert!(
        harness.draft_notes().is_none(),
        "eine zurueckgespielte Datenbankdatei findet keinen Schluessel und damit keinen Entwurf"
    );
    assert!(
        harness.writer_keys_cannot_decrypt(entry_hash),
        "die Rueckspielung gibt den Schluessel des abgeschlossenen Eintrags nicht zurueck"
    );

    // Die VERWORFENE Seite. Sie haengt an derselben Asymmetrie und ist der
    // benannte Abbruchpunkt `BackupRestoreAfterKeyDeletion`.
    let mut discarded = draft_support::DraftHarness::with_nonempty_draft();
    assert!(
        discarded.draft_dek_is_present(),
        "die Fixture MUSS mit einem oeffenbaren Entwurf beginnen, sonst ist die Zusicherung leer"
    );
    discarded
        .discard_with_fault(ea_draft::DiscardFaultPoint::AfterAbsenceConfirmation)
        .expect("das Verwerfen bis zur bestaetigten Abwesenheit muss erreichbar sein");
    discarded
        .restore_captured_backup()
        .expect("die Rueckspielung und der Neustart muessen tragen");
    assert!(
        !discarded.draft_dek_is_present(),
        "die Rueckspielung gibt den Schluessel des verworfenen Entwurfs nicht zurueck"
    );
}
