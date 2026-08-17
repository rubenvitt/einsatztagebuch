//! Ein Bestand, dessen Registrierungsfenster die ECHTE Betriebssystemuhr
//! enthaelt.
//!
//! # Warum es dieses Target gibt
//!
//! Die CLU des Wiederherstellungspfades kennt genau EINE Uhr:
//! `SystemTime::now()`. Unter ihr degenerieren die geerbten Fixtures aus
//! `crates/ea-verify/tests/support` zu einer LEEREN Aussage — gemessen, nicht
//! vermutet: `complete_valid_archive()` liefert bei der Fixture-Uhr 800
//! `object_results().len() == 1`, bei der echten Uhr `0`, und zwar bei
//! unveraendertem `is_fully_verified() == true`. Ein Erfolgspfad, der sich auf
//! diesen Bestand stuetzte, pruefte nichts und saehe trotzdem gruen aus.
//!
//! `the_inherited_fixture_says_nothing_at_the_real_os_clock` haelt genau diesen
//! Kontrastbefund fest, damit die Begruendung dieses Targets nicht als
//! Kommentar behauptet, sondern als Test gemessen wird.

#[path = "support/mod.rs"]
mod support;

use support::{
    LIVE_FORMAT_SCHEMA_FILE_V1, LIVE_MISSING_MIDDLE_SEQUENCE_V1, live_clock, live_clock_archive,
    live_clock_archive_with_a_missing_middle_entry, live_clock_archive_with_foreign_encapsulation,
    live_clock_archive_with_mutated_writer_signature, live_clock_archive_with_two_entries,
    live_clock_archive_without_trust_objects, live_clock_options,
    verify_support::{complete_recipient_key_thumbprint, complete_recipient_private_key},
};

use ea_verify::{VerifyOptions, verify_archive};

/// Der Erfolgspfad unter der ECHTEN Uhr: eine Aussage ueber genau einen
/// Eintrag.
#[test]
fn the_live_fixture_is_fully_verified_at_the_real_os_clock() {
    let built = live_clock_archive();
    let anchor = built.anchor();

    let report = verify_archive(&built.fixture, &anchor, live_clock_options())
        .expect("der Live-Bestand muss durchlaufen");

    assert!(
        report.is_fully_verified(),
        "der Live-Bestand muss unter der echten Uhr vollstaendig verifiziert sein"
    );
    assert!(
        report.object_results().len() == 1,
        "ueber genau einen Eintrag muss etwas ausgesagt werden, nicht ueber {}",
        report.object_results().len()
    );
    assert!(
        report.entry_package_count() == 1,
        "der Bestand traegt genau ein Eintragspaket"
    );
    assert!(
        report.quarantined_objects().len() == 0,
        "kein Objekt des Live-Bestands wird isoliert"
    );
    assert!(
        report.gaps().len() == 0,
        "die Kette des Live-Bestands ist lueckenlos"
    );
    assert!(
        report.public_key_thumbprints().len() == 2,
        "zwei Signaturpruefungen muessen gelingen, nicht {}",
        report.public_key_thumbprints().len()
    );
}

/// Der Kontrastbefund: der GEERBTE Bestand sagt bei derselben Uhr nichts.
///
/// `is_fully_verified()` wird hier ABSICHTLICH NICHT geprueft — es ist wahr,
/// und genau das ist die Falle. Der Bestand traegt ein Eintragspaket, und ueber
/// dieses Paket wird nichts ausgesagt. Ein Erfolgspfad, der sich allein auf
/// `is_fully_verified()` stuetzte, nennte das gruen.
#[test]
fn the_inherited_fixture_says_nothing_at_the_real_os_clock() {
    let built = support::verify_support::complete_valid_archive();
    let anchor = built.anchor();

    let report = verify_archive(&built.fixture, &anchor, live_clock_options())
        .expect("auch der geerbte Bestand muss durchlaufen");

    assert!(
        report.entry_package_count() == 1,
        "der geerbte Bestand traegt weiterhin genau ein Eintragspaket"
    );
    assert!(
        report.object_results().len() == 0,
        "unter der echten Uhr darf ueber KEIN Objekt etwas ausgesagt werden, \
         gemessen wurden {}",
        report.object_results().len()
    );
}

/// Ohne Trust-Objekte traegt Gate `trust` nicht: kein einziger Abdruck.
#[test]
fn a_live_archive_without_trust_objects_proves_no_signer() {
    let built = live_clock_archive_without_trust_objects();
    let anchor = built.anchor();

    let report = verify_archive(&built.fixture, &anchor, live_clock_options())
        .expect("auch ein Bestand ohne Vertrauenskette muss durchlaufen");

    assert!(
        report.public_key_thumbprints().len() == 0,
        "ohne Registrierungslinie ist keine Signaturpruefung gelungen, \
         gemessen wurden {}",
        report.public_key_thumbprints().len()
    );
    assert!(
        report.object_results().len() == 0,
        "ohne Vertrauenskette wird ueber kein Objekt etwas ausgesagt"
    );
}

/// Zwei verkettete Eintraege, zwei Aussagen, keine Luecke.
#[test]
fn two_live_entries_are_both_verified_at_the_real_os_clock() {
    let built = live_clock_archive_with_two_entries();
    let anchor = built.anchor();

    let report = verify_archive(&built.fixture, &anchor, live_clock_options())
        .expect("der zweigliedrige Live-Bestand muss durchlaufen");

    assert!(
        report.is_fully_verified(),
        "der zweigliedrige Live-Bestand muss vollstaendig verifiziert sein"
    );
    assert!(
        report.object_results().len() == 2,
        "ueber beide Eintraege muss etwas ausgesagt werden, nicht ueber {}",
        report.object_results().len()
    );
    assert!(
        report.gaps().len() == 0,
        "zwei aufeinanderfolgende Sequenzen lassen keine Luecke"
    );
}

/// Nur `live_clock_archive()` traegt Beiwerk — und es wird als Beiwerk
/// gezaehlt, nicht isoliert.
///
/// Ohne diese Messung waere `nonObjectFileCount` in jedem Bestand null und
/// jede Aussage der CLI ueber Nicht-Objekt-Dateien VAKUUM-WAHR.
#[test]
fn the_live_fixture_carries_counted_but_never_quarantined_beiwerk() {
    let built = live_clock_archive();
    let anchor = built.anchor();

    let report = verify_archive(&built.fixture, &anchor, live_clock_options())
        .expect("der Live-Bestand muss durchlaufen");

    assert!(
        report.non_object_file_count() == 2,
        "der Live-Bestand traegt zwei Nicht-Objekt-Dateien, gezaehlt wurden {}",
        report.non_object_file_count()
    );
    assert!(
        report.quarantined_objects().len() == 0,
        "Beiwerk wird gezaehlt und NIE isoliert"
    );

    // Die ZAHL allein genuegt nicht: zwei Dateien mit beliebigen Namen auf der
    // Wurzelebene zaehlten genauso. Gepinnt werden deshalb die PFADE — der
    // geschachtelte darunter ist der einzige, der `create_dir_all` im
    // Materialisieren wie im Exportschreiber ueberhaupt ausloest.
    let hints: Vec<&str> = built
        .fixture
        .blobs()
        .iter()
        .map(|(hint, _)| hint.as_str())
        .collect();
    assert!(
        hints.contains(&ea_archive::README_FORMAT_FILE_V1),
        "die Formatbeschreibung muss unter ihrem Layoutpfad liegen, gemessen {hints:?}"
    );
    assert!(
        hints.contains(&LIVE_FORMAT_SCHEMA_FILE_V1),
        "das Schemabeiwerk muss unter seinem Layoutpfad liegen, gemessen {hints:?}"
    );
    assert!(
        LIVE_FORMAT_SCHEMA_FILE_V1.contains('/'),
        "das Schemabeiwerk muss GESCHACHTELT liegen, sonst uebt es kein create_dir_all"
    );

    let sibling = live_clock_archive_with_two_entries();
    let sibling_anchor = sibling.anchor();
    let sibling_report = verify_archive(&sibling.fixture, &sibling_anchor, live_clock_options())
        .expect("der zweigliedrige Live-Bestand muss durchlaufen");
    assert!(
        sibling_report.non_object_file_count() == 0,
        "nur der einfache Live-Bestand traegt Beiwerk; der zweigliedrige traegt {}",
        sibling_report.non_object_file_count()
    );
}

/// Ein verkipptes Byte in der Schreibersignatur: GENAU EIN Signaturbefund.
///
/// Die Trennschaerfe ist der Gegenstand. Ein zweiter Befund — etwa ein
/// verwaister Grant — lenkte die Exitcodeableitung still auf einen anderen Code
/// um, weil sie den KLEINSTEN zutreffenden nimmt.
#[test]
fn a_mutated_writer_signature_is_the_only_finding_at_the_real_os_clock() {
    let built = live_clock_archive_with_mutated_writer_signature();
    let anchor = built.anchor();

    let report = verify_archive(&built.fixture, &anchor, live_clock_options())
        .expect("der mutierte Live-Bestand muss durchlaufen");

    assert!(
        report.signature_errors().len() == 1,
        "genau eine Signaturpruefung muss fehlschlagen, gemessen wurden {}",
        report.signature_errors().len()
    );
    assert!(
        report.decryption_errors().len() == 0,
        "die Mutation trifft die Signatur, nicht die Entkapselung"
    );
    assert!(
        report.object_results().len() == 2,
        "die beiden unversehrten Eintraege bleiben ausgesagt, gemessen wurden {}",
        report.object_results().len()
    );
}

/// Ein fehlender mittlerer Eintrag: GENAU EINE Luecke und kein Bruch.
#[test]
fn a_missing_middle_entry_is_the_only_finding_at_the_real_os_clock() {
    let built = live_clock_archive_with_a_missing_middle_entry();
    let anchor = built.anchor();

    let report = verify_archive(&built.fixture, &anchor, live_clock_options())
        .expect("der lueckenhafte Live-Bestand muss durchlaufen");

    let gaps: Vec<(u64, u64)> = report
        .gaps()
        .map(|gap| (gap.from_sequence().get(), gap.through_sequence().get()))
        .collect();
    assert!(
        gaps == vec![(
            LIVE_MISSING_MIDDLE_SEQUENCE_V1,
            LIVE_MISSING_MIDDLE_SEQUENCE_V1
        )],
        "die Luecke muss genau die ausgelassene Sequenz sein, gemessen {gaps:?}"
    );
    assert!(
        report.signature_errors().len() == 0,
        "ein VERLUST ist kein Signaturbefund"
    );
    assert!(
        report.quarantined_objects().len() == 0,
        "ein VERLUST isoliert kein Objekt"
    );
}

/// Eine fremde Kapselung: GENAU EIN Entschluesselungsbefund.
///
/// Der Empfaengerschluessel MUSS uebergeben werden. Ohne ihn findet gar keine
/// Entkapselung statt, `decryptionErrors` bliebe leer, und die Fixture bewiese
/// nichts.
#[test]
fn a_foreign_encapsulation_is_the_only_finding_at_the_real_os_clock() {
    let built = live_clock_archive_with_foreign_encapsulation();
    let anchor = built.anchor();
    let private_key = complete_recipient_private_key();
    let options = VerifyOptions::new(live_clock())
        .with_recipient(complete_recipient_key_thumbprint(), &private_key);

    let report = verify_archive(&built.fixture, &anchor, options)
        .expect("der fremd gekapselte Live-Bestand muss durchlaufen");

    assert!(
        report.decryption_errors().len() == 1,
        "genau eine Entkapselung muss fehlschlagen, gemessen wurden {}",
        report.decryption_errors().len()
    );
    assert!(
        report.signature_errors().len() == 0,
        "der Ciphertext bleibt unangetastet, also faellt keine Signatur"
    );
    assert!(
        report.gaps().len() == 0,
        "alle drei Eintraege liegen vor, also gibt es keine Luecke"
    );
}
