//! Ein Bestand von der Platte: `FsArchiveSource`.
//!
//! Dies ist die EINZIGE Stelle des Workspace, die Archivbytes aus einem
//! Verzeichnis liest. Alles, was daran gemessen wird, ist deshalb eine Aussage
//! ueber den gesamten Wiederherstellungspfad und nicht ueber eine Hilfsklasse.
//!
//! # Was hier gepinnt wird
//!
//! - **Byteidentitaet.** Ein materialisierter Bestand wird als dieselbe Menge
//!   aus Pfadhinweis und Bytes zurueckgelesen. Ohne das misst kein Gate
//!   dahinter noch den Bestand, den der Aufrufer wirklich hat.
//! - **Relative Hinweise.** Der Pfadhinweis ist der zur Wurzel RELATIVE Pfad
//!   mit `/` als Trenner. Ein absoluter Hostpfad wanderte sonst in Diagnosen
//!   und ueber sie in Ausgaben — was die Global Constraint des Stage-1-Plans
//!   ausdruecklich verbietet.
//! - **Ordnung.** `std::fs::read_dir` gibt KEINE Ordnung. Ohne eine hier
//!   festgelegte waere jede Fehlerreihenfolge und jedes `nonObjectFileCount`
//!   zufallsabhaengig und kein Berichtsvergleich mehr belastbar.
//! - **Symlinks.** Ein Symlink ist weder Datei noch Verzeichnis DIESES
//!   Bestands. Gepinnt wird der teure Fall: ein Symlink auf ein VERZEICHNIS,
//!   und zwar auf die Wurzel selbst. Wuerde er verfolgt, bliese sich der
//!   Bestand aus sich heraus unbegrenzt auf.
//! - **Gleichheit mit dem Speicherbestand.** Derselbe Bestand liefert ueber die
//!   Platte und im Speicher bei GLEICHER Uhr denselben `reportHash`. Das ist
//!   die eigentliche Zusicherung: die Quelle darf am Bericht nichts aendern.

#[path = "support/mod.rs"]
mod support;

use ea_archive::{ArchiveBlob, ArchiveSource};
use ea_recovery::FsArchiveSource;
use ea_types::UnixMillis;
use ea_verify::{VerifyOptions, verify_archive};

use support::{
    materialize, temp_dir,
    verify_support::{
        FIXTURE_OS_WALL_CLOCK_V1, archive_support::ArchiveFixture,
        complete_recipient_key_thumbprint, complete_recipient_private_key, complete_valid_archive,
    },
};

/// Alle Blobs einer Quelle als geordnete Paare, in Durchlaufreihenfolge.
fn drain(source: &dyn ArchiveSource) -> Vec<(String, Vec<u8>)> {
    let mut blobs = Vec::new();
    source
        .visit_blobs(&mut |blob: ArchiveBlob<'_>| {
            blobs.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        })
        .expect("ein vollstaendig gelesener Bestand muss durchlaufbar sein");
    blobs
}

/// Dieselben Paare, nach dem Pfadhinweis sortiert.
///
/// Der Vergleich mit dem Speicherbestand ist eine MENGENAUSSAGE: die Quelle
/// legt ihre eigene Durchlaufreihenfolge fest, und die ist hier nicht der
/// Gegenstand.
fn sorted(blobs: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    let mut sorted = blobs.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    sorted
}

/// Nur die Hinweise. Bytes gehoeren in keine Fehlermeldung.
fn hints(blobs: &[(String, Vec<u8>)]) -> Vec<&str> {
    blobs.iter().map(|(hint, _)| hint.as_str()).collect()
}

/// Legt `fixture` in einem frischen Verzeichnis ab und liest es zurueck.
fn read_back(fixture: &ArchiveFixture, tag: &str) -> (support::TempDir, Vec<(String, Vec<u8>)>) {
    let root = temp_dir(tag);
    materialize(fixture, root.path());
    let source =
        FsArchiveSource::open(root.path()).expect("der abgelegte Bestand muss lesbar sein");
    let blobs = drain(&source);
    (root, blobs)
}

#[test]
fn a_materialized_fixture_is_read_back_byte_for_byte() {
    let archive = complete_valid_archive();
    let (_root, actual) = read_back(&archive.fixture, "fs-source-roundtrip");

    let actual = sorted(&actual);
    let expected = sorted(archive.fixture.blobs());
    assert_eq!(
        hints(&actual),
        hints(&expected),
        "die Menge der Pfadhinweise muss dieselbe sein"
    );
    for ((hint, read), (_, written)) in actual.iter().zip(expected.iter()) {
        assert!(
            read == written,
            "{hint}: {} Bytes gelesen, {} Bytes abgelegt",
            read.len(),
            written.len()
        );
    }
}

#[test]
fn path_hints_are_relative_and_slash_separated() {
    let archive = complete_valid_archive();
    let root = temp_dir("fs-source-hints");
    materialize(&archive.fixture, root.path());
    let source =
        FsArchiveSource::open(root.path()).expect("der abgelegte Bestand muss lesbar sein");

    assert_eq!(
        source.root(),
        root.path(),
        "die Quelle muss ihre Wurzel unveraendert behalten"
    );
    let host_prefix = root.path().display().to_string();
    for (hint, _) in drain(&source) {
        assert!(
            !hint.starts_with(&host_prefix) && !hint.starts_with('/'),
            "der Pfadhinweis darf kein Hostpfad sein: {hint}"
        );
        assert!(
            !hint.contains('\\'),
            "der Pfadhinweis muss `/` als Trenner benutzen: {hint}"
        );
    }
}

#[test]
fn blob_order_is_stable_across_two_opens() {
    let archive = complete_valid_archive();
    let root = temp_dir("fs-source-order");
    materialize(&archive.fixture, root.path());

    let first = drain(&FsArchiveSource::open(root.path()).expect("erster Lauf"));
    let second = drain(&FsArchiveSource::open(root.path()).expect("zweiter Lauf"));

    assert_eq!(
        hints(&first),
        hints(&second),
        "zwei Laeufe ueber denselben Bestand muessen dieselbe Reihenfolge liefern"
    );
    // Die zweite Zusicherung ist die schaerfere: die erste allein bestuende
    // auch bei jeder anderen FESTEN Ordnung. Sie ist zugleich um eine Spur
    // staerker als das, was die Quelle verspricht — die sortiert JE EBENE, hier
    // wird die flachgeklopfte Liste GLOBAL gemessen. Beides faellt auseinander,
    // sobald ein Verzeichnis echtes Praefix eines Geschwisternamens ist und das
    // naechste Byte unter `/` (0x2F) liegt, etwa `format/` neben `format.txt`
    // (`.` ist 0x2E). Kein Fixture dieses Repos hat ein solches Paar, auch
    // keines der geplanten. Faellt dieser Test kuenftig, ist deshalb ZUERST das
    // neue Fixture zu pruefen und nicht die Quelle.
    let mut ascending = hints(&first);
    ascending.sort_unstable();
    assert_eq!(
        hints(&first),
        ascending,
        "der Durchlauf muss je Ebene lexikographisch aufsteigen"
    );
}

/// Kein Fehler dieser Crate darf einen Hostpfad tragen.
///
/// Global Constraint des Stage-1-Plans (Zeile 26): ein Hostpfad darf weder in
/// eine Diagnose noch ueber sie in eine Ausgabe gelangen. `RecoveryError::Io`
/// haelt deshalb ausschliesslich die `io::ErrorKind` und nie den
/// zugrundeliegenden `io::Error`, dessen Anzeige den Pfad je nach Aufrufpfad
/// aufnimmt. Gemessen werden BEIDE Darstellungen — `Display` wie `Debug` —,
/// denn ein Fehler wandert ueber beide nach draussen.
#[test]
fn a_recovery_error_never_names_a_host_path() {
    let root = temp_dir("fs-source-error");
    let missing = root.path().join("kein-bestand");
    // `expect_err` verlangte `Debug` auf `FsArchiveSource`, und die Quelle
    // traegt bewusst keines: sie haelt den Hostpfad, und ein `Debug` darueber
    // gaebe genau ihn heraus. Deshalb von Hand ausgepackt.
    let error = match FsArchiveSource::open(&missing) {
        Ok(_) => panic!("ein fehlendes Verzeichnis ist kein Bestand"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "EA-RECOVERY-IO");
    let host_path = missing.display().to_string();
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(&host_path) && !rendered.contains("kein-bestand"),
            "die Fehlerdarstellung nennt einen Hostpfad: {rendered}"
        );
    }
}

/// Ein Symlink auf die Wurzel selbst — der Fall, der einen Bestand aus sich
/// heraus unbegrenzt aufblaeht, wuerde er verfolgt.
#[cfg(unix)]
#[test]
fn a_symlink_is_not_followed() {
    let archive = complete_valid_archive();
    let root = temp_dir("fs-source-symlink");
    materialize(&archive.fixture, root.path());
    let before = drain(&FsArchiveSource::open(root.path()).expect("Lauf ohne Symlink"));

    std::os::unix::fs::symlink(root.path(), root.path().join("entries").join("loop"))
        .expect("der Symlink muss anlegbar sein");

    let after = drain(&FsArchiveSource::open(root.path()).expect("Lauf mit Symlink"));
    assert_eq!(
        hints(&before),
        hints(&after),
        "ein Symlink darf den Bestand weder erweitern noch verfolgt werden"
    );
}

#[test]
fn the_report_over_the_file_system_equals_the_report_in_memory() {
    let archive = complete_valid_archive();
    let root = temp_dir("fs-source-report");
    materialize(&archive.fixture, root.path());
    let source =
        FsArchiveSource::open(root.path()).expect("der abgelegte Bestand muss lesbar sein");

    let anchor = archive.anchor();
    let key = complete_recipient_private_key();
    let options = || {
        VerifyOptions::new(UnixMillis::new(FIXTURE_OS_WALL_CLOCK_V1))
            .with_recipient(complete_recipient_key_thumbprint(), &key)
    };
    let from_disk = verify_archive(&source, &anchor, options()).expect("Lauf ueber die Platte");
    let from_memory =
        verify_archive(&archive.fixture, &anchor, options()).expect("Lauf im Speicher");

    // Die Gleichheit zweier LEERER Berichte waere vakuum-wahr. Deshalb zuerst
    // ein Inhaltsbefund: unter der Fixture-Uhr traegt dieser Bestand genau
    // einen Eintrag und genau ein Objektergebnis.
    assert_eq!(from_disk.entry_package_count(), 1);
    assert_eq!(from_disk.object_results().len(), 1);
    assert!(from_disk.is_fully_verified());

    // `Hash32` traegt bewusst kein `Debug`; verglichen wird die Hexdarstellung.
    assert_eq!(
        hex::encode(from_disk.report_hash().as_bytes()),
        hex::encode(from_memory.report_hash().as_bytes()),
        "die Bestandsquelle darf den Bericht nicht veraendern"
    );
    assert_eq!(
        from_disk
            .to_canonical_json()
            .expect("der Bericht von der Platte muss kanonisch schreibbar sein"),
        from_memory
            .to_canonical_json()
            .expect("der Bericht aus dem Speicher muss kanonisch schreibbar sein"),
    );
}
