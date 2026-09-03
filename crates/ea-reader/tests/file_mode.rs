//! Der Datei-Modus: EINE exportierte Datei, ein dauerhaft angebundener Ordner,
//! und kein einziger Serveraufruf.
//!
//! Der Modus ist durch seine ABWESENHEIT definiert — dieses Ziel nennt weder
//! `ReaderSyncService` noch `ConfirmedCursor` noch eine Adresse, und es kann
//! das auch gar nicht: die vier Eingaenge von [`ReaderFileMode`] nehmen Bytes
//! und eine Tresorsitzung und sonst nichts.
//!
//! # Beide Wege muenden in EINEN Port
//!
//! Es entsteht KEIN zweiter Archivparser. `ArchiveBundleSource::from_bytes`
//! und die Verzeichnisquelle geben beide `ea_archive::ArchiveSource` heraus,
//! und klassifiziert wird ausschliesslich am 9-Byte-Exact-Object-Praefix, nie
//! an einem Dateinamen. Der Zeuge dafuer ist die BYTEGLEICHHEIT der zwei
//! Berichte und nicht eine Zusicherung ueber Namen.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    ArchiveError, BUNDLE_MAGIC_V1, DirectoryHandleSource, MAX_ARCHIVE_BLOBS_V1, ObjectResultKindV1,
    ReaderFileMode, ReaderMode, ServerConfirmationV1,
};

use verify_fixtures::fixtures;

/// Dieselben BYTES auf beiden Wegen, und deshalb derselbe Bericht.
///
/// Der Name sagt „byte identical reports" und nicht „identical archives", und
/// das ist die Genauigkeit, auf die es hier ankommt: gleiche `reportHash`
/// belegt, dass beide Wege dieselben Objektbytes tragen. Sie belegt NICHT,
/// dass die Bytes unter denselben Adressen liegen — kein Feld von
/// `VerificationReportV1` nennt einen Pfadhinweis, und genau diese
/// Ordnungsunabhaengigkeit macht die Gleichheit ueberhaupt erst erreichbar:
/// der Container ist streng sortiert, der Verzeichnisdurchlauf ist es nicht.
#[test]
fn the_bundle_and_the_same_blobs_produce_byte_identical_reports() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();
    let archive = fixtures::complete_archive();

    let from_file = ReaderFileMode::open_bundle(
        fixtures::exported_bundle_bytes(archive),
        &vault,
        fixtures::EFFECTIVE_NOW,
    )
    .expect("das Buendel der Kulisse muss oeffnen");

    let mut directory = DirectoryHandleSource::new();
    for (path_hint, bytes) in fixtures::directory_blobs(archive) {
        directory
            .push_blob(path_hint, bytes)
            .expect("beide Deckel liegen weit darueber");
    }
    // ANTI-LEERLAUF: ein leerer Ordner verifizierte ebenfalls, und beide
    // Berichte waeren dann aus dem falschen Grund gleich.
    assert_eq!(
        directory.blob_count(),
        fixtures::directory_blobs(archive).len()
    );
    assert!(directory.blob_count() > 0);

    let from_directory = ReaderFileMode::open_directory(directory, &vault, fixtures::EFFECTIVE_NOW)
        .expect("dieselben Blobs muessen dasselbe ergeben");

    // KEIN `assert_eq!`: `Hash32` leitet kein `Debug` ab.
    assert!(from_file.report().report_hash() == from_directory.report().report_hash());
    assert!(from_file.report().is_fully_verified());
    assert_eq!(
        from_file.report().archive_object_count(),
        from_directory.report().archive_object_count(),
    );
    assert_eq!(from_file.mode(), ReaderMode::File);
    assert_eq!(from_directory.mode(), ReaderMode::File);
}

/// Die orthogonale Dimension aus `web-reader-design.md` §17.4: eine EIGENE
/// Spalte, kein Mangel.
///
/// `nicht server-bestaetigt` ist im Datei-Modus der REGELFALL und keine
/// Invariante — deshalb steht hier keine Zusicherung ueber die Abwesenheit von
/// Quittungen, sondern eine ueber die Vertraeglichkeit der zwei Spalten: der
/// Bestand ist gleichzeitig unbestaetigt UND vollstaendig verifiziert.
#[test]
fn every_object_without_a_receipt_is_not_server_confirmed_and_never_a_gap() {
    let opened = ReaderFileMode::open_bundle(
        fixtures::exported_bundle_bytes(fixtures::complete_archive()),
        &fixtures::unlocked_vault_with_pinned_anchor(),
        fixtures::EFFECTIVE_NOW,
    )
    .expect("der lueckenlose Bestand muss oeffnen");
    let report = opened.report();

    // GEMESSEN und nicht gewaehlt: `complete_valid_archive` legt GENAU EINEN
    // Eintrag ab, und `confirm_entries` gibt genau den Eintraegen ein Ergebnis.
    assert_eq!(
        report.object_results().len(),
        fixtures::ENTRIES_IN_THE_COMPLETE_ARCHIVE_V1
    );
    assert!(
        report
            .object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::NotServerConfirmed)
    );
    assert!(
        report
            .object_results()
            .all(|result| result.result() == ObjectResultKindV1::Valid)
    );
    assert_eq!(report.gaps().len(), 0);
    assert_eq!(report.quarantined_objects().len(), 0);
    assert_eq!(report.format_errors().len(), 0);
    // Das ist die Zusage von `design.md` §17.4: eigene Dimension, kein Mangel.
    assert!(report.is_fully_verified());
}

/// Die Gegenkontrolle, und NUR ueber der einen Spalte.
///
/// Ohne sie waere die Zusicherung darueber auch dann gruen, wenn
/// `serverConfirmation` gar keinen zweiten Wert annehmen koennte. Ueber
/// Maengel sagt dieser Bestand ausdruecklich nichts: er traegt die
/// Vorlauf-Luecke `0..=1` der Quittungslinie und ist deshalb GEMESSEN nicht
/// `is_fully_verified()`. Eine Zusage ueber `gaps()` waere hier rot, und zwar
/// aus einem Grund, der mit dem Datei-Modus nichts zu tun hat.
#[test]
fn the_same_entry_point_reports_server_confirmed_when_the_receipts_travel_along() {
    let opened = ReaderFileMode::open_bundle(
        fixtures::exported_bundle_bytes(fixtures::archive_with_receipts()),
        &fixtures::unlocked_vault_with_pinned_anchor(),
        fixtures::EFFECTIVE_NOW,
    )
    .expect("auch der Quittungsbestand muss oeffnen");
    let report = opened.report();

    assert!(report.object_results().len() > 0);
    assert!(
        report
            .object_results()
            .all(|result| result.server_confirmation() == ServerConfirmationV1::ServerConfirmed)
    );
}

/// Der Blobdeckel an seinem ECHTEN Wert.
///
/// Bezahlbar, weil leere Nutzlasten nichts kosten: eine Million `push_blob`
/// kostet eine Million Adress-`String`s und keine einzige Nutzlastzuteilung.
/// Ohne diesen Zeugen bewiese die Kappenpruefung darunter nur, dass
/// `with_caps_for_test` funktioniert, und nichts darueber, welche Zahl `new()`
/// verdrahtet.
#[test]
fn the_directory_source_enforces_the_blob_cap_it_was_built_with() {
    let mut source = DirectoryHandleSource::new();
    for index in 0..MAX_ARCHIVE_BLOBS_V1 {
        source
            .push_blob(&format!("entries/{index}.eip"), &[])
            .expect("bis zur inklusiven Grenze traegt die Quelle");
    }
    assert_eq!(source.blob_count(), MAX_ARCHIVE_BLOBS_V1);
    assert_eq!(
        source.push_blob("entries/one-too-many.eip", &[]),
        Err(ArchiveError::BlobLimit),
    );
    // Und die Quelle hat den abgewiesenen Blob NICHT uebernommen.
    assert_eq!(source.blob_count(), MAX_ARCHIVE_BLOBS_V1);
}

/// Der Bytedeckel gegen eine EINSTELLBARE Schranke.
///
/// Dieselbe Bauform und derselbe Grund wie `open_archive_bundle_capped` in
/// `crates/ea-archive-fs/src/bundle.rs`: mit dem echten Wert braeuchte der
/// Zeuge zwei Gibibyte, die er nie liest. Gemessen wird die REIHENFOLGE — die
/// Summe faellt, bevor die Quelle ihre Kopie anlegt. Ueber den Puffer des
/// AUFRUFERS sagt das nichts: wer ein `&[u8]` uebergibt, hat es schon.
#[test]
fn the_directory_source_enforces_the_byte_cap_before_it_copies() {
    let mut source = DirectoryHandleSource::with_caps_for_test(8, 4);
    source
        .push_blob("entries/a.eip", &[0; 4])
        .expect("genau die Grenze traegt");
    assert_eq!(source.total_bytes(), 4);
    assert_eq!(
        source.push_blob("entries/b.eip", &[0]),
        Err(ArchiveError::TotalByteLimit),
    );
    assert_eq!(source.blob_count(), 1);
    assert_eq!(source.total_bytes(), 4);
}

/// Eine im Transport beschaedigte oder umbenannte Datei.
///
/// KEIN Teilbericht, und das traegt der Typ und nicht eine Zusicherung: der
/// Fehlerarm eines `Result<OpenedArchiveV1, _>` haelt keinen Bericht, und es
/// gibt keinen zweiten Eingang, der einen herausgaebe. Die Endung ist ein
/// HINWEIS — entschieden wird an `BUNDLE_MAGIC_V1`.
#[test]
fn a_truncated_or_wrongly_magicked_container_reports_the_bundle_code_and_no_report() {
    let vault = fixtures::unlocked_vault_with_pinned_anchor();

    let mut truncated = fixtures::exported_bundle_bytes(fixtures::complete_archive());
    truncated.truncate(truncated.len() - 1);
    // `.err()` und nicht `.unwrap_err()`: `OpenedArchiveV1` traegt kein `Debug`.
    assert_eq!(
        ReaderFileMode::open_bundle(truncated, &vault, fixtures::EFFECTIVE_NOW)
            .err()
            .expect("ein angeschnittener Container ist kein Bestand")
            .code(),
        "EA-BUNDLE-MALFORMED",
    );

    let mut renamed = fixtures::exported_bundle_bytes(fixtures::complete_archive());
    renamed[0] ^= 0x01;
    assert_ne!(&renamed[..BUNDLE_MAGIC_V1.len()], &BUNDLE_MAGIC_V1[..]);
    assert_eq!(
        ReaderFileMode::open_bundle(renamed, &vault, fixtures::EFFECTIVE_NOW)
            .err()
            .expect("eine umbenannte Datei ist kein Bestand")
            .code(),
        "EA-BUNDLE-MALFORMED",
    );
}

/// Der dauerhaft angebundene Ordner verliert zwischen zwei Oeffnungen seine
/// Berechtigung.
///
/// Der Zeuge braucht dafuer [`DirectoryHandleSource::mark_unavailable`], und
/// die Methode ist keine Testhilfe, sondern die einzige ehrliche Abbildung
/// eines gemessenen Browserverhaltens: `FileSystemDirectoryHandle` gibt eine
/// entzogene Berechtigung beim NAECHSTEN Zugriff heraus, mitten im Durchlauf.
/// `apps/web/src/features/file-mode/DirectoryHandle.ts` ruft sie ueber
/// `fileModeDirectoryUnavailable`, sobald `queryPermission`/`requestPermission`
/// nicht mehr `granted` liefert. Ohne sie waere `ArchiveError::Unavailable`
/// ueber diesen Eingang gar nicht erreichbar — eine Quelle aus besessenen
/// Bytes kann das Liefern nicht verweigern.
///
/// Der universelle Weg bleibt davon UNBERUEHRT: der Abbruch verbraucht nichts
/// und pinnt nichts, und `open_bundle` nimmt seine Bytes ohnehin nur aus einem
/// gewoehnlichen Dateidialog. Das ist die Szenarienklammer, die das
/// Fehlerpunktmanifest unter `directory-permission-revoked` aufloest.
#[test]
fn a_directory_whose_permission_was_revoked_reports_the_archive_code_and_no_report() {
    let archive = fixtures::complete_archive();
    let mut source = DirectoryHandleSource::new();
    for (path_hint, bytes) in fixtures::directory_blobs(archive) {
        source
            .push_blob(path_hint, bytes)
            .expect("der Vorlauf traegt");
    }
    source.mark_unavailable();

    assert_eq!(
        ReaderFileMode::open_directory(
            source,
            &fixtures::unlocked_vault_with_pinned_anchor(),
            fixtures::EFFECTIVE_NOW,
        )
        .err()
        .expect("ein Ordner ohne Berechtigung ist kein Bestand")
        .code(),
        "EA-ARCHIVE-UNAVAILABLE",
    );

    // Und derselbe Bestand als EINE Datei traegt weiterhin: der universelle Weg
    // bleibt offen, wenn der Komfortweg zumacht.
    assert!(
        ReaderFileMode::open_bundle(
            fixtures::exported_bundle_bytes(archive),
            &fixtures::unlocked_vault_with_pinned_anchor(),
            fixtures::EFFECTIVE_NOW,
        )
        .expect("der universelle Weg bleibt angeboten")
        .report()
        .is_fully_verified()
    );
}
