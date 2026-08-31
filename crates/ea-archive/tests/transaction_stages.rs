//! Der Staging-Vertrag der Archivtransaktion, OHNE Dateisystem.
//!
//! `crates/ea-archive` traegt fuer den Backend-Port keine Implementierung; die
//! Attrappe im Supportmodul haelt Bytes, Flushes und Sperre im Speicher. Damit
//! ist die Zusage „nach einem fehlgeschlagenen Flush existiert keine Zieladresse"
//! nachweisbar, ohne dass diese Crate `std::fs` beruehrt.

mod support;

use ea_archive::{
    ArchiveBackend, ArchivePath, ArchiveTransaction, ENTRIES_DIR_V1, STAGING_SUFFIX_V1,
    StagedBytesV1, StagedObjectV1,
};
use ea_format::encode_entry_package;

use support::InMemoryArchiveBackend;

/// Die Zieladresse des Eintragspakets der Fixture.
fn entry_target() -> ArchivePath {
    ArchivePath::in_dir(ENTRIES_DIR_V1, "000001.eip").expect("die Zieladresse ist gueltig")
}

/// Die Staging-Adresse zu [`entry_target`].
fn entry_staging() -> String {
    format!("{}000001.eip{STAGING_SUFFIX_V1}", ENTRIES_DIR_V1)
}

fn planned_entry() -> StagedObjectV1 {
    let (entry, _) = support::signed_entry_package();
    let bytes = encode_entry_package(&entry).expect("das Eintragspaket der Fixture kodiert");
    StagedObjectV1::new(entry_target(), StagedBytesV1::Object(bytes))
}

#[test]
fn transaction_never_publishes_after_a_failed_flush() {
    let backend = InMemoryArchiveBackend::with_failing_file_sync(Some(1));
    let mut transaction = ArchiveTransaction::new(&backend);
    transaction.plan(planned_entry());
    assert_eq!(transaction.planned_count(), 1);

    let error = transaction
        .commit()
        .expect_err("ein fehlgeschlagener Dateiflush MUSS die Transaktion abbrechen");
    assert_eq!(error.code(), "EA-ARCHIVE-FLUSH-FAILED");

    assert!(
        !backend.exists(entry_target().as_str()),
        "nach einem fehlgeschlagenen Flush darf KEINE Zieladresse existieren"
    );
    assert!(
        backend.exists(&entry_staging()),
        "die vorbereitete Staging-Adresse bleibt liegen und ist ein Gesundheitsbefund"
    );
    assert!(
        !backend.file_synced(&entry_staging()),
        "der fehlgeschlagene Flush darf nicht als erfolgreich gebucht sein"
    );
}

#[test]
fn a_successful_transaction_flushes_file_and_directory_before_it_publishes() {
    let backend = InMemoryArchiveBackend::new();
    let mut transaction = ArchiveTransaction::new(&backend);
    transaction.plan(planned_entry());
    transaction.commit().expect("die Transaktion muss tragen");

    assert!(
        backend.exists(entry_target().as_str()),
        "die Zieladresse MUSS nach dem Umbenennen existieren"
    );
    assert!(
        !backend.exists(&entry_staging()),
        "die Staging-Adresse darf nach dem Umbenennen nicht mehr existieren"
    );
    assert!(
        backend.file_synced(&entry_staging()),
        "die Staging-Datei MUSS vor dem Umbenennen geflusht worden sein"
    );
    assert!(
        backend.directory_synced(ENTRIES_DIR_V1),
        "das tragende Verzeichnis MUSS geflusht worden sein"
    );
}

#[test]
fn the_in_memory_port_is_idempotent_for_equal_bytes_and_rejects_a_byte_conflict() {
    let backend = InMemoryArchiveBackend::new();
    let target = entry_target();
    let (entry, _) = support::signed_entry_package();
    let bytes = encode_entry_package(&entry).expect("das Eintragspaket kodiert");

    backend
        .create_if_absent(&target, &bytes)
        .expect("der erste Schreibvorgang traegt");
    backend
        .create_if_absent(&target, &bytes)
        .expect("eine bytegleiche Wiederholung MUSS idempotent sein");

    // Beiwerk unter derselben Adresse traegt ANDERE Bytes: fail-closed, und
    // ausdruecklich unabhaengig davon, ob die Bytes ein Archivobjekt sind.
    assert_eq!(
        backend
            .create_non_object_if_absent(&target, b"andere Bytes")
            .expect_err("abweichende Bytes MUESSEN abgewiesen werden")
            .code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
}

#[test]
fn an_archive_path_refuses_a_traversal_an_absolute_root_and_an_unlisted_directory() {
    for relative in ["../escape.eip", "/absolute.eip", "", "a//b.eip", "./b.eip"] {
        assert_eq!(
            ArchivePath::in_dir(ENTRIES_DIR_V1, relative)
                .expect_err("die Adresse MUSS abgewiesen werden")
                .code(),
            "EA-ARCHIVE-PATH",
            "{relative} muss abgewiesen werden"
        );
    }
    assert_eq!(
        ArchivePath::in_dir("staging/", "000001.eip")
            .expect_err("ein Verzeichnis ausserhalb der Layoutliste MUSS abgewiesen werden")
            .code(),
        "EA-ARCHIVE-PATH"
    );
    assert_eq!(
        ArchivePath::at_layout_file(ENTRIES_DIR_V1)
            .expect_err("ein Verzeichnis ist keine feste Layoutdatei")
            .code(),
        "EA-ARCHIVE-PATH"
    );
    // Die Unterverzeichnisse eines Vernichtungsvorgangs verlangen ein `/` im
    // zweiten Argument, also MUSS es zulaessig sein.
    assert_eq!(
        ArchivePath::in_dir(ea_archive::DESTRUCTIONS_DIR_V1, "d-1/events/e-1.etb")
            .expect("ein Unterverzeichnis ist zulaessig")
            .as_str(),
        "destructions/d-1/events/e-1.etb"
    );
}

#[test]
fn a_writer_lock_is_released_on_drop() {
    let backend = InMemoryArchiveBackend::new();
    let held = backend
        .acquire_writer_lock()
        .expect("die erste Sperre traegt");
    assert_eq!(
        backend
            .acquire_writer_lock()
            .expect_err("die zweite Sperre MUSS abgewiesen werden")
            .code(),
        "EA-ARCHIVE-ALREADY-LOCKED"
    );
    drop(held);
    assert!(
        backend.acquire_writer_lock().is_ok(),
        "nach dem Verwerfen des Waechters MUSS die Sperre wieder frei sein"
    );
}

#[test]
fn a_second_transaction_never_republishes_a_target_with_other_bytes() {
    let backend = InMemoryArchiveBackend::new();
    let mut first = ArchiveTransaction::new(&backend);
    first.plan(planned_entry());
    first.commit().expect("die erste Publikation traegt");

    let (entry, _) = support::signed_entry_package();
    let published = encode_entry_package(&entry).expect("das Eintragspaket kodiert");

    // Die BYTEGLEICHE Wiederholung traegt: Create-if-absent ist idempotent,
    // und das gilt fuer die Veroeffentlichung genauso.
    let mut again = ArchiveTransaction::new(&backend);
    again.plan(planned_entry());
    again
        .commit()
        .expect("eine bytegleiche Wiederholung MUSS idempotent sein");
    assert_eq!(
        backend.read(entry_target().as_str()).as_deref(),
        Some(published.as_bytes())
    );
    assert!(
        !backend.exists(&entry_staging()),
        "die Staging-Adresse der Wiederholung darf nicht liegenbleiben"
    );

    // Dieselbe Zieladresse, ANDERE Bytes. Create-if-absent schuetzt nur die
    // Staging-Adresse — die war frei —, also muss die Veroeffentlichung selbst
    // fail-closed sein. Ohne das waere „`.eip`-Bytes werden nie
    // ueberschrieben" ueber genau den Weg umgehbar, der Veroeffentlichung
    // sicher machen soll.
    let mut second = ArchiveTransaction::new(&backend);
    second.plan(StagedObjectV1::new(
        entry_target(),
        StagedBytesV1::NonObject(b"andere Bytes unter derselben Adresse".to_vec()),
    ));
    assert_eq!(
        second
            .commit()
            .expect_err("eine zweite Publikation mit ANDEREN Bytes MUSS abgewiesen werden")
            .code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
    assert_eq!(
        backend.read(entry_target().as_str()).as_deref(),
        Some(published.as_bytes()),
        "die veroeffentlichten Bytes MUESSEN unveraendert sein"
    );
    // Die abgewiesenen Bytes bleiben unter ihrer Staging-Adresse liegen: die
    // Ablehnung loescht nichts, und ein liegengebliebenes Staging-Artefakt ist
    // ein Gesundheitsbefund (temporaere Datei).
    assert_eq!(
        backend.read(&entry_staging()).as_deref(),
        Some(b"andere Bytes unter derselben Adresse".as_slice())
    );
}
