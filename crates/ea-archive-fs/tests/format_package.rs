//! Das Formatbeiwerk jedes Bestands (`design.md` §11.4, Zeilen 1252-1288).
//!
//! Zwei Aussagen tragen diese Datei:
//!
//! 1. **Vollstaendigkeit.** Ein frischer Bestand traegt jede Adresse des
//!    Beiwerks — die zwei Wurzeldateien, die vier Verzeichnisse und jedes
//!    Schema des Arbeitsbaums.
//! 2. **Bytegleichheit gegen den ARBEITSBAUM.** Der Vergleichswert kommt aus
//!    `support::repository_bytes` und nicht aus demselben `include_bytes!`, das
//!    die Produktion benutzt: sonst waere die Gleichheit eine Tautologie und
//!    ein falscher Einbettungspfad unsichtbar.
//!
//! Jeder Test nimmt die prozessweite Sperre und arbeitet auf einer eigenen
//! Temporaerwurzel, wie in `backend_capabilities.rs`.

mod support;

use ea_archive::{ArchiveBackend as _, ArchiveInventory, ArchivePath};
use ea_archive_fs::{
    ControlledNetworkBackend, FORMAT_PACKAGE_FILES_V1, FormatPackageOutcomeV1, HealthFinding,
    LocalPathBackend, format_package_target, materialize_format_package,
};

/// Ein Bestand auf einer frischen Temporaerwurzel.
///
/// Er ruft `materialize_format_package` AUSDRUECKLICH NICHT — sonst messe
/// `a_backend_that_creates_an_archive_materializes_the_format_package_without_a_separate_call`
/// den Aufruf des Tests statt den der Erzeugungsstrecke.
fn backend(label: &str) -> (std::sync::MutexGuard<'static, ()>, LocalPathBackend) {
    let (guard, root) = support::temp_root(label);
    let backend = LocalPathBackend::open(
        root.join("archive"),
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .expect("der Bestand muss sich oeffnen lassen");
    (guard, backend)
}

#[test]
fn a_fresh_archive_carries_every_path_of_the_format_package() {
    let (_guard, backend) = backend("format-package-complete");
    materialize_format_package(&backend).unwrap();
    for relative in [
        ea_archive::README_FORMAT_FILE_V1,
        ea_archive::COMPATIBILITY_MATRIX_FILE_V1,
    ] {
        assert!(
            backend.exists_for_test(
                ArchivePath::at_layout_file(relative)
                    .expect("die Wurzeldatei liegt in der Layoutliste")
                    .as_str()
            ),
            "die Wurzeldatei {relative} fehlt"
        );
    }
    for directory in [
        ea_archive::FORMAT_DIR_V1,
        ea_archive::FORMAT_SCHEMAS_DIR_V1,
        ea_archive::FORMAT_TRANSFORMATIONS_DIR_V1,
        ea_archive::RECOVERY_REPORTS_DIR_V1,
    ] {
        assert!(
            backend.directory_exists_for_test(directory),
            "das Verzeichnis {directory} fehlt — ein Leser muss eine leere \
             Verpflichtung von einer fehlenden unterscheiden koennen"
        );
    }
}

#[test]
fn the_written_readme_is_byte_identical_to_the_published_format_package() {
    let (_guard, backend) = backend("format-package-readme");
    materialize_format_package(&backend).unwrap();
    let written = backend.read_for_test(
        ArchivePath::at_layout_file(ea_archive::README_FORMAT_FILE_V1)
            .expect("die Wurzeldatei liegt in der Layoutliste")
            .as_str(),
    );
    assert_eq!(
        written.as_deref(),
        Some(support::repository_bytes("docs/format/README-FORMAT.txt").as_slice())
    );
}

#[test]
fn every_schema_file_of_the_repository_is_mirrored_byte_identically() {
    let (_guard, backend) = backend("format-package-schemas");
    materialize_format_package(&backend).unwrap();
    // `relative_paths_below_for_test` liefert WURZELRELATIVE Pfade; verglichen
    // wird gegen die zu `schemas/` relativen Pfade des Arbeitsbaums.
    let mirrored: Vec<String> = backend
        .relative_paths_below_for_test(ea_archive::FORMAT_SCHEMAS_DIR_V1)
        .iter()
        .map(|found| {
            found
                .strip_prefix(ea_archive::FORMAT_SCHEMAS_DIR_V1)
                .expect("jeder Fund liegt unter dem Schemaverzeichnis")
                .to_owned()
        })
        .collect();
    assert_eq!(
        mirrored,
        support::repository_schema_paths(),
        "jedes Schema des Arbeitsbaums MUSS im Bestand liegen — ein spaeter \
         hinzugefuegtes Schema faellt hier auf statt still zu fehlen"
    );
    for relative in mirrored {
        let path = ArchivePath::in_dir(ea_archive::FORMAT_SCHEMAS_DIR_V1, &relative)
            .expect("die Schemaadresse ist gueltig");
        assert_eq!(
            backend.read_for_test(path.as_str()).as_deref(),
            Some(support::repository_bytes(&format!("schemas/{relative}")).as_slice()),
            "{relative} weicht von den eingecheckten Bytes ab"
        );
    }
    assert_eq!(
        backend
            .read_for_test(
                ArchivePath::at_layout_file(ea_archive::COMPATIBILITY_MATRIX_FILE_V1)
                    .expect("die Wurzeldatei liegt in der Layoutliste")
                    .as_str()
            )
            .as_deref(),
        Some(support::repository_bytes("schemas/compatibility-matrix.json").as_slice())
    );
}

#[test]
fn the_format_package_is_never_an_archive_object_and_never_quarantined() {
    let (_guard, backend) = backend("format-package-inventory");
    let report = materialize_format_package(&backend).unwrap();
    let inventory = ArchiveInventory::build(&backend.as_archive_source()).unwrap();
    assert_eq!(
        inventory.archive_object_count(),
        0,
        "kein Byte des Beiwerks traegt ein Exact-Object-Praefix"
    );
    assert_eq!(
        inventory.non_object_file_count(),
        report.written_file_count(),
        "der Bestand traegt GENAU die Dateien des Beiwerks und keine weitere"
    );
    assert!(inventory.quarantined().is_empty());
    assert!(inventory.format_errors().is_empty());
}

#[test]
fn a_backend_that_creates_an_archive_materializes_the_format_package_without_a_separate_call() {
    let (_guard, backend) = backend("format-package-on-creation");
    for (relative, _) in FORMAT_PACKAGE_FILES_V1 {
        let path = format_package_target(relative).expect("die Zieladresse ist gueltig");
        assert!(
            backend.exists_for_test(path.as_str()),
            "creation path left {relative} unwritten"
        );
    }
}

#[test]
fn a_controlled_network_archive_also_carries_the_format_package_on_creation() {
    let (_guard, root) = support::temp_root("format-package-network");
    let network_root = root.join("network");
    let commit_root = root.join("commit");
    let backend = ControlledNetworkBackend::open(
        network_root,
        Some(support::encrypted_local_commit(commit_root.clone())),
        support::controlled_network_profile(),
        &support::policy_allowing_controlled_network(),
    )
    .expect("das gepinnte Netzprofil muss tragen");

    for (relative, _) in FORMAT_PACKAGE_FILES_V1 {
        let path = format_package_target(relative).expect("die Zieladresse ist gueltig");
        assert!(
            backend.network().exists_for_test(path.as_str()),
            "die Erzeugungsstrecke des Netzbackends liess {relative} unbeschrieben"
        );
        // Die lokale Commit-Komponente ist KEIN Bestand: sie traegt das
        // Beiwerk ausdruecklich nicht.
        assert!(
            !commit_root.join(path.as_str()).exists(),
            "die Commit-Komponente ist kein Bestand und darf {relative} nicht tragen"
        );
    }
}

#[test]
fn materializing_twice_is_idempotent_and_a_changed_beiwerk_byte_conflicts() {
    let (_guard, backend) = backend("format-package-idempotent");
    materialize_format_package(&backend).unwrap();
    materialize_format_package(&backend).unwrap();
    let path = ArchivePath::at_layout_file(ea_archive::README_FORMAT_FILE_V1)
        .expect("die Wurzeldatei liegt in der Layoutliste");
    backend.overwrite_for_test(path.as_str(), b"tampered");
    assert_eq!(
        materialize_format_package(&backend).unwrap_err().code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
}

/// Oeffnet denselben Bestand ERNEUT, mit demselben Profil und derselben Policy.
fn reopen(backend: &LocalPathBackend) -> LocalPathBackend {
    LocalPathBackend::open(
        backend.root().to_path_buf(),
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .expect("das erneute Oeffnen desselben Bestands muss tragen")
}

#[test]
fn a_second_opener_writes_no_beiwerk_byte_while_another_writer_holds_the_lock() {
    let (_guard, first) = backend("format-package-deferred");
    assert_eq!(
        first.format_package_outcome(),
        FormatPackageOutcomeV1::Materialized,
        "die Erzeugungsstrecke des ersten Oeffners MUSS das Beiwerk anlegen"
    );

    // Die Sperre bleibt genommen, und der Bestand wird leergeraeumt: nur so ist
    // MESSBAR, dass der zweite Oeffner nichts schreibt — laege das Beiwerk
    // noch, waere jeder Ausgang ununterscheidbar.
    let held = first
        .acquire_writer_lock()
        .expect("nach `open` ist die Sperre wieder frei");
    for (relative, _) in FORMAT_PACKAGE_FILES_V1 {
        let path = format_package_target(relative).expect("die Zieladresse ist gueltig");
        first.remove_for_test(path.as_str());
    }

    let second = reopen(&first);
    assert_eq!(
        second.format_package_outcome(),
        FormatPackageOutcomeV1::Deferred,
        "an fremder Sperre wird das Beiwerk AUFGESCHOBEN und nicht sperrenfrei geschrieben"
    );
    for (relative, _) in FORMAT_PACKAGE_FILES_V1 {
        let path = format_package_target(relative).expect("die Zieladresse ist gueltig");
        assert!(
            !second.exists_for_test(path.as_str()),
            "der zweite Oeffner hat {relative} OHNE Sperre geschrieben"
        );
    }

    // Und sobald die Sperre frei ist, traegt das Beiwerk nach.
    drop(held);
    let third = reopen(&first);
    assert_eq!(
        third.format_package_outcome(),
        FormatPackageOutcomeV1::Materialized
    );
    for (relative, _) in FORMAT_PACKAGE_FILES_V1 {
        let path = format_package_target(relative).expect("die Zieladresse ist gueltig");
        assert!(
            third.exists_for_test(path.as_str()),
            "das aufgeschobene Beiwerk MUSS beim naechsten Oeffnen nachgetragen werden: \
             {relative} fehlt"
        );
    }
}

#[test]
fn a_changed_beiwerk_byte_keeps_the_archive_openable_and_is_reported_as_a_deviation() {
    let (_guard, first) = backend("format-package-deviating");
    let readme = ArchivePath::at_layout_file(ea_archive::README_FORMAT_FILE_V1)
        .expect("die Wurzeldatei liegt in der Layoutliste");
    first.overwrite_for_test(readme.as_str(), b"eine andere Formatbeschreibung");

    // Das ist der Kern: der Gesundheitscheck haelt ein OFFENES Backend, also
    // darf ein beschaedigtes Beiwerk das Oeffnen nicht verweigern — sonst waere
    // genau der Bestand unbefundbar, fuer den das Werkzeug gebaut ist.
    let second = reopen(&first);
    assert_eq!(
        second.format_package_outcome(),
        FormatPackageOutcomeV1::Deviating
    );
    assert_eq!(
        second.read_for_test(readme.as_str()).as_deref(),
        Some(b"eine andere Formatbeschreibung".as_slice()),
        "die abweichenden Bytes werden NICHT stillschweigend ueberschrieben"
    );
}

#[test]
fn the_health_check_reports_a_changed_beiwerk_byte_as_a_modified_file() {
    let scenario = support::health_scenario_with_a_tampered_beiwerk_byte();
    let report = scenario.run();
    assert!(
        report.contains(HealthFinding::ModifiedFile),
        "ein veraendertes Beiwerkbyte MUSS als geaenderte Datei gemeldet werden; gemeldet \
         wurde {:?}",
        report.findings()
    );
}

#[test]
fn the_directory_primitive_refuses_a_path_outside_the_layout_list() {
    let (_guard, backend) = backend("format-package-directory-guard");
    // Die neue Primitive ist der einzige Weg zu einem LEEREN Verzeichnis. Sie
    // darf deshalb kein frei gewaehltes anlegen — sonst waere sie ein Weg,
    // `LAYOUT_PATHS_V1` faktisch zu erweitern, ohne die Liste anzufassen.
    assert_eq!(
        backend
            .create_directory_if_absent("beliebig/")
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-PATH"
    );
    // Und eine DATEI der Layoutliste ist kein Verzeichnis.
    assert_eq!(
        backend
            .create_directory_if_absent(ea_archive::README_FORMAT_FILE_V1)
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-PATH"
    );
    assert!(
        !backend.root().join("beliebig").exists(),
        "die Ablehnung darf nichts angelegt haben"
    );
}
