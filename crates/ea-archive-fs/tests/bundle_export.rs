//! Der Ein-Datei-Buendelexport: byteerhaltend, berichtsgleich, deterministisch
//! und fail-closed.
//!
//! Die zwei tragenden Zusicherungen spiegeln GENAU die zwei, die den
//! Verzeichnisexport tragen (`apps/cli/tests/export.rs:249-267` und
//! `:284-307`): eine Bytekarte unter identischen relativen Pfaden und der
//! GANZE Bericht statt nur seiner letzten Zeile — die Zaehler
//! `archiveObjectCount` und `nonObjectFileCount` gehoeren zu derselben Aussage.

mod support;

use std::fs;

use ea_archive_fs::{BUNDLE_MAGIC_V1, BundleError, open_archive_bundle, write_archive_bundle};

use support::{BundleHarness, digest_map_of};

#[test]
fn bundle_is_byte_preserving_under_the_same_relative_paths() {
    let harness = BundleHarness::finalized_archive();
    let before = harness.digest_map();

    let report = write_archive_bundle(
        harness.backend(),
        harness.anchor(),
        harness.os_wall_clock(),
        &harness.bundle_path(),
    )
    .expect("der Export muss gelingen");

    let reopened = open_archive_bundle(&harness.bundle_path()).unwrap();
    assert_eq!(digest_map_of(&reopened), before);
    assert_eq!(harness.digest_map(), before, "die Quelle wird nur gelesen");
    assert_eq!(report.blob_count(), before.len());
}

#[test]
fn bundle_verifies_to_the_same_report_as_the_directory() {
    let harness = BundleHarness::finalized_archive();
    write_archive_bundle(
        harness.backend(),
        harness.anchor(),
        harness.os_wall_clock(),
        &harness.bundle_path(),
    )
    .unwrap();

    let from_directory = ea_verify::verify_archive(
        &harness.directory_source(),
        harness.anchor(),
        harness.options(),
    )
    .unwrap();
    let bundle = open_archive_bundle(&harness.bundle_path()).unwrap();
    let from_bundle =
        ea_verify::verify_archive(&bundle, harness.anchor(), harness.options()).unwrap();

    assert!(
        from_directory.is_fully_verified(),
        "eine stumme Quelle belegt nichts"
    );
    assert!(from_bundle.is_fully_verified());
    assert_eq!(
        from_bundle.report_hash().as_bytes(),
        from_directory.report_hash().as_bytes()
    );
    assert_eq!(
        from_bundle.to_canonical_json().unwrap(),
        from_directory.to_canonical_json().unwrap()
    );
}

#[test]
fn two_exports_of_the_same_archive_are_byte_identical() {
    let harness = BundleHarness::finalized_archive();
    let first = harness.bundle_path_named("first");
    let second = harness.bundle_path_named("second");
    write_archive_bundle(
        harness.backend(),
        harness.anchor(),
        harness.os_wall_clock(),
        &first,
    )
    .unwrap();
    write_archive_bundle(
        harness.backend(),
        harness.anchor(),
        harness.os_wall_clock(),
        &second,
    )
    .unwrap();
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
}

#[test]
fn a_bundle_carries_no_exact_object_prefix_and_adds_no_seventh_family() {
    let harness = BundleHarness::finalized_archive();
    write_archive_bundle(
        harness.backend(),
        harness.anchor(),
        harness.os_wall_clock(),
        &harness.bundle_path(),
    )
    .unwrap();
    let bytes = fs::read(harness.bundle_path()).unwrap();

    assert_eq!(&bytes[..BUNDLE_MAGIC_V1.len()], &BUNDLE_MAGIC_V1);
    assert_ne!(
        bytes[0], 0x85,
        "der Container traegt kein Exact-Object-Praefix"
    );
    assert!(matches!(
        ea_format::decode_exact_object(&bytes),
        Err(ea_format::FormatError::Prefix)
    ));
}

#[test]
fn export_refuses_an_archive_that_does_not_fully_verify() {
    let harness = BundleHarness::finalized_archive().with_truncated_entry();
    assert!(matches!(
        write_archive_bundle(
            harness.backend(),
            harness.anchor(),
            harness.os_wall_clock(),
            &harness.bundle_path()
        ),
        Err(BundleError::SourceNotFullyVerified)
    ));
    assert!(
        !harness.bundle_path().exists(),
        "ein Befund erzeugt kein Ziel"
    );
}

#[test]
fn export_refuses_an_occupied_target_without_touching_it() {
    let harness = BundleHarness::finalized_archive();
    fs::write(harness.bundle_path(), b"CANARY-EXISTING").unwrap();
    assert!(matches!(
        write_archive_bundle(
            harness.backend(),
            harness.anchor(),
            harness.os_wall_clock(),
            &harness.bundle_path()
        ),
        Err(BundleError::TargetOccupied)
    ));
    assert_eq!(fs::read(harness.bundle_path()).unwrap(), b"CANARY-EXISTING");
}

/// Eine Zieladresse INNERHALB der Bestandswurzel ist belegt, auch wenn dort
/// keine Datei liegt.
///
/// Laege das Buendel unter der Wurzel, waere es selbst eine Bytesequenz des
/// Bestands: `nonObjectFileCount` stiege, der Bestand verifizierte danach zu
/// einem ANDEREN Bericht als vorher — genau die Groesse, deren Gleichheit
/// `bundle_verifies_to_the_same_report_as_the_directory` belegt —, und ein
/// zweiter Export truege den ersten in sich. Geprueft werden BEIDE Formen: die
/// Wurzel selbst und ein Unterverzeichnis darin, denn ein Deckel, der nur die
/// Wurzel kennt, liesse `format/` offen.
///
/// Die Gegenprobe stehen die uebrigen Tests dieses Ziels: ihre Zieladresse
/// liegt NEBEN der Wurzel und gelingt.
#[test]
fn export_refuses_a_target_inside_the_archive_root() {
    let harness = BundleHarness::finalized_archive();
    let before = harness.digest_map();
    let root = harness.backend().root().to_owned();

    for target in [
        root.join(format!(
            "in-root.{}",
            ea_archive_fs::BUNDLE_FILE_EXTENSION_V1
        )),
        root.join(ea_archive::FORMAT_DIR_V1).join(format!(
            "in-subdirectory.{}",
            ea_archive_fs::BUNDLE_FILE_EXTENSION_V1
        )),
    ] {
        assert!(
            matches!(
                write_archive_bundle(
                    harness.backend(),
                    harness.anchor(),
                    harness.os_wall_clock(),
                    &target
                ),
                Err(BundleError::TargetOccupied)
            ),
            "{} gehoert dem Bestand",
            target.display()
        );
        assert!(!target.exists(), "der Bestand bekommt kein neues Byte");
    }

    assert_eq!(
        harness.digest_map(),
        before,
        "die Bytekarte des Bestands bleibt unveraendert"
    );
}
