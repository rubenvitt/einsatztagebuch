//! Unveraenderliche Stammdatenmomentaufnahmen und ihre Provenienz.
//!
//! Eine erfasste Momentaufnahme ist ein EIGENER Wert und keine Sicht auf die
//! Stammdatenzeile: eine spaetere Stammdatenaenderung darf sie nicht mehr
//! beruehren. Ad-hoc-Eintraege sind strukturell erkennbar und nicht durch ein
//! Kennzeichen — `revision()` und `imported_provenance()` melden beide `None`.

mod support;

use ea_draft::MasterDataError;
use ea_schema::PersonnelSnapshotV1;

use self::support::ImportHarness;

#[test]
fn later_master_change_does_not_modify_captured_snapshot() {
    let harness = ImportHarness::new();
    let repo = harness.master_data_repo();
    harness.import_persons(b"id,display_name,role,active\np1,Ada,Fuehrung,true\n");
    let captured = repo.snapshot_person("p1").unwrap();
    assert_eq!(captured.display_name(), "Ada");
    assert_eq!(captured.revision().unwrap().revision_number(), Some(1));
    repo.rename_person("p1", "Neue Anzeige").unwrap();
    let reread = repo.snapshot_person("p1").unwrap();
    assert_ne!(captured.display_name(), reread.display_name());
    assert_eq!(reread.revision().unwrap().revision_number(), Some(2));
}

#[test]
fn a_writer_snapshot_never_carries_the_changed_at_arm_of_the_revision() {
    // Der Wire-Arm ist `[0, revisionNumber]` (`payload.cddl`:121-123). Task 11
    // versiegelt genau diesen Arm; `ChangedAt` waere dieselbe Position mit
    // anderem Sinn und in einer Writer-Momentaufnahme ein Fehler.
    let harness = ImportHarness::new();
    let repo = harness.master_data_repo();
    harness.import_persons(b"id,display_name,role,active\np1,Ada,Fuehrung,true\n");
    harness.import_vehicles(
        b"id,display_name,radio_call_sign,license_plate,active\n\
          v1,MTW,Rotkreuz 1,HH-DRK 1,true\n",
    );
    let person = repo.snapshot_person("p1").unwrap();
    assert!(person.revision().unwrap().changed_at().is_none());
    let vehicle = repo.snapshot_vehicle("v1").unwrap();
    assert!(vehicle.revision().unwrap().changed_at().is_none());
    assert_eq!(vehicle.revision().unwrap().revision_number(), Some(1));
    assert_eq!(repo.rename_vehicle("v1", "MTW 2").unwrap(), 2);
}

#[test]
fn imported_snapshot_carries_full_provenance_and_adhoc_carries_none() {
    let harness = ImportHarness::new();
    let repo = harness.master_data_repo();
    let report = harness.import_persons(b"id,display_name,role,active\np1,Ada,Fuehrung,true\n");
    let imported = repo.snapshot_person("p1").unwrap();
    let provenance = imported.imported_provenance().unwrap();
    assert_eq!(provenance.source_id(), "csv-persons");
    assert_eq!(provenance.source_format_version(), 1);
    assert_eq!(
        provenance.import_protocol_hash().as_bytes(),
        report.import_protocol_hash().as_bytes()
    );

    let adhoc = repo.ad_hoc_person("Externer Helfer", None).unwrap();
    assert!(matches!(adhoc, PersonnelSnapshotV1::AdHoc { .. }));
    assert!(adhoc.revision().is_none());
    assert!(adhoc.imported_provenance().is_none());
    assert_eq!(repo.person_count().unwrap(), 1);
}

#[test]
fn an_ad_hoc_vehicle_is_structurally_recognizable_and_creates_no_master_row() {
    let harness = ImportHarness::new();
    let repo = harness.master_data_repo();
    let adhoc = repo.ad_hoc_vehicle("Fremdes Fahrzeug", None, None).unwrap();
    assert!(adhoc.revision().is_none());
    assert!(adhoc.imported_provenance().is_none());
    assert_eq!(adhoc.master_vehicle_id(), None);
    assert_eq!(repo.vehicle_count().unwrap(), 0);
}

#[test]
fn an_unknown_master_id_is_a_named_absence_and_not_an_empty_snapshot() {
    let harness = ImportHarness::new();
    let repo = harness.master_data_repo();
    // `PersonnelSnapshotV1` traegt bewusst kein `Debug`, also kein
    // `unwrap_err`; `err()` verlangt keins und verliert keine Staerke.
    assert_eq!(
        repo.snapshot_person("gibt-es-nicht")
            .err()
            .map(MasterDataError::code),
        Some(MasterDataError::UnknownMasterId.code())
    );
    assert_eq!(
        repo.rename_person("gibt-es-nicht", "Egal")
            .err()
            .map(MasterDataError::code),
        Some(MasterDataError::UnknownMasterId.code())
    );
    assert_eq!(
        repo.snapshot_vehicle("gibt-es-nicht")
            .err()
            .map(MasterDataError::code),
        Some(MasterDataError::UnknownMasterId.code())
    );

    // Die drei Zusicherungen darueber vergleichen `code()` mit `code()`: sie
    // messen den PFAD und blieben auch dann gruen, wenn die Zeichenkette
    // wanderte. Der stabile Code ist eine eigene Zusage und wird deshalb
    // gepinnt.
    assert_eq!(
        MasterDataError::UnknownMasterId.code(),
        "EA-MASTER-UNKNOWN-ID"
    );
    // Die zwei uebrigen Codes dieser Grenze sind im Bestand nicht erreichbar —
    // `Snapshot` liegt hinter fuenf `map_err` ueber Konstruktoren, die
    // ausnahmslos `Ok` liefern (`crates/ea-schema/src/model.rs`:820-1000), und
    // `RevisionOverflow` verlangt eine negative Revisionsspalte, die
    // `CHECK (revision >= 1)` in `0003_master_data.sql` ausschliesst. Sie
    // bleiben Vertragsflaeche und werden deshalb gepinnt, aber nicht
    // erzwungen: dieselbe Begruendung wie `ChainError::NodeLimit` in
    // `crates/ea-chain/tests/chain_core.rs`:149.
    assert_eq!(MasterDataError::Snapshot.code(), "EA-MASTER-SNAPSHOT");
    assert_eq!(
        MasterDataError::RevisionOverflow.code(),
        "EA-MASTER-REVISION-OVERFLOW"
    );
}
