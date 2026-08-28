//! Die Dauerhaftigkeitsprimitive des lokalen Wirtbackends.
//!
//! Jeder Test nimmt die prozessweite Sperre und arbeitet auf einer eigenen
//! Temporaerwurzel; die Serialisierung liegt in `support::temp_root`, nicht in
//! einem `--test-threads=1` an der Kommandozeile.

mod support;

use ea_archive::{ArchiveBackend, ArchivePath, GRANTS_DIR_V1};
use ea_archive_fs::LocalPathBackend;

/// Ein Bestand auf einer frischen Temporaerwurzel.
fn backend(label: &str) -> (std::sync::MutexGuard<'static, ()>, LocalPathBackend) {
    let (guard, root) = support::temp_root(label);
    let backend = LocalPathBackend::open(
        root,
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .expect("der Bestand muss sich oeffnen lassen");
    (guard, backend)
}

#[test]
fn create_if_absent_is_idempotent_for_equal_bytes_and_rejects_a_byte_conflict() {
    let (_guard, backend) = backend("create-if-absent");
    let path = ArchivePath::in_dir(GRANTS_DIR_V1, "x.eag").expect("die Adresse ist gueltig");
    let first = support::signed_grant_a();
    let second = support::signed_grant_b();
    assert_ne!(
        first.as_bytes(),
        second.as_bytes(),
        "die beiden Grants MUESSEN sich unterscheiden, sonst belegt der Konflikt nichts"
    );
    backend.create_if_absent(&path, &first).unwrap();
    backend.create_if_absent(&path, &first).unwrap();
    assert_eq!(
        backend.create_if_absent(&path, &second).unwrap_err().code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
    assert_eq!(
        backend.read_for_test(path.as_str()).as_deref(),
        Some(first.as_bytes()),
        "der abgewiesene Schreibvorgang darf die Bytes nicht angetastet haben"
    );
}

#[test]
fn every_declared_capability_is_proven_on_the_host_filesystem() {
    let (_guard, backend) = backend("capabilities");
    let report = backend
        .run_capability_test(&support::capability_test_vector())
        .unwrap();
    assert!(report.exclusive_create_without_overwrite());
    assert!(report.byte_conflict_detection());
    assert!(report.same_filesystem_atomic_rename());
    assert!(report.file_flush() && report.directory_flush());
    assert!(report.exclusive_writer_lock());
    assert!(report.disconnect_and_resume_keeps_exact_bytes());
    assert!(report.all_proven());
}

/// Eine LIEGENGEBLIEBENE Sperrdatei ohne lebende Sperre blockiert nicht.
///
/// Der Fall ist ein harter Abbruch — SIGKILL, Stromausfall — mitten unter der
/// Schreibersperre: die Datei bleibt liegen, der Prozess ist fort. Solange die
/// Sperre am DASEIN der Datei haengt, waere der Bestand danach dauerhaft
/// unbeschreibbar, und `ea-writer`s Wiederaufnahme kaeme nie an ihrer eigenen
/// Sperre vorbei. Die Betriebssystemsperre gibt der Kern beim Prozessende
/// frei; die zurueckgebliebene Datei ist damit ein leeres Gehaeuse.
#[test]
fn a_leftover_lock_file_without_a_live_lock_is_reclaimed() {
    let (_guard, root) = support::temp_root("stale-writer-lock");
    std::fs::write(root.join(ea_archive_fs::CONTROL_FILES_V1[0]), b"")
        .expect("die Sperrdatei muss anlegbar sein");

    let backend = LocalPathBackend::open(
        root,
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .expect("der Bestand muss sich oeffnen lassen");

    // Zwei Aussagen, und beide haengen an derselben Sperre: das Beiwerk
    // entsteht UNTER ihr, also belegt sein Ergebnis, dass `open` sie nehmen
    // konnte — und der ausdrueckliche Griff danach belegt es noch einmal
    // unmittelbar.
    assert_eq!(
        backend.format_package_outcome(),
        ea_archive_fs::FormatPackageOutcomeV1::Materialized,
        "eine tote Sperrdatei darf das Beiwerk NICHT aufschieben"
    );
    assert!(
        backend.acquire_writer_lock().is_ok(),
        "eine tote Sperrdatei darf die Schreibersperre NICHT blockieren"
    );
}

/// Zwei Bestandsgriffe auf DERSELBEN Wurzel lassen genau einen Schreiber zu.
///
/// Der Unterschied zu [`a_second_writer_lock_is_refused_and_released_on_drop`]
/// ist der Beobachtungspunkt und nicht die Zusage: dort steht EIN
/// `LocalPathBackend`, und schon seine prozessinterne Flagge weist den zweiten
/// Griff ab, bevor das Betriebssystem ueberhaupt gefragt wird. Hier tragen
/// zwei Griffe zwei getrennte Flaggen; die Ablehnung kann also nur aus der
/// Sperre des Betriebssystems kommen. Ohne diesen Zeugen liesse sich die
/// aeussere Stufe der Sperre entfernen, ohne dass ein Test rot wird.
#[test]
fn two_backends_on_the_same_root_admit_exactly_one_writer() {
    let (_guard, root) = support::temp_root("cross-backend-writer-lock");
    let first = LocalPathBackend::open(
        root.clone(),
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .expect("der erste Griff muss sich oeffnen lassen");
    let second = LocalPathBackend::open(
        root,
        support::local_profile(),
        &support::policy_allowing_source_and_target(),
    )
    .expect("der zweite Griff muss sich oeffnen lassen");

    let held = first.acquire_writer_lock().unwrap();
    assert_eq!(
        second.acquire_writer_lock().unwrap_err().code(),
        "EA-ARCHIVE-ALREADY-LOCKED"
    );

    drop(held);
    assert!(
        second.acquire_writer_lock().is_ok(),
        "nach dem `Drop` des ersten Halters MUSS der zweite Griff durchkommen"
    );
}

#[test]
fn a_second_writer_lock_is_refused_and_released_on_drop() {
    let (_guard, backend) = backend("writer-lock");
    let held = backend.acquire_writer_lock().unwrap();
    assert_eq!(
        backend.acquire_writer_lock().unwrap_err().code(),
        "EA-ARCHIVE-ALREADY-LOCKED"
    );
    drop(held);
    assert!(backend.acquire_writer_lock().is_ok());
}

#[test]
fn a_rename_across_filesystems_is_refused_instead_of_copied() {
    let (_guard, backend) = backend("cross-filesystem");
    let staged = support::staged_path();
    let foreign = support::foreign_filesystem_path();
    backend
        .create_if_absent(&staged, &support::signed_grant_a())
        .unwrap();

    // Erst der Gegenbeweis: derselbe Aufruf innerhalb desselben Dateisystems
    // TRAEGT. Ohne ihn koennte die Ablehnung unten auch ein Backend sein, das
    // jeden Rename abweist.
    let inside = ArchivePath::in_dir(GRANTS_DIR_V1, "published.eag").expect("gueltige Adresse");
    backend.atomic_rename_same_fs(&staged, &inside).unwrap();
    assert!(backend.exists_for_test(inside.as_str()));

    backend.mark_foreign_filesystem_for_test(foreign.as_str());
    assert_eq!(
        backend
            .atomic_rename_same_fs(&inside, &foreign)
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-NOT-SAME-FILESYSTEM"
    );
    assert!(
        !backend.exists_for_test(foreign.as_str()),
        "ein abgewiesener Rename darf NICHTS kopiert haben"
    );
    assert!(
        backend.exists_for_test(inside.as_str()),
        "die Quelle MUSS unangetastet bleiben"
    );
}

#[test]
fn a_directory_flush_addresses_the_carrying_directory_and_not_the_file() {
    let (_guard, backend) = backend("directory-flush");
    let path = ArchivePath::in_dir(GRANTS_DIR_V1, "flushed.eag").expect("gueltige Adresse");
    backend
        .create_if_absent(&path, &support::signed_grant_a())
        .unwrap();
    backend.sync_file(&path).unwrap();
    backend.sync_directory(&path).unwrap();
    assert!(backend.directory_exists_for_test(GRANTS_DIR_V1));
    assert_eq!(
        backend.relative_paths_below_for_test(GRANTS_DIR_V1),
        vec!["grants/flushed.eag".to_owned()]
    );
}

#[test]
fn a_rename_never_overwrites_an_existing_target_on_the_host_filesystem() {
    let (_guard, backend) = backend("rename-write-once");
    let target = ArchivePath::in_dir(GRANTS_DIR_V1, "published.eag").expect("gueltige Adresse");
    let staged = support::staged_path();
    let published = support::signed_grant_a();
    let other = support::signed_grant_b();

    backend.create_if_absent(&target, &published).unwrap();
    backend.create_if_absent(&staged, &other).unwrap();

    // `fs::rename` ersetzt auf POSIX ein bestehendes Ziel stillschweigend.
    // Genau darueber liesse sich Create-if-absent umgehen: die Staging-Adresse
    // war frei, also traegt der Rename — und die veroeffentlichten Bytes waeren
    // ueberschrieben.
    assert_eq!(
        backend
            .atomic_rename_same_fs(&staged, &target)
            .unwrap_err()
            .code(),
        "EA-ARCHIVE-BYTE-CONFLICT"
    );
    assert_eq!(
        backend.read_for_test(target.as_str()).as_deref(),
        Some(published.as_bytes()),
        "die veroeffentlichten Bytes MUESSEN unveraendert sein"
    );
    assert_eq!(
        backend.read_for_test(staged.as_str()).as_deref(),
        Some(other.as_bytes()),
        "die abgewiesene Quelle bleibt liegen; die Ablehnung loescht nichts"
    );

    // Die BYTEGLEICHE Veroeffentlichung derselben Adresse traegt und laesst
    // keine Staging-Datei zurueck: Create-if-absent ist idempotent, und die
    // Veroeffentlichung ist seine zweite Haelfte.
    let equal = ArchivePath::in_dir(GRANTS_DIR_V1, "equal.eag").expect("gueltige Adresse");
    backend.create_if_absent(&equal, &published).unwrap();
    backend.atomic_rename_same_fs(&equal, &target).unwrap();
    assert!(
        !backend.exists_for_test(equal.as_str()),
        "die bytegleiche Quelle MUSS verworfen sein"
    );
    assert_eq!(
        backend.read_for_test(target.as_str()).as_deref(),
        Some(published.as_bytes())
    );
}

#[test]
fn capability_scratch_leftovers_stay_visible_to_the_inventory() {
    let (_guard, backend) = backend("scratch-visible");
    let leftover = format!(
        "{}/aborted-run/leftover.bin",
        ea_archive_fs::CAPABILITY_SCRATCH_DIR_V1
    );
    backend.materialize_for_test(&leftover, b"Rest eines abgebrochenen Capability-Tests");

    // Der Skip am VERZEICHNISNAMEN machte diese Bytes fuer Inventar,
    // Verifikation und Waisenerkennung unsichtbar — und damit die
    // Vollstaendigkeitszusage des Bestands unwahr.
    let inventory = backend.inventory().expect("das Inventar muss entstehen");
    assert!(
        inventory.content_hash_of(&leftover).is_some(),
        "Bytes unter der Kratzwurzel MUESSEN inventarisiert werden: {:?}",
        inventory
            .entries()
            .iter()
            .map(ea_format::ArchiveInventoryEntryV1::relative_path)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        backend.relative_paths_below_for_test(ea_archive_fs::CAPABILITY_SCRATCH_DIR_V1),
        vec![leftover]
    );

    // Und der Capability-Test raeumt seine eigene Kratzwurzel weiterhin ab:
    // ein Lauf darf nichts hinterlassen, das das Inventar dann fuehrt.
    let before = backend.inventory().expect("das Inventar muss entstehen");
    backend
        .run_capability_test(&support::capability_test_vector())
        .expect("der Capability-Test muss laufen");
    let after = backend.inventory().expect("das Inventar muss entstehen");
    assert_eq!(before.entries().len(), after.entries().len());
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_makes_the_inventory_fail_closed() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_guard, backend) = backend("unreadable-directory");
    backend
        .create_if_absent(&support::staged_path(), &support::signed_grant_a())
        .unwrap();
    let blocked = std::path::Path::new(backend.root()).join(GRANTS_DIR_V1);
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))
        .expect("die Rechte muessen setzbar sein");

    let outcome = backend.inventory();
    // Die Rechte werden VOR der Zusicherung zurueckgesetzt, damit die
    // Temporaerwurzel abraeumbar bleibt.
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755))
        .expect("die Rechte muessen zuruecksetzbar sein");

    assert_eq!(
        outcome
            .expect_err("ein unlesbares Verzeichnis MUSS fail-closed sein")
            .code(),
        "EA-ARCHIVE-IO",
        "ein verschluckter Lesefehler ergaebe ein still kuerzeres Inventar — an der Wurzel ein \
         LEERES, und dann schaltete ein Profilwechsel auf eine Migration um, die nichts \
         uebernommen hat"
    );
}
