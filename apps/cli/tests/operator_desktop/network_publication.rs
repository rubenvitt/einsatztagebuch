//! Publikation der lokalen Commits eines Netz-Writers (EA-CNA-PUB-1 … PUB-8),
//! die Bereinigung beim Öffnen (EA-CNA-SRC-5) und der Sync-Zustand am
//! Desktop. Das Temp-Verzeichnis ist kein Beleg für ein gemountetes
//! Netzdateisystem; die Reihenfolge grants-first/`.eip`-last belegt der
//! Spion im `ea-admin`-Unit-Test `publication_order_is_grants_first_entry_last`.
use super::network_writer::{NetworkWriterInstallation, listing};
use super::*;
use ea_admin::{
    native_archive::{NativeArchiveConfig, NativeArchiveExistingComponent},
    network_publication::{NetworkPublicationHost, NetworkSyncArchiveV1},
};
use ea_archive::BoundArchiveProfilePolicyV1;
use ea_archive_fs::{DetailCause, PublicationOutcomeV1, SyncStatus};
use std::collections::BTreeMap;

/// Committete Zeilen der lokalen Komponente mit ihren Bytes (ohne Staging).
fn committed_rows(installed: &NetworkWriterInstallation) -> BTreeMap<String, Vec<u8>> {
    let db = open_database(&installed.base.installed.database);
    let mut rows = BTreeMap::new();
    let mut last = String::new();
    while let Some(row) = db
        .query_row(
            "SELECT relative_path,exact_bytes FROM local_commit_object WHERE relative_path>?1 ORDER BY relative_path LIMIT 1",
            &[StoreValue::Text(last.clone())],
        )
        .unwrap()
    {
        last = row.text(0).unwrap().to_owned();
        if !ea_archive::is_staging_path(&last) {
            rows.insert(last.clone(), row.blob(1).unwrap().to_vec());
        }
    }
    rows
}

/// Die Archivobjekte des Netzziels (Einträge und Grants) mit ihren Bytes.
fn remote_objects(installed: &NetworkWriterInstallation) -> BTreeMap<String, Vec<u8>> {
    listing(&installed.base.installed.archive)
        .into_iter()
        .map(|(path, bytes)| (path.to_string_lossy().into_owned(), bytes))
        .filter(|(path, _)| {
            (path.starts_with("entries/") && path.ends_with(".eip"))
                || (path.starts_with("grants/") && path.ends_with(".eag"))
        })
        .collect()
}

fn sync_state(native: &Arc<NativeDesktopRuntime>) -> (SyncStatus, Option<DetailCause>) {
    let view = native
        .desktop_state()
        .sync_state_port()
        .expect("ein Netz-Writer registriert seinen Sync-Zustandsport")
        .sync_state()
        .unwrap();
    (view.status, view.detail_cause)
}

/// Öffnet den Desktop, hält seinen Hostlauf an (die Tests lösen Läufe
/// selbst aus) und meldet den Writer an.
fn started(installed: &NetworkWriterInstallation) -> Arc<NativeDesktopRuntime> {
    let native = installed.try_host(&installed.writer_config).unwrap();
    native.stop_network_publication_loop();
    native.login().unwrap();
    native
}

fn publish(native: &Arc<NativeDesktopRuntime>) -> ea_archive_fs::PublicationStateV1 {
    native.run_network_publication_once().unwrap().unwrap()
}

fn finalize(native: &Arc<NativeDesktopRuntime>, number: &str) -> u64 {
    let state = native.desktop_state();
    state
        .drafts()
        .unwrap()
        .save_payload(format!("network incident {number}"))
        .unwrap();
    let writer = state.writer().unwrap();
    let mut input = native_incident();
    input.human_incident_number = number.into();
    let preview = writer.preview(&input).unwrap();
    native.reauthenticate(ReauthPurpose::Finalize).unwrap();
    writer.finalize(&input, &preview).unwrap().sequence.get()
}

#[test]
fn finalize_publishes_grants_then_entry_byte_identically() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    assert_eq!(finalize(&native, "NET-PUB-1"), 1);

    let local = committed_rows(&installed);
    assert_eq!(installed.committed_local_entries(), 1);
    assert!(installed.committed_local_grants() >= 1);
    let remote = remote_objects(&installed);
    for (path, bytes) in &local {
        assert_eq!(
            remote.get(path),
            Some(bytes),
            "{path} liegt byteidentisch am Netzziel"
        );
    }
    assert_eq!(sync_state(&native), (SyncStatus::LocallySaved, None));
    assert_eq!(SyncStatus::LocallySaved.label(), "lokal gesichert");
    let host = native.network_publication_host().unwrap();
    assert!(host.pending().unwrap().is_empty(), "nichts steht mehr aus");
}

#[test]
fn finalize_while_remote_is_gone_reports_upload_pending_network_waiting_then_resumes_after_reconnect()
 {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    let away = installed.base.installed.archive.with_extension("away");
    fs::rename(&installed.base.installed.archive, &away).unwrap();

    assert_eq!(
        finalize(&native, "NET-PUB-2"),
        1,
        "Schritt 12 lässt die Finalisierung nicht scheitern"
    );
    assert!(!installed.base.installed.archive.exists(), "nie angelegt");
    let (status, cause) = sync_state(&native);
    assert_eq!(
        (status, cause),
        (
            SyncStatus::UploadPending,
            Some(DetailCause::NetworkArchiveWaiting)
        )
    );
    assert_eq!(status.label(), "Upload ausstehend");
    assert_eq!(cause.unwrap().label(), "Netzarchiv wartet");

    fs::rename(&away, &installed.base.installed.archive).unwrap();
    let resumed = native.run_network_publication_once().unwrap().unwrap();
    assert_eq!(resumed.outcome(), PublicationOutcomeV1::PublishedCompletely);
    assert!(!resumed.fell_back_to_another_target());
    let local = committed_rows(&installed);
    let remote = remote_objects(&installed);
    assert!(!local.is_empty());
    for (path, bytes) in &local {
        assert_eq!(remote.get(path), Some(bytes), "{path} byteidentisch");
    }
    assert_eq!(sync_state(&native), (SyncStatus::LocallySaved, None));
}

#[test]
fn restart_rederives_the_queue_from_committed_bytes() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    let away = installed.base.installed.archive.with_extension("away");
    fs::rename(&installed.base.installed.archive, &away).unwrap();
    finalize(&native, "NET-PUB-3");
    assert_eq!(
        sync_state(&native).1,
        Some(DetailCause::NetworkArchiveWaiting)
    );
    // Der Host verschwindet mit aufgeschobenem Plan; gespeichert wurde nichts.
    drop(native);
    fs::rename(&away, &installed.base.installed.archive).unwrap();
    let local = committed_rows(&installed);
    assert!(
        local.keys().all(|path| !remote_objects(&installed).contains_key(path)),
        "noch nichts veröffentlicht"
    );

    // Ein frischer Host leitet den Plan allein aus den committed Bytes ab.
    let runtime = installed.base.open_writer_runtime();
    let policy = BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
    let component = NativeArchiveExistingComponent::open_current(
        &runtime,
        NativeArchiveConfig::for_runtime_database(
            installed.base.profile.clone(),
            runtime.database().path(),
        ),
    )
    .unwrap();
    let fresh = NetworkPublicationHost::new(&component, &installed.base.installed.archive, &policy)
        .unwrap();
    let planned = fresh.pending().unwrap();
    let mut order = planned.order();
    let entry_last = order.last().cloned().unwrap();
    assert!(
        entry_last.starts_with("entries/") && entry_last.ends_with(".eip"),
        "das `.eip` zuletzt: {order:?}"
    );
    order.sort();
    assert_eq!(
        order,
        local.keys().cloned().collect::<Vec<_>>(),
        "der Plan ist genau die committed lokale Menge"
    );
    drop(fresh);
    drop(component);
    drop(runtime);

    // Der wiedergestartete Desktop veröffentlicht beim Start (EA-CNA-PUB-8 (b)).
    let reopened = installed.try_host(&installed.writer_config).unwrap();
    reopened.stop_network_publication_loop();
    let remote = remote_objects(&installed);
    for (path, bytes) in &local {
        assert_eq!(remote.get(path), Some(bytes), "{path} byteidentisch");
    }
    assert_eq!(sync_state(&reopened), (SyncStatus::LocallySaved, None));
}

/// Die lokalen Zeilen der Sequenz `sequence`: ihr `.eip` und dessen Grants
/// (`grants/<entry-hash>_…`).
fn rows_of_sequence(
    rows: &BTreeMap<String, Vec<u8>>,
    sequence: u64,
) -> BTreeMap<String, Vec<u8>> {
    let prefix = format!("entries/{sequence:012}_");
    let Some(entry) = rows.keys().find(|path| path.starts_with(&prefix)) else {
        return BTreeMap::new();
    };
    let hash = entry
        .trim_start_matches(&prefix)
        .trim_end_matches(".eip")
        .to_owned();
    rows.iter()
        .filter(|(path, _)| {
            path.as_str() == entry.as_str() || path.starts_with(&format!("grants/{hash}_"))
        })
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .collect()
}

fn union(installed: &NetworkWriterInstallation) -> BTreeMap<String, Vec<u8>> {
    let mut union = remote_objects(installed);
    union.extend(committed_rows(installed));
    union
}

fn staged(installed: &NetworkWriterInstallation) -> Vec<(String, bool)> {
    installed
        .local_paths()
        .into_iter()
        .filter(|(_, staged)| *staged)
        .collect()
}

#[test]
fn reopen_prunes_published_rows_and_keeps_the_union_identical() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    finalize(&native, "NET-PUB-4");
    let first = committed_rows(&installed);
    assert!(!first.is_empty(), "die Commits liegen noch lokal");
    drop(native);

    // Ein Kaltstart erbt keine Grundlinie und bereinigt deshalb nie (Regel (i)).
    let reopened = installed.try_host(&installed.writer_config).unwrap();
    reopened.stop_network_publication_loop();
    assert_eq!(committed_rows(&installed), first, "Kaltstart bereinigt nicht");
    reopened.login().unwrap();
    // Eine Wiederöffnung mit geerbter Grundlinie: das einzige lokale `.eip`
    // ist das höchste und bleibt (Regel (ii)).
    let state = reopened.desktop_state();
    state.drafts().unwrap().load_payload().unwrap();
    assert_eq!(committed_rows(&installed), first, "höchster Eintrag bleibt");

    assert_eq!(finalize(&reopened, "NET-PUB-5"), 2);
    let both = committed_rows(&installed);
    let staged_before = staged(&installed);
    let union_before = union(&installed);
    // Die nächste Wiederöffnung erbt eine Grundlinie mit Eintrag 1, liest das
    // Netzziel live und bereinigt genau Eintrag 1 samt Grants.
    state.drafts().unwrap().load_payload().unwrap();
    assert_eq!(
        committed_rows(&installed),
        rows_of_sequence(&both, 2),
        "nur die höchste Sequenz bleibt lokal"
    );
    assert_eq!(staged(&installed), staged_before, "Staging bleibt unberührt");
    assert_eq!(union(&installed), union_before, "die Vereinigung bleibt gleich");

    // Die Kette läuft über die Vereinigung weiter.
    let writer = state.writer().unwrap();
    let mut next = native_incident();
    next.human_incident_number = "NET-PUB-5B".into();
    native_reauth(&reopened);
    assert_eq!(writer.preview(&next).unwrap().proposed_sequence.get(), 3);
}

fn native_reauth(native: &Arc<NativeDesktopRuntime>) {
    native.reauthenticate(ReauthPurpose::Finalize).unwrap();
}

/// Das Szenario der Review (Fix-Runde 1, Critical): Eintrag N offline
/// committed, danach veröffentlicht; eine Aktion über den Vorschau-Zweig
/// verwirft ihre frische Öffnung; das Netzziel verschwindet wieder. Die
/// behaltene Grundlinie kennt N nicht — also muss N lokal geblieben sein,
/// sonst schlüge die nächste Vorschau erneut N vor (Gabel am Netzziel).
#[test]
fn a_preview_branch_reopen_never_forks_the_chain() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    let away = installed.base.installed.archive.with_extension("away");
    fs::rename(&installed.base.installed.archive, &away).unwrap();
    assert_eq!(finalize(&native, "FORK-1"), 1, "offline committed");
    fs::rename(&away, &installed.base.installed.archive).unwrap();

    // Vorschau ausstellen: die live gelesene Grundlinie kennt Eintrag 1 nicht.
    let state = native.desktop_state();
    let writer = state.writer().unwrap();
    let mut next = native_incident();
    next.human_incident_number = "FORK-2".into();
    assert_eq!(writer.preview(&next).unwrap().proposed_sequence.get(), 2);
    // Eintrag 1 veröffentlichen.
    assert_eq!(
        publish(&native).outcome(),
        PublicationOutcomeV1::PublishedCompletely
    );
    // Eine Aktion über den Vorschau-Zweig: ihre frische Öffnung wird
    // verworfen, weil Kopf und Sequenz gleich sind.
    state.drafts().unwrap().load_payload().unwrap();
    // Netzziel wieder weg; die nächste Vorschau läuft über die Grundlinie.
    fs::rename(&installed.base.installed.archive, &away).unwrap();
    let preview = match writer.preview(&next) {
        Ok(preview) => preview,
        Err(_) => {
            native_reauth(&native);
            writer.preview(&next).unwrap()
        }
    };
    assert_eq!(
        preview.proposed_sequence.get(),
        2,
        "nie ein zweites `.eip` für Sequenz 1"
    );
    native_reauth(&native);
    let preview = writer.preview(&next).unwrap();
    assert_eq!(
        writer.finalize(&next, &preview).unwrap().sequence.get(),
        2
    );
    fs::rename(&away, &installed.base.installed.archive).unwrap();
    publish(&native);
    let sequences: Vec<String> = remote_objects(&installed)
        .keys()
        .filter(|path| path.starts_with("entries/"))
        .map(|path| path["entries/".len().."entries/".len() + 12].to_owned())
        .collect();
    let mut unique = sequences.clone();
    unique.dedup();
    assert_eq!(sequences, unique, "keine Sequenz doppelt: {sequences:?}");
    assert!(sequences.contains(&format!("{:012}", 1)));
    assert!(sequences.contains(&format!("{:012}", 2)));
}

/// Regel (ii) stützt sich darauf, dass eine Vereinigung mit einer Lücke
/// unter dem Kettenkopf die Verifikation nicht besteht.
#[test]
fn a_union_with_a_gap_below_the_head_fails_verification() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    finalize(&native, "GAP-1");
    native_reauth(&native);
    finalize(&native, "GAP-2");
    drop(native);
    let rows = remote_objects(&installed);
    let copy = installed.base.installed.directory.path().join("gap-copy");
    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let path = entry.unwrap().path();
            let target = to.join(path.file_name().unwrap());
            if path.is_dir() {
                copy_dir(&path, &target);
            } else {
                fs::copy(&path, &target).unwrap();
            }
        }
    }
    copy_dir(&installed.base.installed.archive, &copy);
    let complete = ea_admin::operator_runtime::OperatorArchiveSnapshot::open(
        &copy,
        &installed.base.installed.anchor,
        support::live_clock(),
    )
    .unwrap();
    assert_eq!(complete.next_sequence().get(), 3);
    drop(complete);
    let gap = rows_of_sequence(&rows, 1);
    assert!(!gap.is_empty());
    for path in gap.keys() {
        fs::remove_file(copy.join(path)).unwrap();
    }
    assert!(
        ea_admin::operator_runtime::OperatorArchiveSnapshot::open(
            &copy,
            &installed.base.installed.anchor,
            support::live_clock(),
        )
        .is_err(),
        "eine Lücke unter dem Kopf verifiziert nicht"
    );
}

/// EA-CNA-WRT-7: das Netzziel wird unmittelbar vor der Publikation mit
/// seinem kanonischen Wurzelpfad beobachtet.
#[test]
fn publication_observes_the_network_root_before_publishing() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let observed = || {
        let root = fs::canonicalize(&installed.base.installed.archive).unwrap();
        let mut preimage = b"EINSATZARCHIV-MANAGED-ARCHIVE-LOCATION-v1\0".to_vec();
        preimage.extend_from_slice(root.to_str().unwrap().as_bytes());
        let location = ea_crypto::object_hash(&preimage);
        let db = open_database(&installed.base.installed.database);
        let mut last = Vec::new();
        let mut found = false;
        while let Some(row) = db
            .query_row(
                "SELECT record_hash,exact_bytes FROM managed_custody WHERE record_hash>?1 ORDER BY record_hash LIMIT 1",
                &[StoreValue::Blob(last.clone())],
            )
            .unwrap()
        {
            last = row.blob(0).unwrap().to_vec();
            found |= row
                .blob(1)
                .unwrap()
                .windows(32)
                .any(|window| window == location.as_bytes());
        }
        found
    };
    let native = started(&installed);
    assert!(!observed(), "vor der ersten Publikation nicht beobachtet");
    finalize(&native, "OBS-1");
    assert!(observed(), "Schritt 12 beobachtet das Netzziel");
}

#[test]
fn a_baseline_reopen_never_prunes() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    finalize(&native, "NET-PUB-6");
    let published = committed_rows(&installed);
    assert!(!published.is_empty());
    // Ein fremder Halter des SQLCipher-Writer-Locks: die nächste live
    // gelesene Wiederöffnung übernimmt die veröffentlichten Objekte in ihre
    // Grundlinie, darf aber nicht bereinigen.
    let mut lock_path = installed.base.installed.database.clone().into_os_string();
    lock_path.push(".archive-writer.lock");
    let foreign = fs::OpenOptions::new()
        .write(true)
        .open(PathBuf::from(lock_path))
        .unwrap();
    foreign.lock().unwrap();
    let state = native.desktop_state();
    let writer = state.writer().unwrap();
    let mut next = native_incident();
    next.human_incident_number = "NET-PUB-7".into();
    let _ = writer.preview(&next);
    assert_eq!(
        committed_rows(&installed),
        published,
        "mit belegtem Lock entfällt die Bereinigung"
    );
    foreign.unlock().unwrap();
    drop(foreign);

    // Jetzt ist das Netzziel weg: die Wiederöffnung nimmt die Grundlinie,
    // die jedes lokale Objekt enthält — und bereinigt trotzdem nicht.
    let away = installed.base.installed.archive.with_extension("away");
    fs::rename(&installed.base.installed.archive, &away).unwrap();
    native.reauthenticate(ReauthPurpose::Finalize).unwrap();
    let preview = writer.preview(&next).unwrap();
    assert_eq!(preview.proposed_sequence.get(), 2, "über die Grundlinie");
    assert_eq!(
        committed_rows(&installed),
        published,
        "eine Grundlinie ist kein live gelesenes Netzziel"
    );
    fs::rename(&away, &installed.base.installed.archive).unwrap();
}

#[test]
fn an_unqualified_target_never_gets_a_publication_host() {
    use std::os::unix::fs::PermissionsExt;
    let installed = NetworkWriterInstallation::new();
    let component = installed.register();
    let runtime = installed.base.open_writer_runtime();
    let policy = BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
    let root = installed.base.installed.archive.clone();
    // Ein Netzziel, das die Schreibproben der Zulassung nicht trägt: jedes
    // Verzeichnis darin nur lesbar.
    fn directories(directory: &Path, out: &mut Vec<PathBuf>) {
        out.push(directory.to_owned());
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories(&path, out);
            }
        }
    }
    let mut all = Vec::new();
    directories(&root, &mut all);
    let directories = all;
    let set = |mode| {
        for directory in directories.iter().rev() {
            fs::set_permissions(directory, fs::Permissions::from_mode(mode)).unwrap();
        }
    };
    set(0o555);
    let refused = NetworkPublicationHost::new(&component, &root, &policy);
    let desktop = installed.try_host(&installed.writer_config);
    set(0o755);
    let refused = refused.err().expect("ohne bestandene Zulassung kein Host");
    assert_eq!(refused.code(), "EA-ARCHIVE-IO");
    assert_eq!(
        desktop.err().expect("und kein Netz-Writer am Desktop").code,
        "EA-ARCHIVE-IO"
    );
    // Ein Netzziel, das die Zulassung besteht, bekommt einen Host.
    assert!(NetworkPublicationHost::new(&component, &root, &policy).is_ok());
}

/// Fix-Runde 2: ein fremd gehaltener Writer-Lock des Netzziels (etwa eine
/// Recovery-Capture, EA-CNA-REC-2) ist `Netzarchiv wartet`, kein `Fehler`.
#[test]
fn a_held_network_target_lock_waits_instead_of_failing() {
    use ea_archive::ArchiveBackend;
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let runtime = installed.base.open_writer_runtime();
    let policy = BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
    drop(runtime);
    let native = started(&installed);
    let foreign = ea_archive_fs::LocalPathBackend::open_existing(
        installed.base.installed.archive.clone(),
        installed.base.profile.clone(),
        &policy,
    )
    .unwrap();
    let held = foreign.acquire_writer_lock().unwrap();
    assert_eq!(finalize(&native, "HELD-1"), 1);
    assert_eq!(
        sync_state(&native),
        (
            SyncStatus::UploadPending,
            Some(DetailCause::NetworkArchiveWaiting)
        )
    );
    drop(held);
    assert_eq!(
        publish(&native).outcome(),
        PublicationOutcomeV1::PublishedCompletely
    );
    assert_eq!(sync_state(&native), (SyncStatus::LocallySaved, None));
}

/// Fix-Runde 2: der Hostlauf leitet ohne den Wirtszustand ab. Hält ein
/// UI-Einstieg (oder ein Präsenzdialog) den Zustand, laufen saubere Läufe
/// trotzdem weiter; der Zustand wartet nie auf Netz-I/O des Hostlaufs.
#[test]
fn the_host_loop_derives_without_the_native_state_lock() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = installed.try_host(&installed.writer_config).unwrap();
    let host = native.network_publication_host().unwrap();
    let before = host.runs();
    let guard = native.hold_native_state_for_test();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    while host.runs() == before && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(guard);
    assert!(
        host.runs() > before,
        "der Hostlauf lief, während der Zustand gehalten war"
    );
    assert_eq!(sync_state(&native), (SyncStatus::LocallySaved, None));
}

/// Fix-Runde 2, Regel (i) allein: ein Eintrag, der NICHT der höchste ist und
/// live bytegleich am Netzziel liegt, aber in der geerbten Grundlinie fehlt,
/// bleibt lokal. Erst eine Öffnung, deren geerbte Grundlinie ihn trägt,
/// bereinigt ihn.
#[test]
fn a_row_missing_from_the_inherited_baseline_is_not_pruned() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    let away = installed.base.installed.archive.with_extension("away");
    fs::rename(&installed.base.installed.archive, &away).unwrap();
    assert_eq!(finalize(&native, "RULE-I-1"), 1, "offline committed");
    fs::rename(&away, &installed.base.installed.archive).unwrap();
    let first = rows_of_sequence(&committed_rows(&installed), 1);

    // Die Vorschau liest live, bevor Eintrag 1 veröffentlicht ist: ihre
    // Grundlinie kennt ihn nicht. Über den Vorschau-Zweig bleibt diese
    // Laufzeit (samt Grundlinie) bis zum Abschluss von Eintrag 2 erhalten.
    let state = native.desktop_state();
    let writer = state.writer().unwrap();
    let mut next = native_incident();
    next.human_incident_number = "RULE-I-2".into();
    let preview = writer.preview(&next).unwrap();
    assert_eq!(preview.proposed_sequence.get(), 2);
    assert_eq!(
        publish(&native).outcome(),
        PublicationOutcomeV1::PublishedCompletely
    );
    native_reauth(&native);
    assert_eq!(writer.finalize(&next, &preview).unwrap().sequence.get(), 2);
    let rows = committed_rows(&installed);
    assert!(first.iter().all(|(path, bytes)| rows.get(path) == Some(bytes)));
    let remote = remote_objects(&installed);
    assert!(
        first.iter().all(|(path, bytes)| remote.get(path) == Some(bytes)),
        "Eintrag 1 liegt live bytegleich am Netzziel"
    );

    // Diese Wiederöffnung erbt die Grundlinie OHNE Eintrag 1: er ist nicht
    // der höchste und liegt live vor, wird aber nicht bereinigt.
    state.drafts().unwrap().load_payload().unwrap();
    let rows = committed_rows(&installed);
    assert!(
        first.iter().all(|(path, bytes)| rows.get(path) == Some(bytes)),
        "Regel (i): nicht in der geerbten Grundlinie, also nicht bereinigt"
    );
    // Die nächste erbt eine Grundlinie mit Eintrag 1 und bereinigt ihn.
    state.drafts().unwrap().load_payload().unwrap();
    let rows = committed_rows(&installed);
    assert!(first.keys().all(|path| !rows.contains_key(path)));
    assert_eq!(rows, rows_of_sequence(&rows, 2), "Eintrag 2 bleibt");
}

/// EA-CNA-PUB-5: der Sync-Port eines Netz-Writers liest die Vereinigung aus
/// Netzsicht und committeter lokaler Komponente, nicht das Netzziel allein.
///
/// Der Eintrag entsteht, während das Netzziel fehlt, und liegt deshalb NUR
/// lokal. Die Warteschlange des Sync-Klienten findet ihn trotzdem anstehend,
/// mit genau den lokal committeten Bytes als Plan.
#[test]
fn the_sync_port_of_a_network_writer_derives_its_queue_from_the_union() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    let away = installed.base.installed.archive.with_extension("away");
    fs::rename(&installed.base.installed.archive, &away).unwrap();
    assert_eq!(finalize(&native, "NET-SYNC-1"), 1);
    drop(native);
    fs::rename(&away, &installed.base.installed.archive).unwrap();
    let local = committed_rows(&installed);
    let remote = remote_objects(&installed);
    assert!(!local.is_empty(), "der Eintrag liegt lokal committet");
    assert!(
        local.keys().all(|path| !remote.contains_key(path)),
        "und noch nirgends am Netzziel"
    );

    let runtime = installed.base.open_writer_runtime();
    let component = NativeArchiveExistingComponent::open_current(
        &runtime,
        NativeArchiveConfig::for_runtime_database(
            installed.base.profile.clone(),
            runtime.database().path(),
        ),
    )
    .unwrap();
    let archive = NetworkSyncArchiveV1::new(
        component,
        &installed.base.installed.archive,
        runtime.archive_snapshot(),
    )
    .unwrap();
    let port: &dyn ea_sync_client::SyncLocalArchiveV1 = &archive;
    // Das Backend des Ports ist die lokale SQLCipher-Komponente: eine dort
    // abgelegte Staging-Zeile erscheint in deren Zeilen, aber nie in der
    // committeten Quelle.
    let staging = ea_archive::ArchivePath::in_dir("entries/", "000000000009_probe.eip.staging")
        .unwrap();
    port.backend()
        .create_non_object_if_absent(&staging, b"staged-probe")
        .unwrap();
    assert!(
        staged(&installed).contains(&(staging.as_str().to_owned(), true)),
        "die Probe liegt in der lokalen Komponente"
    );
    let source = port.committed_source().unwrap();

    let mut visited = BTreeMap::new();
    source
        .visit_blobs(&mut |blob| {
            visited.insert(blob.path_hint().to_owned(), blob.bytes().to_vec());
            Ok(())
        })
        .unwrap();
    for (path, bytes) in local.iter().chain(&remote) {
        assert_eq!(visited.get(path), Some(bytes), "{path} gehört zur Vereinigung");
    }
    assert!(
        visited.keys().all(|path| !ea_archive::is_staging_path(path)),
        "Staging gehört nie zur committeten Quelle"
    );

    let queue =
        ea_sync_client::SyncQueueV1::derive(source.as_ref(), runtime.anchor(), support::live_clock())
            .unwrap();
    // Aufsteigend nach Sequenz: vor dem lokal committeten Eintrag steht der
    // Genesis-Eintrag aus der Netzsicht an, beide ohne Serverquittung.
    let [genesis, pending] = queue.pending() else {
        panic!("Genesis und der lokal committete Eintrag stehen an");
    };
    assert!(
        genesis
            .publication_plan()
            .iter()
            .all(|(path, bytes)| remote.get(path) == Some(bytes)),
        "der ältere Eintrag stammt aus der Netzsicht"
    );
    let plan: BTreeMap<String, Vec<u8>> = pending.publication_plan().into_iter().collect();
    assert_eq!(plan, local, "der Plan sind genau die lokal committeten Bytes");
}

/// Die Netzhälfte des Sync-Ports wird bei jedem Aufruf LIVE gelesen: ein
/// langlebiger Port, dessen lokale Zeilen nach seiner Konstruktion
/// veröffentlicht und bereinigt wurden (EA-CNA-SRC-5), sieht trotzdem die
/// ganze Kette. Eine beim Bau eingefrorene Netzsicht hätte hier eine Lücke.
#[test]
fn a_long_lived_sync_port_reads_the_network_half_live_after_local_rows_are_pruned() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    let away = installed.base.installed.archive.with_extension("away");
    fs::rename(&installed.base.installed.archive, &away).unwrap();
    assert_eq!(finalize(&native, "NET-SYNC-LIVE-1"), 1);
    drop(native);
    fs::rename(&away, &installed.base.installed.archive).unwrap();
    let first = committed_rows(&installed);

    // Der Port entsteht, solange Eintrag 1 NUR lokal liegt: seine Netzsicht
    // beim Bau kennt ihn nicht.
    let runtime = installed.base.open_writer_runtime();
    let component = NativeArchiveExistingComponent::open_current(
        &runtime,
        NativeArchiveConfig::for_runtime_database(
            installed.base.profile.clone(),
            runtime.database().path(),
        ),
    )
    .unwrap();
    let archive = NetworkSyncArchiveV1::new(
        component,
        &installed.base.installed.archive,
        runtime.archive_snapshot(),
    )
    .unwrap();
    drop(runtime);

    // Der Desktop veröffentlicht Eintrag 1 beim Start, committet Eintrag 2,
    // und die nächste Wiederöffnung bereinigt Eintrag 1 lokal.
    let reopened = started(&installed);
    assert_eq!(finalize(&reopened, "NET-SYNC-LIVE-2"), 2);
    let both = committed_rows(&installed);
    reopened
        .desktop_state()
        .drafts()
        .unwrap()
        .load_payload()
        .unwrap();
    assert_eq!(
        committed_rows(&installed),
        rows_of_sequence(&both, 2),
        "Eintrag 1 ist lokal bereinigt"
    );
    drop(reopened);

    let port: &dyn ea_sync_client::SyncLocalArchiveV1 = &archive;
    let source = port.committed_source().unwrap();
    let mut visited = BTreeMap::new();
    source
        .visit_blobs(&mut |blob| {
            visited.insert(blob.path_hint().to_owned(), blob.bytes().to_vec());
            Ok(())
        })
        .unwrap();
    for (path, bytes) in first.iter().chain(&both) {
        assert_eq!(visited.get(path), Some(bytes), "{path} gehört zur Vereinigung");
    }
    // Nur für den Anker; ein Kaltstart bereinigt nicht.
    let runtime = installed.base.open_writer_runtime();
    let queue = ea_sync_client::SyncQueueV1::derive(
        source.as_ref(),
        runtime.anchor(),
        support::live_clock(),
    )
    .expect("die ganze Kette ergibt eine Warteschlange");
    assert_eq!(queue.pending().len(), 3, "Genesis, Eintrag 1 und Eintrag 2");
}

/// Ein Beobachter, der das Netzziel nur zulässt; die Verwahrungsbeobachtung
/// selbst misst `publication_observes_the_network_root_before_publishing`.
struct AdmitTarget;
impl ea_admin::network_publication::NetworkTargetObserverV1 for AdmitTarget {
    fn observe_network_target(
        &self,
        _target: &ea_archive_fs::LocalPathBackend,
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        Ok(())
    }
}

/// Eine FORMGÜLTIGE `.esr` auf `entry` unter ihrer Klientenadresse
/// `receipts/<objectHash>.esr`. Die Linie dieser Installation trägt kein
/// Serverquittungszertifikat, deshalb ist die Signatur keine, die die Linie
/// bestätigt; für den Ablageweg zählen nur Adresse und exakte Bytes.
fn receipt_for(entry: &ea_sync_client::PendingEntryV1) -> (ea_archive::ArchivePath, Vec<u8>) {
    let ea_format::ParsedArchiveObject::Entry(parsed) =
        ea_format::decode_exact_object(entry.entry_bytes()).unwrap()
    else {
        panic!("ein committetes .eip ist ein Eintragspaket");
    };
    let manifest = parsed.value().manifest().fields();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new([0x9e; 32]));
    let mut grants: Vec<ea_types::ObjectHash> = entry
        .grant_bytes()
        .iter()
        .map(|bytes| ea_crypto::object_hash(bytes))
        .collect();
    grants.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let core = ea_format::ReceiptCoreV1::new(ea_format::ReceiptCoreFieldsV1 {
        organization_id: manifest.organization_id,
        chain_id: manifest.chain_id,
        chain_sequence: manifest.chain_sequence,
        entry_hash: entry.entry_hash(),
        entry_object_hash: entry.entry_object_hash(),
        previous_entry_hash: manifest.previous_entry_hash,
        registry_version: manifest.registry_version,
        registry_head_hash: ea_types::Hash32::try_from(&manifest.registry_head_hash[..]).unwrap(),
        policy_object_hash: ea_types::ObjectHash::try_from(&[0x44_u8; 32][..]).unwrap(),
        initial_grant_plan_hash: ea_types::Hash32::try_from(&manifest.initial_grant_plan_hash[..])
            .unwrap(),
        initial_grant_object_hashes: grants,
        accepted_at_server: support::live_clock(),
        evidence_due_at: None,
        server_key_thumbprint: signer.public_key().unwrap().thumbprint(),
        server_certificate_hash: ea_types::CertificateHash::try_from(&[0x77_u8; 32][..]).unwrap(),
    })
    .unwrap();
    let signature = signer.sign_receipt(core.exact_bytes()).unwrap();
    let bytes = ea_format::encode_receipt(&ea_format::ReceiptV1::new(core, signature).unwrap())
        .unwrap()
        .into_vec();
    let name: String = entry
        .entry_object_hash()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (
        ea_archive::ArchivePath::in_dir("receipts/", &format!("{name}.esr")).unwrap(),
        bytes,
    )
}

/// Was der Sync-Klient über den Netzport ablegt — die Quittung —, landet in
/// der SQLCipher-Komponente und erreicht das Netzziel nur über die
/// Publikationswarteschlange, nie durch einen direkten Schreibzugriff.
///
/// Gemessen wird der Ablageweg des Ports mit genau den drei Aufrufen, die
/// `persist_verified_receipt` nach der Verifikation macht.
#[test]
fn a_receipt_stored_through_the_sync_port_reaches_the_network_only_via_publication() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    assert_eq!(finalize(&native, "NET-SYNC-RCPT"), 1);
    drop(native);

    let runtime = installed.base.open_writer_runtime();
    let open = || {
        NativeArchiveExistingComponent::open_current(
            &runtime,
            NativeArchiveConfig::for_runtime_database(
                installed.base.profile.clone(),
                runtime.database().path(),
            ),
        )
        .unwrap()
    };
    let archive = NetworkSyncArchiveV1::new(
        open(),
        &installed.base.installed.archive,
        runtime.archive_snapshot(),
    )
    .unwrap();
    let port: &dyn ea_sync_client::SyncLocalArchiveV1 = &archive;
    assert!(port.requires_network_publication());
    let entry = {
        let source = port.committed_source().unwrap();
        let queue = ea_sync_client::SyncQueueV1::derive(
            source.as_ref(),
            runtime.anchor(),
            support::live_clock(),
        )
        .unwrap();
        queue.pending().last().unwrap().clone()
    };
    let (receipt, bytes) = receipt_for(&entry);

    port.backend()
        .create_non_object_if_absent(&receipt, &bytes)
        .unwrap();
    port.backend().sync_file(&receipt).unwrap();
    port.backend().sync_directory(&receipt).unwrap();
    let remote_receipt = installed.base.installed.archive.join(receipt.as_str());
    assert_eq!(
        committed_rows(&installed).get(receipt.as_str()),
        Some(&bytes),
        "die Quittung liegt in der SQLCipher-Komponente"
    );
    assert!(!remote_receipt.exists(), "und nicht direkt am Netzziel");

    // Erst die Warteschlange des Publikationshosts bringt sie ans Netzziel,
    // byteidentisch.
    let policy = BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
    let component = open();
    let host =
        NetworkPublicationHost::new(&component, &installed.base.installed.archive, &policy)
            .unwrap();
    let planned = host.pending().unwrap();
    assert_eq!(planned.order(), vec![receipt.as_str().to_owned()]);
    assert_eq!(
        host.run_once(&AdmitTarget).unwrap().outcome(),
        PublicationOutcomeV1::PublishedCompletely
    );
    assert_eq!(fs::read(&remote_receipt).unwrap(), bytes);
}
