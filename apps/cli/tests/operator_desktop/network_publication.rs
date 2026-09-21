//! Publikation der lokalen Commits eines Netz-Writers (EA-CNA-PUB-1 … PUB-8),
//! die Bereinigung beim Öffnen (EA-CNA-SRC-5) und der Sync-Zustand am
//! Desktop. Das Temp-Verzeichnis ist kein Beleg für ein gemountetes
//! Netzdateisystem; die Reihenfolge grants-first/`.eip`-last belegt der
//! Spion im `ea-admin`-Unit-Test `publication_order_is_grants_first_entry_last`.
use super::network_writer::{NetworkWriterInstallation, listing};
use super::*;
use ea_admin::{
    native_archive::{NativeArchiveConfig, NativeArchiveExistingComponent},
    network_publication::NetworkPublicationHost,
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

/// Öffnet den Desktop, hält seinen Hostlauf an (die Tests rufen `run_once`
/// selbst) und meldet den Writer an.
fn started(installed: &NetworkWriterInstallation) -> Arc<NativeDesktopRuntime> {
    let native = installed.try_host(&installed.writer_config).unwrap();
    native.stop_network_publication_loop();
    native.login().unwrap();
    native
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
    let host = native.network_publication_host().unwrap();
    let resumed = host.run_once();
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

#[test]
fn reopen_prunes_published_rows_and_keeps_the_union_identical() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = started(&installed);
    finalize(&native, "NET-PUB-4");
    let local_before = committed_rows(&installed);
    assert!(!local_before.is_empty(), "die Commits liegen noch lokal");
    let mut union_before = remote_objects(&installed);
    union_before.extend(local_before.clone());
    let staged_before: Vec<_> = installed
        .local_paths()
        .into_iter()
        .filter(|(_, staged)| *staged)
        .collect();
    drop(native);

    // Kaltstart mit live gelesenem Netzziel: jede bytegleich veröffentlichte
    // committed Zeile fällt lokal weg.
    let reopened = installed.try_host(&installed.writer_config).unwrap();
    reopened.stop_network_publication_loop();
    assert!(
        committed_rows(&installed).is_empty(),
        "alle committed Zeilen lagen bytegleich am Netzziel"
    );
    let staged_after: Vec<_> = installed
        .local_paths()
        .into_iter()
        .filter(|(_, staged)| *staged)
        .collect();
    assert_eq!(staged_after, staged_before, "Staging bleibt unberührt");
    let mut union_after = remote_objects(&installed);
    union_after.extend(committed_rows(&installed));
    assert_eq!(union_after, union_before, "die Vereinigung bleibt gleich");

    // Die Kette läuft über die Vereinigung weiter.
    reopened.login().unwrap();
    let state = reopened.desktop_state();
    let writer = state.writer().unwrap();
    let mut next = native_incident();
    next.human_incident_number = "NET-PUB-5".into();
    assert_eq!(writer.preview(&next).unwrap().proposed_sequence.get(), 2);
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
    assert!(
        matches!(
            refused.code(),
            "EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS" | "EA-ARCHIVE-IO"
        ),
        "{}",
        refused.code()
    );
    assert!(desktop.is_err(), "und kein Netz-Writer am Desktop");
    // Ein Netzziel, das die Zulassung besteht, bekommt einen Host.
    assert!(NetworkPublicationHost::new(&component, &root, &policy).is_ok());
}
