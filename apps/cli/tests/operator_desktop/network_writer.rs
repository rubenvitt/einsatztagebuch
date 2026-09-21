//! Desktop-Writer auf der lokalen SQLCipher-Komponente eines kontrollierten
//! Netzprofils (EA-CNA-WRT-1 … WRT-7). Der Writer registriert seine eigene
//! Datenbank (EA-CNA-REG-1); das Temp-Verzeichnis ist kein Beleg für ein
//! gemountetes Netzdateisystem.
use super::super::recovery::native_archive_writer_registration::{
    NetworkWriterInstallation as Base, network_profile,
};
use super::*;
use ea_admin::native_archive::{
    NativeArchiveConfig, NativeArchiveExistingComponent, NativeArchiveRegistrationOutcome,
    register_network_component,
};
use ea_archive::ArchiveBackendProfileV1;
use std::collections::BTreeMap;

fn profile_json(profile: &ArchiveBackendProfileV1) -> Value {
    let ArchiveBackendProfileV1::ControlledNetworkPath(p) = profile else {
        panic!("network profile fixture");
    };
    json!({
        "kind":"controlled-network-path",
        "filesystem_row_id":p.filesystem_row_id,"protocol_id":p.protocol_id,
        "server_product":p.server_product,"server_version":p.server_version,
        "mount_options":p.mount_options,"failover_config_id":p.failover_config_id,
        "capability_test_vector_id":p.capability_test_vector_id,
        "queue_max_objects":p.queue_max_objects,"queue_max_bytes":p.queue_max_bytes,
        "resume_backoff_initial_ms":p.resume_backoff_initial_ms,
        "resume_backoff_max_ms":p.resume_backoff_max_ms,
        "resume_max_attempts":p.resume_max_attempts
    })
}

/// Die Desktop-Writer-`Installation` mit Netzprofil-Policy und einer
/// Writer-Konfiguration, deren `local_commit_database_path` die eigene
/// Datenbank der Writer-Runtime nennt.
struct NetworkWriterInstallation {
    base: Base,
    writer_config: PathBuf,
}
impl NetworkWriterInstallation {
    fn new() -> Self {
        Self::with_profile(network_profile(10_000))
    }
    fn with_profile(profile: ArchiveBackendProfileV1) -> Self {
        let base = Base::with_profile(profile);
        let writer_config = base.installed.directory.path().join("writer.json");
        fs::write(
            &writer_config,
            serde_json::to_vec(&json!({
                "version":1,"timezone":"Europe/Berlin",
                "archive_profile":profile_json(&base.profile),
                "local_commit_database_path":"operator.sqlite"
            }))
            .unwrap(),
        )
        .unwrap();
        Self {
            base,
            writer_config,
        }
    }

    /// Der Writer registriert seine eigene Datenbank über seine
    /// Current-Runtime und gibt sie vor dem Desktop-Start frei. Die
    /// zurückgegebene Komponente trägt keine Autorität, nur die Ablage.
    fn register(&self) -> NativeArchiveExistingComponent {
        let runtime = self.base.open_writer_runtime();
        let (outcome, component) = register_network_component(
            &runtime,
            NativeArchiveConfig::for_runtime_database(
                self.base.profile.clone(),
                runtime.database().path(),
            ),
        )
        .unwrap();
        assert_eq!(outcome, NativeArchiveRegistrationOutcome::Registered);
        component
    }

    fn try_host(
        &self,
        writer_config: &Path,
    ) -> Result<Arc<NativeDesktopRuntime>, ea_desktop::commands::CommandError> {
        let native = NativeOperatorProvider::open_test_fixture(
            self.base
                .installed
                .directory
                .path()
                .join("ea-native-operator"),
            false,
        )
        .unwrap();
        let runtime = InteractiveOperatorRuntime::open_with_test_native(
            OperatorRuntimeConfig::load(&self.base.installed.config).unwrap(),
            &self.base.installed.anchor,
            support::live_clock(),
            native,
        )
        .unwrap();
        NativeDesktopRuntime::open_with_test_runtime(
            DesktopLaunchConfig {
                operator_config: self.base.installed.config.clone(),
                trust_anchor: self.base.installed.anchor.clone(),
                writer_config: Some(writer_config.to_owned()),
                destruction_config: None,
                recovery_config: None,
                administration_config: None,
            },
            runtime,
        )
    }

    /// Committete Zeilen der lokalen Komponente: (Pfad, Staging?).
    fn local_paths(&self) -> Vec<(String, bool)> {
        let db = open_database(&self.base.installed.database);
        let mut paths = Vec::new();
        let mut last = String::new();
        while let Some(row) = db
            .query_row(
                "SELECT relative_path FROM local_commit_object WHERE relative_path>?1 ORDER BY relative_path LIMIT 1",
                &[StoreValue::Text(last.clone())],
            )
            .unwrap()
        {
            last = row.text(0).unwrap().to_owned();
            paths.push((last.clone(), ea_archive::is_staging_path(&last)));
        }
        paths
    }
    fn committed_local_entries(&self) -> usize {
        self.local_paths()
            .iter()
            .filter(|(path, staged)| {
                !staged && path.starts_with("entries/") && path.ends_with(".eip")
            })
            .count()
    }
    fn committed_local_grants(&self) -> usize {
        self.local_paths()
            .iter()
            .filter(|(path, staged)| {
                !staged && path.starts_with("grants/") && path.ends_with(".eag")
            })
            .count()
    }
}

/// Jede Datei unter `root` mit ihren Bytes.
fn listing(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, directory: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn writer_config_with(installed: &NetworkWriterInstallation, name: &str, config: Value) -> PathBuf {
    let path = installed.base.installed.directory.path().join(name);
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    path
}

#[test]
fn network_writer_finalizes_into_the_local_component_and_not_the_remote() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = installed.try_host(&installed.writer_config).unwrap();
    native.login().unwrap();
    let state = native.desktop_state();
    state
        .drafts()
        .unwrap()
        .save_payload("active network incident".into())
        .unwrap();
    let writer = state.writer().expect("native network Writer service");
    let input = native_incident();
    let preview = writer.preview(&input).unwrap();
    native.reauthenticate(ReauthPurpose::Finalize).unwrap();
    let remote_before = listing(&installed.base.installed.archive);
    let outcome = writer.finalize(&input, &preview).unwrap();
    assert_eq!(outcome.sequence.get(), 1, "the next chain sequence");
    assert_eq!(state.drafts().unwrap().load_payload().unwrap(), "");
    assert_eq!(installed.committed_local_entries(), 1, "the .eip is local");
    assert!(installed.committed_local_grants() >= 1, "grants are local");
    assert!(
        installed.local_paths().iter().all(|(_, staged)| !staged),
        "no staging row remains after a completed finalize"
    );
    assert!(
        listing(&installed.base.installed.archive) == remote_before,
        "the Writer never writes the remote"
    );
    drop(state);
    drop(native);
    // Ein Kaltstart sieht Netzziel ⊎ lokale Komponente und damit die nächste
    // Sequenz; das Netzziel allein kennt sie nicht.
    let remote_only = ea_admin::operator_runtime::OperatorArchiveSnapshot::open(
        &installed.base.installed.archive,
        &installed.base.installed.anchor,
        support::live_clock(),
    )
    .unwrap();
    assert_eq!(remote_only.next_sequence().get(), 1);
    let reopened = installed.try_host(&installed.writer_config).unwrap();
    reopened.login().unwrap();
    let state = reopened.desktop_state();
    let writer = state.writer().unwrap();
    let mut next = input.clone();
    next.human_incident_number = "DESKTOP-NATIVE-915".into();
    let preview = writer.preview(&next).unwrap();
    assert_eq!(
        preview.proposed_sequence.get(),
        2,
        "the union advances the chain"
    );
}

#[test]
fn network_writer_finalizes_after_the_remote_disappears_mid_session() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let native = installed.try_host(&installed.writer_config).unwrap();
    native.login().unwrap();
    let away = installed.base.installed.archive.with_extension("away");
    fs::rename(&installed.base.installed.archive, &away).unwrap();
    let state = native.desktop_state();
    state
        .drafts()
        .unwrap()
        .save_payload("offline network incident".into())
        .unwrap();
    let writer = state.writer().unwrap();
    let input = native_incident();
    let preview = writer.preview(&input).unwrap();
    native.reauthenticate(ReauthPurpose::Finalize).unwrap();
    let outcome = writer.finalize(&input, &preview).unwrap();
    assert_eq!(outcome.sequence.get(), 1);
    assert_eq!(installed.committed_local_entries(), 1);
    assert!(
        !installed.base.installed.archive.exists(),
        "nothing recreates the remote root"
    );
}

#[test]
fn network_writer_config_requires_the_runtime_database_path() {
    let installed = NetworkWriterInstallation::new();
    drop(installed.register());
    let profile = profile_json(&installed.base.profile);
    let missing = writer_config_with(
        &installed,
        "writer-missing.json",
        json!({"version":1,"timezone":"Europe/Berlin","archive_profile":profile}),
    );
    assert_eq!(
        installed.try_host(&missing).err().unwrap().code,
        "EA-DESKTOP-LAUNCH-CONFIG"
    );
    // Eine andere, vorhandene Datei ist nicht die Datenbank der Runtime.
    fs::write(
        installed
            .base
            .installed
            .directory
            .path()
            .join("other.sqlite"),
        b"",
    )
    .unwrap();
    let other = writer_config_with(
        &installed,
        "writer-other.json",
        json!({"version":1,"timezone":"Europe/Berlin","archive_profile":profile,
               "local_commit_database_path":"other.sqlite"}),
    );
    assert_eq!(
        installed.try_host(&other).err().unwrap().code,
        "EA-NATIVE-ARCHIVE-CONFIG"
    );
    // Für LocalPath ist das Feld verboten.
    let local = writer_config_with(
        &installed,
        "writer-local.json",
        json!({"version":1,"timezone":"Europe/Berlin","archive_profile":{
            "kind":"local-path","filesystem_row_id":"fixture-native-writer-fs",
            "capability_test_vector_id":"native-desktop-cap-v1"},
            "local_commit_database_path":"operator.sqlite"}),
    );
    assert_eq!(
        installed.try_host(&local).err().unwrap().code,
        "EA-DESKTOP-LAUNCH-CONFIG"
    );
    assert!(installed.try_host(&installed.writer_config).is_ok());
}

#[test]
fn network_writer_refuses_when_sqlcipher_capability_fails() {
    let installed = NetworkWriterInstallation::new();
    let foreign = installed.register();
    let held = foreign.local_backend().acquire_writer_lock().unwrap();
    assert_eq!(
        installed
            .try_host(&installed.writer_config)
            .err()
            .unwrap()
            .code,
        "EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS"
    );
    drop(held);
    assert!(installed.try_host(&installed.writer_config).is_ok());
}

#[test]
fn network_writer_queue_limit_blocks_before_irreversible_step() {
    let installed = NetworkWriterInstallation::with_profile(network_profile(1));
    drop(installed.register());
    let native = installed.try_host(&installed.writer_config).unwrap();
    native.login().unwrap();
    let state = native.desktop_state();
    let draft = "queue-limited network incident";
    state.drafts().unwrap().save_payload(draft.into()).unwrap();
    let writer = state.writer().unwrap();
    let input = native_incident();
    let preview = writer.preview(&input).unwrap();
    native.reauthenticate(ReauthPurpose::Finalize).unwrap();
    let remote_before = listing(&installed.base.installed.archive);
    let refused = writer.finalize(&input, &preview).err().unwrap().code;
    // `put_in` meldet die erreichte Queuegrenze beim Staging (Schritt 8).
    assert_eq!(refused, "EA-ARCHIVE-PENDING-PUBLICATION");
    assert_eq!(state.drafts().unwrap().load_payload().unwrap(), draft);
    assert_eq!(installed.committed_local_entries(), 0, "no committed .eip");
    assert!(listing(&installed.base.installed.archive) == remote_before);
}
