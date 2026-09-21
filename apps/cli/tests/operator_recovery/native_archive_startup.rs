//! Startquelle eines registrierten Netzprofils (EA-CNA-SRC-1 … SRC-4): der
//! Start verifiziert das Netzziel vereinigt mit der lokal committeten
//! Komponente. Das Temp-Verzeichnis ist kein Beleg für ein gemountetes
//! Netzdateisystem.
use super::native_archive_existing_component::{config, observe_archive_writes, profile, state};
use super::*;
use ea_admin::native_archive::{NativeArchiveExistingComponent, register_network_component};
use ea_admin::operator_runtime::OperatorRuntimeError;
use ea_archive::ArchivePath;

/// Die Kettenadressen des Epochenschritts, den `historical=true` als höchste
/// Sequenz ins Netzziel legt.
pub(super) const MOVED: [(&str, &str); 2] = [
    ("grants/", "000000000001_epoch.eag"),
    ("entries/", "000000000001_epoch.eip"),
];

/// Wie `RecoveryInstallation::open`, aber mit dem Fehler statt eines Panics.
fn try_open(installed: &RecoveryInstallation) -> Result<OperatorRuntime, OperatorRuntimeError> {
    try_open_with(installed, false)
}

/// Wie `try_open`; `initialize_native` wie bei `operator provision`.
fn try_open_with(
    installed: &RecoveryInstallation,
    initialize_native: bool,
) -> Result<OperatorRuntime, OperatorRuntimeError> {
    let native = NativeOperatorProvider::open_test_fixture(
        installed.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let host: Arc<dyn ea_key_provider::DevicePostureProvider> =
        Arc::new(ea_key_provider::DevicePostureProviderFake::unknown(
            ea_key_provider::PostureRequirement::FullDiskEncryption,
        ));
    OperatorRuntime::open_with_test_native_and_posture(
        OperatorRuntimeConfig::load(&installed.config).unwrap(),
        &installed.anchor,
        support::live_clock(),
        initialize_native,
        native,
        host,
    )
}

fn code<T>(result: Result<T, OperatorRuntimeError>) -> &'static str {
    match result {
        Ok(_) => panic!("open must refuse"),
        Err(error) => error.code(),
    }
}

/// Registriert die Komponente und verschiebt den höchsten Kettenschritt samt
/// Grant aus dem Netzziel in die lokale Komponente: Grants zuerst, `.eip`
/// zuletzt, jeweils dauerhaft, bevor die Netzkopie verschwindet. Das Netzziel
/// behält den Eintrag der Sequenz 0.
pub(super) fn register_and_move_head(installed: &RecoveryInstallation) -> ChainSequence {
    let runtime = installed.open();
    let with_both_in_remote = runtime.next_sequence();
    let (_, component) =
        register_network_component(&runtime, config(&runtime, installed.profile.clone())).unwrap();
    move_into_component(installed, &component);
    drop(component);
    drop(runtime);
    assert!(
        installed
            .archive
            .join("entries/000000000000_entry.eip")
            .exists(),
        "the remote keeps at least one entry"
    );
    with_both_in_remote
}

fn move_into_component(
    installed: &RecoveryInstallation,
    component: &NativeArchiveExistingComponent,
) {
    let _lock = component.local_backend().acquire_writer_lock().unwrap();
    for (directory, name) in MOVED {
        let path = ArchivePath::in_dir(directory, name).unwrap();
        let remote = installed.archive.join(path.as_str());
        let bytes = fs::read(&remote).unwrap();
        component
            .local_backend()
            .create_non_object_if_absent(&path, &bytes)
            .unwrap();
        component.local_backend().sync_file(&path).unwrap();
        fs::remove_file(&remote).unwrap();
    }
}

#[test]
fn network_startup_verifies_remote_union_local_and_advances_next_sequence() {
    let installed = RecoveryInstallation::with_profile(None, true, Some(profile()));
    let expected = register_and_move_head(&installed);
    assert_eq!(expected.get(), 2, "fixture: epoch step is sequence 1");
    for (directory, name) in MOVED {
        assert!(!installed.archive.join(directory).join(name).exists());
    }
    let runtime = installed.open();
    assert_eq!(runtime.next_sequence(), expected);
    assert!(
        runtime.archive_snapshot().remote_baseline().is_some(),
        "a network snapshot keeps the live remote view"
    );
    // Die Vereinigung schreibt nichts ins Netzziel zurück.
    for (directory, name) in MOVED {
        assert!(!installed.archive.join(directory).join(name).exists());
    }
}

#[test]
fn network_startup_refuses_byte_conflict_between_remote_and_local() {
    let installed = RecoveryInstallation::with_profile(None, true, Some(profile()));
    register_and_move_head(&installed);
    // Dieselbe Adresse im Netzziel mit anderen Bytes: kein Vorrang einer Seite.
    let (directory, name) = MOVED[0];
    fs::write(
        installed.archive.join(directory).join(name),
        b"DIFFERENT-REMOTE-BYTES-AT-THE-SAME-ADDRESS",
    )
    .unwrap();
    assert_eq!(
        code(try_open(&installed)),
        "EA-OPERATOR-NETWORK-ARCHIVE-CONFLICT"
    );
}

#[test]
fn network_cold_start_refuses_unreadable_remote() {
    let installed = RecoveryInstallation::with_profile(None, true, Some(profile()));
    register_and_move_head(&installed);
    fs::rename(&installed.archive, installed.archive.with_extension("away")).unwrap();
    assert_eq!(
        code(try_open(&installed)),
        "EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE"
    );
}

#[test]
fn network_reopen_for_action_uses_baseline_when_remote_disappears() {
    let installed = RecoveryInstallation::with_profile(None, true, Some(profile()));
    let expected = register_and_move_head(&installed);
    let runtime = installed.open();
    assert_eq!(runtime.next_sequence(), expected);
    fs::rename(&installed.archive, installed.archive.with_extension("away")).unwrap();
    let reopened = runtime.reopened_for_action().unwrap();
    assert_eq!(reopened.next_sequence(), expected);
    // Die Grundlinie ist dieselbe unveränderte Netzsicht, nicht die
    // Vereinigung mit den lokalen Bytes.
    assert!(Arc::ptr_eq(
        runtime.archive_snapshot().remote_baseline().unwrap(),
        reopened.archive_snapshot().remote_baseline().unwrap(),
    ));
    // Ein zweiter Kaltstart desselben Zustands bleibt verweigert.
    assert_eq!(
        code(try_open(&installed)),
        "EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE"
    );
}

#[test]
fn local_path_startup_is_unchanged() {
    let installed = RecoveryInstallation::with_target_and_epochs(None, true);
    let runtime = installed.open();
    let expected = runtime.next_sequence();
    // Temp-Trigger sehen nur Schreibzugriffe dieser Verbindung; die Zeilen
    // selbst sieht sie auch nach den Commits einer zweiten Runtime.
    observe_archive_writes(&runtime);
    let before = state(&runtime);
    let reopened = installed.open();
    assert_eq!(reopened.next_sequence(), expected);
    let fresh = reopened.reopened_for_action().unwrap();
    assert_eq!(fresh.next_sequence(), expected);
    assert!(reopened.archive_snapshot().remote_baseline().is_none());
    assert!(fresh.archive_snapshot().remote_baseline().is_none());
    assert_eq!(state(&runtime), before, "no archive storage row touched");
    // Ohne Registrierung gibt es keine Grundlinie: dasselbe Io wie bisher.
    fs::rename(&installed.archive, installed.archive.with_extension("away")).unwrap();
    assert_eq!(code(reopened.reopened_for_action()), "EA-OPERATOR-IO");
    assert_eq!(code(try_open(&installed)), "EA-OPERATOR-IO");
}

/// Ohne Datenbank kann es keine Registrierung geben: der Archiv-Snapshot
/// wird wie vor DRK-320 vor nativem Schlüssel und Datenbank geöffnet. Eine
/// Bereitstellung gegen ein fehlendes Archiv endet deshalb wie bisher mit
/// Io und hinterlässt weder Datenbank noch Schlüsselmaterial. Ohne
/// Bereitstellung weist schon das Erwerbstor die fehlende Datenbank ab, vor
/// jedem Archivzugriff — auch das unverändert.
#[test]
fn local_path_cold_start_opens_the_archive_before_key_and_database() {
    let installed = RecoveryInstallation::with_target_and_epochs(None, false);
    let database = installed.directory.path().join("operator.sqlite");
    let calls = installed.directory.path().join("helper-calls");
    fs::remove_file(&database).unwrap();
    fs::rename(&installed.archive, installed.archive.with_extension("away")).unwrap();
    // Ohne Schlüssel würde eine Bereitstellung ihn erzeugen: `contains`
    // meldet ihn als fehlend, `generate` wäre die Erzeugung.
    fs::write(installed.directory.path().join("helper-mode"), "database-key-missing").unwrap();

    assert_eq!(code(try_open(&installed)), "EA-OPERATOR-DATABASE-REQUIRED");
    assert!(!database.exists(), "no database without provisioning");

    let before = fs::read_to_string(&calls).unwrap_or_default().lines().count();
    assert_eq!(code(try_open_with(&installed, true)), "EA-OPERATOR-IO");
    assert!(!database.exists(), "provisioning left a database file");
    let after = fs::read_to_string(&calls).unwrap_or_default();
    let key_calls: Vec<_> = after
        .lines()
        .skip(before)
        .filter(|line| line.starts_with("contains ") || line.starts_with("generate "))
        .collect();
    assert!(
        key_calls.is_empty(),
        "no key probe or key creation before the archive: {key_calls:?}"
    );
}

/// EA-CNA-SRC-4: eine Grundlinie tritt nur an die Stelle DESSELBEN
/// kanonischen Netzziels. Zeigt der konfigurierte Pfad inzwischen woanders
/// hin (hier ein umgebogener Symlink), ist das Netzziel nicht lesbar — die
/// alte Grundlinie wird weder genommen noch ihr Ort live gelesen.
#[test]
fn a_baseline_stands_in_only_for_the_same_canonical_target() {
    let installed = RecoveryInstallation::with_profile(None, true, Some(profile()));
    let expected = register_and_move_head(&installed);
    let real = installed.archive.with_extension("real");
    fs::rename(&installed.archive, &real).unwrap();
    std::os::unix::fs::symlink(&real, &installed.archive).unwrap();
    let runtime = installed.open();
    assert_eq!(runtime.next_sequence(), expected);
    let retarget = |target: &Path| {
        fs::remove_file(&installed.archive).unwrap();
        std::os::unix::fs::symlink(target, &installed.archive).unwrap();
    };

    // Kanonisierbar, aber ein anderes und nicht lesbares Ziel.
    let decoy = installed.directory.path().join("decoy-file");
    fs::write(&decoy, b"not an archive").unwrap();
    retarget(&decoy);
    assert_eq!(
        code(runtime.reopened_for_action()),
        "EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE"
    );

    // Nicht kanonisierbar: der Pfad zeigt ins Leere.
    retarget(&installed.directory.path().join("gone"));
    assert_eq!(
        code(runtime.reopened_for_action()),
        "EA-OPERATOR-NETWORK-ARCHIVE-UNAVAILABLE"
    );

    // Gegenprobe: dasselbe kanonische Ziel, nur nicht lesbar — die
    // Grundlinie trägt.
    use std::os::unix::fs::PermissionsExt as _;
    retarget(&real);
    fs::set_permissions(&real, fs::Permissions::from_mode(0o000)).unwrap();
    let reopened = runtime.reopened_for_action();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(reopened.unwrap().next_sequence(), expected);
}
