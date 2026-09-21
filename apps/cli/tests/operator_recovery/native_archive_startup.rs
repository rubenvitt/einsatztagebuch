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
        false,
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
