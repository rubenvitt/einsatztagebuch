//! Der Aufbau der FIXTURE-Laufzeit, ohne Fenster.
//!
//! Diese Datei ist der gesamte Unterschied zwischen `ea-desktop-fixture` und
//! dem ausgelieferten Wirt: statt `NativeDesktopRuntime::open` (und damit
//! `NativeOperatorProvider::open_installed`) geht sie über die drei
//! vorhandenen Fixture-Konstruktoren hinter `test-support`:
//!
//! 1. `NativeOperatorProvider::open_test_fixture` — der Helfer ist der
//!    Fixture-Helfer im Stationsverzeichnis, ohne Identitätsprüfung,
//! 2. `InteractiveOperatorRuntime::open_with_test_native`,
//! 3. `NativeDesktopRuntime::open_with_test_runtime`.
//!
//! Dieselbe Folge wie `apps/cli/tests/operator_desktop/mod.rs` (Writer) und
//! `apps/cli/tests/operator_administration/host.rs` (Verwaltung). Keine neue
//! Injektionsstelle. `tests/fixture_demo_world.rs` bindet genau diese Datei ein
//! und prüft damit denselben Text, den das Programm ausführt.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use ea_admin::{
    native_provider::NativeOperatorProvider,
    operator_runtime::{OperatorRuntimeConfig, writer::InteractiveOperatorRuntime},
};
use ea_demo_world::native_fixture::HELPER_FILE_NAME;
use ea_desktop::runtime::{DesktopLaunchConfig, NativeDesktopRuntime};
use ea_types::UnixMillis;

/// Der Bauname des Fixture-Helfers neben `ea-desktop-fixture`.
pub const HELPER_BUILD_NAME: &str = if cfg!(windows) {
    "ea-native-operator-fixture.exe"
} else {
    "ea-native-operator-fixture"
};

/// Das Stationsverzeichnis: das Verzeichnis der `--operator-config`.
///
/// # Errors
///
/// Wenn die Konfiguration kein Elternverzeichnis hat oder es nicht existiert.
pub fn station_directory(launch: &DesktopLaunchConfig) -> Result<PathBuf, String> {
    launch
        .operator_config
        .parent()
        .ok_or_else(|| "--operator-config hat kein Verzeichnis".to_owned())?
        .canonicalize()
        .map_err(|error| format!("das Stationsverzeichnis fehlt: {error}"))
}

/// Legt den Fixture-Helfer als `ea-native-operator` in das
/// Stationsverzeichnis. Liegt dort schon dieselbe Datei, bleibt sie stehen —
/// unter Windows ließe sich ein noch laufender Helfer ohnehin nicht ersetzen.
///
/// Geschrieben wird erst unter einem Zwischennamen und dann umbenannt: ein
/// halb kopierter Helfer ist nie unter dem Namen sichtbar, den der Wirt
/// startet.
///
/// # Errors
///
/// Wenn der Bau des Helfers fehlt oder die Kopie scheitert.
pub fn install_helper(source: &Path, station: &Path) -> Result<PathBuf, String> {
    let built = fs::read(source).map_err(|error| {
        format!(
            "der Fixture-Helfer {} fehlt ({error}); er entsteht mit \
             `cargo build -p ea-desktop --features test-support --bin {}`",
            source.display(),
            HELPER_BUILD_NAME.trim_end_matches(".exe")
        )
    })?;
    let target = station.join(HELPER_FILE_NAME);
    if fs::read(&target).is_ok_and(|installed| installed == built) {
        return Ok(target);
    }
    let staging = station.join(format!("{HELPER_FILE_NAME}.new"));
    fs::copy(source, &staging).map_err(|error| {
        format!(
            "der Fixture-Helfer ließ sich nicht nach {} kopieren: {error}",
            staging.display()
        )
    })?;
    fs::rename(&staging, &target).map_err(|error| {
        let _ = fs::remove_file(&staging);
        format!(
            "{} ließ sich nicht ersetzen ({error}); läuft noch ein Fixture-Fenster \
             dieser Station?",
            target.display()
        )
    })?;
    Ok(target)
}

fn now() -> Result<UnixMillis, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .map(UnixMillis::new)
        .ok_or_else(|| "die Systemuhr steht vor 1970".to_owned())
}

/// Baut die Laufzeit einer Station über die Fixture-Konstruktoren.
///
/// Die erste Sitzung entsteht auch hier erst mit der Anmeldung
/// (`RuntimeSessionPort::login`), genau wie im ausgelieferten Wirt.
///
/// # Errors
///
/// Mit dem stabilen Fehlercode der Stufe, die abgewiesen hat.
pub fn open_fixture_runtime(
    launch: DesktopLaunchConfig,
    helper: &Path,
) -> Result<Arc<NativeDesktopRuntime>, String> {
    let config = OperatorRuntimeConfig::load(&launch.operator_config)
        .map_err(|error| format!("Bedienerkonfiguration: {}", error.code()))?;
    let native = NativeOperatorProvider::open_test_fixture(helper.to_path_buf(), false)
        .map_err(|error| format!("Fixture-Helfer: {}", error.code()))?;
    let runtime = InteractiveOperatorRuntime::open_with_test_native(
        config,
        &launch.trust_anchor,
        now()?,
        native,
    )
    .map_err(|error| format!("Bedienerlaufzeit: {}", error.code()))?;
    NativeDesktopRuntime::open_with_test_runtime(launch, runtime)
        .map_err(|error| format!("Wirt: {}", error.code))
}
