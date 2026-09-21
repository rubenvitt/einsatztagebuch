//! FIXTURE-HELFER OHNE NATIVE SICHERHEITSKETTE.
//!
//! Spricht das JSON-Protokoll von `ea-native-operator` und antwortet mit den
//! öffentlich bekannten Schlüsseln der gesäten Demowelt
//! (`ea_demo_world::native_fixture`). Er ersetzt den Testhelfer der CLI, der
//! ein `/bin/sh`-Skript war und deshalb unter Windows nicht lief: dies ist ein
//! echtes Programm, das `Command::new` direkt startet.
//!
//! Er existiert nur mit dem Merkmal `test-support` und antwortet nur als
//! `ea-native-operator` in einem Stationsverzeichnis — dorthin legt ihn
//! `ea-desktop-fixture` selbst.

fn main() {
    if let Err(reason) = ea_demo_world::native_fixture::run_helper_process() {
        eprintln!("{reason}");
        std::process::exit(1);
    }
}
