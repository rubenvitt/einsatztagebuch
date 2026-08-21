#![forbid(unsafe_code)]
//! Der Wirt der Writer-Oberflaeche.
//!
//! Hier — und nur hier — lebt Async. Jeder `#[tauri::command]`-Rumpf schickt
//! seine synchrone Kernoperation ueber `tauri::async_runtime::spawn_blocking`
//! (`commands::run_blocking`), damit die fsync-schwere Finalisierung den
//! Main-Thread nicht blockiert. Der Rust-Kern unter `crates/` bleibt synchron.
//!
//! Die Anwendung traegt weder eine Reader- noch eine Verwaltungsflaeche: der
//! Reader ist eine Browser-PWA, die Verwaltung ist Stufe 5. Deshalb steht in
//! [`COMMAND_NAMES`] kein Kommando fuer eine von beiden, und
//! `apps/desktop/src/app/role-gate.ts` traegt fuer sie keine Route.

pub mod commands;
pub mod state;

pub use commands::COMMAND_NAMES;

/// Jeder Kommandoname, den [`run`] registriert.
#[must_use]
pub fn registered_command_names() -> &'static [&'static str] {
    COMMAND_NAMES
}

/// Startet die Anwendung.
///
/// Der Zustand geht OHNE Rolle, ohne Nachweis, ohne Startpfad und ohne
/// geoeffnete Datenbank hinein: die Aufloesung der Root-signierten
/// Bedienerbindung, der Schreibdienst und die entschluesselte Datenbank gehoeren
/// Task 16. Bis dahin antwortet jedes Kommando mit einer BENANNTEN Abwesenheit,
/// und die Schale zeigt ihre Flaeche ohne Sitzung.
///
/// # Panics
///
/// Wenn der Wirt sich nicht starten laesst. Ein halb gestarteter Writer waere
/// kein Zustand, in dem weitergearbeitet werden darf.
pub fn run() {
    tauri::Builder::default()
        .manage(state::DesktopState::new(
            state::SessionState::new(None, None),
            None,
            None,
        ))
        .invoke_handler(tauri::generate_handler![
            commands::session::verified_session,
            commands::session::invalidate_session_on_lock,
            commands::session::startup_recovery,
            commands::master_data::master_data_counts
        ])
        .run(tauri::generate_context!())
        .expect("der Wirt der Writer-Oberflaeche liess sich nicht starten");
}

#[cfg(test)]
mod tests {
    use super::{COMMAND_NAMES, registered_command_names};

    /// Die Quellen der Kommandomodule, wie sie uebersetzt wurden.
    const COMMAND_SOURCES: [(&str, &str); 2] = [
        ("commands/session.rs", include_str!("commands/session.rs")),
        (
            "commands/master_data.rs",
            include_str!("commands/master_data.rs"),
        ),
    ];

    /// Diese Datei selbst — die Quelle der Registrierung.
    const HOST_SOURCE: &str = include_str!("lib.rs");

    /// Jedes Kommando, das eine Modulquelle DEKLARIERT.
    ///
    /// Die Marke wird aus zwei Teilen gefuegt, damit dieser Zeuge nicht sich
    /// selbst findet.
    fn declared_commands() -> Vec<String> {
        let marker = concat!("#[tauri::", "command]");
        let mut names = Vec::new();
        for (file, source) in COMMAND_SOURCES {
            for chunk in source.split(marker).skip(1) {
                let head = chunk.trim_start();
                assert!(
                    head.starts_with("pub async fn "),
                    "{file}: ein Kommando ohne `pub async fn` — dann laeuft sein Kern auf dem Main-Thread"
                );
                let rest = &head["pub async fn ".len()..];
                let name = rest
                    .split('(')
                    .next()
                    .expect("split liefert mindestens ein Stueck")
                    .trim()
                    .to_owned();
                assert!(
                    chunk.contains("run_blocking("),
                    "{file}: {name} fuehrt seinen Kern nicht ueber spawn_blocking aus"
                );
                names.push(name);
            }
        }
        names
    }

    /// Jeder Name, den der `invoke_handler` REGISTRIERT.
    fn registered_in_handler() -> Vec<String> {
        let marker = concat!("generate_handler", "![");
        let source = HOST_SOURCE;
        let start = source.find(marker).expect("die Registrierung fehlt") + marker.len();
        let end = start
            + source[start..]
                .find(']')
                .expect("die Registrierung ist nicht geschlossen");
        source[start..end]
            .split(',')
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(|path| {
                path.rsplit("::")
                    .next()
                    .expect("rsplit liefert mindestens ein Stueck")
                    .to_owned()
            })
            .collect()
    }

    /// Ohne diesen Zeugen koennten beide Zusicherungen darunter ueber LEERE
    /// Mengen laufen und gruen bleiben.
    #[test]
    fn reads_both_sides_it_compares() {
        assert!(!declared_commands().is_empty());
        assert!(!registered_in_handler().is_empty());
        assert!(!COMMAND_NAMES.is_empty());
    }

    /// Ein deklariertes, aber nicht registriertes Kommando ist von der
    /// Oberflaeche aus unerreichbar; ein registriertes, aber nicht in
    /// [`COMMAND_NAMES`] genanntes ist an keiner Stelle mehr aufgefuehrt.
    #[test]
    fn every_declared_command_is_registered_and_named() {
        let mut declared = declared_commands();
        declared.sort();
        let mut registered = registered_in_handler();
        registered.sort();
        let mut named: Vec<String> = COMMAND_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        named.sort();

        assert_eq!(declared, registered);
        assert_eq!(registered, named);
        assert_eq!(registered_command_names(), COMMAND_NAMES);
    }

    /// Die Namen sind eindeutig und in Schlangenschreibweise — die Drahtform,
    /// die `invoke` erwartet.
    #[test]
    fn every_command_name_is_unique_and_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for name in COMMAND_NAMES {
            assert!(seen.insert(*name), "{name} steht zweimal in der Liste");
            assert!(
                name.chars()
                    .all(|character| character.is_ascii_lowercase() || character == '_'),
                "{name} ist nicht in Schlangenschreibweise"
            );
        }
    }

    /// Der Desktop traegt keine Reader- und keine Verwaltungsflaeche, und
    /// dieser Zeuge haelt die Abwesenheit auf der Kommandoseite fest.
    #[test]
    fn no_command_serves_a_reader_or_an_administration_surface() {
        for name in COMMAND_NAMES {
            for forbidden in [
                "reader",
                "read_archive",
                "admin",
                "registry_edit",
                "history",
            ] {
                assert!(
                    !name.contains(forbidden),
                    "{name} bedient eine Flaeche, die dieser Ausbaustufe nicht gehoert"
                );
            }
        }
    }
}
