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

/// Das Ereignis, mit dem der Wirt eine Sperre oder einen Sitzungswechsel des
/// Betriebssystems an die Oberflaeche meldet.
///
/// Zeichengleich mit `SESSION_LOCK_EVENT` in
/// `apps/desktop/src/app/session-lock.ts`; der Zeuge unten liest die
/// TypeScript-Quelle und vergleicht sie mit dieser Konstante.
pub const SESSION_LOCK_EVENT: &str = "ea://session-lock";

/// Jeder Kommandoname, den [`run`] registriert.
#[must_use]
pub fn registered_command_names() -> &'static [&'static str] {
    COMMAND_NAMES
}

/// Die EINE Stelle, an der eine Sperre des Betriebssystems wirkt.
///
/// Die Reihenfolge IST die Zusage: zuerst entwertet der Wirt seine Sitzung,
/// danach erfaehrt die Oberflaeche davon. Umgekehrt gaebe es ein Fenster, in dem
/// die Webview neu laedt und `verified_session` noch eine gueltige Sitzung
/// liefert, obwohl der Bildschirm gesperrt war. Das Kommando
/// `invalidate_session_on_lock`, das die Oberflaeche danach ruft, ist deshalb
/// nur die VERSTAERKUNG und nie die einzige Wirkung.
///
/// Wer das Sperrsignal der Plattform beobachtet — Windows-Sitzungswechsel,
/// macOS-Screen-Lock-Notification, Ubuntu-Sitzungsmanager —, ruft genau diese
/// Funktion und nicht `emit` allein. Der Beobachter selbst fehlt noch: er
/// braucht plattformnahe Abhaengigkeiten, die dieser Task nicht ziehen darf.
pub fn honor_session_lock(state: &state::DesktopState, announce: impl FnOnce()) {
    state.invalidate_session_on_lock();
    announce();
}

/// [`honor_session_lock`] mit dem Melder des Wirts.
///
/// Die Zeile, die ein Plattformbeobachter aufruft. Ein Fehlschlag des `emit`
/// aendert die Entwertung nicht mehr — sie ist zu diesem Zeitpunkt geschehen —
/// und die Oberflaeche faellt beim naechsten `verified_session` ohnehin auf ihre
/// Flaeche ohne Sitzung zurueck.
pub fn announce_session_lock<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let state = tauri::Manager::state::<state::DesktopState>(app);
    honor_session_lock(state.inner(), || {
        let _ = tauri::Emitter::emit(app, SESSION_LOCK_EVENT, ());
    });
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

    /// Die Faehigkeitserklaerung des Fensters, wie sie eingecheckt ist.
    ///
    /// `include_str!` und nicht `fs::read_to_string`: verschwindet die Datei,
    /// UEBERSETZT dieses Paket nicht mehr. Ein Zeuge, der sie zur Laufzeit liest,
    /// waere in einem Baum ohne sie bloss rot — und `gen/schemas/capabilities.json`
    /// waere wieder `{}`, also die ACL, unter der `listen()` verweigert wird.
    const CAPABILITY_SOURCE: &str = include_str!("../capabilities/default.json");

    /// Die Wirtskonfiguration, aus der das Fensterlabel kommt.
    const TAURI_CONF_SOURCE: &str = include_str!("../tauri.conf.json");

    /// Die Quelle der Sperrpflicht der Oberflaeche.
    const SESSION_LOCK_SOURCE: &str = include_str!("../../src/app/session-lock.ts");

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

    /// Die Faehigkeitserklaerung deckt GENAU das Fenster, das die
    /// Konfiguration erklaert.
    ///
    /// Quelle gegen Quelle und nicht Konstante gegen Konstante: das Label steht
    /// in `tauri.conf.json`, die Fensterliste in `capabilities/default.json`.
    /// Deckt die Erklaerung ein anderes Fenster, greift die ACL fuer das
    /// erzeugte nicht — und `listen()` in `session-lock.ts` ist verweigert, ohne
    /// dass irgendetwas rot wird.
    #[test]
    fn the_capability_covers_the_window_the_configuration_declares() {
        let capability: serde_json::Value = serde_json::from_str(CAPABILITY_SOURCE)
            .expect("die Faehigkeitserklaerung ist kein JSON");
        let conf: serde_json::Value =
            serde_json::from_str(TAURI_CONF_SOURCE).expect("die Wirtskonfiguration ist kein JSON");
        let windows = conf["app"]["windows"]
            .as_array()
            .expect("die Konfiguration erklaert kein Fenster");
        assert!(!windows.is_empty());
        let covered = capability["windows"]
            .as_array()
            .expect("die Faehigkeitserklaerung nennt keine Fensterliste");
        assert!(!covered.is_empty());
        for window in windows {
            let label = window["label"]
                .as_str()
                .expect("jedes Fenster traegt ein AUSGESCHRIEBENES Label, damit dieser Vergleich keinen Vorgabewert raten muss");
            assert!(
                covered.iter().any(|entry| entry.as_str() == Some(label)),
                "das Fenster {label} traegt keine Faehigkeitserklaerung"
            );
        }
    }

    /// Der Wirt und die Oberflaeche nennen DASSELBE Sperrereignis.
    ///
    /// Zwei Zeichenketten in zwei Sprachen: laeuft eine davon fort, meldet der
    /// Wirt in ein Ereignis, auf das niemand hoert — und die Sperrpflicht faellt
    /// still aus.
    #[test]
    fn the_shell_listens_to_the_event_the_host_announces() {
        assert!(
            SESSION_LOCK_SOURCE.contains(&format!("'{}'", super::SESSION_LOCK_EVENT)),
            "session-lock.ts nennt {} nicht",
            super::SESSION_LOCK_EVENT
        );
        assert!(
            SESSION_LOCK_SOURCE.contains("'invalidate_session_on_lock'"),
            "session-lock.ts ruft das Verstaerkungskommando nicht"
        );
        assert!(COMMAND_NAMES.contains(&"invalidate_session_on_lock"));
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
