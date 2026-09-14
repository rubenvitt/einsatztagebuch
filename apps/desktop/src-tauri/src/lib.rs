#![forbid(unsafe_code)]
//! Der Wirt der Writer-Oberflaeche.
//!
//! Hier — und nur hier — lebt Async. Jeder `#[tauri::command]`-Rumpf schickt
//! seine synchrone Kernoperation ueber `tauri::async_runtime::spawn_blocking`
//! (`commands::run_blocking`), damit die fsync-schwere Finalisierung den
//! Main-Thread nicht blockiert. Der Rust-Kern unter `crates/` bleibt synchron.
//!
//! Die Anwendung traegt die Writer- und — seit Stufe 5, Task 6 (DRK-274) —
//! die Verwaltungsflaeche (`commands::admin`, siebzehn `admin_*`-Kommandos
//! hinter dem Rollentor `OrganizationAdmin` und der Faehigkeit
//! `administration`). Sie traegt KEINE Reader-Flaeche: der Reader ist eine
//! Browser-PWA. Deshalb steht in [`COMMAND_NAMES`] kein Kommando fuer ihn, und
//! `apps/desktop/src/app/role-gate.ts` traegt fuer ihn keine Route.

pub mod commands;
pub mod runtime;
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
/// Funktion und nicht `emit` allein. Der konfigurierte native Host beobachtet
/// die bereits installierte plattformgebundene Subscription kontinuierlich.
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
/// An explicit public operator configuration and independent anchor compose the
/// native session. The first proof still requires the user's login action.
///
/// # Panics
///
/// Wenn der Wirt sich nicht starten laesst. Ein halb gestarteter Writer waere
/// kein Zustand, in dem weitergearbeitet werden darf.
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let config = runtime::DesktopLaunchConfig::parse(std::env::args_os().skip(1))
                .map_err(|error| std::io::Error::other(error.code))?;
            let state = if let Some(config) = config {
                let native = runtime::NativeDesktopRuntime::open(config)
                    .map_err(|error| std::io::Error::other(error.code))?;
                let state = native.desktop_state();
                let handle = tauri::Manager::app_handle(app).clone();
                let monitor =
                    runtime::NativeSessionMonitor::start(native, state.clone(), move || {
                        let _ = tauri::Emitter::emit(&handle, SESSION_LOCK_EVENT, ());
                    });
                tauri::Manager::manage(app, monitor);
                state
            } else {
                state::DesktopState::new(
                    state::SessionState::new(None, None),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            };
            tauri::Manager::manage(app, state);
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::Destroyed)
                && let Some(monitor) =
                    tauri::Manager::try_state::<runtime::NativeSessionMonitor>(window)
            {
                monitor.stop();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::session::verified_session,
            commands::session::session_login,
            commands::session::invalidate_session_on_lock,
            commands::session::startup_recovery,
            commands::master_data::master_data_counts,
            commands::writer::session_reauthenticate,
            commands::writer::master_data_search,
            commands::writer::draft_load_active,
            commands::writer::draft_save,
            commands::writer::draft_discard_begin,
            commands::writer::draft_discard_resume,
            commands::writer::writer_recover_pending,
            commands::writer::writer_amendment_import,
            commands::writer::draft_save_amendment,
            commands::writer::writer_preview_amendment,
            commands::writer::writer_finalize_amendment,
            commands::writer::writer_acknowledge_stale_amendment,
            commands::writer::writer_preview,
            commands::writer::writer_acknowledge_stale_registry,
            commands::writer::writer_finalize,
            commands::writer::archive_health_report,
            commands::writer::device_posture_report,
            commands::writer::archive_export_bundle_file,
            commands::destruction::destruction_read,
            commands::destruction::destruction_prepare,
            commands::destruction::destruction_start,
            commands::destruction::destruction_resume,
            commands::destruction::destruction_import_progress,
            commands::destruction::destruction_export_reader_delivery,
            commands::destruction::destruction_synchronize,
            commands::destruction::destruction_authenticate_custodian,
            commands::destruction::destruction_mark_incomplete,
            commands::destruction_evidence::destruction_evidence_preview,
            commands::destruction_evidence::destruction_evidence_finalize,
            commands::destruction_evidence::destruction_evidence_recover,
            commands::destruction_evidence::destruction_evidence_discard,
            commands::recovery::recovery_read,
            commands::recovery::recovery_start,
            commands::recovery::recovery_submit,
            commands::recovery::recovery_cancel,
            commands::sync::sync_state,
            commands::admin::admin_pending_device_requests,
            commands::admin::admin_open_ceremonies,
            commands::admin::admin_ceremony_begin,
            commands::admin::admin_ceremony_read,
            commands::admin::admin_ceremony_confirm_fingerprint,
            commands::admin::admin_ceremony_authorize,
            commands::admin::admin_ceremony_export_request,
            commands::admin::admin_ceremony_import_reply,
            commands::admin::admin_ceremony_publish,
            commands::admin::admin_policy_profile,
            commands::admin::admin_registry_health,
            commands::admin::admin_writer_lock_diagnosis,
            commands::admin::admin_go_live_checklist,
            commands::admin::admin_go_live_export_unresolved,
            commands::admin::admin_clock_release_offer,
            commands::admin::admin_clock_release_issue,
            commands::admin::admin_writer_transition_state,
            commands::admin::admin_writer_transition_prepare,
            commands::admin::admin_writer_transition_activate,
            commands::admin::admin_revocation_effect
        ])
        .run(tauri::generate_context!())
        .expect("der Wirt der Writer-Oberflaeche liess sich nicht starten");
}

#[cfg(test)]
mod tests {
    use super::{COMMAND_NAMES, registered_command_names};

    /// Die Quellen der Kommandomodule, wie sie uebersetzt wurden.
    const COMMAND_SOURCES: [(&str, &str); 8] = [
        ("commands/session.rs", include_str!("commands/session.rs")),
        (
            "commands/master_data.rs",
            include_str!("commands/master_data.rs"),
        ),
        ("commands/sync.rs", include_str!("commands/sync.rs")),
        ("commands/writer.rs", include_str!("commands/writer.rs")),
        ("commands/admin.rs", include_str!("commands/admin.rs")),
        ("commands/recovery.rs", include_str!("commands/recovery.rs")),
        (
            "commands/destruction.rs",
            include_str!("commands/destruction.rs"),
        ),
        (
            "commands/destruction_evidence.rs",
            include_str!("commands/destruction_evidence.rs"),
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

    /// Die Quelle der Verwerfensflaeche.
    ///
    /// Dieselbe Bauart wie [`SESSION_LOCK_SOURCE`]: `include_str!` und nicht
    /// `fs::read_to_string`, damit ein Verschwinden der Datei die UEBERSETZUNG
    /// bricht und nicht bloss einen Zeugen rot faerbt.
    const DISCARD_ACTION_SOURCE: &str =
        include_str!("../../src/features/writer/DiscardDraftAction.tsx");

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

    /// Die Oberflaeche kennt JEDEN Phasencode, zu dem es nichts fortzusetzen
    /// gibt — beim Namen, den der WIRT vergibt.
    ///
    /// Zwei Sprachen, eine Wahrheit: `phaseCode` ist am Draht eine freie
    /// Zeichenkette, und `ea-ui-contracts` emittiert dafuer keine Vereinigung,
    /// die `no-hand-written-contracts.test.ts` bewachen koennte. Ohne diesen
    /// Zeugen liefen die Literale der Schale und
    /// `commands::writer::restart_state_code` auseinander, ohne dass irgendetwas
    /// rot wird: die Schale fiele auf ihren Sammelzweig zurueck und schriebe
    /// „Verwerfen gebucht — die Fortsetzung steht aus" ueber einen
    /// unveraenderten Entwurf, samt einer Handhabe, die nichts fortsetzen kann.
    ///
    /// Die drei Ausgaenge sind hier ausgeschrieben und nicht aus einer
    /// Konstanten gelesen, weil `ea_draft::RestartState` kein `ALL` traegt; ein
    /// vierter Ausgang bricht dafuer den Sammelzweig-freien `match` in
    /// `restart_state_code` und faellt dort auf.
    #[test]
    fn the_shell_names_every_discard_phase_without_a_continuation() {
        use ea_draft::RestartState;

        let mut checked = 0_usize;
        for state in [
            RestartState::NewBlankDraft,
            RestartState::OriginalDraftUnchanged,
            RestartState::PreparedFinalizationPending,
        ] {
            let view = crate::commands::writer::discard_view(state);
            if view.complete {
                continue;
            }
            checked += 1;
            assert!(
                DISCARD_ACTION_SOURCE.contains(&format!("'{}'", view.phase_code)),
                "DiscardDraftAction.tsx nennt den Phasencode {} nicht",
                view.phase_code
            );
        }
        // Ohne diese Zusicherung liefe die Schleife ueber die leere Menge, wenn
        // eines Tages jeder Ausgang `complete` waere — und der Zeuge bliebe
        // gruen, ohne etwas zu vergleichen.
        assert_eq!(checked, 2, "genau zwei Ausgaenge tragen keine Fortsetzung");
    }

    /// Der Desktop traegt keine Reader-Flaeche, und dieser Zeuge haelt die
    /// Abwesenheit auf der Kommandoseite fest.
    ///
    /// Die VERWALTUNGSFLAECHE ist mit Stufe 5, Task 6 (DRK-274) angekommen und
    /// steht deshalb nicht mehr in dieser Verbotsliste: jedes `admin_*`-Kommando
    /// ist in `commands::admin` auf die Rolle `OrganizationAdmin` und in
    /// `commands::session::capabilities_of` auf die Faehigkeit
    /// `administration` gebunden. `registry_edit` bleibt verboten — eine
    /// Registry wird ueber eine Zeremonie in Schritten VEROEFFENTLICHT und nie
    /// editiert.
    ///
    /// GENAU EINE Ausnahme vom Wort `reader`, beim vollen Namen und fuer kein
    /// anderes Verbotswort: `destruction_export_reader_delivery` (Stufe 5,
    /// Task 13, Plan-Nachmessung 2026-09-13) ist KEINE Reader-Leseflaeche. Es
    /// ist ein Vernichtungskommando der Verwaltung — an `OrganizationAdmin`
    /// gebunden (`tests/reader_delivery_commands.rs`), in der Oberflaeche nur
    /// unter `/verwaltung` erreichbar — und gibt drei UNVERAENDERTE oeffentliche
    /// Originale (Authorization-ETB, Started-ETB, `DestructionJobUploadV1`)
    /// heraus, die ein Reader zum Vollzug braucht. Es entschluesselt nichts,
    /// liest kein Archiv und zeigt keinen Klartext; die Administrationsrolle
    /// verleiht weiterhin keinen Inhaltszugriff (`web-reader-design.md` §3).
    /// Jeder weitere Name mit `reader` faellt hier weiter.
    #[test]
    fn no_command_serves_a_reader_surface() {
        const READER_DELIVERY_EXPORT: &str = "destruction_export_reader_delivery";
        // Die Ausnahme ist registriert — sonst stuende hier eine Freigabe fuer
        // einen Namen, den niemand mehr misst.
        assert!(COMMAND_NAMES.contains(&READER_DELIVERY_EXPORT));
        for name in COMMAND_NAMES {
            for forbidden in ["reader", "read_archive", "registry_edit", "history"] {
                if forbidden == "reader" && *name == READER_DELIVERY_EXPORT {
                    continue;
                }
                assert!(
                    !name.contains(forbidden),
                    "{name} bedient eine Flaeche, die dieser Ausbaustufe nicht gehoert"
                );
            }
        }
    }

    /// Die Verwaltungsflaeche ist GENAU der Vertrag aus
    /// `.superpowers/admin-ui-contract.md` §5: siebzehn Namen, jeder einmal, in
    /// dieser Reihenfolge hinter `sync_state`.
    ///
    /// Ausgeschrieben und nicht aus `commands::admin` abgeleitet: der Zeuge
    /// misst die Registrierung gegen den Vertrag, den die Schale liest, und
    /// nicht gegen die Quelle, die er bewacht.
    #[test]
    fn every_administration_command_is_named_exactly_once_and_matches_the_contract() {
        const CONTRACT: [&str; 20] = [
            "admin_pending_device_requests",
            "admin_open_ceremonies",
            "admin_ceremony_begin",
            "admin_ceremony_read",
            "admin_ceremony_confirm_fingerprint",
            "admin_ceremony_authorize",
            "admin_ceremony_export_request",
            "admin_ceremony_import_reply",
            "admin_ceremony_publish",
            "admin_policy_profile",
            "admin_registry_health",
            "admin_writer_lock_diagnosis",
            "admin_go_live_checklist",
            "admin_go_live_export_unresolved",
            "admin_clock_release_offer",
            "admin_clock_release_issue",
            "admin_writer_transition_state",
            "admin_writer_transition_prepare",
            "admin_writer_transition_activate",
            "admin_revocation_effect",
        ];
        let registered: Vec<&str> = COMMAND_NAMES
            .iter()
            .copied()
            .filter(|name| name.starts_with("admin_"))
            .collect();
        assert_eq!(registered, CONTRACT);
        for name in CONTRACT {
            assert_eq!(
                COMMAND_NAMES.iter().filter(|entry| **entry == name).count(),
                1,
                "{name} steht nicht genau einmal in COMMAND_NAMES"
            );
        }
        let sync_at = COMMAND_NAMES
            .iter()
            .position(|name| *name == "sync_state")
            .expect("sync_state fehlt");
        assert_eq!(&COMMAND_NAMES[sync_at + 1..], &CONTRACT[..]);
    }
}
