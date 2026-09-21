//! FIXTURE-WIRT OHNE NATIVE SICHERHEITSKETTE.
//!
//! Ruling A (DRK-437, 2026-09-20): eine Fixture-Variante ohne native Kette
//! existiert ausschließlich hinter `test-support` und ist aus einem
//! Produktivbau nicht auswählbar. Dies ist sie — ein EIGENES Programm, kein
//! Zweig in `ea_desktop::run()`. Der ausgelieferte Wirt (`src/main.rs`) ruft
//! weiter immer `NativeOperatorProvider::open_installed`.
//!
//! Was hier fehlt, fehlt wirklich: kein signierter, installierter Helfer, keine
//! Identitätsprüfung des Helferprozesses, kein Schlüsselbund, keine
//! Anwesenheitsprüfung, keine Beobachtung der Bildschirmsperre. Alle
//! Schlüssel sind Quelltextkonstanten der Demowelt. Das Programm dient der
//! Handprobe der Oberfläche gegen `xtask seed-demo` — nichts anderem.
//!
//! Startflags wie beim echten Wirt: `--operator-config`, `--trust-anchor` und
//! `--writer-config` ODER `--administration-config`. Die zwei schließen sich am
//! Wirt aus; Writer und Verwaltung sind deshalb zwei Prozesse.
//!
//! Bewusst OHNE `windows_subsystem = "windows"`: das Konsolenfenster trägt den
//! Fixture-Hinweis und jede Fehlermeldung beim Start.

mod fixture;

use ea_desktop::{SESSION_LOCK_EVENT, commands, runtime};

const BANNER: &str = "\
========================================================================
  FIXTURE-ANWENDUNG OHNE NATIVE SICHERHEITSKETTE
  ea-desktop-fixture ist NICHT der ausgelieferte Wirt. Kein signierter
  Helfer, keine Identitätsprüfung, kein Schlüsselbund, keine
  Anwesenheits- und keine Sperrprüfung. Alle Schlüssel sind öffentlich
  bekannte Konstanten der Demowelt. Nur für die Handprobe gegen
  `xtask seed-demo` – nie gegen echte Daten.
========================================================================";

const USAGE: &str = "\
ea-desktop-fixture --operator-config <station>/operator.json \\
                   --trust-anchor <demowelt>/fixture-demo-trust-anchor.etb \\
                   (--writer-config <station>/writer.json | \\
                    --administration-config <station>/administration.json)";

fn fail(reason: &str) -> ! {
    eprintln!("ABBRUCH: {reason}");
    std::process::exit(1);
}

fn main() {
    eprintln!("{BANNER}");
    let launch = match runtime::DesktopLaunchConfig::parse(std::env::args_os().skip(1)) {
        Ok(Some(launch)) => launch,
        Ok(None) => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("{}\n{USAGE}", error.code);
            std::process::exit(2);
        }
    };
    let station_label = match (&launch.writer_config, &launch.administration_config) {
        (Some(_), None) => "Writer",
        (None, Some(_)) => "Verwaltung",
        _ => {
            eprintln!("genau eines von --writer-config und --administration-config\n{USAGE}");
            std::process::exit(2);
        }
    };
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| fail(&format!("der eigene Pfad ist nicht bestimmbar: {error}")));
    let source = executable
        .parent()
        .unwrap_or_else(|| fail("das Programm liegt in keinem Verzeichnis"))
        .join(fixture::HELPER_BUILD_NAME);
    let station = fixture::station_directory(&launch).unwrap_or_else(|reason| fail(&reason));
    let helper = fixture::install_helper(&source, &station).unwrap_or_else(|reason| fail(&reason));
    eprintln!("Station    : {station_label}");
    eprintln!("Verzeichnis: {}", station.display());
    eprintln!("Helfer     : {} (FIXTURE)", helper.display());
    let native =
        fixture::open_fixture_runtime(launch, &helper).unwrap_or_else(|reason| fail(&reason));
    eprintln!("Laufzeit offen. Die Sitzung beginnt mit der Anmeldung im Fenster.");
    let title = format!("FIXTURE ohne native Sicherheitskette – Einsatzarchiv {station_label}");

    tauri::Builder::default()
        .setup(move |app| {
            let state = native.desktop_state();
            let handle = tauri::Manager::app_handle(app).clone();
            let monitor = runtime::NativeSessionMonitor::start(native, state.clone(), move || {
                let _ = tauri::Emitter::emit(&handle, SESSION_LOCK_EVENT, ());
            });
            tauri::Manager::manage(app, monitor);
            tauri::Manager::manage(app, state);
            // Das Fenster behält das Etikett `main`: die Erlaubnisliste in
            // `tauri.conf.json` gilt nur für `main`.
            if let Some(window) = tauri::Manager::get_webview_window(app, "main") {
                let _ = window.set_title(&title);
            }
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
        // Zeichengleich mit der Liste in `ea_desktop::run()`; der Zeuge
        // `the_fixture_host_registers_exactly_the_shipped_command_list` in
        // `tests/fixture_demo_world.rs` vergleicht beide Quelltexte.
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
        .expect("der Fixture-Wirt ließ sich nicht starten");
}
