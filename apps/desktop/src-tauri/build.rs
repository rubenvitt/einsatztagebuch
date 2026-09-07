// `tauri_build` liest `src-tauri/tauri.conf.json` und erzeugt daraus die ACL-
// und Kontextbeiwerke, die `tauri::generate_context!` in `src/lib.rs` einliest.
//
// # Warum ein App-ACL-Manifest
//
// Ohne erklaertes App-Manifest umgehen die Kommandos aus `generate_handler!`
// die Zugriffsliste vollstaendig: `tauri-2.11.5/src/webview/mod.rs` prueft ein
// Kommando nur, wenn es ein Plugin-Kommando ist, die Herkunft entfernt ist ODER
// die Anwendung ein eigenes Manifest fuehrt (`has_app_acl_manifest`). Mit
// diesem Manifest gilt die Erlaubnisliste aus `tauri.conf.json` fuer JEDES
// Kommando dieses Pakets — und eine Erlaubnis, die kein Kommando von hier
// benennt, laesst `tauri::generate_context!` mit `UnknownPermission`
// abbrechen. Die zwei Listen koennen deshalb nicht auseinanderlaufen, ohne dass
// der Bau oder die Laufzeit es sagt.
//
// Die Liste steht hier ein zweites Mal, weil ein Bauskript vor seiner eigenen
// Crate uebersetzt und `ea_desktop::COMMAND_NAMES` nicht importieren kann. Der
// Zeuge `the_app_acl_manifest_declares_every_registered_command` in
// `tests/writer_commands.rs` liest DIESE Quelle und vergleicht sie mit der
// registrierten Menge.
const EA_COMMANDS: &[&str] = &[
    "verified_session",
    "invalidate_session_on_lock",
    "startup_recovery",
    "master_data_counts",
    "session_reauthenticate",
    "master_data_search",
    "draft_load_active",
    "draft_save",
    "draft_discard_begin",
    "draft_discard_resume",
    "writer_recover_pending",
    "writer_preview",
    "writer_acknowledge_stale_registry",
    "writer_finalize",
    "archive_health_report",
    "device_posture_report",
    "archive_export_bundle_file",
    "sync_state",
    "admin_pending_device_requests",
    "admin_ceremony_begin",
    "admin_ceremony_confirm_fingerprint",
    "admin_ceremony_authorize",
    "admin_ceremony_export_request",
    "admin_ceremony_import_reply",
    "admin_ceremony_publish",
    "admin_policy_profile",
    "admin_registry_health",
    "admin_go_live_checklist",
    "admin_go_live_export_unresolved",
    "admin_clock_release_offer",
    "admin_clock_release_issue",
    "admin_writer_transition_state",
    "admin_writer_transition_prepare",
    "admin_writer_transition_activate",
    "admin_revocation_effect",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(EA_COMMANDS)),
    )
    .expect("die ACL- und Kontextbeiwerke des Wirts liessen sich nicht erzeugen");
}
