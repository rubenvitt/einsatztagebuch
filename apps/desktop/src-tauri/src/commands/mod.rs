//! Die EINE Registrierungsstelle der Kommandos.
//!
//! Jedes Kommandomodul ist hier erklaert, und [`COMMAND_NAMES`] nennt jeden
//! registrierten Namen. Task 16 hat `mod writer;` und seine Namen hier
//! hinzugefuegt, Stufe 5 Task 6 (DRK-274) `mod admin;` und die siebzehn Namen
//! der Verwaltungsflaeche — hier und nirgends sonst; der Zeuge in `crate` liest
//! beide Seiten aus der Quelle und faellt, sobald eine der drei Listen
//! auseinanderlaeuft.

pub mod admin;
pub mod destruction;
pub mod destruction_evidence;
pub mod master_data;
pub mod recovery;
pub mod session;
pub mod sync;
pub mod writer;

use serde::Serialize;

/// Ein Fehlschlag an der Kommandogrenze — ein CODE und kein Fliesstext.
///
/// Die Oberflaeche zeigt ihren eigenen Wortlaut; ein durchgereichter
/// Fehlertext waere ein zweiter, unuebersetzter Kanal, und ein Fehlertext aus
/// dem Kern koennte einen Pfad oder eine Kennung nennen.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CommandError {
    pub code: &'static str,
}

impl CommandError {
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

/// Es gilt keine Bedienerbindung mit frischer Praesenz.
pub const NO_VERIFIED_SESSION: &str = "EA-DESKTOP-NO-VERIFIED-SESSION";
/// Das Schloss der Sitzung ist vergiftet — fail-closed.
pub const SESSION_STATE_UNREADABLE: &str = "EA-DESKTOP-SESSION-STATE-UNREADABLE";
/// Kein Startpfad verdrahtet.
pub const STARTUP_RECOVERY_UNAVAILABLE: &str = "EA-DESKTOP-STARTUP-RECOVERY-UNAVAILABLE";
/// Der Startpfad hat abgelehnt.
pub const STARTUP_RECOVERY_FAILED: &str = "EA-DESKTOP-STARTUP-RECOVERY-FAILED";
/// Keine geoeffnete Stammdatenablage.
pub const MASTER_DATA_UNAVAILABLE: &str = "EA-DESKTOP-MASTER-DATA-UNAVAILABLE";
/// Die Stammdatenablage hat abgelehnt.
pub const MASTER_DATA_UNREADABLE: &str = "EA-DESKTOP-MASTER-DATA-UNREADABLE";
/// Keine geoeffnete Entwurfsablage.
pub const DRAFTS_UNAVAILABLE: &str = "EA-DESKTOP-DRAFTS-UNAVAILABLE";
/// Kein Bestand fuer den Gesundheitscheck geoeffnet.
pub const ARCHIVE_HEALTH_UNAVAILABLE: &str = "EA-DESKTOP-ARCHIVE-HEALTH-UNAVAILABLE";
/// Kein aufgeloester `WriterService` auf diesem Geraet.
pub const WRITER_UNAVAILABLE: &str = "EA-DESKTOP-WRITER-UNAVAILABLE";
/// Keine native Wiederanmeldung aufgeloest.
pub const REAUTH_UNAVAILABLE: &str = "EA-DESKTOP-REAUTH-UNAVAILABLE";
/// Der Bestaetigungspfad des veralteten Head existiert im Kern nicht.
pub const STALE_ACK_UNAVAILABLE: &str = "EA-DESKTOP-STALE-ACK-UNAVAILABLE";
/// Kein Verwerfensdienst aufgeloest.
pub const DISCARD_UNAVAILABLE: &str = "EA-DESKTOP-DISCARD-UNAVAILABLE";
/// Die Nutzlast des Entwurfs ist keine Erfassung dieser Grenze.
///
/// Sie liegt entsiegelt vor und ist trotzdem nicht lesbar: dann ist sie von
/// einer anderen Fassung dieser Anwendung geschrieben worden. Ein leerer Rumpf
/// waere hier die stille Loeschung einer Erfassung.
pub const DRAFT_PAYLOAD_UNREADABLE: &str = "EA-DESKTOP-DRAFT-PAYLOAD-UNREADABLE";
/// Dieser Wirt hat keine Vorschau ausgestellt, gegen die bestaetigt werden kann.
pub const PREVIEW_NOT_ISSUED: &str = "EA-DESKTOP-PREVIEW-NOT-ISSUED";
/// Die bestaetigte Vorschau ist nicht die ausgestellte.
pub const PREVIEW_MISMATCH: &str = "EA-DESKTOP-PREVIEW-MISMATCH";
/// Kein aufgeloester Vertrauensanker fuer den Buendelexport.
pub const BUNDLE_EXPORT_UNAVAILABLE: &str = "EA-DESKTOP-BUNDLE-EXPORT-UNAVAILABLE";
/// Der Blockierthread ist verlorengegangen.
pub const BLOCKING_WORK_LOST: &str = "EA-DESKTOP-BLOCKING-WORK-LOST";
/// Kein aufgeloester Sync-Zustandsport auf diesem Geraet.
pub const SYNC_STATE_UNAVAILABLE: &str = "EA-DESKTOP-SYNC-STATE-UNAVAILABLE";
/// Kein aufgeloester Verwaltungsport auf diesem Geraet (Stufe 5, Task 6).
///
/// Die vier Workflow-Dienste aus `ea-admin` verlangen einen gewaehlten Head,
/// einen Trust-Speicher, den Schluesselport und einen Nachweis; bis zur
/// Verdrahtung antwortet jedes `admin_*`-Kommando mit diesem Code.
pub const ADMINISTRATION_UNAVAILABLE: &str = "EA-DESKTOP-ADMINISTRATION-UNAVAILABLE";
/// Die Sitzung traegt nicht die Rolle `OrganizationAdmin`.
///
/// Ein Writer, ein Reader und eine fehlende Sitzung bekommen denselben Code:
/// keiner von ihnen ist ein Administrator, und die Schale erfaehrt die
/// fehlende Sitzung ohnehin aus `verified_session` und nicht aus einem
/// Verwaltungskommando.
pub const ADMINISTRATION_FORBIDDEN: &str = "EA-DESKTOP-ADMINISTRATION-FORBIDDEN";
/// Ein Drahtwort, das in keiner emittierten Vereinigung steht — die
/// Zeremonieart, die Begruendung einer Uhrenfreigabe oder ein Zielhash, der
/// kein Hash ist. Kein Vorgabewert: ein fremdes Wort ist keine Wahl.
pub const ADMINISTRATION_WIRE_VALUE: &str = "EA-DESKTOP-ADMINISTRATION-WIRE-VALUE";
/// Der Schritt verlangt eine FRISCHE Wiederanmeldung fuer genau seinen
/// Zweck, und die Sitzung traegt keine unverbrauchte Marke dafuer.
///
/// `AdminAuthorized` und `RegistryPublished` (`ea_admin::ceremony_steps::
/// requires_fresh_reauth`) sowie die Aktivierung des Writer-Uebergangs
/// verlangen `AdminRootCeremony`; die Uhrenfreigabe verlangt
/// `ClockSkewRelease`. Die Schale ruft `session_reauthenticate` mit dem
/// Zweck und wiederholt den Schritt.
pub const REAUTH_REQUIRED: &str = "EA-DESKTOP-REAUTH-REQUIRED";
/// Der Zweck der Wiederanmeldung ist kein `ReauthPurpose::label()`.
pub const REAUTH_PURPOSE_UNKNOWN: &str = "EA-DESKTOP-REAUTH-PURPOSE-UNKNOWN";
/// Ein Zeremonieschritt ausser der Reihe — verlangt von der Schale oder
/// behauptet vom Port.
///
/// Die Grenze prueft beides gegen `ea_admin::ceremony_steps::next_step`: der
/// verlangte Schritt muss der EINE Nachfolger des erreichten sein, und der
/// Port muss danach genau diesen erreicht haben. Ein Sprung oder ein
/// Rueckfall wird nicht hingenommen.
pub const CEREMONY_STEP_OUT_OF_ORDER: &str = "EA-DESKTOP-CEREMONY-STEP-OUT-OF-ORDER";
/// Die Aktivierung des Writer-Uebergangs verlangt den Stand `Prepared` — und
/// die Grenze liest ihn VOR der Praesenz.
///
/// Ohne vorbereiteten Uebergang (`NoTransition`) oder nach einer Aktivierung
/// (`Activated`) gibt es nichts zu aktivieren; der Kern lehnte ohnehin ab
/// (`EA-TRANSITION-*`). Wuerde die Frischemarke davor verbraucht, muesste
/// sich der Administrator fuer einen Schritt neu anmelden, den es nicht gibt.
/// Dieselbe Reihenfolge wie bei einer Zeremonie: Reihenfolge vor Praesenz,
/// Praesenz vor dem Port. Der Stand kommt vom Port, der Code von hier.
pub const TRANSITION_NOT_PREPARED: &str = "EA-DESKTOP-TRANSITION-NOT-PREPARED";

/// Jeder Name, den [`crate::run`] registriert — in Registrierungsreihenfolge.
pub const COMMAND_NAMES: &[&str] = &[
    "verified_session",
    "session_login",
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
    "writer_amendment_import",
    "draft_save_amendment",
    "writer_preview_amendment",
    "writer_finalize_amendment",
    "writer_acknowledge_stale_amendment",
    "writer_preview",
    "writer_acknowledge_stale_registry",
    "writer_finalize",
    "archive_health_report",
    "device_posture_report",
    "archive_export_bundle_file",
    "destruction_read",
    "destruction_prepare",
    "destruction_start",
    "destruction_resume",
    "destruction_import_progress",
    "destruction_export_reader_delivery",
    "destruction_synchronize",
    "destruction_authenticate_custodian",
    "destruction_evidence_preview",
    "destruction_evidence_finalize",
    "destruction_evidence_recover",
    "destruction_evidence_discard",
    "recovery_read",
    "recovery_start",
    "recovery_submit",
    "recovery_cancel",
    "sync_state",
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

/// Fuehrt die SYNCHRONE Kernoperation auf einem Blockierthread aus.
///
/// Die EINE Stelle, an der das geschieht. Die fsync-schwere Finalisierung
/// (`design.md`:446-462) darf den Main-Thread nicht blockieren, und ein
/// Kommandorumpf, der seinen Kern direkt aufruft, tut genau das. Der Zeuge in
/// `crate` liest die Quellen der Kommandomodule und verlangt diesen Aufruf in
/// jedem Rumpf.
pub(crate) async fn run_blocking<T, F>(work: F) -> Result<T, CommandError>
where
    F: FnOnce() -> Result<T, CommandError> + Send + 'static,
    T: Send + 'static,
{
    match tauri::async_runtime::spawn_blocking(work).await {
        Ok(result) => result,
        Err(_) => Err(CommandError::new(BLOCKING_WORK_LOST)),
    }
}
