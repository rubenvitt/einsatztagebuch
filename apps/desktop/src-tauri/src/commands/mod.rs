//! Die EINE Registrierungsstelle der Kommandos.
//!
//! Jedes Kommandomodul ist hier erklaert, und [`COMMAND_NAMES`] nennt jeden
//! registrierten Namen. Task 16 fuegt `mod writer;` und seine Namen hier hinzu
//! und nirgends sonst; der Zeuge in `crate` liest beide Seiten aus der Quelle
//! und faellt, sobald eine der drei Listen auseinanderlaeuft.

pub mod master_data;
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

/// Jeder Name, den [`crate::run`] registriert — in Registrierungsreihenfolge.
pub const COMMAND_NAMES: &[&str] = &[
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
