//! Die EINE Registrierungsstelle der Kommandos.
//!
//! Jedes Kommandomodul ist hier erklaert, und [`COMMAND_NAMES`] nennt jeden
//! registrierten Namen. Task 16 fuegt `mod writer;` und seine Namen hier hinzu
//! und nirgends sonst; der Zeuge in `crate` liest beide Seiten aus der Quelle
//! und faellt, sobald eine der drei Listen auseinanderlaeuft.

pub mod master_data;
pub mod session;

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
/// Der Blockierthread ist verlorengegangen.
pub const BLOCKING_WORK_LOST: &str = "EA-DESKTOP-BLOCKING-WORK-LOST";

/// Jeder Name, den [`crate::run`] registriert — in Registrierungsreihenfolge.
pub const COMMAND_NAMES: &[&str] = &[
    "verified_session",
    "invalidate_session_on_lock",
    "startup_recovery",
    "master_data_counts",
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
