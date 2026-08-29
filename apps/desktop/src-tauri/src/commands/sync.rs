//! Das EINE Sync-Kommando dieser Stufe: der Zustand, nie das Auslösen.
//!
//! # Warum es nur LIEST
//!
//! `SyncClient::push_pending` gehoert an einen Hintergrundlauf und nicht an
//! einen Knopf: die Warteschlange arbeitet die Kette in ihrer Reihenfolge ab,
//! sie wartet zwischen den Versuchen die begrenzte Wiederaufnahmezeit ab, und
//! ein Kommando, das sie von aussen anstiesse, waere ein zweiter Ausloeser
//! neben jenem Lauf. Die Oberflaeche fragt deshalb nach dem ZUSTAND — und der
//! entsteht, wie alles in dieser Stufe, aus committeten Archivbytes und dem
//! dauerhaften Wiederaufnahmezustand.
//!
//! # Warum es trotzdem `run_blocking` benutzt
//!
//! Weil sein Kern SYNCHRON ist: die Ableitung liest den Bestand auf dem
//! Wirtdateisystem und die lokale verschluesselte Ablage. Beides gehoert nicht
//! auf den Main-Thread, und der Zeuge in `crate` verlangt den Aufruf in jedem
//! Kommandorumpf.
//!
//! # Benannte Abwesenheit
//!
//! Solange dieses Geraet keinen aufgeloesten Sync-Port hat, ist KEIN Port
//! verdrahtet, und die Abwesenheit sitzt genau dort — am fehlenden Port und
//! nicht an einer fehlenden Zeile. Ein Vorgabewert waere hier die Behauptung
//! `synchronisiert` ueber einen Bestand, ueber den nichts bekannt ist.

use ea_ui_contracts::SyncStateView;
use serde::{Deserialize, Serialize};

use super::{CommandError, SYNC_STATE_UNAVAILABLE, run_blocking};
use crate::state::{DesktopState, SyncStatePort};

/// Die Drahtform von [`SyncStateView`].
///
/// `rename_all = "camelCase"` wie jede andere: sie ist die EINE Serialisierung
/// ihres Ansichtsmodells aus `ea-ui-contracts` und deklariert kein zweites.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStateDto {
    pub status: &'static str,
    pub detail_cause: Option<&'static str>,
}

impl From<&SyncStateView> for SyncStateDto {
    fn from(view: &SyncStateView) -> Self {
        Self {
            status: view.status.label(),
            detail_cause: view.detail_cause.map(ea_archive_fs::DetailCause::label),
        }
    }
}

/// Der Sync-Zustand dieses Geraets.
///
/// # Errors
///
/// [`SYNC_STATE_UNAVAILABLE`], wenn kein Sync-Port aufgeloest ist oder er
/// ablehnt.
#[tauri::command]
pub async fn sync_state(
    state: tauri::State<'_, DesktopState>,
) -> Result<SyncStateDto, CommandError> {
    let port = state.inner().sync_state_port();
    run_blocking(move || sync_state_core(port.as_deref())).await
}

/// Der Kern von [`sync_state`].
fn sync_state_core(
    port: Option<&(dyn SyncStatePort + Send + Sync)>,
) -> Result<SyncStateDto, CommandError> {
    let view = port
        .ok_or_else(|| CommandError::new(SYNC_STATE_UNAVAILABLE))?
        .sync_state()
        .map_err(|_| CommandError::new(SYNC_STATE_UNAVAILABLE))?;
    Ok(SyncStateDto::from(&view))
}

#[cfg(test)]
mod tests {
    use super::{SyncStateDto, sync_state_core};
    use crate::state::SyncStatePort;
    use ea_ui_contracts::SyncStateView;

    struct FixedPort(SyncStateView);

    impl SyncStatePort for FixedPort {
        fn sync_state(&self) -> Result<SyncStateView, ea_archive::ArchiveBackendError> {
            Ok(self.0)
        }
    }

    /// Ohne aufgeloesten Port gibt es einen CODE und keinen Vorgabewert.
    ///
    /// Ein Vorgabewert waere hier die Behauptung, ueber den Bestand sei etwas
    /// bekannt — und die freundlichste Behauptung waere zufaellig
    /// `synchronisiert`.
    #[test]
    fn an_unresolved_port_answers_with_a_code_and_never_with_a_default() {
        assert_eq!(
            sync_state_core(None).unwrap_err().code,
            "EA-DESKTOP-SYNC-STATE-UNAVAILABLE"
        );
    }

    /// Die Drahtform traegt die WOERTLICHE Oberflaechenkopie beider Namen.
    ///
    /// Aus `label()` und nicht aus einem Literal dieser Datei: die vier
    /// Zustandsnamen und die vier Ursachennamen haben ihre EINE Quelle in
    /// `crates/ea-archive-fs/src/publication_queue.rs`.
    #[test]
    fn the_wire_form_carries_the_labels_of_the_one_source() {
        let port = FixedPort(SyncStateView {
            status: ea_archive_fs::SyncStatus::UploadPending,
            detail_cause: Some(ea_archive_fs::DetailCause::NetworkArchiveWaiting),
        });
        assert_eq!(
            sync_state_core(Some(&port)).expect("der Port antwortet"),
            SyncStateDto {
                status: ea_archive_fs::SyncStatus::UploadPending.label(),
                detail_cause: Some(ea_archive_fs::DetailCause::NetworkArchiveWaiting.label()),
            }
        );
    }
}
