//! Die LESENDE Stammdatenflaeche.

use serde::Serialize;

use super::{CommandError, MASTER_DATA_UNAVAILABLE, MASTER_DATA_UNREADABLE, run_blocking};
use crate::state::DesktopState;

/// Der Umfang der erfassten Stammdaten.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MasterDataCountsDto {
    pub persons: u64,
    pub vehicles: u64,
}

pub(crate) fn master_data_counts_core(
    state: &DesktopState,
) -> Result<MasterDataCountsDto, CommandError> {
    let repository = state
        .master_data()
        .ok_or_else(|| CommandError::new(MASTER_DATA_UNAVAILABLE))?;
    let persons = repository
        .person_count()
        .map_err(|_| CommandError::new(MASTER_DATA_UNREADABLE))?;
    let vehicles = repository
        .vehicle_count()
        .map_err(|_| CommandError::new(MASTER_DATA_UNREADABLE))?;
    Ok(MasterDataCountsDto { persons, vehicles })
}

/// Wie viele Personen- und Fahrzeugzeilen erfasst sind.
///
/// Ausschliesslich LESEND: ein Import und eine Umbenennung sind Kommandos
/// spaeterer Tasks. Der Fehlertext der Ablage erreicht die Oberflaeche nie —
/// er koennte einen Pfad nennen.
///
/// # Errors
///
/// [`MASTER_DATA_UNAVAILABLE`], solange keine entschluesselte Datenbank
/// geoeffnet ist; [`MASTER_DATA_UNREADABLE`], wenn die Ablage ablehnt.
#[tauri::command]
pub async fn master_data_counts(
    state: tauri::State<'_, DesktopState>,
) -> Result<MasterDataCountsDto, CommandError> {
    let state = state.inner().clone();
    run_blocking(move || master_data_counts_core(&state)).await
}

#[cfg(test)]
mod tests {
    use super::master_data_counts_core;
    use crate::commands::MASTER_DATA_UNAVAILABLE;
    use crate::state::{DesktopState, SessionState};

    /// Fail-closed: ohne geoeffnete Datenbank gibt es keine Zahl, und die Null
    /// waere eine Aussage ueber leere Stammdaten.
    #[test]
    fn a_shell_without_an_open_database_gets_a_named_absence() {
        let state = DesktopState::new(SessionState::new(None, None), None, None, None, None);
        assert_eq!(
            master_data_counts_core(&state).unwrap_err().code,
            MASTER_DATA_UNAVAILABLE
        );
    }
}
