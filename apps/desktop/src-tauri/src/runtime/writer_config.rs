//! Explicit Writer settings shared by ordinary capture and the evidence Writer.
//! Parsing supplies no session, policy admission or filesystem capability.
use super::{CONFIG_ERROR, archive_config::ProfileConfig};
use crate::commands::CommandError;
use ea_archive::ArchiveBackendProfileV1;
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriterConfig {
    version: u8,
    timezone: String,
    archive_profile: ProfileConfig,
    /// Nur für ein Netzprofil: die SQLCipher-Datei der eigenen Runtime
    /// (EA-CNA-WRT-2). Relativ zur Datei dieser Konfiguration aufgelöst.
    #[serde(default)]
    local_commit_database_path: Option<PathBuf>,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct WriterSettings {
    pub(super) timezone: String,
    pub(super) archive_profile: ArchiveBackendProfileV1,
    /// Gesetzt genau für ein Netzprofil. Liefert weder Schlüssel noch
    /// Namensraum noch Grenzen; die Komponente prüft, dass es die Datenbank
    /// der Writer-Runtime ist.
    pub(super) local_commit_database_path: Option<PathBuf>,
}
impl WriterSettings {
    pub(super) fn load(path: &Path) -> Result<Self, CommandError> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| CommandError::new(CONFIG_ERROR))?
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| CommandError::new(CONFIG_ERROR))?;
        if bytes.len() > 65_536 {
            return Err(CommandError::new(CONFIG_ERROR));
        }
        let config: WriterConfig =
            serde_json::from_slice(&bytes).map_err(|_| CommandError::new(CONFIG_ERROR))?;
        if config.version != 1 {
            return Err(CommandError::new(CONFIG_ERROR));
        }
        ea_schema::validate_timezone(&config.timezone)
            .map_err(|error| CommandError::new(error.code()))?;
        let archive_profile = config.archive_profile.into_profile();
        let network = matches!(
            archive_profile,
            ArchiveBackendProfileV1::ControlledNetworkPath(_)
        );
        if network != config.local_commit_database_path.is_some() {
            return Err(CommandError::new(CONFIG_ERROR));
        }
        let local_commit_database_path = config.local_commit_database_path.map(|configured| {
            path.parent()
                .map_or_else(|| configured.clone(), |base| base.join(&configured))
        });
        Ok(Self {
            timezone: config.timezone,
            archive_profile,
            local_commit_database_path,
        })
    }
}
