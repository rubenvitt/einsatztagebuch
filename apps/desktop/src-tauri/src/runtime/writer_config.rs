//! Explicit Writer settings shared by ordinary capture and the evidence Writer.
//! Parsing supplies no session, policy admission or filesystem capability.
use super::{CONFIG_ERROR, archive_config::ProfileConfig};
use crate::commands::CommandError;
use ea_archive::ArchiveBackendProfileV1;
use serde::Deserialize;
use std::{fs::File, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriterConfig {
    version: u8,
    timezone: String,
    archive_profile: ProfileConfig,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct WriterSettings {
    pub(super) timezone: String,
    pub(super) archive_profile: ArchiveBackendProfileV1,
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
        Ok(Self {
            timezone: config.timezone,
            archive_profile: config.archive_profile.into_profile(),
        })
    }
}
