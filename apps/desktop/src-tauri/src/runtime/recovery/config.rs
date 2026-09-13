use crate::commands::CommandError;
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u8,
    pub key_inventory_path: PathBuf,
    pub archive_profile_path: PathBuf,
    pub media_sources_path: PathBuf,
    pub restored_source_database_path: PathBuf,
    pub initial_restore: Option<InitialRestore>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialRestore {
    pub exact_source_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub passphrase_file: PathBuf,
}
impl Config {
    pub(super) fn parse(exact: &[u8], base: &Path) -> Result<Self, CommandError> {
        let error = || CommandError::new(super::super::CONFIG_ERROR);
        if exact.len() > 65_536 {
            return Err(error());
        }
        let mut value: Self = serde_json::from_slice(exact).map_err(|_| error())?;
        if value.version != 1 {
            return Err(error());
        }
        let resolve = |path: &mut PathBuf| -> Result<(), CommandError> {
            if path.as_os_str().is_empty() {
                return Err(error());
            }
            if path.is_relative() {
                *path = base.join(&*path);
            }
            Ok(())
        };
        resolve(&mut value.key_inventory_path)?;
        resolve(&mut value.archive_profile_path)?;
        resolve(&mut value.media_sources_path)?;
        resolve(&mut value.restored_source_database_path)?;
        if let Some(restore) = &mut value.initial_restore {
            resolve(&mut restore.exact_source_path)?;
            resolve(&mut restore.snapshot_path)?;
            resolve(&mut restore.passphrase_file)?;
        }
        Ok(value)
    }
    pub(super) fn load(path: &Path) -> Result<Self, CommandError> {
        Self::parse(
            &read(path, 65_536)?,
            path.parent().unwrap_or_else(|| Path::new(".")),
        )
    }
}
pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, CommandError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| CommandError::new(super::super::CONFIG_ERROR))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CommandError::new(super::super::CONFIG_ERROR))?;
    if bytes.len() > limit {
        return Err(CommandError::new(super::super::CONFIG_ERROR));
    }
    Ok(bytes)
}
pub(super) fn resolve_medium_source(
    source: &mut ea_admin::recovery_test_runtime::RecoveryMediumInput,
    base: &Path,
) -> Result<(), CommandError> {
    use ea_admin::recovery_test_runtime::RecoveryMediumInput;
    use ea_recovery::{KeySourceSpec, Pkcs11KeyReference};
    let resolve = |path: &mut PathBuf| {
        if path.is_relative() {
            *path = base.join(&*path);
        }
    };
    match source {
        RecoveryMediumInput::Offline(KeySourceSpec::File(path)) => resolve(path),
        RecoveryMediumInput::Offline(KeySourceSpec::Container {
            path,
            passphrase_file,
        }) => {
            resolve(path);
            resolve(passphrase_file);
        }
        RecoveryMediumInput::Offline(KeySourceSpec::Pkcs11 {
            reference,
            pin_file,
        }) => {
            let mut module = reference.module().to_owned();
            resolve(&mut module);
            *reference = Pkcs11KeyReference::new(
                module,
                reference.token_label().to_owned(),
                &super::guide::hex(reference.key_id()),
            )
            .map_err(|_| CommandError::new(super::super::CONFIG_ERROR))?;
            resolve(pin_file);
        }
        RecoveryMediumInput::NativeSigningSlot(_) => {}
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> serde_json::Value {
        serde_json::json!({"version":1,"key_inventory_path":"inventory.json",
            "archive_profile_path":"profile.json","media_sources_path":"media.json",
            "restored_source_database_path":"restored.db",
            "initial_restore":{"exact_source_path":"source.cbor","snapshot_path":"snapshot.db",
                "passphrase_file":"passphrase"}})
    }
    #[test]
    fn file_references_resolve_against_configuration_location() {
        let c = Config::parse(
            &serde_json::to_vec(&config()).unwrap(),
            Path::new("/config"),
        )
        .unwrap();
        assert_eq!(
            c.key_inventory_path,
            PathBuf::from("/config/inventory.json")
        );
        assert_eq!(
            c.archive_profile_path,
            PathBuf::from("/config/profile.json")
        );
        assert_eq!(c.media_sources_path, PathBuf::from("/config/media.json"));
        assert_eq!(
            c.restored_source_database_path,
            PathBuf::from("/config/restored.db")
        );
        assert_eq!(
            c.initial_restore.unwrap().passphrase_file,
            PathBuf::from("/config/passphrase")
        );
    }
    #[test]
    fn unknown_fields_and_partial_or_empty_restore_configuration_are_refused() {
        let mut invalid = config();
        invalid["identity_verified"] = serde_json::json!(true);
        let mut partial = config();
        partial["initial_restore"]
            .as_object_mut()
            .unwrap()
            .remove("snapshot_path");
        let mut empty = config();
        empty["initial_restore"]["passphrase_file"] = serde_json::json!("");
        for c in [invalid, partial, empty] {
            assert!(Config::parse(&serde_json::to_vec(&c).unwrap(), Path::new("/config")).is_err());
        }
        assert!(Config::parse(&vec![b' '; 65_537], Path::new("/config")).is_err());
    }
    #[test]
    fn private_medium_paths_resolve_against_media_file_without_rewriting_token_or_absolute_paths() {
        use ea_admin::recovery_test_runtime::{RecoveryMediumInput, RecoveryNativeSigningSlot};
        use ea_recovery::KeySourceSpec;
        let mut container = RecoveryMediumInput::Offline(
            KeySourceSpec::parse(std::ffi::OsStr::new(
                "container:keys/root.cbor;passphrase-file=/offline/phrase",
            ))
            .unwrap(),
        );
        resolve_medium_source(&mut container, Path::new("/media")).unwrap();
        let RecoveryMediumInput::Offline(KeySourceSpec::Container {
            path,
            passphrase_file,
        }) = container
        else {
            panic!("container");
        };
        assert_eq!(path, Path::new("/media/keys/root.cbor"));
        assert_eq!(passphrase_file, Path::new("/offline/phrase"));
        let mut pkcs = RecoveryMediumInput::Offline(
            KeySourceSpec::parse(std::ffi::OsStr::new(
                "pkcs11:module=lib/token.so;token=local-token;id=00ff;pin-file=pin",
            ))
            .unwrap(),
        );
        resolve_medium_source(&mut pkcs, Path::new("/media")).unwrap();
        let RecoveryMediumInput::Offline(KeySourceSpec::Pkcs11 {
            reference,
            pin_file,
        }) = pkcs
        else {
            panic!("pkcs11");
        };
        assert_eq!(reference.module(), Path::new("/media/lib/token.so"));
        assert_eq!(reference.token_label(), "local-token");
        assert_eq!(reference.key_id(), &[0, 255]);
        assert_eq!(pin_file, Path::new("/media/pin"));
        let mut native = RecoveryMediumInput::NativeSigningSlot(RecoveryNativeSigningSlot::Admin);
        resolve_medium_source(&mut native, Path::new("/media")).unwrap();
        assert!(matches!(
            native,
            RecoveryMediumInput::NativeSigningSlot(RecoveryNativeSigningSlot::Admin)
        ));
    }
}
