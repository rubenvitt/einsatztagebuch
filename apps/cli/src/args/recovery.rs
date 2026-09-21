//! Closed recovery modes. Source paths select inputs, never identity or readiness.
use super::{PathBuf, UsageError};
use std::collections::BTreeMap;
pub const MODE: &str = "--recovery-mode";
pub const SWITCHES: [&str; 8] = [
    "--archive-profile",
    "--source-envelope",
    "--snapshot",
    "--backup-passphrase-file",
    "--restore-database",
    "--media-sources",
    "--completed-report",
    // Exportverzeichnis der lokalen Komponente eines Netzprofils (EA-CNA-REC-3).
    "--component-export",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRuntimeArguments {
    pub config: PathBuf,
    pub profile: PathBuf,
    pub action: RecoveryRuntimeAction,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryRuntimeAction {
    Capture {
        snapshot: PathBuf,
        passphrase: PathBuf,
        /// Pflicht für ein Netzprofil, abgelehnt für LocalPath; entschieden
        /// wird am gelesenen Profil, nicht hier.
        component_export: Option<PathBuf>,
    },
    RestoreRun {
        source: PathBuf,
        snapshot: PathBuf,
        passphrase: PathBuf,
        restore: PathBuf,
        media: PathBuf,
    },
    Import {
        source: PathBuf,
        report: PathBuf,
    },
    Status,
    FailureStatus {
        restore: PathBuf,
    },
}
fn required(
    map: &mut BTreeMap<&'static str, PathBuf>,
    switch: &'static str,
) -> Result<PathBuf, UsageError> {
    map.remove(switch).ok_or(UsageError::MissingSwitch {
        switch,
        command: "recovery-test",
    })
}
pub(super) fn build(
    mode: Option<PathBuf>,
    config: Option<PathBuf>,
    mut paths: BTreeMap<&'static str, PathBuf>,
) -> Result<Option<RecoveryRuntimeArguments>, UsageError> {
    let Some(mode) = mode else {
        if config.is_some() || !paths.is_empty() {
            return Err(UsageError::MissingSwitch {
                switch: MODE,
                command: "recovery-test",
            });
        }
        return Ok(None);
    };
    let config = config.ok_or(UsageError::MissingSwitch {
        switch: super::OPERATOR_CONFIG_SWITCH,
        command: "recovery-test",
    })?;
    let profile = required(&mut paths, "--archive-profile")?;
    let action = match mode.to_str() {
        Some("capture") => RecoveryRuntimeAction::Capture {
            snapshot: required(&mut paths, "--snapshot")?,
            passphrase: required(&mut paths, "--backup-passphrase-file")?,
            component_export: paths.remove("--component-export"),
        },
        Some("restore-run") => RecoveryRuntimeAction::RestoreRun {
            source: required(&mut paths, "--source-envelope")?,
            snapshot: required(&mut paths, "--snapshot")?,
            passphrase: required(&mut paths, "--backup-passphrase-file")?,
            restore: required(&mut paths, "--restore-database")?,
            media: required(&mut paths, "--media-sources")?,
        },
        Some("import") => RecoveryRuntimeAction::Import {
            source: required(&mut paths, "--source-envelope")?,
            report: required(&mut paths, "--completed-report")?,
        },
        Some("status") => RecoveryRuntimeAction::Status,
        Some("failure-status") => RecoveryRuntimeAction::FailureStatus {
            restore: required(&mut paths, "--restore-database")?,
        },
        _ => {
            return Err(UsageError::UnknownSubcommand {
                command: "recovery-test",
                value: mode.to_string_lossy().into_owned(),
                expected: "capture|restore-run|import|status|failure-status",
            });
        }
    };
    if let Some((switch, _)) = paths.into_iter().next() {
        return Err(UsageError::SwitchNotAllowed {
            switch,
            command: "recovery-test mode",
        });
    }
    Ok(Some(RecoveryRuntimeArguments {
        config,
        profile,
        action,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_status_requires_the_actual_restored_source_and_no_secret_inputs() {
        let invoke = |restore: bool, secret: bool| {
            let mut paths = BTreeMap::from([("--archive-profile", PathBuf::from("profile.json"))]);
            if restore {
                paths.insert("--restore-database", PathBuf::from("restored.sqlite"));
            }
            if secret {
                paths.insert("--backup-passphrase-file", PathBuf::from("secret"));
            }
            build(
                Some(PathBuf::from("failure-status")),
                Some(PathBuf::from("operator.json")),
                paths,
            )
        };
        assert!(
            invoke(true, false).is_ok(),
            "durable diagnosis needs no reimport or private medium"
        );
        assert!(invoke(false, false).is_err());
        assert!(invoke(true, true).is_err());
    }
    #[test]
    fn component_export_belongs_to_capture_only() {
        let invoke = |mode: &str| {
            let mut paths = BTreeMap::from([
                ("--archive-profile", PathBuf::from("profile.json")),
                ("--component-export", PathBuf::from("export")),
            ]);
            if mode == "capture" {
                paths.insert("--snapshot", PathBuf::from("snapshot.db"));
                paths.insert("--backup-passphrase-file", PathBuf::from("secret"));
            }
            build(
                Some(PathBuf::from(mode)),
                Some(PathBuf::from("operator.json")),
                paths,
            )
        };
        let Ok(Some(RecoveryRuntimeArguments {
            action:
                RecoveryRuntimeAction::Capture {
                    component_export, ..
                },
            ..
        })) = invoke("capture")
        else {
            panic!("capture accepts a component export");
        };
        assert_eq!(component_export, Some(PathBuf::from("export")));
        assert!(invoke("status").is_err());
    }
}
