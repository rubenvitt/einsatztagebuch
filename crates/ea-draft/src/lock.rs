//! Die ausschliessliche Entwurfssperre.

use core::fmt;
use std::{
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use crate::model::DraftError;

/// Der Namenszusatz der Sperrdatei neben der Datenbank.
const LOCK_SUFFIX: &str = ".draft-lock";

/// Ein RAII-Waechter ueber die ausschliessliche Entwurfssperre.
///
/// Sein `Drop` gibt die Sperre frei. Er ist AUSDRUECKLICH nicht die
/// archivseitige Writer-Sperre aus Task 9: eine Verwerfensfortsetzung und eine
/// Abschlussfortsetzung duerfen nie denselben Waechter teilen, und zwei
/// getrennte Typen machen das Teilen unausdrueckbar statt bloss unerwuenscht.
pub struct DraftLock {
    path: PathBuf,
}

impl DraftLock {
    /// Nimmt die Sperre neben `database_path`.
    ///
    /// `create_new` ist auf allen drei Plattformen atomar: das Anlegen
    /// gelingt genau einem Bewerber. Die Sperre ist damit prozessuebergreifend
    /// und nicht bloss prozessintern — zwei Writer-Instanzen auf demselben
    /// Konto sind der Fall, gegen den sie steht.
    pub(crate) fn acquire(database_path: &Path) -> Result<Self, DraftError> {
        let path = lock_path(database_path);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => Ok(Self { path }),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(DraftError::LockHeld),
            Err(_) => Err(DraftError::LockHeld),
        }
    }
}

impl Drop for DraftLock {
    fn drop(&mut self) {
        // Ein Fehlschlag beim Entfernen ist nicht behandelbar: der Waechter
        // faellt gerade. Eine liegengebliebene Sperrdatei ist fail-closed —
        // sie verweigert den naechsten Zugriff, statt einen zweiten zuzulassen.
        let _ = fs::remove_file(&self.path);
    }
}

impl fmt::Debug for DraftLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DraftLock(<held>)")
    }
}

fn lock_path(database_path: &Path) -> PathBuf {
    let mut name = database_path.as_os_str().to_os_string();
    name.push(LOCK_SUFFIX);
    PathBuf::from(name)
}
