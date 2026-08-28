//! Die ausschliessliche Entwurfssperre.

use core::fmt;
use std::{
    fs::{File, OpenOptions},
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
    file: File,
}

impl DraftLock {
    /// Nimmt die Sperre neben `database_path`.
    ///
    /// Die Sperre ist eine BETRIEBSSYSTEMSPERRE ueber der Sperrdatei —
    /// `flock(2)` auf Unix, `LockFileEx` auf Windows, beides ueber
    /// [`File::try_lock`] — und ausdruecklich NICHT das blosse Anlegen der
    /// Datei. Der Unterschied ist der harte Abbruch: `create_new` haengt die
    /// Sperre an das DASEIN der Datei, und nach `SIGKILL` oder Stromausfall
    /// liegt sie fuer immer da. Der Entwurf waere dann dauerhaft unerreichbar,
    /// denn der Neustartpfad nimmt selbst diese Sperre und kaeme nie an ihr
    /// vorbei. Der Kern dagegen gibt die Sperre beim Prozessende frei; die
    /// zurueckbleibende Datei ist danach ein leeres Gehaeuse.
    ///
    /// # Kein Reaper und keine PID-Pruefung
    ///
    /// Beide waeren die uebliche Nacharbeit an einer Dasein-Sperre und beide
    /// sind hier UEBERFLUESSIG: eine hinterlegte PID muss geraten werden
    /// (sie kann laengst neu vergeben sein), und ein Aufraeumer, der eine
    /// „alte" Sperrdatei entfernt, entscheidet ueber Leben und Tod eines
    /// fremden Prozesses ohne Beleg. Die Sperre des Kerns kennt die Antwort
    /// dagegen genau und ohne Heuristik.
    ///
    /// Die Datei wird mit `create(true)` geoeffnet und NICHT abgeschnitten:
    /// sie traegt keinen Inhalt, und ein `truncate` waere ein Schreibzugriff,
    /// bevor die Sperre steht.
    ///
    /// Prozessuebergreifend UND prozessintern: `flock` bindet je Dateigriff,
    /// also weist die Sperre auch einen zweiten Griff im selben Prozess ab —
    /// zwei Writer-Instanzen auf demselben Konto sind der Fall, gegen den sie
    /// steht.
    pub(crate) fn acquire(database_path: &Path) -> Result<Self, DraftError> {
        let path = lock_path(database_path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| DraftError::LockHeld)?;
        // Fail-closed und eng: JEDER Ausgang ausser der genommenen Sperre ist
        // `LockHeld`. Ein Fehler des Wirtdateisystems waere ein zweiter
        // Fehlercode an einer Stelle, an der der Aufrufer ohnehin nur EINE
        // Handlung hat — nicht schreiben.
        file.try_lock().map_err(|_| DraftError::LockHeld)?;
        Ok(Self { file })
    }
}

impl Drop for DraftLock {
    fn drop(&mut self) {
        // Die Sperre wird geloest, die DATEI bleibt liegen — und das ist
        // Absicht und keine Nachlaessigkeit. Wer sie entfernte, oeffnete ein
        // Fenster: ein zweiter Halter kann den Griff auf denselben Inode schon
        // haben, waehrend ein dritter unter demselben Namen eine NEUE Datei
        // anlegt und darauf ungehindert sperrt — zwei Halter derselben Sperre.
        // Die liegengebliebene Datei ist harmlos: sie traegt keinen Inhalt und
        // sperrt nichts.
        //
        // Ein Fehlschlag ist nicht behandelbar: der Waechter faellt gerade.
        // Er ist auch folgenlos, denn das Schliessen des Griffs gibt die
        // Sperre ohnehin frei.
        let _ = self.file.unlock();
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
