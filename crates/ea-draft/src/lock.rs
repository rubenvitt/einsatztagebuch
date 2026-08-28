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
    /// Prozessuebergreifend UND prozessintern: `flock` bindet je Dateigriff,
    /// also weist die Sperre auch einen zweiten Griff im selben Prozess ab —
    /// zwei Writer-Instanzen auf demselben Konto sind der Fall, gegen den sie
    /// steht.
    pub(crate) fn acquire(database_path: &Path) -> Result<Self, DraftError> {
        open_and_lock_exclusively(&lock_path(database_path))
            .map(|file| Self { file })
            .ok_or(DraftError::LockHeld)
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

/// Oeffnet `path` und belegt es mit der exklusiven Betriebssystemsperre.
///
/// `None`, wenn schon jemand sperrt ODER die Datei sich nicht oeffnen laesst.
/// Die beiden Faelle werden ABSICHTLICH nicht unterschieden: der Aufrufer hat
/// an dieser Stelle ohnehin nur EINE Handlung — nicht schreiben.
///
/// `create(true)` und NICHT `truncate`: die Datei traegt keinen Inhalt, und ein
/// Abschneiden waere ein Schreibzugriff, BEVOR die Sperre steht.
///
/// Wortgleich zu `LocalPathBackend::acquire_writer_lock` in
/// `crates/ea-archive-fs/src/local_path.rs`. Die beiden Crates duerfen nicht
/// voneinander abhaengen, also steht die Sperre zweimal da; sie steht dann aber
/// auch in derselben Gestalt, damit ein Leser die eine an der anderen pruefen
/// kann.
fn open_and_lock_exclusively(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .ok()?;
    file.try_lock().ok()?;
    Some(file)
}

fn lock_path(database_path: &Path) -> PathBuf {
    let mut name = database_path.as_os_str().to_os_string();
    name.push(LOCK_SUFFIX);
    PathBuf::from(name)
}
