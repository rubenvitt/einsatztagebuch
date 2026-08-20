use ea_format::ExactObjectBytes;

use crate::{ArchiveBackendError, ArchivePath, WriterLock};

/// Der SCHREIBENDE Port ueber einen Bestand, mit expliziten
/// Dauerhaftigkeitsprimitiven.
///
/// Jede Zusage steht als eigene Methode da, weil jede von ihnen einzeln
/// fehlschlagen kann und `design.md` §11.5 fuer jede einzeln einen
/// Capability-Test verlangt. Eine `write`-Methode, die Flush und Rename
/// verbirgt, liesse sich nicht getrennt nachweisen.
///
/// Alle Methoden sind SYNCHRON, wie der ganze Rust-Kern. Diese Crate enthaelt
/// bewusst KEINE Implementierung: `ea-archive` traegt nur
/// zielunabhaengige Ports und kein `std::fs`. Jede Wirtimplementierung lebt in
/// `ea-archive-fs`.
pub trait ArchiveBackend: Send + Sync {
    /// Legt ein Archivobjekt an, wenn der Pfad frei ist.
    ///
    /// Idempotent fuer BYTEGLEICHE Wiederholungen; ein Pfad mit anderen Bytes
    /// liefert [`ArchiveBackendError::ByteConflict`]. Nie ueberschreibend.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ByteConflict`] bei abweichenden Bytes, sonst der
    /// Fehler des Wirtdateisystems.
    fn create_if_absent(
        &self,
        relative: &ArchivePath,
        bytes: &ExactObjectBytes,
    ) -> Result<(), ArchiveBackendError>;

    /// Dieselbe Semantik fuer Bytes, die KEIN Archivobjekt sind.
    ///
    /// Eine eigene Methode, weil das Formatbeiwerk kein
    /// Exact-Object-Praefix traegt (`design.md` §11.4) und
    /// `ExactObjectBytes::new` in `ea-format` `pub(crate)` ist — jene Bytes
    /// koennen als [`ExactObjectBytes`] gar nicht reisen. Der Typunterschied
    /// ist damit die Klassifikation und nicht ihr Ersatz.
    ///
    /// # Errors
    ///
    /// Wie [`Self::create_if_absent`].
    fn create_non_object_if_absent(
        &self,
        relative: &ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ArchiveBackendError>;

    /// Macht die Bytes dieser Datei dauerhaft.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::FlushFailed`], wenn der Wirt es nicht bestaetigt.
    fn sync_file(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError>;

    /// Macht den VERZEICHNISEINTRAG dauerhaft.
    ///
    /// Ohne diesen zweiten Flush kann ein neu angelegter Name nach einem
    /// Stromausfall fehlen, obwohl seine Bytes geschrieben waren.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::FlushFailed`], wenn der Wirt es nicht bestaetigt.
    fn sync_directory(&self, relative: &ArchivePath) -> Result<(), ArchiveBackendError>;

    /// Benennt ATOMAR um, ausschliesslich innerhalb desselben Dateisystems —
    /// und NIE ueber eine bestehende Zieladresse hinweg.
    ///
    /// Das ist die zweite Haelfte von Create-if-absent und keine Zutat: die
    /// Staging-Stufe schuetzt nur die STAGING-Adresse, und ein Rename, der ein
    /// bestehendes Ziel ersetzt, hebelte die Zusage „`.eip`-Bytes werden nie
    /// ueberschrieben" ueber genau den Weg aus, der Veroeffentlichung sicher
    /// machen soll. Die Semantik ist deshalb dieselbe wie die von
    /// [`Self::create_if_absent`]: eine bytegleiche Wiederholung traegt (die
    /// Quelladresse wird verworfen, das Ziel bleibt Byte fuer Byte dasselbe),
    /// abweichende Bytes am Ziel liefern
    /// [`ArchiveBackendError::ByteConflict`].
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::NotSameFilesystem`], wenn Quelle und Ziel nicht
    /// auf demselben Dateisystem liegen — ABGELEHNT und nie durch Kopieren
    /// ersetzt; [`ArchiveBackendError::ByteConflict`], wenn die Zieladresse
    /// schon existiert und ANDERE Bytes traegt.
    fn atomic_rename_same_fs(
        &self,
        from: &ArchivePath,
        to: &ArchivePath,
    ) -> Result<(), ArchiveBackendError>;

    /// Nimmt die exklusive Schreibersperre.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::AlreadyLocked`], wenn sie schon gehalten wird.
    fn acquire_writer_lock(&self) -> Result<WriterLock, ArchiveBackendError>;
}
