//! Der lokale Archivport des Sync-Klienten (EA-CNA-PUB-5).
//!
//! Er liegt hier und nicht in `ea-sync-client`, weil er nur Typen aus
//! `ea-archive` braucht: so kann die Umsetzung für die lokale Komponente
//! eines Netzprofils in `ea-admin` liegen, ohne dass `ea-admin` eine Kante auf
//! den Sync-Klienten trägt. `ea-sync-client` exportiert ihn unter demselben
//! Namen weiter.

use ea_archive::{ArchiveBackend, ArchiveBackendError, ArchiveSource};

use crate::LocalPathBackend;

/// Der lokale committete Bestand, wie der Sync-Klient ihn sieht.
///
/// Zwei Rollen, bewusst getrennt: die QUELLE, aus der die Warteschlange
/// entsteht und gegen die eine Quittung verifiziert wird, und das BACKEND, in
/// das die verifizierte Quittung per Create-if-absent gelegt wird. Für
/// LocalPath ist beides dieselbe Wurzel. Für ein kontrolliertes Netzprofil ist
/// die Quelle die Vereinigung aus Netzsicht und committeter lokaler
/// Komponente (EA-CNA-SRC-2) und das Backend die lokale Komponente — nie ein
/// `LocalPathBackend` des Netzziels.
pub trait SyncLocalArchiveV1: Send + Sync {
    /// Die Ablage der verifizierten Quittung: Create-if-absent, danach
    /// `sync_file` und `sync_directory`.
    fn backend(&self) -> &dyn ArchiveBackend;

    /// Die committete Lesesicht, bei jedem Aufruf neu gebildet. Staging
    /// gehört nie dazu.
    ///
    /// # Errors
    ///
    /// Der Fehler beim Bilden der Sicht; der Klient meldet ihn als
    /// Archivbefund und nicht als wartendes Netzarchiv.
    fn committed_source(&self) -> Result<Box<dyn ArchiveSource + '_>, ArchiveBackendError>;

    /// Verlangt dieser Bestand eine Netzarchiv-Publikation vor jedem
    /// Serverupload? Ein Port, der `true` meldet, ergibt ohne
    /// Netzarchiv-Warteschlange keinen Klienten.
    fn requires_network_publication(&self) -> bool {
        false
    }
}

impl SyncLocalArchiveV1 for LocalPathBackend {
    fn backend(&self) -> &dyn ArchiveBackend {
        self
    }

    fn committed_source(&self) -> Result<Box<dyn ArchiveSource + '_>, ArchiveBackendError> {
        Ok(Box::new(self.as_archive_source()))
    }
}
