//! Das kontrollierte Netzbackend — gepinntes Profil oder gar nichts.

use std::path::{Path, PathBuf};

use ea_archive::{ArchiveBackendError, ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1};

use crate::LocalPathBackend;

/// Die lokale Offline-Commit-Komponente eines Netzbackends.
///
/// `design.md` §11.5 verlangt sie VERSCHLUESSELT. Der Zustand steht deshalb im
/// Typ und nicht in einem Kommentar: `plaintext` existiert ausschliesslich,
/// damit ein Test die Ablehnung belegen kann.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCommitComponentV1 {
    root: PathBuf,
    encrypted: bool,
}

impl LocalCommitComponentV1 {
    /// Eine verschluesselte Komponente.
    #[must_use]
    pub const fn encrypted(root: PathBuf) -> Self {
        Self {
            root,
            encrypted: true,
        }
    }

    /// Eine UNVERSCHLUESSELTE Komponente. Wird beim Oeffnen abgewiesen.
    #[must_use]
    pub const fn plaintext(root: PathBuf) -> Self {
        Self {
            root,
            encrypted: false,
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }
}

/// Ein Bestand auf einem kontrollierten Netzlaufwerk.
///
/// Er traegt ZWEI Bestandswurzeln: das entfernte Ziel und die verschluesselte
/// lokale Commit-Komponente. Beide werden getrennt gehalten, weil die
/// Finalisierung ohne Netz durchlaufen MUSS (`design.md` §11.5) und die lokale
/// Komponente genau dafuer existiert.
pub struct ControlledNetworkBackend {
    network: LocalPathBackend,
    local_commit: LocalPathBackend,
}

impl ControlledNetworkBackend {
    /// Oeffnet das Netzbackend.
    ///
    /// Die Reihenfolge der Ablehnungen ist die Zusage:
    ///
    /// 1. Ein Profil, das KEIN kontrolliertes Netzprofil ist, ist ein
    ///    generischer UNC-, SMB-, NFS- oder WebDAV-Pfad ohne freigegebenes
    ///    Profil und wird abgewiesen.
    /// 2. Eine unverschluesselte oder fehlende lokale Commit-Komponente wird
    ///    abgewiesen.
    /// 3. Erst danach zaehlt die Policy — und zwar BEVOR irgendein Pfad des
    ///    Ziels benutzt wird.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::UnprofiledNetworkPath`],
    /// [`ArchiveBackendError::MissingLocalCommitComponent`] oder
    /// [`ArchiveBackendError::ProfileNotAllowed`], jeweils fail-closed.
    pub fn open(
        network_root: PathBuf,
        local_commit: LocalCommitComponentV1,
        profile: ArchiveBackendProfileV1,
        policy: &BoundArchiveProfilePolicyV1,
    ) -> Result<Self, ArchiveBackendError> {
        if !matches!(profile, ArchiveBackendProfileV1::ControlledNetworkPath(_)) {
            return Err(ArchiveBackendError::UnprofiledNetworkPath);
        }
        if !local_commit.is_encrypted() {
            return Err(ArchiveBackendError::MissingLocalCommitComponent);
        }
        policy.require(profile.profile_hash()?)?;
        let network = LocalPathBackend::open(network_root, profile.clone(), policy)?;
        let commit = LocalPathBackend::open(local_commit.root().to_path_buf(), profile, policy)?;
        Ok(Self {
            network,
            local_commit: commit,
        })
    }

    /// Das entfernte Ziel.
    #[must_use]
    pub const fn network(&self) -> &LocalPathBackend {
        &self.network
    }

    /// Die verschluesselte lokale Commit-Komponente.
    ///
    /// Hier landet jede Publikation zuerst; das Netz ist die ZWEITE Ablage und
    /// nie die einzige.
    #[must_use]
    pub const fn local_commit(&self) -> &LocalPathBackend {
        &self.local_commit
    }
}

impl std::fmt::Debug for ControlledNetworkBackend {
    /// Nennt weder die Netzwurzel noch die Wurzel der Commit-Komponente, aus
    /// demselben Grund wie [`LocalPathBackend`]. Der Rumpf existiert, damit
    /// `Result::unwrap_err` an diesem Typ aufrufbar ist.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControlledNetworkBackend(<pinned network profile>)")
    }
}
