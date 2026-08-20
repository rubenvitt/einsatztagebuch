//! Das kontrollierte Netzbackend — gepinntes Profil oder gar nichts.

use std::path::{Path, PathBuf};

use ea_archive::{ArchiveBackendError, ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1};

use crate::LocalPathBackend;

/// Die Sonde, mit der die Verschluesselung der lokalen Commit-Komponente
/// GEMESSEN wird.
///
/// Sie ist ein fester Klartext und kein Zufallswert: der Nachweis vergleicht
/// die Bytes AM RUHEORT gegen genau ihn, und ein Vergleich gegen einen Wert,
/// den nur die Ablage kennt, wuerde nichts belegen.
const AT_REST_PROBE_RELATIVE_V1: &str = ".ea-at-rest-probe";
const AT_REST_PROBE_PLAINTEXT_V1: &[u8] = b"EINSATZARCHIV-AT-REST-PROBE-v1";

/// Enthaelt `haystack` die Folge `needle`?
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Die Ablage, die die lokale Commit-Komponente traegt.
///
/// `design.md` §11.5 verlangt sie VERSCHLUESSELT. Diese Crate implementiert
/// dafuer ausdruecklich keinen eigenen Kryptobehaelter — Domain, Kanonisierung
/// und Schluesselherkunft eines Ruheort-Behaelters gehoeren nicht hierher —,
/// sondern sie MISST die Zusage an der uebergebenen Ablage:
/// [`Self::bytes_at_rest`] darf den Klartext der Sonde nicht enthalten,
/// waehrend [`Self::get`] ihn wiederherstellen MUSS. Ein `bool`, das eine
/// Konstruktorstelle setzt, waere keine Eigenschaft der Ablage, sondern ein
/// Name.
///
/// Alle Methoden sind SYNCHRON, wie der ganze Rust-Kern.
pub trait AtRestEncryptedStoreV1: Send + Sync {
    /// Legt `bytes` unter `relative` ab.
    ///
    /// # Errors
    ///
    /// Der Fehler der Ablage.
    fn put(&self, relative: &str, bytes: &[u8]) -> Result<(), ArchiveBackendError>;

    /// Die WIEDERHERGESTELLTEN Bytes unter `relative`.
    fn get(&self, relative: &str) -> Option<Vec<u8>>;

    /// Die Bytes, wie sie AM RUHEORT liegen.
    ///
    /// Genau dieser Leser macht die Verschluesselung pruefbar: er zeigt, was
    /// ein Angreifer mit Zugriff auf den Datentraeger sieht.
    fn bytes_at_rest(&self, relative: &str) -> Option<Vec<u8>>;

    /// Entfernt `relative`, sofern vorhanden.
    fn remove(&self, relative: &str);
}

/// Die ANGEMELDETE lokale Offline-Commit-Komponente eines Netzbackends.
///
/// Sie ist eine Absichtserklaerung und noch kein Nachweis: erst
/// [`ControlledNetworkBackend::open`] misst sie und haelt danach eine
/// [`ProvenLocalCommitComponentV1`]. Diese Trennung ist der Grund, aus dem es
/// keinen Konstruktor `encrypted()` mehr gibt — er benannte eine Zusage, statt
/// sie zu pruefen.
pub struct LocalCommitComponentV1 {
    root: PathBuf,
    store: Box<dyn AtRestEncryptedStoreV1>,
}

impl LocalCommitComponentV1 {
    /// Meldet eine Komponente unter `root` an, getragen von `store`.
    #[must_use]
    pub fn new(root: PathBuf, store: Box<dyn AtRestEncryptedStoreV1>) -> Self {
        Self { root, store }
    }

    /// Der angemeldete Ort der Komponente.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// MISST die Verschluesselung am Ruheort.
    ///
    /// Drei Aussagen in einer Messung: die Sonde ist ablegbar, sie ist
    /// wiederherstellbar, und ihr Klartext steht NICHT am Ruheort. Faellt eine
    /// davon aus, ist die Komponente fuer dieses Backend nicht vorhanden — eine
    /// unverschluesselte Ablage ist keine schwaechere Komponente, sondern
    /// keine.
    ///
    /// Die Messung schreibt in `root`. Sie laeuft deshalb erst NACH der
    /// Policypruefung: vor ihr darf kein Pfad angelegt werden.
    fn prove_encryption_at_rest(self) -> Result<ProvenLocalCommitComponentV1, ArchiveBackendError> {
        self.store
            .put(AT_REST_PROBE_RELATIVE_V1, AT_REST_PROBE_PLAINTEXT_V1)
            .map_err(|_| ArchiveBackendError::MissingLocalCommitComponent)?;
        let restored = self.store.get(AT_REST_PROBE_RELATIVE_V1);
        let at_rest = self.store.bytes_at_rest(AT_REST_PROBE_RELATIVE_V1);
        self.store.remove(AT_REST_PROBE_RELATIVE_V1);

        let restored = restored.ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        let at_rest = at_rest.ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        if restored != AT_REST_PROBE_PLAINTEXT_V1 {
            // Eine Ablage, die ihre eigenen Bytes nicht zurueckgibt, waere
            // keine dauerhafte Commit-Komponente.
            return Err(ArchiveBackendError::MissingLocalCommitComponent);
        }
        if contains_subsequence(&at_rest, AT_REST_PROBE_PLAINTEXT_V1) {
            return Err(ArchiveBackendError::MissingLocalCommitComponent);
        }
        Ok(ProvenLocalCommitComponentV1 {
            root: self.root,
            store: self.store,
        })
    }
}

impl std::fmt::Debug for LocalCommitComponentV1 {
    /// Nennt den Ort NICHT, aus demselben Grund wie [`LocalPathBackend`].
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalCommitComponentV1(<declared>)")
    }
}

/// Eine lokale Commit-Komponente, deren Verschluesselung GEMESSEN ist.
///
/// Der Typ ist der Nachweis: er entsteht ausschliesslich aus
/// [`LocalCommitComponentV1::prove_encryption_at_rest`], also gibt es keinen
/// Weg, eine unverschluesselte Ablage als Commit-Komponente zu halten.
pub struct ProvenLocalCommitComponentV1 {
    root: PathBuf,
    store: Box<dyn AtRestEncryptedStoreV1>,
}

impl ProvenLocalCommitComponentV1 {
    /// Der Ort der Komponente.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Legt Bytes ab, wenn die Adresse frei ist.
    ///
    /// Dieselbe Semantik wie
    /// [`ArchiveBackend::create_if_absent`](ea_archive::ArchiveBackend::create_if_absent):
    /// bytegleich idempotent, sonst
    /// [`ArchiveBackendError::ByteConflict`]. Die Bytes reisen durch die
    /// gemessene Ablage und nie an ihr vorbei — ein zweiter Schreibweg waere
    /// genau die Stelle, an der Klartext im Commit-Bereich landete.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ByteConflict`] bei abweichenden Bytes, sonst der
    /// Fehler der Ablage.
    pub fn create_if_absent(
        &self,
        relative: &str,
        bytes: &[u8],
    ) -> Result<(), ArchiveBackendError> {
        match self.store.get(relative) {
            Some(existing) if existing == bytes => Ok(()),
            Some(_) => Err(ArchiveBackendError::ByteConflict),
            None => self.store.put(relative, bytes),
        }
    }

    /// Die wiederhergestellten Bytes unter `relative`.
    #[must_use]
    pub fn read(&self, relative: &str) -> Option<Vec<u8>> {
        self.store.get(relative)
    }

    /// Die Bytes, wie sie AM RUHEORT liegen.
    #[must_use]
    pub fn bytes_at_rest(&self, relative: &str) -> Option<Vec<u8>> {
        self.store.bytes_at_rest(relative)
    }
}

impl std::fmt::Debug for ProvenLocalCommitComponentV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProvenLocalCommitComponentV1(<encryption at rest measured>)")
    }
}

/// Ein Bestand auf einem kontrollierten Netzlaufwerk.
///
/// Er traegt ZWEI Ablagen: das entfernte Ziel und die verschluesselte lokale
/// Commit-Komponente. Beide werden getrennt gehalten, weil die Finalisierung
/// ohne Netz durchlaufen MUSS (`design.md` §11.5) und die lokale Komponente
/// genau dafuer existiert.
pub struct ControlledNetworkBackend {
    network: LocalPathBackend,
    local_commit: ProvenLocalCommitComponentV1,
}

impl ControlledNetworkBackend {
    /// Oeffnet das Netzbackend.
    ///
    /// Die Reihenfolge der Ablehnungen ist die Zusage:
    ///
    /// 1. Ein Profil, das KEIN kontrolliertes Netzprofil ist, ist ein
    ///    generischer UNC-, SMB-, NFS- oder WebDAV-Pfad ohne freigegebenes
    ///    Profil und wird abgewiesen.
    /// 2. Danach die Policy — und zwar BEVOR irgendein Pfad benutzt wird.
    /// 3. Erst danach die lokale Commit-Komponente: sie fehlt, oder ihre
    ///    Verschluesselung am Ruheort ist nicht messbar. Diese Messung SCHREIBT
    ///    eine Sonde, darf also nicht vor der Policyentscheidung laufen.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::UnprofiledNetworkPath`],
    /// [`ArchiveBackendError::ProfileNotAllowed`] oder
    /// [`ArchiveBackendError::MissingLocalCommitComponent`], jeweils
    /// fail-closed.
    pub fn open(
        network_root: PathBuf,
        local_commit: Option<LocalCommitComponentV1>,
        profile: ArchiveBackendProfileV1,
        policy: &BoundArchiveProfilePolicyV1,
    ) -> Result<Self, ArchiveBackendError> {
        if !matches!(profile, ArchiveBackendProfileV1::ControlledNetworkPath(_)) {
            return Err(ArchiveBackendError::UnprofiledNetworkPath);
        }
        policy.require(profile.profile_hash()?)?;
        // FEHLEND heisst hier tatsaechlich fehlend: ohne `Option` gaebe es
        // keinen Aufruf, der diesen Arm erreicht.
        let declared = local_commit.ok_or(ArchiveBackendError::MissingLocalCommitComponent)?;
        let local_commit = declared.prove_encryption_at_rest()?;
        let network = LocalPathBackend::open(network_root, profile, policy)?;
        Ok(Self {
            network,
            local_commit,
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
    pub const fn local_commit(&self) -> &ProvenLocalCommitComponentV1 {
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
