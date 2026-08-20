use core::fmt;

use ea_crypto::archive_profile_digest;
use ea_format::{
    ArchiveBackendProfileCoreFieldsV1, ArchiveBackendProfileCoreV1, ArchiveProfileKindV1,
    PolicyFieldsV1, encode_archive_backend_profile_core,
};
use ea_types::Hash32;

use crate::ArchiveBackendError;

/// Ein gepinntes lokales Dateisystemprofil.
///
/// Es traegt KEINEN Ausgabepfad: der Pfad ist eine Eigenschaft der
/// Installation, das Profil eine Eigenschaft des Dateisystems. Nur so ist
/// `archiveProfileHash` ueber Organisationsgrenzen hinweg reproduzierbar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPathProfileV1 {
    /// Zeilen-ID der `support-matrix.json` der Stufe 7.
    pub filesystem_row_id: String,
    /// Kennung des Capability-Testvektors, den dieses Profil bestanden hat.
    pub capability_test_vector_id: String,
}

/// Ein gepinntes kontrolliertes Netzlaufwerksprofil.
///
/// `design.md` §11.5 verlangt Protokoll, Serverprodukt und -version,
/// Mountoptionen, Failoverkonfiguration und Capability-Testvektor. Ein
/// generischer UNC-, SMB-, NFS- oder WebDAV-Pfad OHNE diese Angaben ist
/// unzulaessig, und weil dieser Typ sie alle verlangt, kann er ihn nicht
/// ausdruecken.
///
/// Die verschluesselte lokale Commit-Komponente steht NICHT hier: sie ist eine
/// Eigenschaft der Installation und darf nicht in das Hashurbild eingehen, das
/// `schemas/archive/v1/archive-profile.cddl` schliesst. Der Wirtbackend
/// verlangt sie beim Oeffnen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlledNetworkProfileV1 {
    pub filesystem_row_id: String,
    pub protocol_id: String,
    pub server_product: String,
    pub server_version: String,
    /// Byteweise aufsteigend und duplikatfrei.
    pub mount_options: Vec<String>,
    pub failover_config_id: String,
    pub capability_test_vector_id: String,
    pub queue_max_objects: u64,
    pub queue_max_bytes: u64,
    pub resume_backoff_initial_ms: u64,
    pub resume_backoff_max_ms: u64,
    pub resume_max_attempts: u64,
}

/// Das Archivbackendprofil — GESCHLOSSEN, zwei Arme.
///
/// Genau eines davon konfiguriert ein Writer (`design.md` §11.5). Ein dritter
/// Arm waere ein unprofiliertes Backend, und genau das lehnt die Norm ab.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveBackendProfileV1 {
    LocalPath(LocalPathProfileV1),
    ControlledNetworkPath(ControlledNetworkProfileV1),
}

impl ArchiveBackendProfileV1 {
    /// Der geschlossene Kern, ueber den `archiveProfileHash` rechnet.
    ///
    /// # Errors
    ///
    /// Der Formfehler von [`ArchiveBackendProfileCoreV1::new`], etwa bei
    /// unsortierten oder doppelten Mountoptionen.
    pub fn core(&self) -> Result<ArchiveBackendProfileCoreV1, ArchiveBackendError> {
        let fields = match self {
            Self::LocalPath(profile) => ArchiveBackendProfileCoreFieldsV1 {
                kind: ArchiveProfileKindV1::LocalPath,
                filesystem_row_id: profile.filesystem_row_id.clone(),
                protocol_id: String::new(),
                server_product: String::new(),
                server_version: String::new(),
                mount_options: Vec::new(),
                failover_config_id: String::new(),
                capability_test_vector_id: profile.capability_test_vector_id.clone(),
                queue_max_objects: 0,
                queue_max_bytes: 0,
                resume_backoff_initial_ms: 0,
                resume_backoff_max_ms: 0,
                resume_max_attempts: 0,
            },
            Self::ControlledNetworkPath(profile) => ArchiveBackendProfileCoreFieldsV1 {
                kind: ArchiveProfileKindV1::ControlledNetworkPath,
                filesystem_row_id: profile.filesystem_row_id.clone(),
                protocol_id: profile.protocol_id.clone(),
                server_product: profile.server_product.clone(),
                server_version: profile.server_version.clone(),
                mount_options: profile.mount_options.clone(),
                failover_config_id: profile.failover_config_id.clone(),
                capability_test_vector_id: profile.capability_test_vector_id.clone(),
                queue_max_objects: profile.queue_max_objects,
                queue_max_bytes: profile.queue_max_bytes,
                resume_backoff_initial_ms: profile.resume_backoff_initial_ms,
                resume_backoff_max_ms: profile.resume_backoff_max_ms,
                resume_max_attempts: profile.resume_max_attempts,
            },
        };
        ArchiveBackendProfileCoreV1::new(fields).map_err(ArchiveBackendError::Format)
    }

    /// `archiveProfileHash` ueber den konkret versionierten Kern.
    ///
    /// NEU BERECHNET und nie gespeichert: ein mitgefuehrter Hash koennte von
    /// dem Profil abweichen, das tatsaechlich benutzt wird — und genau darauf
    /// beruht die Policyzusage.
    ///
    /// # Errors
    ///
    /// Wie [`Self::core`], zusaetzlich der Kodierfehler.
    pub fn profile_hash(&self) -> Result<Hash32, ArchiveBackendError> {
        let core = self.core()?;
        let bytes =
            encode_archive_backend_profile_core(&core).map_err(ArchiveBackendError::Format)?;
        Ok(archive_profile_digest(&bytes))
    }
}

/// Die wirksame Profilzulassung der GEBUNDENEN Policy.
///
/// Sie entsteht ausschliesslich aus `allowed-archive-profile-hashes` des
/// Root-signierten `policy-core-v1` (`crates/ea-format/src/etb.rs`), das der
/// Aufrufer ueber den GEWAEHLTEN Registrierungskopf bezieht. Dieser Typ
/// bezieht ihn nicht selbst: er traegt keine Registrierungskante und darf
/// keine haben, sonst waere `ea-archive` nicht mehr zielunabhaengig.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundArchiveProfilePolicyV1 {
    allowed: Vec<Hash32>,
}

impl BoundArchiveProfilePolicyV1 {
    /// Uebernimmt die Zulassungsliste der gebundenen Policy.
    #[must_use]
    pub fn from_policy(policy: &PolicyFieldsV1) -> Self {
        Self {
            allowed: policy.allowed_archive_profile_hashes.clone(),
        }
    }

    /// Traegt die Policy diesen Profilhash?
    #[must_use]
    pub fn permits(&self, profile_hash: Hash32) -> bool {
        self.allowed.contains(&profile_hash)
    }

    /// FAIL-CLOSED: jede Abweichung ist ein Fehler, nie eine Warnung.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ProfileNotAllowed`], wenn der Hash nicht in der
    /// wirksamen Policy steht.
    pub fn require(&self, profile_hash: Hash32) -> Result<(), ArchiveBackendError> {
        if self.permits(profile_hash) {
            Ok(())
        } else {
            Err(ArchiveBackendError::ProfileNotAllowed)
        }
    }

    /// Die Zahl der zugelassenen Profile.
    #[must_use]
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Traegt die Policy kein einziges zugelassenes Profil?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

impl fmt::Debug for BoundArchiveProfilePolicyV1 {
    /// Nennt die Zahl der zugelassenen Profile, nicht ihre Hashes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundArchiveProfilePolicyV1")
            .field("allowed", &self.allowed.len())
            .finish()
    }
}
