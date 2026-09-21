//! Das PRODUKTIONSZIEL der Publikationswarteschlange: ein kontrolliertes
//! Netzarchiv, gelesen und geschrieben über ein gewöhnliches
//! [`LocalPathBackend`] auf dessen kanonischem Wurzelpfad.
//!
//! `EA-CNA-PUB-3` ist die tragende Zusage: veröffentlicht wird mit
//! Create-if-absent, anschließendem Datei- und Verzeichnis-Flush, und ein
//! Objekt gilt erst als publiziert, wenn ein ERNEUTES Lesen des Netzziels
//! dieselben Bytes liefert. `EA-CNA-PUB-6` ist die zweite: es gibt kein
//! Ausweichen auf ein anderes Ziel — dieser Typ öffnet ausschließlich seine
//! EIGENE Wurzel und reicht Fehler durch, statt irgendwohin sonst zu
//! schreiben.

use std::{
    path::PathBuf,
    sync::{Mutex, PoisonError},
};

use ea_archive::{
    ArchiveBackend, ArchiveBackendError, ArchiveBackendProfileV1, ArchivePath,
    BoundArchiveProfilePolicyV1,
};

use crate::{LocalPathBackend, PublicationTargetV1};

/// Das Netzarchiv als Publikationsziel.
///
/// Der gehaltene Griff ist ein Cache für [`Self::publish_one`] und keine
/// zweite Wahrheit über die Erreichbarkeit: EA-CNA-PUB-4 verlangt, dass ein
/// verlorenes Netzziel den Zustand `Upload ausstehend` auslöst, und dafür
/// MUSS [`PublicationTargetV1::is_connected`] die Wurzel bei JEDEM Aufruf neu
/// prüfen — ein einmal gecachter Erfolg dürfte niemals ewig weitergelten,
/// sonst bliebe ein verschwundenes Laufwerk unbemerkt, bis ein harter
/// Schreibfehler es verrät.
pub struct NetworkArchiveTargetV1 {
    network_root: PathBuf,
    profile: ArchiveBackendProfileV1,
    policy: BoundArchiveProfilePolicyV1,
    held: Mutex<Option<LocalPathBackend>>,
}

impl NetworkArchiveTargetV1 {
    /// Baut das Ziel. KEIN Dateisystemzugriff — nur die Policyprüfung des
    /// gepinnten Profils.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ProfileNotAllowed`] fail-closed, wenn die Policy
    /// das Profil nicht trägt; sonst der Kodierfehler des Profilkerns.
    pub fn new(
        network_root: PathBuf,
        profile: ArchiveBackendProfileV1,
        policy: BoundArchiveProfilePolicyV1,
    ) -> Result<Self, ArchiveBackendError> {
        policy.require(profile.profile_hash()?)?;
        Ok(Self {
            network_root,
            profile,
            policy,
            held: Mutex::new(None),
        })
    }

    /// Öffnet die Netzwurzel — NIEMALS anlegend, NIEMALS ein anderes Profil.
    fn open_backend(&self) -> Result<LocalPathBackend, ArchiveBackendError> {
        LocalPathBackend::open_existing(
            self.network_root.clone(),
            self.profile.clone(),
            &self.policy,
        )
    }

    /// Ob ein Fehler von [`Self::publish_via_backend`] auf eine VERLORENE
    /// Verbindung hindeutet, statt auf einen reinen Datenbefund.
    ///
    /// `ByteConflict` bleibt hier bewusst draußen: das Ziel ist erreichbar und
    /// lehnt eine ANDERE Bytefolge an derselben Adresse ab — der gehaltene
    /// Griff ist deshalb weiterhin gültig, ein Verwerfen wäre nur teurer
    /// Leerlauf beim nächsten Aufruf.
    fn indicates_lost_connectivity(error: &ArchiveBackendError) -> bool {
        matches!(
            error,
            ArchiveBackendError::Io | ArchiveBackendError::FlushFailed
        )
    }

    /// Create-if-absent, Datei- und Verzeichnis-Flush, dann ein ERNEUTES
    /// Lesen — EA-CNA-PUB-3 ist erst erfüllt, wenn dieses Lesen dieselben
    /// Bytes liefert.
    fn publish_via_backend(
        backend: &LocalPathBackend,
        relative: &ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ArchiveBackendError> {
        let lock = backend.acquire_writer_lock()?;
        backend.create_non_object_if_absent(relative, bytes)?;
        backend.sync_file(relative)?;
        backend.sync_directory(relative)?;
        drop(lock);

        match backend.read_relative(relative.as_str()) {
            Some(actual) if actual == bytes => Ok(()),
            // Eine ABWEICHUNG hier ist kein Bytekonflikt im Sinn von
            // Create-if-absent — der hat bereits getragen —, sondern eine
            // nicht bestätigte Dauerhaftigkeit.
            Some(_) => Err(ArchiveBackendError::FlushFailed),
            None => Err(ArchiveBackendError::Io),
        }
    }
}

impl PublicationTargetV1 for NetworkArchiveTargetV1 {
    fn is_connected(&self) -> bool {
        // BILLIGE, bei JEDEM Aufruf WIEDERHOLTE Prüfung: nur ob die Wurzel
        // noch ein Verzeichnis ist. `LocalPathBackend::open_existing` wäre
        // hier FALSCH — es nimmt die exklusive Schreibersperre und
        // materialisiert bei Bedarf das Formatbeiwerk, und
        // `PublicationQueue::publish` hält seine eigene Sperre über genau
        // diesen Aufruf. Kein Cache: EA-CNA-PUB-4 verlangt, dass ein
        // verschwundenes Netzlaufwerk SOFORT als `Upload ausstehend` zählt
        // und nicht erst am nächsten harten Schreibfehler auffällt.
        std::fs::metadata(&self.network_root)
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false)
    }

    fn reconnect(&self) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        // Der Cache wird VERWORFEN, nicht nur neu geprüft: ein Netzlaufwerk,
        // das wieder eingehängt wurde, kann unter derselben Wurzel ein
        // frisches Verzeichnis-Handle verlangen.
        *held = None;
        if let Ok(backend) = self.open_backend() {
            *held = Some(backend);
        }
    }

    fn publish_one(&self, relative: &ArchivePath, bytes: &[u8]) -> Result<(), ArchiveBackendError> {
        // Nur Archivobjekte gehen ans Netzziel — das Formatbeiwerk des
        // Netzbestands entsteht mit dessen eigenem `open`, nicht über die
        // Publikationswarteschlange.
        ea_format::decode_exact_object(bytes)?;

        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_none() {
            *held = Some(self.open_backend()?);
        }
        let backend = held
            .as_ref()
            .expect("der Griff wurde soeben befüllt oder war schon da");

        let result = Self::publish_via_backend(backend, relative, bytes);
        if let Err(error) = &result
            && Self::indicates_lost_connectivity(error)
        {
            // Verbindung mitten in der Operation verloren: der Cache darf
            // kein totes Handle überleben lassen — sonst hielte der nächste
            // Aufruf einen Griff auf ein Verzeichnis, das nicht mehr
            // erreichbar ist.
            *held = None;
        }
        result
    }
}
