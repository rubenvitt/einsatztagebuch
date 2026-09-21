//! Das PRODUKTIONSZIEL der Publikationswarteschlange: ein kontrolliertes
//! Netzarchiv, gelesen und geschrieben ueber ein gewoehnliches
//! [`LocalPathBackend`] auf dessen kanonischem Wurzelpfad.
//!
//! `EA-CNA-PUB-3` ist die tragende Zusage: veroeffentlicht wird mit
//! Create-if-absent, anschliessendem Datei- und Verzeichnis-Flush, und ein
//! Objekt gilt erst als publiziert, wenn ein ERNEUTES Lesen des Netzziels
//! dieselben Bytes liefert. `EA-CNA-PUB-6` ist die zweite: es gibt kein
//! Ausweichen auf ein anderes Ziel — dieser Typ oeffnet ausschliesslich seine
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
/// Der gehaltene Griff ist ein CACHE und keine zweite Wahrheit: er entsteht
/// aus genau derselben `LocalPathBackend::open_existing`-Pruefung, die auch
/// [`Self::is_connected`] traegt, und wird nach [`Self::reconnect`] verworfen
/// und neu versucht. Zwischen zwei Aufrufen macht er wiederholte
/// Netzpublikationen billig, ohne die Wurzel bei jedem Objekt neu zu oeffnen.
pub struct NetworkArchiveTargetV1 {
    network_root: PathBuf,
    profile: ArchiveBackendProfileV1,
    policy: BoundArchiveProfilePolicyV1,
    held: Mutex<Option<LocalPathBackend>>,
}

impl NetworkArchiveTargetV1 {
    /// Baut das Ziel. KEIN Dateisystemzugriff — nur die Policypruefung des
    /// gepinnten Profils.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::ProfileNotAllowed`] fail-closed, wenn die Policy
    /// das Profil nicht traegt; sonst der Kodierfehler des Profilkerns.
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

    /// Oeffnet die Netzwurzel — NIEMALS anlegend, NIEMALS ein anderes Profil.
    fn open_backend(&self) -> Result<LocalPathBackend, ArchiveBackendError> {
        LocalPathBackend::open_existing(
            self.network_root.clone(),
            self.profile.clone(),
            &self.policy,
        )
    }
}

impl PublicationTargetV1 for NetworkArchiveTargetV1 {
    fn is_connected(&self) -> bool {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_some() {
            return true;
        }
        match self.open_backend() {
            Ok(backend) => {
                *held = Some(backend);
                true
            }
            Err(_) => false,
        }
    }

    fn reconnect(&self) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        // Der Cache wird VERWORFEN, nicht nur neu geprueft: ein Netzlaufwerk,
        // das wieder eingehaengt wurde, kann unter derselben Wurzel ein
        // frisches Verzeichnis-Handle verlangen.
        *held = None;
        if let Ok(backend) = self.open_backend() {
            *held = Some(backend);
        }
    }

    fn publish_one(&self, relative: &ArchivePath, bytes: &[u8]) -> Result<(), ArchiveBackendError> {
        // Nur Archivobjekte gehen ans Netzziel — das Formatbeiwerk des
        // Netzbestands entsteht mit dessen eigenem `open`, nicht ueber die
        // Publikationswarteschlange.
        ea_format::decode_exact_object(bytes)?;

        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_none() {
            *held = Some(self.open_backend()?);
        }
        let backend = held
            .as_ref()
            .expect("der Griff wurde soeben befuellt oder war schon da");

        let lock = backend.acquire_writer_lock()?;
        backend.create_non_object_if_absent(relative, bytes)?;
        backend.sync_file(relative)?;
        backend.sync_directory(relative)?;
        drop(lock);

        // EA-CNA-PUB-3: publiziert ist erst, was ein ERNEUTES Lesen
        // byteidentisch zurueckgibt. Eine Abweichung hier ist kein
        // Bytekonflikt im Sinn von Create-if-absent — der hat bereits
        // getragen —, sondern eine nicht bestaetigte Dauerhaftigkeit.
        match backend.read_relative(relative.as_str()) {
            Some(actual) if actual == bytes => Ok(()),
            Some(_) => Err(ArchiveBackendError::FlushFailed),
            None => Err(ArchiveBackendError::Io),
        }
    }
}
