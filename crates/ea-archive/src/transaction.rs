use ea_format::ExactObjectBytes;

use crate::{ArchiveBackend, ArchiveBackendError, ArchivePath};

/// Die Bytes eines geplanten Schreibvorgangs — GESCHLOSSEN, zwei Arme.
///
/// Die Trennung ist dieselbe wie die des Inventars: Bytes MIT
/// Exact-Object-Praefix sind Archivobjekte, Bytes ohne sind Beiwerk. Sie kann
/// hier nicht verloren gehen, weil [`ExactObjectBytes`] nur aus `ea-format`
/// entsteht.
pub enum StagedBytesV1 {
    /// Ein Archivobjekt.
    Object(ExactObjectBytes),
    /// Formatbeiwerk ohne Exact-Object-Praefix.
    NonObject(Vec<u8>),
}

/// Ein geplanter Schreibvorgang: Zieladresse und Bytes.
pub struct StagedObjectV1 {
    target: ArchivePath,
    bytes: StagedBytesV1,
}

impl StagedObjectV1 {
    #[must_use]
    pub const fn new(target: ArchivePath, bytes: StagedBytesV1) -> Self {
        Self { target, bytes }
    }

    #[must_use]
    pub const fn target(&self) -> &ArchivePath {
        &self.target
    }
}

/// Der Suffix, unter dem ein Objekt vor seiner Veroeffentlichung liegt.
///
/// Absichtlich im ZIELVERZEICHNIS und nicht in einem Sammelverzeichnis: nur so
/// ist [`ArchiveBackend::atomic_rename_same_fs`] schon durch die Bauweise ein
/// Rename innerhalb desselben Dateisystems. Der Staging-Bereich der
/// Profilmigration ist ein anderer — er gehoert zur lokalen Commit-Komponente
/// des ZIELPROFILS (`design.md` §11.5) und wird deshalb ueber eine eigene
/// Bestandswurzel adressiert, nicht ueber diesen Suffix.
///
/// Eine liegengebliebene Datei mit diesem Suffix ist ein Gesundheitsbefund
/// (temporaere Datei) und kein Archivobjekt: sie traegt dieselben Bytes wie
/// das Ziel, aber das Inventar klassifiziert am Praefix und nicht am Namen.
pub const STAGING_SUFFIX_V1: &str = ".staging";

/// Eine Archivtransaktion mit expliziter Staging-Stufe.
///
/// Die Reihenfolge ist die Zusage, nicht eine Vorliebe:
///
/// 1. Jedes Objekt per Create-if-absent unter seinem Staging-Namen anlegen.
/// 2. Jede Staging-Datei flushen.
/// 3. Jedes tragende Verzeichnis flushen.
/// 4. ERST DANN jedes Objekt atomar auf seinen Zielnamen umbenennen.
///
/// Faellt irgendein Schritt vor Stufe 4 aus, existiert KEINE Zieladresse. Genau
/// das ist der Unterschied zwischen einer veroeffentlichten und einer
/// vorbereiteten Publikation; ohne diese Reihenfolge waere ein halb
/// geschriebenes Objekt unter seinem endgueltigen Namen sichtbar.
pub struct ArchiveTransaction<'a> {
    backend: &'a dyn ArchiveBackend,
    planned: Vec<StagedObjectV1>,
}

impl<'a> ArchiveTransaction<'a> {
    #[must_use]
    pub fn new(backend: &'a dyn ArchiveBackend) -> Self {
        Self {
            backend,
            planned: Vec::new(),
        }
    }

    /// Nimmt einen Schreibvorgang in die Transaktion auf.
    ///
    /// Die Reihenfolge der Aufnahme IST die Veroeffentlichungsreihenfolge.
    pub fn plan(&mut self, object: StagedObjectV1) {
        self.planned.push(object);
    }

    /// Die Zahl der aufgenommenen Schreibvorgaenge.
    #[must_use]
    pub fn planned_count(&self) -> usize {
        self.planned.len()
    }

    /// Fuehrt die vier Stufen aus.
    ///
    /// # Errors
    ///
    /// Der Fehler der Stufe, die nicht getragen hat. Nach einem Fehler vor
    /// Stufe 4 existiert keine Zieladresse.
    pub fn commit(self) -> Result<(), ArchiveBackendError> {
        let staged = self
            .planned
            .iter()
            .map(|object| staging_path(object.target()))
            .collect::<Result<Vec<_>, _>>()?;

        for (object, staging) in self.planned.iter().zip(&staged) {
            match &object.bytes {
                StagedBytesV1::Object(bytes) => {
                    self.backend.create_if_absent(staging, bytes)?;
                }
                StagedBytesV1::NonObject(bytes) => {
                    self.backend.create_non_object_if_absent(staging, bytes)?;
                }
            }
        }
        for staging in &staged {
            self.backend.sync_file(staging)?;
        }
        for staging in &staged {
            self.backend.sync_directory(staging)?;
        }
        for (object, staging) in self.planned.iter().zip(&staged) {
            self.backend
                .atomic_rename_same_fs(staging, object.target())?;
        }
        for object in &self.planned {
            self.backend.sync_directory(object.target())?;
        }
        Ok(())
    }
}

/// Die Staging-Adresse zu einer Zieladresse.
///
/// Beide liegen im SELBEN Layoutverzeichnis; das macht den Rename
/// dateisystemintern.
fn staging_path(target: &ArchivePath) -> Result<ArchivePath, ArchiveBackendError> {
    let directory = target.directory();
    let relative = &target.as_str()[directory.len()..];
    if directory.is_empty() {
        // Eine feste Wurzeldatei der Layoutliste hat kein tragendes
        // Verzeichnis; sie wird nicht ueber Staging veroeffentlicht.
        return Err(ArchiveBackendError::Path);
    }
    ArchivePath::in_dir(directory, &format!("{relative}{STAGING_SUFFIX_V1}"))
}
