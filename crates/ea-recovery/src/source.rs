use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource, MAX_TOTAL_ARCHIVE_BYTES_V1};

use crate::RecoveryError;

/// Ein Archivbestand, der in einem Verzeichnis liegt.
///
/// Die EINZIGE dateisystemgestuetzte [`ArchiveSource`] des Workspace.
/// `ea-archive` enthaelt ausdruecklich keine, weil es geteilter Browsercode
/// bleibt; hier entsteht sie, und nur hier.
///
/// # Warum vollstaendig eingelesen wird
///
/// [`ArchiveSource::visit_blobs`] reicht dem Besucher `&[u8]` mit der
/// Lebenszeit des Aufrufs. Ein Leser, der je Blob nachlaedt, muesste diese
/// Bytes irgendwo halten, das der Besucher ueberdauert — es gaebe keinen Ort
/// dafuer, der nicht wieder der ganze Bestand waere. Der Puffer ist deshalb
/// nicht Bequemlichkeit, sondern die Form des Ports.
///
/// Gedeckelt wird er von [`MAX_TOTAL_ARCHIVE_BYTES_V1`]. Der Deckel wird hier
/// NICHT dupliziert: das Inventar faellt weiterhin sein eigenes Urteil
/// ([`ArchiveError::TotalByteLimit`]) ueber einen durchlaufenen Bestand. Hier
/// begrenzt derselbe Wert lediglich den Puffer, BEVOR er entsteht, und meldet
/// [`RecoveryError::ArchiveTooLarge`].
///
/// [`ArchiveError::BlobLimit`] hat hier bewusst KEINE Entsprechung: eine Zahl
/// von Blobs kostet nichts, was vor dem Inventar begrenzt werden muesste.
///
/// # Kein `Debug`
///
/// Bewusst nicht abgeleitet. Dieser Typ haelt als einziger den HOSTPFAD, und
/// ein abgeleitetes `Debug` gaebe ihn heraus — samt aller Bestandsbytes. Beides
/// verbietet die Global Constraint des Stage-1-Plans.
pub struct FsArchiveSource {
    root: PathBuf,
    blobs: Vec<(String, Vec<u8>)>,
}

impl FsArchiveSource {
    /// Liest den gesamten Bestand unter `root` ein.
    ///
    /// # Durchlauf und Ordnung
    ///
    /// Rekursiv, und je Ebene sind die Verzeichniseintraege lexikographisch
    /// aufsteigend nach ihrem Namen sortiert. [`fs::read_dir`] gibt KEINE
    /// Ordnung; ohne die hier festgelegte haengen `nonObjectFileCount`, die
    /// Reihenfolge von Fehlern und damit jeder Berichtsvergleich am Zufall der
    /// Verzeichnisimplementierung.
    ///
    /// # Symlinks
    ///
    /// Werden uebersprungen. Ein Symlink ist weder Datei noch Verzeichnis
    /// DIESES Bestands: verfolgt man ihn, laesst sich ein Bestand aus sich
    /// heraus unbegrenzt aufblaehen — ein Symlink auf die eigene Wurzel
    /// genuegt. Gemessen wird mit [`fs::symlink_metadata`], nie mit
    /// [`fs::metadata`], denn letzteres folgt.
    ///
    /// Aus demselben Grund wird alles uebersprungen, was weder Datei noch
    /// Verzeichnis ist (Sockets, FIFOs, Geraete): es traegt keine Archivbytes,
    /// und ein Lesen darauf blockierte.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Io`], wenn ein Verzeichnis oder eine Datei nicht
    /// gelesen werden kann oder ein Dateiname kein gueltiges UTF-8 ist — ein
    /// unbenennbares Element stillschweigend zu ueberspringen hiesse, Bytes des
    /// Bestands zu verlieren, ohne es zu sagen. [`RecoveryError::ArchiveTooLarge`],
    /// wenn die Gesamtzahl der Bytes [`MAX_TOTAL_ARCHIVE_BYTES_V1`] uebersteigt.
    pub fn open(root: &Path) -> Result<Self, RecoveryError> {
        let mut blobs = Vec::new();
        let mut total_bytes = 0usize;
        read_directory(root, "", &mut blobs, &mut total_bytes)?;
        Ok(Self {
            root: root.to_path_buf(),
            blobs,
        })
    }

    /// Das Wurzelverzeichnis, wie es uebergeben wurde.
    ///
    /// Der Hostpfad lebt AUSSCHLIESSLICH hier. Er gelangt nie in einen
    /// Pfadhinweis und damit nie in eine Diagnose oder eine Ausgabe.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl ArchiveSource for FsArchiveSource {
    /// Reicht die eingelesenen Blobs in Durchlaufreihenfolge weiter.
    ///
    /// Ein Fehler des Besuchers haelt VOR dem naechsten Element an und wird
    /// durchgereicht — genau so setzt das Inventar seine Schranken durch. Ein
    /// Lesefehler kann hier nicht mehr entstehen, weil er bereits in
    /// [`FsArchiveSource::open`] aufgetreten waere.
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for (path_hint, bytes) in &self.blobs {
            visitor(ArchiveBlob::new(path_hint, bytes))?;
        }
        Ok(())
    }
}

/// Liest ein Verzeichnis und steigt in seine Unterverzeichnisse ab.
///
/// `prefix` ist der bereits gebildete relative Pfad dieses Verzeichnisses,
/// leer fuer die Wurzel.
fn read_directory(
    directory: &Path,
    prefix: &str,
    blobs: &mut Vec<(String, Vec<u8>)>,
    total_bytes: &mut usize,
) -> Result<(), RecoveryError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(RecoveryError::Io(ErrorKind::InvalidData))?
            .to_owned();
        entries.push((name, entry.path()));
    }
    // Der Pfadhinweis wird aus den Namen zusammengesetzt und nie aus einer
    // Plattformdarstellung des ganzen Pfades: ein Namensbestandteil enthaelt
    // auf keiner Plattform einen Verzeichnistrenner, weshalb das Ergebnis
    // ueberall `/`-getrennt und relativ ist.
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    for (name, path) in entries {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_symlink() {
            continue;
        }
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if metadata.is_dir() {
            read_directory(&path, &relative, blobs, total_bytes)?;
        } else if metadata.is_file() {
            // ZUERST die angekuendigte Laenge, DANN das Lesen. Andersherum legte
            // eine einzelne uebergrosse Datei ihren Puffer vollstaendig an,
            // bevor er verworfen wuerde — der Deckel schuetzte dann nichts
            // mehr. Auf einer 32-Bit-Plattform ist eine Laenge, die nicht in
            // `usize` passt, aus demselben Grund bereits zu gross.
            let declared =
                usize::try_from(metadata.len()).map_err(|_| RecoveryError::ArchiveTooLarge)?;
            if total_bytes.saturating_add(declared) > MAX_TOTAL_ARCHIVE_BYTES_V1 {
                return Err(RecoveryError::ArchiveTooLarge);
            }
            // Gezaehlt wird danach die TATSAECHLICH gelesene Laenge: zwischen
            // `symlink_metadata` und `read` kann die Datei gewachsen sein, und
            // die Buchhaltung muss dem folgen, was im Speicher liegt.
            let bytes = fs::read(&path)?;
            *total_bytes = total_bytes.saturating_add(bytes.len());
            if *total_bytes > MAX_TOTAL_ARCHIVE_BYTES_V1 {
                return Err(RecoveryError::ArchiveTooLarge);
            }
            blobs.push((relative, bytes));
        }
    }
    Ok(())
}
