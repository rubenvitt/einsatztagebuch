use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use ea_archive::{
    ArchiveBackendError, ArchiveBlob, ArchiveError, ArchivePath, ArchiveSource, LAYOUT_PATHS_V1,
    MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1,
};

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
/// Genauso gedeckelt wird die ZAHL der Bytesequenzen, und zwar aus demselben
/// Grund. Der Bytedeckel allein traegt sie nicht: eine leere Datei zaehlt null
/// Bytes und kostet im Puffer trotzdem einen `String` und einen `Vec` — ein
/// Verzeichnisbaum aus leeren Dateien passiert [`MAX_TOTAL_ARCHIVE_BYTES_V1`]
/// vollstaendig und legte vor dem Inventar beliebig viel Speicher an. Gedeckelt
/// wird deshalb auf [`MAX_ARCHIVE_BLOBS_V1`] — auf denselben Wert, den das
/// Inventar anschliessend als [`ArchiveError::BlobLimit`] durchsetzt, und mit
/// derselben inklusiven Grenze: genau so viele Blobs bleiben zulaessig.
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
    /// Vereinigt diesen bereits eingelesenen Bestand mit den Bytes einer EXAKT
    /// gebundenen Komponente.
    ///
    /// Die Bytes der Komponente bleiben ungeprueftes Eingabematerial des
    /// gewoehnlichen Verifikationswegs: hier entsteht nur eine
    /// Bytevereinigung, kein Urteil. Die Vereinigung entsteht ausschliesslich
    /// im Speicher und schreibt KEINE Komponentenbytes in das Dateisystem —
    /// `root` bleibt unberuehrt, und ein erneutes [`FsArchiveSource::open`]
    /// auf derselben Wurzel sieht denselben Bestand wie zuvor.
    ///
    /// # Adresse vor Bytes
    ///
    /// Jede eingehende Adresse wird zuerst gegen den Adressvertrag eines
    /// Bestands geprueft ([`ArchivePath`]), bevor ihre Bytes ueberhaupt
    /// betrachtet werden. Die Adresse entscheidet dabei nie darueber, ob die
    /// Bytes ein Archivobjekt SIND — das entscheidet weiterhin allein das
    /// 9-Byte-Exact-Object-Praefix beim Inventarisieren. Hier wird adressiert,
    /// nicht klassifiziert.
    ///
    /// # Bytegleich einmal, bytefremd gar nicht
    ///
    /// Eine Adresse, die dieser Bestand schon traegt, ist fuer bytegleiche
    /// Wiederholungen idempotent — sie bleibt genau einmal in der Vereinigung
    /// — und fuer abweichende Bytes fail-closed
    /// ([`ArchiveBackendError::ByteConflict`]). Das ist dieselbe Zusage, die
    /// `create_if_absent` beim Schreiben gibt
    /// (`crates/ea-archive/src/backend.rs:20`); ein stilles Ersetzen gaebe es
    /// hier so wenig wie dort. Die Ordnung ist fest: zuerst die Zeilen dieses
    /// Bestands in ihrer Durchlaufreihenfolge, danach die neuen Zeilen der
    /// Komponente in ihrer Besuchsreihenfolge.
    ///
    /// # Staging
    ///
    /// Staging-Adressen der Komponente werden UEBERNOMMEN. Sie bleiben
    /// Sicherungsmaterial und werden nie Kettenfortschritt: genau dafuer
    /// schneidet [`FsArchiveSource::committed_view`] sie wieder heraus, und
    /// zwar aus derselben eingefrorenen Vereinigung, ohne erneut zu lesen.
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Path`], wenn eine eingehende Adresse keine
    /// gueltige Transportadresse eines Bestands ist.
    /// [`ArchiveBackendError::ByteConflict`], wenn dieselbe Adresse
    /// abweichende Bytes traegt. [`ArchiveBackendError::InventoryMismatch`],
    /// wenn die Komponente sich nicht zu Ende aufzaehlen laesst oder ihre
    /// Aufzaehlung eine Ressourcengrenze des Bestands reisst: beides heisst,
    /// dass sie ein Inventar behauptet, das sich mit diesem nicht vereinigen
    /// laesst. Ein Fehler verwirft IMMER die ganze Vereinigung; eine
    /// unvollstaendige Komponente wird nie teilweise uebernommen.
    pub fn with_exact_component(
        self,
        source: &dyn ArchiveSource,
    ) -> Result<Self, ArchiveBackendError> {
        let Self { root, mut blobs } = self;
        // Ein linearer Vergleich je Zeile waere quadratisch, und die Schranke
        // dieses Bestands ist `MAX_ARCHIVE_BLOBS_V1`: die Adresse muss in
        // konstanter Zeit auffindbar sein, sonst ist die Grenze selbst der
        // Angriff.
        let mut address_of: HashMap<String, usize> = blobs
            .iter()
            .enumerate()
            .map(|(at, (path_hint, _))| (path_hint.clone(), at))
            .collect();
        let mut total_bytes = blobs
            .iter()
            .fold(0usize, |sum, (_, bytes)| sum.saturating_add(bytes.len()));
        let mut enumerated = 0usize;
        let mut refusal: Option<ArchiveBackendError> = None;
        let walked = source.visit_blobs(&mut |blob| {
            // Eine Quelle, die den Fehler des Besuchers verschluckt und
            // weiterreicht, darf die Vereinigung nicht doch noch wachsen
            // lassen.
            if refusal.is_some() {
                return Err(ArchiveError::Unavailable);
            }
            // GEZAEHLT WIRD DER BESUCH, nicht die gewachsene Vereinigung.
            // Bytegleiche Wiederholungen fallen unten zusammen und kosteten
            // die Aufzaehlung sonst gar nichts — eine Quelle, die dieselbe
            // leere Zeile beliebig oft reicht, liefe damit unbegrenzt weiter.
            enumerated = enumerated.saturating_add(1);
            if enumerated > MAX_ARCHIVE_BLOBS_V1 {
                refusal = Some(ArchiveBackendError::InventoryMismatch);
                return Err(ArchiveError::BlobLimit);
            }
            if let Err(error) = component_address(blob.path_hint()) {
                refusal = Some(error);
                return Err(ArchiveError::Unavailable);
            }
            if let Some(&at) = address_of.get(blob.path_hint()) {
                if blobs[at].1 != blob.bytes() {
                    refusal = Some(ArchiveBackendError::ByteConflict);
                    return Err(ArchiveError::Unavailable);
                }
                return Ok(());
            }
            // Dieselben INKLUSIVEN Grenzen wie beim Einlesen: genau
            // `MAX_ARCHIVE_BLOBS_V1` Zeilen und genau
            // `MAX_TOTAL_ARCHIVE_BYTES_V1` Bytes bleiben zulaessig. Gedeckelt
            // wird VOR dem Anlegen, sonst entstuende genau der Puffer, den der
            // Deckel verhindern soll.
            if blobs.len() >= MAX_ARCHIVE_BLOBS_V1 {
                refusal = Some(ArchiveBackendError::InventoryMismatch);
                return Err(ArchiveError::BlobLimit);
            }
            total_bytes = total_bytes.saturating_add(blob.bytes().len());
            if total_bytes > MAX_TOTAL_ARCHIVE_BYTES_V1 {
                refusal = Some(ArchiveBackendError::InventoryMismatch);
                return Err(ArchiveError::TotalByteLimit);
            }
            address_of.insert(blob.path_hint().to_owned(), blobs.len());
            blobs.push((blob.path_hint().to_owned(), blob.bytes().to_vec()));
            Ok(())
        });
        if let Some(error) = refusal {
            return Err(error);
        }
        // Ein Fehler der QUELLE selbst. Er bleibt eine Aussage ueber das
        // Inventar der Komponente und wird nie zu einem Befund ueber ein
        // einzelnes Objekt.
        walked.map_err(|_| ArchiveBackendError::InventoryMismatch)?;
        Ok(Self { root, blobs })
    }
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
    /// wenn die Gesamtzahl der Bytes [`MAX_TOTAL_ARCHIVE_BYTES_V1`] oder die Zahl
    /// der Bytesequenzen [`MAX_ARCHIVE_BLOBS_V1`] uebersteigt.
    pub fn open(root: &Path) -> Result<Self, RecoveryError> {
        Self::open_with_staging(root, true)
    }

    /// Frozen operational view of committed archive bytes. Staging remains
    /// available through `open` for forensic recovery, but cannot supply an
    /// operation's next committed sequence before the final atomic rename.
    pub fn open_committed(root: &Path) -> Result<Self, RecoveryError> {
        Self::open_with_staging(root, false)
    }

    /// Select committed objects from the already frozen bytes. Recovery source
    /// scopes retain staging too, while their chain/sample verification uses
    /// this exact snapshot without another filesystem read.
    pub fn committed_view(&self) -> Self {
        Self {
            root: self.root.clone(),
            blobs: self
                .blobs
                .iter()
                .filter(|(path, _)| !ea_archive::is_staging_path(path))
                .cloned()
                .collect(),
        }
    }

    fn open_with_staging(root: &Path, include_staging: bool) -> Result<Self, RecoveryError> {
        let mut blobs = Vec::new();
        let mut total_bytes = 0usize;
        read_directory(root, "", &mut blobs, &mut total_bytes, include_staging)?;
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

/// Prueft eine EINGEHENDE Adresse gegen den Adressvertrag eines Bestands.
///
/// Kein zweiter Vertrag, sondern [`ArchivePath`] auf einen wurzelrelativen
/// Pfadhinweis angewandt: entweder eine der festen Dateien der Layoutliste,
/// oder eine Adresse unterhalb eines ihrer Verzeichnisse. Genommen wird das
/// LAENGSTE passende Verzeichnis, damit `format/schemas/x` unter
/// `format/schemas/` faellt und nicht unter `format/`.
///
/// Geprueft wird damit genau das, was auch das Schreiben durchsetzt, und es
/// bleibt eine Aussage ueber die ADRESSE: was die Bytes sind, entscheidet
/// weiterhin allein das Inventar.
fn component_address(path_hint: &str) -> Result<(), ArchiveBackendError> {
    if ArchivePath::at_layout_file(path_hint).is_ok() {
        return Ok(());
    }
    let directory = LAYOUT_PATHS_V1
        .into_iter()
        .filter(|candidate| candidate.ends_with('/') && path_hint.starts_with(candidate))
        .max_by_key(|candidate| candidate.len())
        .ok_or(ArchiveBackendError::Path)?;
    ArchivePath::in_dir(directory, &path_hint[directory.len()..]).map(|_| ())
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
    include_staging: bool,
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
        // AUCH DIESE EBENE IST EIN PUFFER. Ihre Namen liegen vollstaendig im
        // Speicher, bevor der erste Blob entsteht; der Deckel am Push allein
        // greift fuer sie deshalb zu spaet. Mehr Eintraege als
        // `MAX_ARCHIVE_BLOBS_V1` kann keine Ebene eines zulaessigen Bestands
        // tragen — waeren es Dateien, ueberschritten sie die Schranke bereits
        // fuer sich allein.
        if entries.len() > MAX_ARCHIVE_BLOBS_V1 {
            return Err(RecoveryError::ArchiveTooLarge);
        }
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
            read_directory(&path, &relative, blobs, total_bytes, include_staging)?;
        } else if metadata.is_file() {
            if !include_staging && ea_archive::is_staging_path(&relative) {
                continue;
            }
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
            // Nach dem Push und mit `>`: genau `MAX_ARCHIVE_BLOBS_V1` Blobs
            // bleiben zulaessig, dieselbe inklusive Grenze wie in
            // `crates/ea-archive/src/inventory.rs:447`.
            if blobs.len() > MAX_ARCHIVE_BLOBS_V1 {
                return Err(RecoveryError::ArchiveTooLarge);
            }
        }
    }
    Ok(())
}
