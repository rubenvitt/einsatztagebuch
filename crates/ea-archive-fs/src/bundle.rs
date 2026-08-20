//! Der Ein-Datei-Buendelexport und sein Leser.
//!
//! # Warum dieser Container existiert
//!
//! Der Datei-Modus des Web-Readers hat zwei Wege hinein, und nur einer davon
//! funktioniert ueberall: `showDirectoryPicker` fehlt in Safari und Firefox,
//! also MUSS der universelle Weg — EINE exportierte Datei durch den gewoehnlichen
//! Dateidialog — immer angeboten werden
//! (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md:139-145`,
//! §12 auf `:441-442`).
//!
//! # Es entsteht KEINE siebte Objektfamilie
//!
//! Der Container traegt UEBERHAUPT KEIN Exact-Object-Praefix. Die sechs
//! Praefixe und ihre Kodierer (`crates/ea-format/src/lib.rs:39-45`), der Pin
//! gegen die Grammatik (`tools/xtask/tests/spec_completeness.rs:6-8`) und
//! `schemas/archive/v1/archive.cddl:19-62` bleiben byteweise unberuehrt; es
//! entsteht keine CDDL, keine Vektorfamilie und keine `TrustSubtypeV1`-Variante.
//! Die Magie beginnt mit `0x45` (`b'E'`) und kann deshalb nie mit einem
//! Exact-Object-Praefix verwechselt werden, dessen erste zwei Bytes `0x85 0x44`
//! sind (`crates/ea-format/src/parser.rs:21-26`). Faellt ein Buendel je in ein
//! Bestandsverzeichnis, klassifiziert das Inventar es am Praefix und zaehlt es
//! unter `nonObjectFileCount` (`crates/ea-archive/src/lib.rs:22-38`) — die
//! Klasse ist nicht durch Umbenennen waehlbar, und genau diese Eigenschaft
//! erlaubt diesem Container, NEBEN dem eingefrorenen Format zu existieren statt
//! darin.
//!
//! # Es wird nichts signiert und nichts entschluesselt
//!
//! Ein Buendel ist eine Transportschale ueber Bytes, die ihre Signaturen
//! bereits selbst tragen, und niemals eine neue Autoritaet: die Verifikation im
//! Datei-Modus laeuft stets gegen den Root-Anker im Tresor des Readers, und
//! Trust-Objekte, die IN der geoeffneten Datei liegen, begruenden von sich aus
//! kein Vertrauen (`design.md` des Web-Readers, `:147-156`). Es gibt hier kein
//! `--key`, keinen Empfaengerschluessel und keinen Klartext; ein Buendel ist
//! verschluesselt, WEIL seine Objekte es sind.
//!
//! # Das Containerformat
//!
//! ```text
//! [0 ..32)        BUNDLE_MAGIC_V1                     (32 ASCII-Bytes)
//! [32..40)        u64 big-endian: Blobzahl
//! [40..48)        u64 big-endian: Bytelaenge n der Indexregion
//! [48..48+n)      Indexregion: ein Satz je Blob, in Indexreihenfolge
//!                   u16 big-endian: Bytelaenge p der Adresse
//!                   p Bytes:        die relative Adresse als NFC-UTF-8
//!                   u64 big-endian: Offset in die Nutzlastregion
//!                   u64 big-endian: Bytelaenge des Blobs
//! [48+n.. )       Nutzlastregion: die Blobs, wortwoertlich, in Indexreihenfolge
//! ```
//!
//! Jedes Kopf- und Indexfeld ist eine vorzeichenlose Big-Endian-Ganzzahl fester
//! Breite. Es gibt kein CBOR, keine Laengenpraefix-Ambiguitaet und keine
//! selbstbeschreibende Typschicht — und deshalb KEINE neue Abhaengigkeit:
//! `ea-archive-fs` behaelt genau die sechs Workspace-Kanten aus Task 9,
//! `Cargo.lock` bleibt wie er ist.
//!
//! Indexsaetze sind STRENG aufsteigend ueber die Adressbytes sortiert, keine
//! Adresse kommt zweimal vor, und die Offsets sind zusammenhaengend ab null:
//! der erste Blob beginnt bei `0`, jeder folgende genau dort, wo sein Vorgaenger
//! endete, und die Nutzlastregion endet genau am Dateiende. Es gibt keine
//! Fuellung, keine Ausrichtung und keinen freien Platz — deshalb sind zwei
//! Exporte desselben Bestands dieselbe Datei, und jedes eingeschobene Byte ist
//! eine Abweisung und keine still geduldete Differenz.

use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::Path,
};

use ea_archive::{
    ArchiveBlob, ArchiveError, ArchiveSource, MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1,
};
use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;
use ea_verify::{VerifyOptions, verify_archive};

use crate::{BundleError, LocalPathBackend, format_package::materialize_format_package_reporting};

/// Die Magie am Dateianfang.
///
/// 32 ASCII-Bytes, beginnend mit `b'E'` — nie mit `0x85`. Das erste Byte IST
/// die Zusage, dass dieser Container kein Archivobjekt vorgibt zu sein.
pub const BUNDLE_MAGIC_V1: [u8; 32] = *b"EINSATZARCHIV-ARCHIVE-BUNDLE-v1\n";

/// Die Bytelaenge des Kopfes: Magie, Blobzahl, Indexlaenge.
pub const BUNDLE_HEADER_BYTES_V1: usize = 48;

/// Die Dateiendung eines Archivbuendels, ohne Punkt.
pub const BUNDLE_FILE_EXTENSION_V1: &str = "eabundle";

/// Die Bytelaenge eines Indexsatzes ohne seine Adresse.
const INDEX_RECORD_FIXED_BYTES: usize = 2 + 8 + 8;

/// Was ein Buendelexport getan hat.
///
/// Traegt die Zahl der uebertragenen Bytesequenzen und sonst nichts: sie ist
/// die eine Aussage, die eine Bytekarte des Ziels gegen die der Quelle stellt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleExportReport {
    blob_count: usize,
}

impl BundleExportReport {
    /// Die Zahl der uebertragenen Bytesequenzen.
    #[must_use]
    pub const fn blob_count(&self) -> usize {
        self.blob_count
    }
}

/// Ein Indexsatz des Containers, geprueft.
struct BundleIndexEntry {
    path: String,
    offset: usize,
    length: usize,
}

/// Ein Archivbestand, der als EINE Datei vorliegt.
///
/// Die Lesequelle des Containers. Sie ist STRENG: Magie, Indexlaenge und Index
/// werden vollstaendig geprueft — sortiert, duplikatfrei, zusammenhaengend, in
/// den Grenzen, innerhalb beider Deckel — und erst danach ueberhaupt ein Blob
/// herausgegeben. Eine Strukturverletzung ist ein Fehler und NIE ein
/// uebersprungener Eintrag: einen Blob stillschweigend fallenzulassen hiesse,
/// Archivbytes zu verlieren, ohne es zu sagen.
///
/// # Kein `Debug`
///
/// Bewusst nicht abgeleitet. Der Typ haelt den vollstaendigen Bestand im
/// Speicher; ein abgeleitetes `Debug` gaebe jedes Byte heraus.
pub struct ArchiveBundleSource {
    bytes: Vec<u8>,
    index: Vec<BundleIndexEntry>,
    payload_start: usize,
}

impl ArchiveBundleSource {
    /// Liest ein Buendel von der Platte.
    ///
    /// # Errors
    ///
    /// [`BundleError::Io`], wenn die Datei nicht lesbar ist; sonst der Befund
    /// von [`Self::from_bytes`].
    pub fn open(path: &Path) -> Result<Self, BundleError> {
        let bytes = fs::read(path).map_err(|_| BundleError::Io)?;
        Self::from_bytes(bytes)
    }

    /// Prueft Containerbytes vollstaendig und uebernimmt sie.
    ///
    /// # Die Reihenfolge der Pruefungen ist die Zusage
    ///
    /// Die Blobgrenze wird aus dem KOPF durchgesetzt, bevor ein Indexsatz
    /// angefasst wird: sonst muesste ein Angreifer erst
    /// [`MAX_ARCHIVE_BLOBS_V1`] Saetze mitliefern, um die Grenze zu erreichen,
    /// und die Grenze schuetzte nichts. Der Bytedeckel wird beim Aufsummieren
    /// der Blobs durchgesetzt, also ebenfalls bevor er ueberschritten sein kann.
    /// Beide sind dieselben Werte und dieselben INKLUSIVEN Grenzen, die der
    /// Verzeichnisleser benutzt (`crates/ea-recovery/src/source.rs:30-41`) —
    /// nie ein zweiter Satz Zahlen.
    ///
    /// # Errors
    ///
    /// [`BundleError::Malformed`] fuer jede Strukturverletzung,
    /// [`BundleError::BlobLimit`] und [`BundleError::TotalByteLimit`] fuer die
    /// zwei Deckel.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, BundleError> {
        if bytes.len() < BUNDLE_HEADER_BYTES_V1 {
            return Err(BundleError::Malformed);
        }
        if bytes[..BUNDLE_MAGIC_V1.len()] != BUNDLE_MAGIC_V1 {
            return Err(BundleError::Malformed);
        }
        // Eine Blobzahl, die nicht in `usize` passt, IST eine Ueberschreitung des
        // Deckels und keine Formverletzung: [`MAX_ARCHIVE_BLOBS_V1`] passt in
        // 32 Bit, also liegt jeder nicht wandelbare Wert darueber. Ohne diese
        // Unterscheidung truege derselbe Container auf wasm32 (`usize` = 32 Bit)
        // einen anderen Befund als auf einem 64-Bit-Wirt.
        let blob_count = match usize::try_from(read_u64_raw(&bytes, 32)?) {
            Ok(count) if count <= MAX_ARCHIVE_BLOBS_V1 => count,
            _ => return Err(BundleError::BlobLimit),
        };
        let index_length = read_u64(&bytes, 40)?;
        let payload_start = BUNDLE_HEADER_BYTES_V1
            .checked_add(index_length)
            .ok_or(BundleError::Malformed)?;
        if payload_start > bytes.len() {
            return Err(BundleError::Malformed);
        }

        let mut index: Vec<BundleIndexEntry> = Vec::new();
        let mut at = BUNDLE_HEADER_BYTES_V1;
        let mut consumed: usize = 0;
        while at < payload_start {
            let path_length = usize::from(u16::from_be_bytes(
                bytes
                    .get(at..at + 2)
                    .ok_or(BundleError::Malformed)?
                    .try_into()
                    .map_err(|_| BundleError::Malformed)?,
            ));
            let record_end = at
                .checked_add(INDEX_RECORD_FIXED_BYTES)
                .and_then(|end| end.checked_add(path_length))
                .ok_or(BundleError::Malformed)?;
            if record_end > payload_start {
                return Err(BundleError::Malformed);
            }
            let path = core::str::from_utf8(&bytes[at + 2..at + 2 + path_length])
                .map_err(|_| BundleError::Malformed)?
                .to_owned();
            validate_bundle_path(&path)?;
            // STRENG aufsteigend — das ist zugleich die Duplikatpruefung: eine
            // Adresse, die zweimal vorkommt, ist nicht mehr streng aufsteigend.
            if let Some(previous) = index.last()
                && previous.path.as_bytes() >= path.as_bytes()
            {
                return Err(BundleError::Malformed);
            }
            let offset = read_u64(&bytes, at + 2 + path_length)?;
            let length = read_u64(&bytes, at + 2 + path_length + 8)?;
            // ZUSAMMENHAENGEND ab null: der erste Blob beginnt bei 0, jeder
            // folgende genau dort, wo sein Vorgaenger endete. Damit gibt es
            // weder eine Luecke noch eine Ueberlappung, und ein eingeschobenes
            // Byte kann nicht als Fuellung durchgehen.
            if offset != consumed {
                return Err(BundleError::Malformed);
            }
            consumed = consumed
                .checked_add(length)
                .ok_or(BundleError::TotalByteLimit)?;
            if consumed > MAX_TOTAL_ARCHIVE_BYTES_V1 {
                return Err(BundleError::TotalByteLimit);
            }
            index.push(BundleIndexEntry {
                path,
                offset,
                length,
            });
            at = record_end;
        }
        // Der Index geht GENAU auf: genau so viele Saetze, wie der Kopf
        // behauptet. Dass die Indexregion dabei exakt endet, erzwingt schon
        // `record_end > payload_start` oben — ein angeschnittener letzter Satz
        // ist dort bereits abgewiesen, und eine zweite Bedingung dafuer koennte
        // nie feuern.
        if index.len() != blob_count {
            return Err(BundleError::Malformed);
        }
        // Die Nutzlastregion endet GENAU am Dateiende.
        if bytes.len() - payload_start != consumed {
            return Err(BundleError::Malformed);
        }
        Ok(Self {
            bytes,
            index,
            payload_start,
        })
    }

    /// Die rohen Containerbytes.
    ///
    /// Crate-intern: [`write_archive_bundle`] verifiziert die kodierten Bytes
    /// durch diesen Typ hindurch und schreibt danach GENAU sie. Ein zweiter
    /// Puffer daneben waere bei einem Bestand an der Obergrenze ein zweites
    /// Gigabyte, und — schlimmer — er koennte abweichen.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ArchiveSource for ArchiveBundleSource {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        for entry in &self.index {
            let start = self.payload_start + entry.offset;
            visitor(ArchiveBlob::new(
                &entry.path,
                &self.bytes[start..start + entry.length],
            ))?;
        }
        Ok(())
    }
}

/// Liest acht Big-Endian-Bytes ab `at` als `usize`.
///
/// `usize` und nicht `u64`, weil jeder Leser dieses Wertes indexiert. Auf
/// wasm32 ist `usize` 32 Bit breit; ein Wert, der dort nicht passt, ist genau
/// deshalb eine Strukturverletzung und keine stille Verkuerzung.
fn read_u64(bytes: &[u8], at: usize) -> Result<usize, BundleError> {
    usize::try_from(read_u64_raw(bytes, at)?).map_err(|_| BundleError::Malformed)
}

/// Liest acht Big-Endian-Bytes ab `at`, ohne sie zu verengen.
fn read_u64_raw(bytes: &[u8], at: usize) -> Result<u64, BundleError> {
    let slice = bytes.get(at..at + 8).ok_or(BundleError::Malformed)?;
    Ok(u64::from_be_bytes(
        slice.try_into().map_err(|_| BundleError::Malformed)?,
    ))
}

/// Die Adressregeln eines Indexsatzes.
///
/// Dieselben Regeln, die `validate_inventory_path`
/// (`crates/ea-format/src/archive_profile.rs:295-317`) an einen
/// Inventarpfad stellt, mit einer benannten Ausnahme: die NFC-Pruefung
/// braucht `unicode_normalization`, und dieser Task darf keine neue
/// Abhaengigkeitskante ziehen. NFC bleibt damit eine Zusage der ERZEUGENDEN
/// Seite — die Adressen eines Exports kommen aus dem Bestand, dessen Inventar
/// die volle Regel schon durchsetzt.
fn validate_bundle_path(path: &str) -> Result<(), BundleError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(BundleError::Malformed);
    }
    // Ein Windows-Laufwerksbuchstabe ist ebenso eine absolute Wurzel wie ein
    // fuehrender Schraegstrich.
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return Err(BundleError::Malformed);
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(BundleError::Malformed);
        }
    }
    Ok(())
}

/// Exportiert einen Bestand als EIN verifizierbares Buendel.
///
/// # Die Reihenfolge, und warum sie diese ist
///
/// Sie folgt der, die der Verzeichnisexport schon aufgestellt hat
/// (`crates/ea-recovery/src/export.rs:26-42`), und aus demselben Grund: ein
/// Export ist eine KOPIE und keine Neuausgabe, und es wird nichts kopiert,
/// worueber nicht zuvor geurteilt wurde.
///
/// 1. Das Formatbeiwerk materialisieren, falls der Bestand es nicht traegt —
///    ein Buendel ist nie ein weniger vollstaendiger Bestand als das
///    Verzeichnis, aus dem es kommt. `nonObjectFileCount` gehoert zum Bericht,
///    und ein Buendel ohne `README-FORMAT.txt` verifizierte zu einem ANDEREN
///    Bericht. Dieser Schritt steht VOR dem Lesen: liefe er danach, enthielte
///    der Puffer genau das nicht, was er hinzufuegt.
/// 2. Den Bestand EINMAL lesen, gedeckelt von [`MAX_ARCHIVE_BLOBS_V1`] und
///    [`MAX_TOTAL_ARCHIVE_BYTES_V1`].
/// 3. Die Containerbytes kodieren und durch [`ArchiveBundleSource::from_bytes`]
///    zuruecklesen — die Selbstpruefung, die belegt, dass das Geschriebene die
///    strengen Regeln des Lesers erfuellt.
/// 4. GENAU DIESE Bytes vollstaendig gegen den von aussen uebergebenen
///    [`TrustAnchorV1`] verifizieren. Ein Bericht, der nicht vollstaendig
///    verifiziert ist, beendet den Lauf und erzeugt KEIN Ziel.
/// 5. Erst jetzt anlegen — mit `O_CREAT|O_EXCL`, das ein belegtes Ziel abweist,
///    bevor ein einziges Byte fliesst. Dieselbe Freies-Ziel-Regel, die
///    `crates/ea-recovery/src/target.rs` einmal aufschreibt, in EINER
///    Formulierung.
/// 6. Schreiben, dann Datei und Verzeichnis flushen.
///
/// Es wird nichts entschluesselt, nichts neu kodiert, nichts umsortiert und
/// nichts ausgelassen.
///
/// # Errors
///
/// [`BundleError::SourceNotFullyVerified`], [`BundleError::TargetOccupied`],
/// [`BundleError::Malformed`], die zwei Deckel und [`BundleError::Io`].
pub fn write_archive_bundle(
    source: &LocalPathBackend,
    anchor: &TrustAnchorV1,
    os_wall_clock: UnixMillis,
    target: &Path,
) -> Result<BundleExportReport, BundleError> {
    // Schritt 1. Der BERICHTENDE Weg: eine abweichende Beiwerkadresse ist hier
    // KEIN Abbruchgrund, sondern bleibt unangetastet und reist wortwoertlich
    // mit — dieselbe Entscheidung, die `LocalPathBackend::open` fuer das
    // Oeffnen eines Bestands schon getroffen hat. Der Aufruf ist idempotent;
    // auf einem Bestand, den `open` erzeugt hat, ist er ein Leerlauf.
    let (_written, _deviating) =
        materialize_format_package_reporting(source).map_err(|_| BundleError::Io)?;

    // Schritt 2.
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total: usize = 0;
    for relative in source.relative_paths().map_err(|_| BundleError::Io)? {
        let bytes = source.read_relative(&relative).ok_or(BundleError::Io)?;
        total = total
            .checked_add(bytes.len())
            .ok_or(BundleError::TotalByteLimit)?;
        if total > MAX_TOTAL_ARCHIVE_BYTES_V1 {
            return Err(BundleError::TotalByteLimit);
        }
        blobs.push((relative, bytes));
        // Nach dem Push und mit `>`, wortgleich zu
        // `crates/ea-recovery/src/source.rs:188-193`: genau
        // `MAX_ARCHIVE_BLOBS_V1` Blobs bleiben zulaessig, dieselbe INKLUSIVE
        // Grenze, die das Inventar anschliessend selbst durchsetzt.
        if blobs.len() > MAX_ARCHIVE_BLOBS_V1 {
            return Err(BundleError::BlobLimit);
        }
    }

    // Schritt 3. `blobs` wird nach dem Kodieren FALLENGELASSEN: der Container
    // ist eine vollstaendige Kopie der Nutzlast, und zwei Puffer nebeneinander
    // waeren an der Obergrenze zwei Gibibyte zuviel.
    let blob_count = blobs.len();
    let container = encode_bundle(&blobs)?;
    drop(blobs);
    let bundle = ArchiveBundleSource::from_bytes(container)?;

    // Schritt 4. OHNE Empfaengerschluessel: auf diesem Weg gibt es keinen, und
    // ein Vorgabewert waere hier eine Erfindung.
    let report = verify_archive(&bundle, anchor, VerifyOptions::new(os_wall_clock))
        .map_err(|_| BundleError::SourceNotFullyVerified)?;
    if !report.is_fully_verified() {
        return Err(BundleError::SourceNotFullyVerified);
    }

    // Schritt 5 UND 6 in einem: `create_new` IST die Zielpruefung.
    //
    // Bewusst KEIN vorangestelltes `exists`/`symlink_metadata` daneben. Anders
    // als bei `crates/ea-recovery/src/target.rs`, wo die vorgezogene Pruefung
    // eine Exitcode-Reihenfolge herstellt, gaebe eine zweite Formulierung hier
    // genau denselben Befund an genau derselben Stelle — und eine Regel, die
    // zweimal geschrieben wird, ist eine Regel, die zweimal falsch werden kann.
    // `O_CREAT|O_EXCL` weist ein belegtes Ziel ab, BEVOR ein Byte fliesst, und
    // es weist auch ein Verzeichnis und einen baumelnden Symlink ab, denen ein
    // `exists` ins Nichts folgte.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => BundleError::TargetOccupied,
            _ => BundleError::Io,
        })?;
    file.write_all(bundle.bytes())
        .map_err(|_| BundleError::Io)?;
    file.sync_all().map_err(|_| BundleError::Io)?;
    drop(file);
    sync_parent_directory(target)?;

    Ok(BundleExportReport { blob_count })
}

/// Kodiert die Containerbytes aus `blobs`.
///
/// `blobs` kommt aus dem Verzeichnisdurchlauf und ist damit byteweise
/// aufsteigend und duplikatfrei; die Selbstpruefung in Schritt 3 von
/// [`write_archive_bundle`] belegt das, statt es zu behaupten.
fn encode_bundle(blobs: &[(String, Vec<u8>)]) -> Result<Vec<u8>, BundleError> {
    let mut index = Vec::new();
    let mut offset: usize = 0;
    for (path, bytes) in blobs {
        let path_length = u16::try_from(path.len()).map_err(|_| BundleError::Malformed)?;
        index.extend_from_slice(&path_length.to_be_bytes());
        index.extend_from_slice(path.as_bytes());
        index.extend_from_slice(&u64_of(offset)?);
        index.extend_from_slice(&u64_of(bytes.len())?);
        offset = offset
            .checked_add(bytes.len())
            .ok_or(BundleError::TotalByteLimit)?;
    }
    let mut container = Vec::with_capacity(BUNDLE_HEADER_BYTES_V1 + index.len() + offset);
    container.extend_from_slice(&BUNDLE_MAGIC_V1);
    container.extend_from_slice(&u64_of(blobs.len())?);
    container.extend_from_slice(&u64_of(index.len())?);
    container.extend_from_slice(&index);
    for (_, bytes) in blobs {
        container.extend_from_slice(bytes);
    }
    Ok(container)
}

fn u64_of(value: usize) -> Result<[u8; 8], BundleError> {
    u64::try_from(value)
        .map(u64::to_be_bytes)
        .map_err(|_| BundleError::Malformed)
}

/// Flusht das Verzeichnis, in dem die Zieldatei liegt.
///
/// Ohne diesen zweiten Flush kann der neu angelegte NAME nach einem
/// Stromausfall fehlen, obwohl die Bytes dauerhaft sind. Auf Plattformen, die
/// ein Verzeichnis nicht als Datei oeffnen, bleibt der dauerhafte
/// Verzeichniseintrag eine Zusage des Wirtsystems — wie beim uebrigen Backend
/// dieser Crate.
fn sync_parent_directory(target: &Path) -> Result<(), BundleError> {
    #[cfg(unix)]
    {
        let Some(parent) = parent_for_sync(target) else {
            return Ok(());
        };
        let directory = File::open(parent).map_err(|_| BundleError::Io)?;
        directory.sync_all().map_err(|_| BundleError::Io)
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Ok(())
    }
}

/// Das zu flushende Verzeichnis einer Zieladresse.
///
/// [`Path::parent`] liefert fuer einen EINKOMPONENTIGEN relativen Pfad
/// `Some("")` und nicht `None` — und `File::open("")` ist `ENOENT`. Ohne diese
/// Uebersetzung endete ein GELUNGENER Export an seinem Verzeichnisflush: die
/// Datei laege vollstaendig und geflusht am Ziel, der Aufruf meldete
/// [`BundleError::Io`], und jede Wiederholung scheiterte danach dauerhaft an
/// `create_new`. Der leere Elternpfad IST das Arbeitsverzeichnis und heisst
/// hier `.`.
///
/// `None` bleibt genau dem Fall vorbehalten, in dem es kein Elternverzeichnis
/// gibt — der Wurzel selbst. Eine Zieladresse ohne Eltern ist keine Datei, die
/// dieser Weg angelegt haben kann; es gibt dann nichts zu flushen.
fn parent_for_sync(target: &Path) -> Option<&Path> {
    match target.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Some(Path::new(".")),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{Path, parent_for_sync};

    /// Der leere Elternpfad ist das Arbeitsverzeichnis, nicht „kein Eltern".
    ///
    /// Ein Integrationstest koennte das nicht messen: er muesste das
    /// Arbeitsverzeichnis des Prozesses umstellen, und die Fixture dieses
    /// Ziels serialisiert Tests ueber eine Sperre, nicht ueber Prozesse.
    #[test]
    fn a_bare_relative_target_flushes_the_working_directory() {
        assert_eq!(
            parent_for_sync(Path::new("bundle.eabundle")),
            Some(Path::new(".")),
            "Path::parent liefert hier Some(\"\"), und File::open(\"\") ist ENOENT"
        );
        assert_eq!(
            parent_for_sync(Path::new("./bundle.eabundle")),
            Some(Path::new("."))
        );
        assert_eq!(
            parent_for_sync(Path::new("/tmp/bundle.eabundle")),
            Some(Path::new("/tmp"))
        );
        assert_eq!(
            parent_for_sync(Path::new("out/bundle.eabundle")),
            Some(Path::new("out"))
        );
        assert_eq!(
            parent_for_sync(Path::new("/")),
            None,
            "die Wurzel hat kein Elternverzeichnis, und es gibt nichts zu flushen"
        );
    }
}
