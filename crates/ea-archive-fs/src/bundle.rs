//! Der Ein-Datei-Buendelexport und der Dateizugriff auf seinen Container.
//!
//! # Was hier liegt und was nicht
//!
//! Der Container selbst — Magie, Kopf, Index, die strengen Strukturregeln und
//! [`ArchiveBundleSource`] — liegt in `crates/ea-archive/src/bundle.rs`. Er ist
//! geteilter Browsercode: der Datei-Modus des Web-Readers liest ihn im
//! wasm32-Ziel, und ein Leser, der Bytes entgegennimmt, braucht dafuer kein
//! Dateisystem (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md`
//! §9 und §12).
//!
//! Hier bleibt GENAU das, was den Wirt anfasst: [`open_archive_bundle`] mit
//! seiner Laengenpruefung VOR dem Lesen, [`write_archive_bundle`] mit
//! `O_CREAT|O_EXCL`, Datei- und Verzeichnisflush, und die Kodierung, die den
//! Bestand in Containerbytes ueberfuehrt. `std::fs` kommt in dieser Datei vor
//! und in `crates/ea-archive` nicht — das ist die Trennlinie und zugleich der
//! Grund, aus dem diese Crate auf `WASM32_EXEMPT_CRATES` steht.
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

use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::Path,
};

use ea_archive::{
    ArchiveBundleSource, BUNDLE_HEADER_BYTES_V1, BUNDLE_MAGIC_V1, BundleError,
    INDEX_RECORD_FIXED_BYTES, MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1,
};
use ea_trust::TrustAnchorV1;
use ea_types::UnixMillis;
use ea_verify::{VerifyOptions, verify_archive};

use crate::{LocalPathBackend, format_package::materialize_format_package_reporting};

/// Die groesste Dateilaenge, die [`open_archive_bundle`] ueberhaupt in den
/// Speicher holt.
///
/// # Es ist eine WIRTsschranke und KEINE Strukturregel
///
/// Der Deckel entscheidet nichts darueber, was ein gueltiger Container ist —
/// das tut allein [`ArchiveBundleSource::from_bytes`], und dessen Regeln
/// bleiben unveraendert. Er ist die Allokationsschranke des Wirtsteils, genau
/// die Zweistufigkeit, die der Verzeichnisleser schon traegt
/// (`crates/ea-recovery/src/source.rs:170-178`: ZUERST `metadata.len()` gegen
/// den Deckel, DANN `fs::read`). Ohne sie allokierte eine unvertraute Datei
/// vollstaendig, bevor irgendeine Regel je gefeuert haette.
///
/// # Er ist ABGELEITET und kein zweiter Satz Zahlen
///
/// Kopf, plus die groesste Indexregion, die die zwei bestehenden Deckel
/// ueberhaupt zulassen — [`MAX_ARCHIVE_BLOBS_V1`] Saetze mit ihren festen
/// Bytes und einer Adresse, deren Laenge ein `u16` traegt —, plus
/// [`MAX_TOTAL_ARCHIVE_BYTES_V1`] Nutzlast. Alle vier Zahlen kommen aus
/// `ea-archive`, also aus dem Container selbst; hier wird keine davon
/// nachgeschrieben. Die Schranke ist damit LOSE (Groessenordnung 71 GB): sie
/// ist bewusst so gewaehlt, dass sie keine Datei abweist, die `from_bytes`
/// annehmen wuerde, und trotzdem das tut, was sie tun muss — eine Datei
/// jenseits jeder moeglichen Containergroesse wird abgewiesen, BEVOR ein Byte
/// allokiert ist.
const MAX_BUNDLE_FILE_BYTES_V1: u64 = BUNDLE_HEADER_BYTES_V1 as u64
    + (MAX_ARCHIVE_BLOBS_V1 as u64) * (INDEX_RECORD_FIXED_BYTES as u64 + u16::MAX as u64)
    + MAX_TOTAL_ARCHIVE_BYTES_V1 as u64;

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

/// Liest ein Buendel von der Platte.
///
/// Eine freie Funktion und keine inhaerente Methode: [`ArchiveBundleSource`]
/// gehoert seit dem Umzug `ea-archive`, und eine fremde Crate kann einem
/// fremden Typ keine inhaerente Methode anhaengen. Ein Erweiterungstrait waere
/// die Alternative und ist die schlechtere — er machte aus einer Funktion einen
/// Import, den jeder Aufrufer zusaetzlich fuehren muesste, ohne eine einzige
/// Zusage hinzuzufuegen.
///
/// Die Datei ist UNVERTRAUT: sie kommt durch den gewoehnlichen
/// Dateidialog. Deshalb wird ZUERST ihre angekuendigte Laenge gegen
/// [`MAX_BUNDLE_FILE_BYTES_V1`] geprueft und DANN gelesen — dieselbe
/// Reihenfolge, die `crates/ea-recovery/src/source.rs:170-178` fuer den
/// Verzeichnisleser aufschreibt. Andersherum legte eine uebergrosse Datei
/// ihren Puffer vollstaendig an, bevor eine Regel sie je abgewiesen haette.
///
/// # Errors
///
/// [`BundleError::Io`], wenn die Datei nicht lesbar ist,
/// [`BundleError::TotalByteLimit`], wenn sie jenseits jeder moeglichen
/// Containergroesse liegt; sonst der Befund von
/// [`ArchiveBundleSource::from_bytes`].
pub fn open_archive_bundle(path: &Path) -> Result<ArchiveBundleSource, BundleError> {
    open_archive_bundle_capped(path, MAX_BUNDLE_FILE_BYTES_V1)
}

/// [`open_archive_bundle`] mit einstellbarer Wirtsschranke.
///
/// Die Schranke ist ein Parameter, damit die Reihenfolge MESSBAR ist: mit
/// einem Deckel unterhalb der Dateilaenge muss der Befund
/// [`BundleError::TotalByteLimit`] sein und nicht der Strukturbefund der
/// Bytes, die sonst gelesen wuerden. Ein Zeuge mit der echten Schranke
/// braeuchte eine Datei von zig Gigabyte, und das ist kein Test.
///
/// `fs::metadata` und NICHT `symlink_metadata`: `fs::read` folgt einem
/// Symlink, also muss gemessen werden, was tatsaechlich gelesen wird.
fn open_archive_bundle_capped(path: &Path, cap: u64) -> Result<ArchiveBundleSource, BundleError> {
    let declared = fs::metadata(path).map_err(|_| BundleError::Io)?.len();
    if declared > cap {
        return Err(BundleError::TotalByteLimit);
    }
    let bytes = fs::read(path).map_err(|_| BundleError::Io)?;
    ArchiveBundleSource::from_bytes(bytes)
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

    // Schritt 5, erster Teil: eine Zieladresse, die dem BESTAND gehoert, ist
    // belegt — auch wenn dort noch keine Datei liegt.
    //
    // `create_new` prueft nur, ob die Adresse FREI ist, nicht, wem sie gehoert.
    // Laege das Ziel unter der Bestandswurzel, wuerde das Buendel selbst eine
    // Bytesequenz des Bestands: `nonObjectFileCount` stiege, der Bestand
    // verifizierte danach zu einem ANDEREN Bericht als vorher — genau die
    // Groesse, deren Gleichheit dieser Weg belegt —, und ein zweiter Export
    // truege den ersten in sich. `TargetOccupied` ist der richtige Befund und
    // die geschlossene Sechserliste bleibt geschlossen: die Adresse ist nicht
    // frei, sondern vergeben.
    if target_belongs_to_holding(source.root(), target)? {
        return Err(BundleError::TargetOccupied);
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
    file.write_all(bundle.container_bytes())
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
/// Ob die Zieladresse unter der Bestandswurzel liegt.
///
/// Verglichen werden KANONISIERTE Pfade, nicht Zeichenketten: sonst fuehrte
/// jeder `..`-Schritt und jeder Symlink am Deckel vorbei. Kanonisiert wird das
/// ELTERNVERZEICHNIS des Ziels, weil das Ziel selbst noch nicht existiert —
/// und zwar durch [`parent_for_sync`], damit die eine Regel ueber den leeren
/// Elternpfad (`Some("")` IST das Arbeitsverzeichnis) genau einmal
/// aufgeschrieben ist.
///
/// Ein Elternverzeichnis, das nicht existiert, laesst `canonicalize`
/// fehlschlagen und liefert [`BundleError::Io`] — genau den Befund, den
/// `create_new` unmittelbar danach ohnehin gaebe. Es ist also kein
/// verschluckter Fehler, sondern derselbe Fehler eine Zeile frueher.
///
/// `None` bleibt der Wurzel des Dateisystems vorbehalten: sie ist kein Ziel,
/// das unter einer Bestandswurzel liegen koennte.
fn target_belongs_to_holding(root: &Path, target: &Path) -> Result<bool, BundleError> {
    let Some(parent) = parent_for_sync(target) else {
        return Ok(false);
    };
    let parent = fs::canonicalize(parent).map_err(|_| BundleError::Io)?;
    let root = fs::canonicalize(root).map_err(|_| BundleError::Io)?;
    Ok(parent.starts_with(&root))
}

fn parent_for_sync(target: &Path) -> Option<&Path> {
    match target.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Some(Path::new(".")),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BundleError, MAX_BUNDLE_FILE_BYTES_V1, Path, fs, open_archive_bundle_capped,
        parent_for_sync,
    };

    /// Die Laengenpruefung liegt VOR dem Lesen, und ihre Grenze ist inklusiv.
    ///
    /// Gemessen wird an der Schranke selbst, nicht an der echten: eine Datei
    /// jenseits von [`MAX_BUNDLE_FILE_BYTES_V1`] waere zig Gigabyte gross und
    /// kein Test. Der Beweis ist die UNTERSCHEIDUNG der zwei Befunde auf
    /// DENSELBEN Bytes — mit einem Deckel unterhalb der Laenge kommt
    /// `TotalByteLimit`, also ohne dass die Bytes je angesehen wurden; mit
    /// einem Deckel genau AUF der Laenge kommt der Strukturbefund, also
    /// nachdem sie gelesen wurden.
    #[test]
    fn the_reader_checks_the_declared_file_length_before_it_reads() {
        let path = std::env::temp_dir().join(format!(
            "ea-archive-fs-open-capped-{}.bin",
            std::process::id()
        ));
        let bytes = vec![0_u8; 100];
        fs::write(&path, &bytes).expect("die Kratzdatei muss schreibbar sein");

        assert_eq!(
            open_archive_bundle_capped(&path, 99).err(),
            Some(BundleError::TotalByteLimit),
            "unterhalb der Laenge darf NICHTS gelesen werden"
        );
        assert_eq!(
            open_archive_bundle_capped(&path, 100).err(),
            Some(BundleError::Malformed),
            "genau auf der Laenge wird gelesen und die Struktur entscheidet"
        );
        // Die echte Schranke weist keine gewoehnliche Datei ab. Als
        // `const`-Block, weil die Aussage zur Uebersetzungszeit entschieden ist.
        const {
            assert!(MAX_BUNDLE_FILE_BYTES_V1 > 100);
        }

        fs::remove_file(&path).expect("die Kratzdatei muss entfernbar sein");
    }

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
