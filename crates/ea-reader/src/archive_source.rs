//! Die zwei Wege des Datei-Modus, und der EINE Port darunter.
//!
//! `web-reader-design.md` §5.2 nennt zwei Eingaenge: die EINE exportierte
//! Datei aus dem gewoehnlichen Dateidialog — der universelle Weg, weil
//! `showDirectoryPicker` in Safari und Firefox fehlt — und den dauerhaft
//! angebundenen Ordner ueber ein `FileSystemDirectoryHandle`. Beide muenden
//! hier in [`ea_archive::ArchiveSource`], und damit entsteht KEIN zweiter
//! Archivparser: klassifiziert wird weiterhin ausschliesslich am
//! 9-Byte-Exact-Object-Praefix (`design.md` §11.4), nie an einem Dateinamen
//! und nie an einer Dateiendung.
//!
//! # Der Container wird UNVERTRAUT gelesen
//!
//! Die Bytes des universellen Weges kommen aus einem Dateidialog und sind
//! damit feindlich, bis das Gegenteil geprueft ist. Gelesen werden sie
//! AUSSCHLIESSLICH ueber [`ea_archive::ArchiveBundleSource::from_bytes`], das
//! Magie, Blobzahl, Index und beide Deckel vollstaendig prueft, BEVOR ein
//! einziger Blob herausgegeben wird. `ea_archive_fs::open_archive_bundle` und
//! sein gedeckeltes Gegenstueck bleiben ausdruecklich draussen: sie sitzen auf
//! `std::fs`, und `ea-archive-fs` steht auf `WASM32_EXEMPT_CRATES`.
//!
//! # Der Ordner kommt als PUSH und nicht als Pfad
//!
//! Es gibt im Browser keinen Wirtspfad, den eine Quelle nachschlagen koennte.
//! `apps/web/src/features/file-mode/DirectoryHandle.ts` laeuft den Handle
//! rekursiv ab und reicht jede Bytefolge EINZELN ueber die Bruecke; die
//! Buchhaltung darueber fuehrt [`DirectoryHandleSource`], und zwar in Rust.
//! TypeScript zaehlt nichts, vergleicht nichts und entscheidet nichts — es
//! bricht auf den durchgereichten Fehlercode ab.

use ea_archive::{
    ArchiveBlob, ArchiveBundleSource, ArchiveError, ArchiveSource, MAX_ARCHIVE_BLOBS_V1,
    MAX_TOTAL_ARCHIVE_BYTES_V1,
};

/// Der Bestand des Datei-Modus, auf dem einen oder dem anderen Weg geoeffnet.
///
/// GESCHLOSSEN und zweiwertig, aus demselben Grund, aus dem
/// [`crate::ReaderMode`] es ist: ein `Box<dyn ArchiveSource>` naehme jede
/// Quelle entgegen und liesse damit offen, was der Datei-Modus eigentlich
/// oeffnet. Die Aufzaehlung benennt die zwei Wege von §5.2 und macht einen
/// dritten zu einem Uebersetzungsfehler statt zu einer Verabredung.
///
/// Es steht KEINE Lesart in dieser Aufzaehlung, nur eine Herkunft. Die
/// Weiche in [`Self::visit_blobs`] waehlt aus, WER die Bytes haelt, und beide
/// Arme geben danach dieselbe Sorte [`ArchiveBlob`] heraus.
///
/// # Kein `Debug`
///
/// Beide Arme halten den vollstaendigen Bestand im Speicher — der eine als
/// Containerbytes, der andere als Blobliste. Dieselbe Begruendung wie bei
/// [`ea_archive::ArchiveBundleSource`] und `ea_recovery::FsArchiveSource`: ein
/// abgeleitetes `Debug` gaebe jedes Byte heraus, und Bestandsbytes koennen
/// Chiffrat sein.
pub enum ReaderArchiveSourceV1 {
    /// Die EINE exportierte Datei, bereits vollstaendig strukturgeprueft.
    Bundle(ArchiveBundleSource),
    /// Der angebundene Ordner, Bytefolge fuer Bytefolge eingereicht.
    Directory(DirectoryHandleSource),
}

impl ArchiveSource for ReaderArchiveSourceV1 {
    /// Reicht durch, was der gewaehlte Arm liefert.
    ///
    /// Hier wird nichts gefiltert, nichts umsortiert und nichts uebersprungen.
    /// Ein Blob stillschweigend fallenzulassen hiesse, Archivbytes zu
    /// verlieren, ohne es zu sagen; und eine Umsortierung setzte nichts durch,
    /// weil kein Feld von `VerificationReportV1` einen Pfadhinweis nennt.
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        match self {
            Self::Bundle(source) => source.visit_blobs(visitor),
            Self::Directory(source) => source.visit_blobs(visitor),
        }
    }
}

/// Ein angebundener Archivordner, dessen Bytes einzeln eingereicht werden.
///
/// # Warum eingereicht und nicht gelesen
///
/// `ea_recovery::FsArchiveSource` bekommt eine Wurzel und liest selbst; im
/// Browser gibt es diese Wurzel nicht. Ein `FileSystemDirectoryHandle` ist ein
/// JavaScript-Objekt, sein Durchlauf ist asynchron, und
/// [`ArchiveSource::visit_blobs`] ist es nicht. Die Quelle nimmt deshalb
/// entgegen, statt zu holen — und genau deshalb liegt die Buchhaltung hier und
/// nicht im Aufrufer.
///
/// # Beide Deckel fallen in RUST
///
/// [`Self::push_blob`] prueft [`MAX_ARCHIVE_BLOBS_V1`] und
/// [`MAX_TOTAL_ARCHIVE_BYTES_V1`] an derselben INKLUSIVEN Grenze wie der
/// Verzeichnisleser der Wiederherstellung (`crates/ea-recovery/src/source.rs`)
/// und wie das Inventar dahinter: genau so viele Blobs und genau so viele
/// Bytes bleiben zulaessig. Ein zweiter Satz Zahlen entsteht dabei nicht — die
/// Werte werden importiert. Die Zusage ist klein und genau: die Quelle legt
/// IHRE Kopie erst an, wenn beide Deckel getragen haben. Ueber den Puffer des
/// Aufrufers sagt sie nichts, denn wer ein `&[u8]` uebergibt, hat es bereits.
///
/// # Sie sortiert AUSDRUECKLICH nicht
///
/// Der Container ist streng ueber seine Adressbytes sortiert, ein
/// Verzeichnisdurchlauf ist es nicht: `DirectoryHandle.ts` laeuft rekursiv und
/// je Ebene lexikografisch, und eine ebenenweise Ordnung ist nicht die Ordnung
/// ueber die vollen Adressbytes — `a-b.txt` steht global vor `a/z.txt`, weil
/// `0x2D` vor `0x2F` kommt, ebenenweise aber dahinter. Eine Sortierung hier
/// setzte trotzdem nichts durch: jedes Sammelfeld von `VerificationReportV1`
/// ist eine `BTreeMap` oder ein `BTreeSet` ueber Hashes, und kein Berichtsfeld
/// nennt einen Pfadhinweis. Sie verstellte nur den Blick auf die Eigenschaft,
/// die die Bytegleichheit der zwei Wege wirklich traegt.
///
/// # Kein `Debug`
///
/// Wie bei [`ReaderArchiveSourceV1`]: der Typ haelt den ganzen Bestand.
pub struct DirectoryHandleSource {
    blobs: Vec<(String, Vec<u8>)>,
    total_bytes: usize,
    max_blobs: usize,
    max_total_bytes: usize,
    available: bool,
}

impl Default for DirectoryHandleSource {
    /// Dasselbe wie [`DirectoryHandleSource::new`].
    ///
    /// Vorhanden, weil `clippy::new_without_default` unter `-D warnings` sonst
    /// bricht; `ea_archive`s `ArchiveFixture` traegt aus demselben Grund ein
    /// abgeleitetes `Default` neben seinem `new()`.
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryHandleSource {
    /// Ein leerer Ordner mit den ECHTEN Deckeln.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_caps(MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1)
    }

    /// Dieselbe Quelle mit EINSTELLBAREN Deckeln, nur fuer Zeugen.
    ///
    /// RELEASEAUSSCHLUSS hinter demselben Merkmalstor wie die zwei
    /// beschaedigenden Tresorhilfen, und aus demselben Cargo-Grund
    /// (`crates/ea-reader/Cargo.toml`): `default = ["test-support"]`, weil ein
    /// Integrationstest das Merkmal SEINER EIGENEN Crate nicht einschalten
    /// kann, und abgeschaltet an der geteilten Wurzelkante, sodass das
    /// ausgelieferte wasm-Modul die Funktion nicht sieht.
    ///
    /// Der Grund fuer ihre Existenz ist gemessen und derselbe, den
    /// `ea_archive_fs::open_archive_bundle_capped` schon aufschreibt:
    /// [`MAX_TOTAL_ARCHIVE_BYTES_V1`] sind zwei Gibibyte, und ein Zeuge, der
    /// sie zuteilt, um kein einziges Byte davon zu lesen, ist kein Test. Der
    /// BLOB-Deckel braucht sie nicht — eine Million leerer Nutzlasten ist
    /// bezahlbar — und wird deshalb an seinem echten Wert bezeugt.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn with_caps_for_test(max_blobs: usize, max_total_bytes: usize) -> Self {
        Self::with_caps(max_blobs, max_total_bytes)
    }

    const fn with_caps(max_blobs: usize, max_total_bytes: usize) -> Self {
        Self {
            blobs: Vec::new(),
            total_bytes: 0,
            max_blobs,
            max_total_bytes,
            available: true,
        }
    }

    /// Uebernimmt eine Bytefolge, NACHDEM beide Deckel getragen haben.
    ///
    /// Die Reihenfolge ist die Zusage: erst die Blobzahl, dann die Summe, dann
    /// die Kopie. Waere es andersherum, legte die Quelle den Puffer an, den der
    /// Deckel gerade verbietet, und der Deckel schuetzte nichts mehr. Gezaehlt
    /// wird die Summe mit `saturating_add`, damit ein Ueberlauf nicht in eine
    /// kleine Zahl umschlaegt und die Schranke unterlaeuft.
    ///
    /// Der Pfadhinweis wird uebernommen, wie er kommt: er ist ein HINWEIS und
    /// entscheidet nie, ob die Bytes ein Archivobjekt sind.
    ///
    /// # Errors
    ///
    /// [`ArchiveError::BlobLimit`], wenn die Quelle bereits `max_blobs`
    /// Bytefolgen haelt, und [`ArchiveError::TotalByteLimit`], wenn diese
    /// Bytefolge die Summe ueber `max_total_bytes` hoebe. Beide Codes kommen
    /// unveraendert aus `ea-archive`; ein eigener daneben waere eine zweite
    /// Wahrheit ueber denselben Befund.
    pub fn push_blob(&mut self, path_hint: &str, bytes: &[u8]) -> Result<(), ArchiveError> {
        if self.blobs.len() >= self.max_blobs {
            return Err(ArchiveError::BlobLimit);
        }
        let total = self.total_bytes.saturating_add(bytes.len());
        if total > self.max_total_bytes {
            return Err(ArchiveError::TotalByteLimit);
        }
        self.blobs.push((path_hint.to_owned(), bytes.to_vec()));
        self.total_bytes = total;
        Ok(())
    }

    /// Der Ordner liefert keine Bytes mehr — die Berechtigung wurde entzogen.
    ///
    /// KEINE Testhilfe, sondern die einzige ehrliche Abbildung eines gemessenen
    /// Browserverhaltens: ein `FileSystemDirectoryHandle` meldet eine entzogene
    /// Berechtigung erst beim NAECHSTEN Zugriff, also mitten im Durchlauf.
    /// `DirectoryHandle.ts` ruft sie ueber die Bruecke, sobald
    /// `queryPermission`/`requestPermission` nicht mehr `granted` liefert.
    ///
    /// Sie wird NICHT zurueckgenommen. Ein Ordner, der einmal aufgehoert hat zu
    /// liefern, hat einen unvollstaendigen Bestand hinterlassen; ihn spaeter
    /// weiterzureichen hiesse, aus Teilbytes ein Urteil zu bilden. Der Weg
    /// zurueck ist eine neue Quelle — und der universelle Weg ueber die eine
    /// Datei bleibt davon ohnehin unberuehrt.
    pub const fn mark_unavailable(&mut self) {
        self.available = false;
    }

    /// Wie viele Bytefolgen die Quelle haelt.
    #[must_use]
    pub const fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    /// Wie viele Nutzlastbytes die Quelle haelt.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

impl ArchiveSource for DirectoryHandleSource {
    /// Reicht die eingereichten Blobs in EINREICHUNGSREIHENFOLGE weiter.
    ///
    /// Ein entzogener Zugriff faellt VOR dem ersten Blob und nicht mittendrin:
    /// ein halb durchlaufener Bestand ergaebe einen Bericht ueber Teilbytes,
    /// und ein Bericht ist eine Aussage. [`ArchiveError::Unavailable`] ist
    /// genau dafuer da — er beschreibt ausschliesslich, dass der Bestand nicht
    /// weiter durchlaufen werden kann, und nie einen Befund ueber ein einzelnes
    /// Objekt.
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        if !self.available {
            return Err(ArchiveError::Unavailable);
        }
        for (path_hint, bytes) in &self.blobs {
            visitor(ArchiveBlob::new(path_hint, bytes))?;
        }
        Ok(())
    }
}
