//! Der Ein-Datei-Buendelcontainer und sein Leser.
//!
//! # Warum er in DIESER Crate liegt
//!
//! Der Container ist geteilter Browsercode: der Datei-Modus des Web-Readers
//! liest ihn im wasm32-Ziel, und `web-reader-design.md` §9 macht genau die
//! Verifikationskette bis `ea-verify` zu geteiltem Rust. Der Leser beruehrt
//! kein `std::fs` — er nimmt Bytes entgegen und gibt Bytes heraus —, also
//! gehoert er neben die Ports und nicht neben die Wirtimplementierungen. Was
//! den Wirt braucht, blieb in `crates/ea-archive-fs`: der Export
//! `write_archive_bundle`, das Lesen von der Platte
//! `open_archive_bundle` und deren Wirtsschranke.
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
//! unter `nonObjectFileCount` (Abschnitt „Drei Inventarklassen" der Moduldoku
//! dieser Crate) — die
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
//! `from_bytes` benutzt ausser `core` nur [`MAX_ARCHIVE_BLOBS_V1`] und
//! [`MAX_TOTAL_ARCHIVE_BYTES_V1`] derselben Crate, `ea-archive` behaelt genau
//! seine vier Workspace-Kanten.
//!
//! Indexsaetze sind STRENG aufsteigend ueber die Adressbytes sortiert, keine
//! Adresse kommt zweimal vor, und die Offsets sind zusammenhaengend ab null:
//! der erste Blob beginnt bei `0`, jeder folgende genau dort, wo sein Vorgaenger
//! endete, und die Nutzlastregion endet genau am Dateiende. Es gibt keine
//! Fuellung, keine Ausrichtung und keinen freien Platz — deshalb sind zwei
//! Exporte desselben Bestands dieselbe Datei, und jedes eingeschobene Byte ist
//! eine Abweisung und keine still geduldete Differenz.

use crate::{
    ArchiveBlob, ArchiveError, ArchiveSource, BundleError, MAX_ARCHIVE_BLOBS_V1,
    MAX_TOTAL_ARCHIVE_BYTES_V1,
};

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
///
/// OEFFENTLICH, und zwar aus genau einem Grund: `MAX_BUNDLE_FILE_BYTES_V1` in
/// `crates/ea-archive-fs/src/bundle.rs` leitet die Wirtsschranke aus dieser
/// Zahl ab. Sie dort ein zweites Mal hinzuschreiben waere ein zweiter Satz
/// Zahlen ueber demselben Format.
pub const INDEX_RECORD_FIXED_BYTES: usize = 2 + 8 + 8;

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
/// Die Bytes kommen als `Vec<u8>` herein und nie von einer Adresse: der
/// Datei-Modus des Readers reicht den Inhalt eines `File`-Objekts aus dem
/// Browser durch, und ein Wirtspfad existiert dort nicht. Wer eine Datei
/// oeffnen will, benutzt `ea_archive_fs::open_archive_bundle`.
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
    /// Frueher `pub(crate) fn bytes`. Der Zugriff WIRD oeffentlich, weil
    /// `write_archive_bundle` in `crates/ea-archive-fs` durch diesen Typ
    /// hindurch verifiziert und danach genau diese Bytes schreibt; ein zweiter
    /// Puffer daneben waere bei einem Bestand an der Obergrenze ein zweites
    /// Gigabyte und koennte abweichen. Er gibt nichts preis, was der Port nicht
    /// ohnehin herausgibt: [`Self::visit_blobs`] liefert dieselben Nutzlastbytes
    /// stueckweise, und darueber liegen 48 Kopfbytes und ein Index aus Pfaden,
    /// Offsets und Laengen.
    #[must_use]
    pub fn container_bytes(&self) -> &[u8] {
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
/// braucht `unicode_normalization`, und der Container zieht keine
/// Abhaengigkeitskante. NFC bleibt damit eine Zusage der ERZEUGENDEN
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
