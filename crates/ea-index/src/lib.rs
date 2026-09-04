#![forbid(unsafe_code)]
//! Der invertierte Index des Readers und sein als Ganzes versiegelter Blob.
//!
//! `web-reader-design.md` §8.1 ersetzt SQLCipher im READER-Pfad durch einen
//! invertierten Index ueber entschluesselte Feldwerte, der als GANZES mit
//! ChaCha20-Poly1305 verschluesselt in OPFS liegt und beim Entsperren in den
//! WASM-Speicher geladen wird. Diese Crate ist dieser Index. Der Writer behaelt
//! SQLCipher unveraendert; `docs/adr/0002-local-database-encryption.md` bleibt
//! davon unberuehrt.
//!
//! # Die Kantenrichtung, und warum sie EINSEITIG ist
//!
//! Die Eingabe dieser Crate heisst [`IndexableRecordV1`] und wird HIER
//! deklariert, nicht in `crates/ea-reader`. Naehme die Aufnahme den Zeugentyp
//! des Readers entgegen, braeuchte `ea-index` eine Kante auf `ea-reader`,
//! waehrend `ea-reader` gleichzeitig eine Kante auf `ea-index` braucht, um zu
//! suchen. `cargo metadata` weist einen solchen Kreis ab, und mit ihm faellt
//! der GANZE Arbeitsbereich. Die Kante laeuft deshalb einseitig,
//! `ea-reader → ea-index`.
//!
//! Dieselbe Entscheidung traegt die Klartextdisziplin, und das ist kein zweiter
//! Grund, sondern derselbe. Der Zeugentyp haelt seine Nutzlast in einem
//! Geheimniswrapper und gibt sie ausschliesslich AUSLEIHEND heraus; die
//! Umwandlung geschieht innerhalb dieser Ausleihe und gehoert deshalb
//! `crates/ea-reader`. Was die Crategrenze ueberquert, sind fertige,
//! normalisierte Zeichenketten und Herkunftsspalten — nie ein Wrapper und nie
//! eine Ausleihe auf Klartextbytes.
//!
//! Ein Geheimniswrapper entsteht in dieser Crate an GENAU EINER Stelle und
//! verlaesst sie nie: `ea_crypto::aead_seal` nimmt seinen Klartext besitzend
//! als `ea_crypto::SecretVec`, also baut [`IndexBlobV1::seal`] einen — aus dem
//! eigenen, bereits abgeleiteten Indexkoerper und um ihn beim Versiegeln unter
//! `ZeroizeOnDrop` zu stellen. `src/inverted.rs` kennt ihn nicht, und der
//! Quelltextzeuge `exactly_one_ingestion_method_exists_and_it_never_names_a_reader_type`
//! haelt das fest.
//!
//! # Was diese Crate NICHT tut
//!
//! Sie greift auf nichts zu: kein Dateisystem, keine Uhr, keine Entropie, kein
//! Netz. Schluessel und Nonce sind PARAMETER, genau wie Uhr, Trust Anchor und
//! Empfaengerschluessel in `ea-verify` Parameter sind. Das hat drei messbare
//! Folgen: die Crate zieht `getrandom` nicht in ihren Graphen, sie ist
//! byteweise reproduzierbar — was der bytegleiche Rebuild ueberhaupt erst
//! pruefbar macht —, und die Wahl einer frischen Nonce je Versiegelung bleibt
//! eine Entscheidung von `crates/ea-reader`, wo sie hingehoert.
//!
//! Ebenso ausgeschlossen sind `std::fs`, `std::time`, `HashMap` und `HashSet`:
//! der Bestand liegt in `BTreeMap`/`BTreeSet`, weil eine Streuordnung die
//! Bytegleichheit des Rebuilds sporadisch kippte und in Unit-Tests unauffaellig
//! bliebe. Das ist dieselbe Begruendung, mit der `crates/ea-verify/src/lib.rs`
//! beide ausschliesst.
//!
//! Nicht gebaut werden hier: ein segmentierter Index, ein verschluesselndes
//! SQLite-VFS im Browser und ein zweiter Index in TypeScript — die letzten
//! beiden verbietet §8.1 ausdruecklich.
//!
//! # Die Schwelle
//!
//! [`MONOLITHIC_INDEX_MAX_PACKAGES_V1`] steht bei 50 000 PAKETEN, nicht
//! Einsaetzen: ein Einsatz traegt ein Original plus seine Nachtraege, und
//! `design.md` `NFR-PERF-003` / Abnahmekriterium 31 zaehlt Pakete. Die Aufnahme
//! VERWEIGERT oberhalb der Schwelle nicht — eine Verweigerung naehme einem
//! Reader den Zugriff auf Inhalte, fuer die er einen gueltigen Grant besitzt,
//! und fehlender Zugriff folgt nie aus einer Ressourcengrenze. Stattdessen
//! liefert sie [`IndexPressureV1::SegmentationRequired`], das gemessene
//! Signal fuer die von §8.1 VORAB genehmigte Segmentierung.

mod blob;
mod inverted;
mod schema_view;

use core::fmt;

use ea_cbor::CborError;
use ea_crypto::CryptoError;
use ea_schema::SchemaError;

pub use blob::{
    INDEX_BLOB_HEADER_BYTES_V1, INDEX_BLOB_MAGIC_V1, INDEX_BLOB_MAX_PACKAGES_V1,
    INDEX_FORMAT_VERSION_V1, INDEX_PARSER_LIMITS_V1, IndexBlobV1,
};
pub use inverted::{
    IndexPressureV1, IndexableRecordV1, InvertedIndexV1, MONOLITHIC_INDEX_MAX_PACKAGES_V1,
    ReaderQueryV1, ReaderSearchHitV1,
};
pub use schema_view::SchemaViewV1;

/// Der Befund dieser Crate.
///
/// Flaches Aufzaehlungswerk, ein stabiler Code je Arm, FREMDE Codes
/// DURCHGEREICHT, [`fmt::Display`] schreibt ausschliesslich den Code,
/// [`fmt::Debug`] delegiert an [`fmt::Display`] — dieselbe Form, die
/// `ea-verify`, `ea-schema` und `ea-reader` fuehren.
///
/// GENAU EIN eigener Code: `EA-INDEX-BLOB-FORMAT`. Alles andere kommt
/// unveraendert von dort, wo die Tatsache entstanden ist — ein zweiter Code
/// fuer einen fehlgeschlagenen AEAD-Tag oder fuer ein nicht unterstuetztes
/// Schema waere eine zweite Wahrheit ueber denselben Vorgang.
///
/// # Kein `Clone`, kein `Copy`, kein `PartialEq`
///
/// [`SchemaError`] traegt eine besitzende `Unsupported`-Variante und
/// deklariert selbst keine Ableitungen; damit nimmt auch [`IndexError::code`]
/// hier `&self`. Dieselbe Begruendung, die `ReaderVaultError` in
/// `crates/ea-reader/src/vault.rs` fuer seine `Host(String)`-Variante
/// ausschreibt.
pub enum IndexError {
    /// Das ARTEFAKT ist keines dieses Formats — Kopf oder Koerper.
    ///
    /// Am Kopf: falsche Laenge, fremdes Magic, eine Formatversion, die diese
    /// Fassung nicht kennt. Das faellt VOR jeder Beruehrung des Schluessels;
    /// ein Kopf, der erst am AEAD-Tag scheiterte, gaebe „das ist kein
    /// Indexblob" und „der Schluessel passt nicht" denselben Code, und die zwei
    /// sind verschiedene Befunde.
    ///
    /// Am Koerper: eine Zeile falscher Stelligkeit, ein Entry-Hash, der keine
    /// 32 Byte hat, ein Optionsbehaelter der Laenge zwei, zwei Zeilen unter
    /// derselben Herkunft, absteigende Zeilen oder Terme. Alle diese Koerper
    /// sind wohlgeformtes, kanonisches, grenzenkonformes CBOR —
    /// `ea_cbor::validate` gibt ueber sie `Ok(())` —, und ein `EA-CBOR-*`
    /// daneben behauptete einen Befund, den `ea-cbor` nie erhoben hat.
    BlobFormat,
    /// Die Versiegelung oder die Oeffnung hat nicht getragen.
    Crypto(CryptoError),
    /// Der Indexkoerper ist kein wohlgeformter deterministischer CBOR-Wert
    /// innerhalb von [`INDEX_PARSER_LIMITS_V1`].
    Cbor(CborError),
    /// Das Zielschema laesst sich von dieser Fassung nicht projizieren.
    Schema(SchemaError),
}

impl IndexError {
    /// Der stabile Code des Befunds.
    ///
    /// Zusicherungen stehen gegen ihn und nie gegen eine Formatierung.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BlobFormat => "EA-INDEX-BLOB-FORMAT",
            Self::Crypto(error) => error.code(),
            Self::Cbor(error) => error.code(),
            Self::Schema(error) => error.code(),
        }
    }
}

impl From<CryptoError> for IndexError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<CborError> for IndexError {
    fn from(error: CborError) -> Self {
        Self::Cbor(error)
    }
}

impl From<SchemaError> for IndexError {
    fn from(error: SchemaError) -> Self {
        Self::Schema(error)
    }
}

impl fmt::Display for IndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for IndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for IndexError {}
