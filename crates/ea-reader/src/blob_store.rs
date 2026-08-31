//! Der Bytespeicher des Readers: ein Port ueber OPAKE Bytes und ein Doppel.
//!
//! Die Trennung ist die Aussage dieses Moduls. Der Port beschreibt AUSSCHLIESS-
//! LICH das Ablegen und Holen von Bytefolgen; das Doppel haelt sie im Speicher.
//! Der Wirt — OPFS im dedizierten Worker — kommt in der Bruecken-Crate dazu und
//! nicht hier: `ea-reader` steht auf der wasm32-Positivliste, und ein Griff nach
//! `web-sys` an dieser Stelle machte aus einer geteilten Crate eine Browsercrate.

use core::fmt;
use std::collections::BTreeMap;

/// Die Obergrenze eines Schluessels in Byte.
///
/// Sie steht hier und nicht als Zahl im Rumpf: OPFS-Implementierungen
/// beschraenken Dateinamen unterschiedlich, und ein Schluessel, der auf dem
/// Doppel durchgeht und im Browser abgewiesen wird, faellt erst dort auf.
const MAX_KEY_BYTES: usize = 128;

/// Der Schluessel eines Blobs: ein beschraenkter ASCII-Pfad ohne Traversierung.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReaderBlobKey(String);

impl ReaderBlobKey {
    /// # Errors
    /// `EA-READER-BLOB-KEY` fuer leer, laenger als 128 Byte, nicht-ASCII,
    /// fuehrenden `/` oder ein `..`-Segment.
    pub fn new(value: &str) -> Result<Self, ReaderBlobError> {
        let rejected = value.is_empty()
            || value.len() > MAX_KEY_BYTES
            || !value.is_ascii()
            || value.starts_with('/')
            || value.split('/').any(|segment| segment == "..");
        if rejected {
            return Err(ReaderBlobError::Key);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Der Fehlschlag des Bytespeichers.
///
/// ZWEI Faelle und nicht einer: ein abgewiesener Schluessel ist ein Fehler des
/// Aufrufers und in jedem Lauf derselbe, ein Fehlschlag des Wirtspeichers ist
/// eine Lage der Umgebung. Wer beide in einen Wert faltet, kann eine
/// Traversierung nicht mehr von einer vollen Platte unterscheiden.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReaderBlobError {
    /// Der Schluessel ist kein beschraenkter ASCII-Pfad ohne Traversierung.
    Key,
    /// Der Wirtspeicher hat den Zugriff abgewiesen; der Text kommt von ihm.
    Host(String),
}

impl ReaderBlobError {
    /// Der stabile Code des Fehlschlags.
    ///
    /// Er verlaesst die Crate, waehrend der Text der Wirtsmeldung es nicht
    /// muss: Zusicherungen stehen gegen den Code und nie gegen eine
    /// Formatierung, dieselbe Regel wie bei [`crate::ReaderMode::code`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Key => "EA-READER-BLOB-KEY",
            Self::Host(_) => "EA-READER-BLOB-HOST",
        }
    }
}

impl fmt::Display for ReaderBlobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReaderBlobError {}

/// Der Port ueber OPAKE Bytes.
///
/// Er kennt WEDER Struktur NOCH Bedeutung: jeder Aufrufer legt Chiffrat ab und
/// holt Chiffrat. Waere hier ein typisierter Zugriff, gaebe es eine zweite
/// Stelle, an der ueber Klartext entschieden wird — und `web-reader-design.md`
/// §9 laesst Kryptographie ausschliesslich in geteiltem Rust zu.
pub trait ReaderBlobStore {
    /// # Errors
    /// Jeder Fehlschlag des Wirtspeichers, ohne den Schluesselinhalt zu nennen.
    fn put(&mut self, key: &ReaderBlobKey, bytes: &[u8]) -> Result<(), ReaderBlobError>;
    /// # Errors
    /// Wie [`ReaderBlobStore::put`]. Ein fehlender Blob ist `Ok(None)`.
    fn get(&self, key: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError>;
    /// # Errors
    /// Wie [`ReaderBlobStore::put`]. Ein fehlender Blob ist kein Fehler.
    fn delete(&mut self, key: &ReaderBlobKey) -> Result<(), ReaderBlobError>;
    /// # Errors
    /// Wie [`ReaderBlobStore::put`]. Die Reihenfolge ist die Schluesselordnung.
    fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError>;
}

/// Das Doppel, mit dem jeder spaetere `cargo test -p ea-reader` ohne Browser laeuft.
///
/// Bewusst NICHT hinter `cfg(test)` — dieselbe Entscheidung wie bei
/// `ea_verify::RecordingObserver`: die Integrationstests von `ea-reader` und die
/// Systemtests unter `tests/ea-system-tests` greifen darauf zu.
///
/// Die Ablage ist eine `BTreeMap` und keine `HashMap`: `keys()` ist Teil des
/// Contracts, und eine Streuordnung faellt in Unit-Tests nicht auf und kippt
/// spaeter den Wiederaufbau des Index sporadisch — dieselbe Begruendung, die
/// `crates/ea-verify/src/lib.rs` fuer seine Sammlungen ausschreibt.
#[derive(Debug, Default)]
pub struct InMemoryReaderBlobStore {
    blobs: BTreeMap<ReaderBlobKey, Vec<u8>>,
}

impl InMemoryReaderBlobStore {
    /// Ein leeres Doppel.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReaderBlobStore for InMemoryReaderBlobStore {
    fn put(&mut self, key: &ReaderBlobKey, bytes: &[u8]) -> Result<(), ReaderBlobError> {
        self.blobs.insert(key.clone(), bytes.to_vec());
        Ok(())
    }

    fn get(&self, key: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError> {
        Ok(self.blobs.get(key).cloned())
    }

    fn delete(&mut self, key: &ReaderBlobKey) -> Result<(), ReaderBlobError> {
        self.blobs.remove(key);
        Ok(())
    }

    fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError> {
        Ok(self.blobs.keys().cloned().collect())
    }
}
