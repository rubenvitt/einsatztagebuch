//! Die EINE Umwandlung vom Zeugentyp in die Eingabe des Index.
//!
//! `crates/ea-index` kennt [`VerifiedDecryptedRecord`] nicht und darf ihn nicht
//! kennen: naehme seine Aufnahme den Zeugentyp entgegen, braeuchte es eine
//! Kante auf diese Crate, waehrend diese Crate gleichzeitig eine Kante auf
//! `ea-index` braucht, um zu suchen. `cargo metadata` weist einen solchen Kreis
//! ab, und mit ihm faellt der GANZE Arbeitsbereich.
//!
//! Dieselbe Entscheidung traegt die Klartextdisziplin, und das ist kein zweiter
//! Grund, sondern derselbe. [`VerifiedDecryptedRecord`] haelt seine Nutzlast in
//! `ea_crypto::SecretVec` und gibt sie ausschliesslich AUSLEIHEND heraus. Die
//! Projektion laeuft deshalb INNERHALB von
//! [`VerifiedDecryptedRecord::with_payload`]: weder der Geheimniswrapper noch
//! eine Ausleihe auf Klartextbytes ueberquert die Crategrenze; was hinuebergeht,
//! sind fertige Zeichenketten und Herkunftsspalten. `WR-082`, `FR-105` und die
//! Produktinvariante ueber Klartext in OPFS-Bytes, Caches, Protokollen und
//! Telemetrie verlangen genau das.
//!
//! # Die vier Filterachsen
//!
//! Der Zeitraum laeuft ueber `IncidentV1::occurred_at()`, das Stichwort ueber
//! `KeywordV1::as_free_text()` und den ANZEIGETEXT des Referenzarms, das
//! Fahrzeug ueber `VehicleSnapshotV1::{display_name, radio_call_sign,
//! license_plate}` und die Person ueber `PersonnelSnapshotV1::display_name()`.
//! Alles laeuft LOKAL; eine serverseitige Inhaltssuche ist ein festes
//! Nicht-Ziel (`design.md` Nichtziele, `web-reader-design.md` §13).
//!
//! # Was NICHT indiziert wird
//!
//! Ausschliesslich der EINSATZ. Genesis, Nachtrag, Schluesseluebergang und
//! Vernichtungsnachweis liefern `EA-READER-SCHEMA-UNSUPPORTED` und werden
//! ISOLIERT — es entsteht keine erfundene Einsatzzeile. Die
//! Original/Nachtrag-Projektion ist die naechste Aufgabe dieser Stufe; bis
//! dahin waere eine halbe Nachtragszeile schlechter als keine.

use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes};
use ea_index::{
    IndexBlobV1, IndexError, IndexPressureV1, IndexableRecordV1, InvertedIndexV1, ReaderQueryV1,
    ReaderSearchHitV1,
};
use ea_schema::{IncidentV1, PayloadV1};

use ea_types::EntryHash;

use crate::decrypt::VerifiedDecryptedRecord;
use crate::verify::ReaderError;

/// Die EINE Umwandlung von einem verifiziert entschluesselten Datensatz in die
/// Eingabe des Index.
///
/// # Errors
/// `EA-READER-SCHEMA-UNSUPPORTED`, wenn die Nutzlast kein Einsatz ist. Das ist
/// keine Beschaedigung und kein fehlender Grant, sondern die Aussage, dass
/// diese Fassung fuer dieses Paket keine fachliche Zeile bilden kann.
pub fn indexable_record(
    record: &VerifiedDecryptedRecord,
) -> Result<IndexableRecordV1, ReaderError> {
    let (source_schema_id, source_schema_version) = record.source_schema();
    let (target_schema_id, target_schema_version) = record.target_schema();
    record.with_payload(|payload| {
        let PayloadV1::Incident(incident) = payload else {
            return Err(ReaderError::UnsupportedSchema);
        };
        Ok(IndexableRecordV1 {
            source_entry_hash: record.entry_hash(),
            chain_sequence: record.chain_sequence(),
            record_id: incident.header().record_id(),
            source_schema_id: source_schema_id.to_owned(),
            source_schema_version,
            target_schema_id: target_schema_id.to_owned(),
            target_schema_version,
            human_incident_number: incident.human_incident_number().to_owned(),
            occurred_at_start: incident.occurred_at().start(),
            occurred_at_end: incident.occurred_at().end(),
            keyword_terms: keyword_terms(incident),
            vehicle_terms: vehicle_terms(incident),
            person_terms: person_terms(incident),
        })
    })
}

/// Der lokale Index einer entsperrten Sitzung.
///
/// Er haelt den Bestand, reicht das Schwellensignal als technischen Zustand an
/// die Oberflaeche weiter und besitzt die Wahl der Nonce je Versiegelung — die
/// Index-Crate zieht selbst keine Entropie.
///
/// # Zwei Fehlerarten, und warum sie getrennt bleiben
///
/// Aufnehmen kann an EINER Tatsache scheitern: das Paket traegt keine fachliche
/// Zeile. Das ist eine Readeraussage und traegt deshalb [`ReaderError`].
/// Versiegeln und Oeffnen scheitern an Kryptografie und Form des Blobs; diese
/// Befunde gehoeren `crates/ea-index` und werden mit ihren eigenen, bereits
/// stabilen Codes DURCHGEREICHT statt in einen Readercode uebersetzt. Ein
/// gemeinsamer Fehlertyp braeuchte einen neuen Arm in [`ReaderError`] — und der
/// waere nicht ableitbar, weil `IndexError` weder `Clone` noch `PartialEq`
/// traegt.
#[derive(Default)]
pub struct ReaderSearch {
    index: InvertedIndexV1,
    pressure: IndexPressureV1,
}

impl ReaderSearch {
    /// Der leere Bestand einer frisch entsperrten Sitzung.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Nimmt einen verifiziert entschluesselten Datensatz auf.
    ///
    /// # Errors
    /// `EA-READER-SCHEMA-UNSUPPORTED`, wenn das Paket keine fachliche Zeile
    /// traegt — sei es, dass die Nutzlast kein Einsatz ist, sei es, dass der
    /// Index die Beschriftung nicht projizieren kann. Beides ist DIESELBE
    /// Tatsache, und ein zweiter Code dafuer waere eine zweite Wahrheit.
    pub fn index(
        &mut self,
        record: &VerifiedDecryptedRecord,
    ) -> Result<IndexPressureV1, ReaderError> {
        let indexable = indexable_record(record)?;
        self.pressure = self
            .index
            .upsert(&indexable)
            .map_err(|_| ReaderError::UnsupportedSchema)?;
        Ok(self.pressure)
    }

    /// Die vier Filter ueber den lokalen Bestand.
    ///
    /// # Errors
    /// Durchgereicht aus `crates/ea-index`.
    pub fn search(&self, query: &ReaderQueryV1) -> Result<Vec<ReaderSearchHitV1>, IndexError> {
        self.index.search(query)
    }

    /// Der Weg zurueck an einen Treffer ueber seine Herkunftskennung.
    #[must_use]
    pub fn hit_for(&self, entry_hash: EntryHash) -> Option<&ReaderSearchHitV1> {
        self.index.hit_for(entry_hash)
    }

    /// Die Zahl der indizierten Pakete.
    #[must_use]
    pub fn indexed_packages(&self) -> usize {
        self.index.indexed_packages()
    }

    /// Der zuletzt gemeldete Schwellenzustand.
    ///
    /// `SegmentationRequired` ist ein technischer Zustand fuer die Oberflaeche
    /// und keine Weigerung: die Suche bleibt vollstaendig korrekt.
    #[must_use]
    pub const fn pressure(&self) -> IndexPressureV1 {
        self.pressure
    }

    /// Versiegelt den Bestand unter dem Indexschluessel der Sitzung.
    ///
    /// Die Nonce ist ein Parameter DIESER Crate und keine Eigenleistung des
    /// Index: der Aufrufer zieht sie frisch je Versiegelung.
    ///
    /// # Errors
    /// Durchgereicht aus `crates/ea-index`.
    pub fn seal(
        &self,
        index_key: &SecretBytes<CEK_SIZE>,
        nonce: &SecretBytes<AEAD_NONCE_SIZE>,
    ) -> Result<IndexBlobV1, IndexError> {
        IndexBlobV1::seal(&self.index, index_key, nonce)
    }

    /// Oeffnet einen versiegelten Bestand aus OPFS-Bytes.
    ///
    /// Der Schwellenzustand wird dabei NEU gerechnet und nicht mitversiegelt:
    /// er ist eine Aussage ueber den geladenen Bestand, keine Eigenschaft
    /// seiner Bytes.
    ///
    /// # Errors
    /// Durchgereicht aus `crates/ea-index`.
    pub fn open(bytes: &[u8], index_key: &SecretBytes<CEK_SIZE>) -> Result<Self, IndexError> {
        let index = IndexBlobV1::open(bytes, index_key)?;
        let pressure = index.pressure();
        Ok(Self { index, pressure })
    }
}

/// Der Stichworttext: der freie Text, oder der ANZEIGETEXT des Referenzarms.
///
/// Die Referenzkennung selbst wandert NICHT in den Index: sie ist ein
/// technischer Schluessel eines Stammdatensatzes und kein Wort, nach dem
/// jemand sucht.
fn keyword_terms(incident: &IncidentV1) -> Vec<String> {
    let keyword = incident.keyword();
    if let Some(free_text) = keyword.as_free_text() {
        return vec![free_text.to_owned()];
    }
    keyword
        .as_reference()
        .map(|(_, display_text)| vec![display_text.to_owned()])
        .unwrap_or_default()
}

/// Anzeigename, Funkrufname und Kennzeichen jedes Fahrzeugs.
fn vehicle_terms(incident: &IncidentV1) -> Vec<String> {
    let mut terms = Vec::new();
    for vehicle in incident.vehicles() {
        terms.push(vehicle.display_name().to_owned());
        if let Some(radio_call_sign) = vehicle.radio_call_sign() {
            terms.push(radio_call_sign.to_owned());
        }
        if let Some(license_plate) = vehicle.license_plate() {
            terms.push(license_plate.to_owned());
        }
    }
    terms
}

/// Der Anzeigename jeder eingesetzten Person.
fn person_terms(incident: &IncidentV1) -> Vec<String> {
    incident
        .personnel()
        .iter()
        .map(|person| person.display_name().to_owned())
        .collect()
}
