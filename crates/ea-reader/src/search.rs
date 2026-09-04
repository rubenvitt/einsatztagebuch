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
        self.pressure = self.index.upsert(&indexable).map_err(|error| {
            // Die Einebnung ist HEUTE vollstaendig: die Aufnahme des Index kann
            // ausschliesslich an der Schemaprojektion scheitern. Sie ist
            // trotzdem eine Einebnung, und die Zusicherung haelt sie ehrlich —
            // bekaeme die Aufnahme je einen zweiten Fehlschlag (eine
            // Kapazitaets- oder Kodiertatsache), erschiene er hier sonst still
            // als Schemaweigerung, und `EA-READER-SCHEMA-UNSUPPORTED` sagte
            // etwas Falsches ueber das Paket.
            debug_assert!(
                matches!(error, IndexError::Schema(_)),
                "die Aufnahme des Index kennt nur die Schemaweigerung, hier war es {}",
                error.code()
            );
            ReaderError::UnsupportedSchema
        })?;
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

#[cfg(test)]
mod tests {
    //! Die Projektion der drei Textachsen, ueber von Hand gebaute Einsaetze.
    //!
    //! Sie steht HIER und nicht in `tests/`, weil die drei Projektionen
    //! modulprivat sind und bleiben sollen: sie sind Teile EINER Umwandlung und
    //! keine zweite oeffentliche Flaeche. Der Weg vom Zeugentyp in sie hinein
    //! ist ueber `tests/index_projection.rs` bezeugt.

    use ea_schema::{
        CommonHeaderV1, IncidentV1, KeywordV1, LocationV1, NativeSourceV1, OccurredAtV1,
        OperatorSnapshotV1, PatientCount, PersonnelSnapshotV1, VehicleSnapshotV1,
    };
    use ea_types::{
        ObjectHash, OperatorSubjectId, OrganizationId, RecordId, RegistryVersion, UnixMillis,
    };

    use super::{keyword_terms, person_terms, vehicle_terms};

    /// Eine Datensatzkennung in der Form, die `ea-schema` verlangt: UUIDv7.
    ///
    /// Zeichengleich zu `crates/ea-schema/tests/v1_validation.rs`; eine
    /// beliebige 16-Byte-Folge weist `IncidentV1::new` mit
    /// `EA-SCHEMA-UUID-V7` ab.
    fn record_id(seed: u8) -> RecordId {
        let mut bytes = [seed; 16];
        bytes[6] = 0x70 | (seed & 0x0f);
        bytes[8] = 0x80 | (seed & 0x3f);
        RecordId::try_from(bytes.as_slice()).unwrap()
    }

    fn header() -> CommonHeaderV1 {
        CommonHeaderV1::new(
            record_id(0x01),
            UnixMillis::new(1_771_000_000_000),
            "Europe/Berlin",
            OperatorSnapshotV1::new(
                OrganizationId::try_from(&[0x10_u8; 16][..]).unwrap(),
                OperatorSubjectId::try_from(&[0x20_u8; 16][..]).unwrap(),
                "Erika Beispiel",
                "Einsatzleitung",
                [0x30; 32],
                ObjectHash::try_from(&[0x40_u8; 32][..]).unwrap(),
            )
            .unwrap(),
            NativeSourceV1::new("writer-native", 1).unwrap(),
            RegistryVersion::new(7),
        )
        .unwrap()
    }

    fn incident(
        keyword: KeywordV1,
        vehicles: Vec<VehicleSnapshotV1>,
        personnel: Vec<PersonnelSnapshotV1>,
    ) -> IncidentV1 {
        let vehicles_empty_reason = vehicles.is_empty().then(|| "Keine Fahrzeuge".to_owned());
        let personnel_empty_reason = personnel.is_empty().then(|| "Keine Kräfte".to_owned());
        IncidentV1::new(
            header(),
            "2026-0001",
            OccurredAtV1::new(UnixMillis::new(1_771_000_000_000), None).unwrap(),
            keyword,
            LocationV1::free_text("Hauptstraße", None).unwrap(),
            personnel,
            personnel_empty_reason,
            vehicles,
            vehicles_empty_reason,
            PatientCount::Known(0),
            None,
            vec![],
        )
        .unwrap()
    }

    /// Der freie Text ist der Term; die Referenz gibt ihren ANZEIGETEXT her und
    /// NIE ihre Kennung.
    ///
    /// Die Kennung ist ein technischer Schluessel eines Stammdatensatzes. Truege
    /// der Index sie, faende eine Suche nach ihr Einsaetze — und die Kennung
    /// steht in keiner Oberflaeche, nach der jemand suchen koennte.
    #[test]
    fn a_keyword_projects_its_free_text_or_the_display_text_of_its_reference() {
        assert_eq!(
            keyword_terms(&incident(
                KeywordV1::free_text("Brand").unwrap(),
                vec![],
                vec![]
            )),
            vec!["Brand".to_owned()]
        );

        let referenced = incident(
            KeywordV1::reference("KW-42", "Verkehrsunfall").unwrap(),
            vec![],
            vec![],
        );
        assert_eq!(
            keyword_terms(&referenced),
            vec!["Verkehrsunfall".to_owned()]
        );
        assert!(
            !keyword_terms(&referenced)
                .iter()
                .any(|term| term == "KW-42"),
            "die Referenzkennung ist kein Suchbegriff"
        );
    }

    /// Ein Fahrzeug projiziert ALLE DREI Bezeichner, und die beiden optionalen
    /// verschwinden, wenn sie fehlen.
    #[test]
    fn a_vehicle_projects_display_name_radio_call_sign_and_licence_plate() {
        let full = VehicleSnapshotV1::AdHoc {
            display_name: "Löschfahrzeug".to_owned(),
            radio_call_sign: Some("LF 10".to_owned()),
            license_plate: Some("B-FW 1234".to_owned()),
        };
        let bare = VehicleSnapshotV1::AdHoc {
            display_name: "MTW".to_owned(),
            radio_call_sign: None,
            license_plate: None,
        };
        assert_eq!(
            vehicle_terms(&incident(
                KeywordV1::free_text("Brand").unwrap(),
                vec![full, bare],
                vec![]
            )),
            vec![
                "Löschfahrzeug".to_owned(),
                "LF 10".to_owned(),
                "B-FW 1234".to_owned(),
                "MTW".to_owned(),
            ]
        );
    }

    /// Jede eingesetzte Person projiziert ihren Anzeigenamen — und ein Einsatz
    /// ohne Kraefte traegt keine erfundene Zeile.
    #[test]
    fn every_person_projects_its_display_name_and_an_empty_crew_projects_nothing() {
        let crew = vec![
            PersonnelSnapshotV1::AdHoc {
                display_name: "Ada Lovelace".to_owned(),
                role_or_function: Some("Gruppenführerin".to_owned()),
            },
            PersonnelSnapshotV1::AdHoc {
                display_name: "Grace Hopper".to_owned(),
                role_or_function: None,
            },
        ];
        assert_eq!(
            person_terms(&incident(
                KeywordV1::free_text("Brand").unwrap(),
                vec![],
                crew
            )),
            vec!["Ada Lovelace".to_owned(), "Grace Hopper".to_owned()]
        );
        assert!(
            person_terms(&incident(
                KeywordV1::free_text("Brand").unwrap(),
                vec![],
                vec![]
            ))
            .is_empty()
        );
    }
}
