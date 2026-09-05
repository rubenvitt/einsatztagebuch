//! Die Kulisse der Reader-Kanarienvoegel: EIN Einsatz, dessen jedes fachliche
//! Feld genau einen eigenen Marker traegt, durch den vollstaendigen
//! Stufe-4-Reader gefahren.
//!
//! # Der Bestand wird NICHT nachgebaut
//!
//! Er kommt ueber dieselbe `#[path]`-Kette, die
//! `tests/ea-system-tests/tests/file_mode_interop_support/mod.rs` und
//! `crates/ea-reader-wasm` schon fahren:
//! `crates/ea-reader/tests/verify_fixtures/mod.rs` und darunter
//! `crates/ea-verify/tests/support/mod.rs`. Neu ist allein der KLARTEXT —
//! `verify_support::complete_valid_archive_with_plaintext` nimmt ihn als
//! Parameter, und `crates/ea-reader/tests/fixtures/mod.rs` bleibt unberuehrt
//! (es zieht `ea-sync-protocol`, und das ist in dieser Testcrate keine Kante).
//!
//! # Die eine Naht, die diese Kulisse schliesst
//!
//! `crates/ea-reader/tests/index_projection.rs` haelt im Kopf fest, dass
//! „keine Kulisse dieses Arbeitsbaums eine `ea.incident`-Nutzlast in einen
//! Archivbestand verschluesselt" und der positive Weg in den fachlichen Index
//! deshalb dort nicht bezeugbar ist. [`canary_incident_plaintext`] baut genau
//! eine solche Nutzlast — mit `ea_schema::encode_payload` —, und der Zeuge
//! faehrt sie durch `decrypt_verified` und `ReaderSearch::index`. Der Klartext
//! ist damit vom Reader selbst erzeugt und taugt AUSDRUECKLICH nicht als
//! Kodierbeleg (dafuer steht `vectors/format/payload-v1/genesis.hex`); er
//! taugt als Traeger von Markern, und das ist hier seine einzige Rolle.
//!
//! # `InMemoryReaderBlobStore` IST hier „die rohen OPFS-Bytes"
//!
//! Ein Rust-Test kann kein echtes OPFS anfassen. `InMemoryReaderBlobStore` ist
//! das prozessinterne Doppel des Byteports, den `crates/ea-reader-wasm`
//! ueber `FileSystemSyncAccessHandle` implementiert; was hier in seinen Blobs
//! steht, steht im Browser in den Dateien. Die Zeugen lesen ihn deshalb
//! genauso, wie es `crates/ea-reader/tests/cache_canaries.rs` tut: ueber
//! `keys()` und `get()` und niemals ueber Cache, Zustandsspeicher oder
//! Protokoll — also mit der Sicht eines Angreifers auf OPFS und nicht mit der
//! des Readers.
//!
//! # Es gibt KEINE Konstante fuer die Adresse des Indexblobs
//!
//! Gemessen am 2026-09-05: `crates/ea-reader` fuehrt
//! `READER_VAULT_BLOB_KEY_V1`, `READER_AUDIT_LOG_BLOB_KEY_V1`,
//! `READER_SYNC_CURSOR_BLOB_KEY_V1` und `READER_SYNC_OBJECTS_BLOB_KEY_V1`, aber
//! keine Adresse fuer den versiegelten Index — `ReaderSearch::seal` gibt Bytes
//! heraus und legt sie nicht ab. Diese Kulisse legt sie unter
//! [`INDEX_BLOB_KEY_IN_THIS_WITNESS_V1`] ab und sagt damit, was sie tut: die
//! Adresse ist eine Setzung DIESES Zeugen und kein Vertrag der Crate.
//!
//! `#[path]`-Includes werden je Testziel uebersetzt; daher `allow(dead_code)`.
#![allow(dead_code)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use ea_crypto::{AEAD_NONCE_SIZE, SecretBytes};
use ea_format::{LocalAuditActionV1, decode_local_audit_event};
use ea_reader::{
    ChainSequence, EntryHash, EntryStatus, InMemoryReaderBlobStore, ObjectHash,
    READER_VAULT_BLOB_KEY_V1, ReaderAuditLogSink, ReaderAuditLogStore, ReaderBlobKey,
    ReaderBlobStore, ReaderConfirmationPurpose, ReaderEntryStateStore, ReaderEntryStateV1,
    ReaderExportError, ReaderExportService, ReaderExportTarget, ReaderExportTargetError,
    ReaderExportTargetKindV1, ReaderObjectCache, ReaderQueryV1, ReaderSearch, ReaderSession,
    ReaderSyncService, ReaderVault, SchemaRegistry, ServerConfirmationV1, SilentObserver,
    UnixMillis, VerificationStatus, decrypt_verified, indexable_record,
};
use ea_schema::{
    CommonHeaderV1, IncidentV1, KeywordV1, LocationV1, NativeSourceV1, OccurredAtV1,
    OperatorSnapshotV1, PatientCount, PayloadV1, PersonnelSnapshotV1, VehicleSnapshotV1,
    encode_payload,
};
use ea_types::{
    ObjectHash as TypesObjectHash, OperatorSubjectId, OrganizationId, RecordId, RegistryVersion,
};

/// Das Fixture-Modul des Readers, unveraendert weiterverwendet.
#[path = "../../../../crates/ea-reader/tests/verify_fixtures/mod.rs"]
pub mod verify_fixtures;

pub use verify_fixtures::{fixtures, verify_support};

// ---------------------------------------------------------------------------
// Die Marker
// ---------------------------------------------------------------------------

/// Der Ereigniszeitpunkt des Kanarieneinsatzes.
///
/// Er ist SELBST ein Marker, und zwar der einzige nichttextliche: `occurredAt`
/// ist eine Millisekundenzahl, und ein Text ist dafuer nicht konstruierbar.
/// Gesucht wird seine 8-Byte-Darstellung in Netzreihenfolge — genau die
/// Bytefolge, die CBOR fuer eine Zahl dieser Groesse ausschreibt
/// (Hauptkategorie 0, Argumentlaenge 8). Ein kleiner Zahlenwert waere in jedem
/// Bytestrom zufaellig zu finden; acht Byte dieser Gestalt sind es nicht.
pub const CANARY_OCCURRED_AT_MS_V1: i64 = 1_771_022_600_999;

/// Dieselbe Zahl als Bytemarker.
pub const CANARY_OCCURRED_AT_BYTES_V1: [u8; 8] = CANARY_OCCURRED_AT_MS_V1.to_be_bytes();

/// Die Zeitzone des Kanarieneinsatzes — ebenfalls ein Marker.
///
/// Sie kann keinen erfundenen Wert tragen: `CommonHeaderV1::new` prueft gegen
/// die IANA-Datenbank (`EA-SCHEMA-TIMEZONE`). Der Marker ist deshalb eine
/// ECHTE, aber seltene Zone; `Europe/Berlin` waere als Marker wertlos, weil die
/// Zeichenkette in diesem Baum an Dutzenden Stellen ohnehin steht.
pub const CANARY_TIMEZONE_V1: &str = "Antarctica/Troll";

/// Der Dateiname, den das Exportziel dem Wirt gegenueber traegt.
///
/// Er ist kein Feld der Nutzlast und trotzdem ein Marker: die Zusage lautet
/// „NIE ein Klartext-Dateiname in der Auditzeile", und ohne einen Marker AM
/// Ziel waere sie nicht messbar.
pub const CANARY_EXPORT_FILENAME_V1: &str = "kanarie-reader-dateiname-5e77.json";

/// Je fachlichem Feld GENAU EIN eigener Marker.
///
/// Ein gemeinsamer Marker fuer zwei Felder liesse offen, welches von beiden
/// geleckt hat — dieselbe Regel, die
/// `tests/ea-system-tests/tests/privacy_canaries_writer.rs` durchsetzt.
///
/// # Warum die Textmarker KLEINGESCHRIEBEN sind
///
/// GEMESSEN am 2026-09-05 und nicht Geschmack: `normalize_term` in
/// `crates/ea-index/src/inverted.rs` faltet jeden Suchbegriff ueber
/// `NFC → str::to_lowercase → NFC`. Ein GROSS geschriebener Marker stuende in
/// einem leckenden Indexkoerper nur in seiner gefalteten Gestalt, und die
/// Suche nach dem Originalmarker faende ihn NICHT — der Zeuge waere fuer
/// Stichwort-, Personal- und Fahrzeugterme still blind. Kleingeschriebene
/// ASCII-Marker sind unter dieser Faltung Fixpunkte;
/// `every_named_field_carries_its_own_marker_and_the_vault_gives_it_back`
/// haelt das fest. Der Zeitzonenmarker ist die eine Ausnahme — eine IANA-Zone
/// schreibt ihre Grossbuchstaben vor —, und er ist zugleich das eine Feld, das
/// `indexable_record` gar nicht in einen Term projiziert.
///
/// KEINEN Marker tragen, und das ist gemessen und nicht vergessen:
/// * `patient_count` — `PatientCount::Known(u32) | Unknown`
///   (`crates/ea-schema/src/model.rs`) fuehrt keinen Bedienertext, und eine
///   kleine Zahl als Marker waere in jedem Strom zufaellig zu finden.
/// * `record_id` — `RecordId` ist eine UUIDv7 (`EA-SCHEMA-UUID-V7`); die
///   Gestalt laesst keinen Text zu.
/// * `finalized_at_device` und `registry_version` — dieselbe Lage wie
///   `occurredAt`, und EIN Zeitmarker genuegt: was einen 8-Byte-Zahlenmarker
///   durchliesse, liesse jeden zweiten auch durch.
pub const READER_CANARY_MARKERS: [(&str, &[u8]); 11] = [
    (
        "human_incident_number",
        b"kanarie-reader-einsatznummer-4a17",
    ),
    ("keyword", b"kanarie-reader-stichwort-8b02"),
    ("location", b"kanarie-reader-ort-3c9e"),
    ("personnel", b"kanarie-reader-personal-7d41"),
    ("vehicles", b"kanarie-reader-fahrzeug-2e6b"),
    ("notes", b"kanarie-reader-freitext-9f55"),
    ("external_organizations", b"kanarie-reader-fremdorg-1d08"),
    ("operator", b"kanarie-reader-bediener-6a3c"),
    ("timezone", CANARY_TIMEZONE_V1.as_bytes()),
    ("occurred_at", &CANARY_OCCURRED_AT_BYTES_V1),
    ("export_filename", CANARY_EXPORT_FILENAME_V1.as_bytes()),
];

/// Der Marker des Feldes `field`.
///
/// # Panics
/// Wenn `field` kein benanntes Feld dieser Kulisse ist.
#[must_use]
pub fn canary(field: &str) -> &'static [u8] {
    READER_CANARY_MARKERS
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, marker)| *marker)
        .expect("jedes benannte Feld traegt einen Marker")
}

/// Der Marker des Feldes `field` als Text.
///
/// # Panics
/// Fuer `occurred_at`: der Zahlenmarker ist kein Text.
#[must_use]
pub fn canary_text(field: &str) -> &'static str {
    core::str::from_utf8(canary(field)).expect("dieser Marker ist Text")
}

// ---------------------------------------------------------------------------
// Der Kanarieneinsatz
// ---------------------------------------------------------------------------

/// Eine Datensatzkennung in der Form, die `ea-schema` verlangt: UUIDv7.
///
/// Zeichengleich zu `crates/ea-reader/src/search.rs::tests::record_id`; eine
/// beliebige 16-Byte-Folge weist `IncidentV1::new` mit `EA-SCHEMA-UUID-V7` ab.
fn canary_record_id() -> RecordId {
    let mut bytes = [0x2c_u8; 16];
    bytes[6] = 0x7c;
    bytes[8] = 0xac;
    RecordId::try_from(bytes.as_slice()).expect("eine UUIDv7 aus festen Bytes")
}

/// Der Kanarieneinsatz als Nutzlast: jedes benannte Feld traegt seinen Marker.
///
/// # Panics
/// Wenn ein Marker die Schemapruefung nicht besteht — dann ist der Marker
/// falsch gewaehlt und nicht das Schema.
#[must_use]
pub fn canary_incident() -> IncidentV1 {
    let header = CommonHeaderV1::new(
        canary_record_id(),
        UnixMillis::new(CANARY_OCCURRED_AT_MS_V1),
        CANARY_TIMEZONE_V1,
        OperatorSnapshotV1::new(
            OrganizationId::try_from(&[0x71_u8; 16][..]).expect("16 Byte"),
            OperatorSubjectId::try_from(&[0x72_u8; 16][..]).expect("16 Byte"),
            canary_text("operator"),
            "Einsatzleitung",
            [0x73; 32],
            TypesObjectHash::try_from(&[0x74_u8; 32][..]).expect("32 Byte"),
        )
        .expect("die Bedienerspalte der Kulisse ist gueltig"),
        NativeSourceV1::new("ea.system-tests.reader-canary", 1).expect("die Quelle ist gueltig"),
        RegistryVersion::new(7),
    )
    .expect("der Kopf des Kanarieneinsatzes ist gueltig");
    IncidentV1::new(
        header,
        canary_text("human_incident_number"),
        OccurredAtV1::new(UnixMillis::new(CANARY_OCCURRED_AT_MS_V1), None)
            .expect("das Intervall ist gueltig"),
        KeywordV1::free_text(canary_text("keyword")).expect("das Stichwort ist gueltig"),
        LocationV1::free_text(canary_text("location"), None).expect("der Ort ist gueltig"),
        vec![
            PersonnelSnapshotV1::ad_hoc(canary_text("personnel"), None)
                .expect("die Personalzeile ist gueltig"),
        ],
        None,
        vec![
            VehicleSnapshotV1::ad_hoc(canary_text("vehicles"), None, None)
                .expect("die Fahrzeugzeile ist gueltig"),
        ],
        None,
        // `patient_count` traegt keinen Marker, siehe [`READER_CANARY_MARKERS`].
        PatientCount::Unknown,
        Some(canary_text("notes").to_owned()),
        vec![
            ea_schema::ExternalOrganizationV1::new(None, canary_text("external_organizations"))
                .expect("die Fremdorganisation ist gueltig"),
        ],
    )
    .expect("der Kanarieneinsatz ist schemagueltig")
}

/// Derselbe Einsatz als KLARTEXTBYTES, so wie der Writer sie verschluesselt
/// haette.
///
/// # Panics
/// Wenn der Kodierer die Nutzlast abweist.
#[must_use]
pub fn canary_incident_plaintext() -> Vec<u8> {
    encode_payload(&PayloadV1::Incident(canary_incident())).expect("der Kanarieneinsatz kodiert")
}

// ---------------------------------------------------------------------------
// Das Exportziel
// ---------------------------------------------------------------------------

/// Ein Exportziel im Speicher, das einen WIRTSPFAD traegt.
///
/// Der Pfad ist die Attrappe dessen, was der Browser kennt und das Audit nie
/// sehen darf — dieselbe Bauform wie `MemoryTarget` in
/// `crates/ea-reader/tests/export.rs`, hier mit einem MARKER als Namen.
pub struct CanaryExportTarget {
    host_path: &'static str,
    received: Option<Vec<u8>>,
}

impl Default for CanaryExportTarget {
    fn default() -> Self {
        Self {
            host_path: CANARY_EXPORT_FILENAME_V1,
            received: None,
        }
    }
}

impl CanaryExportTarget {
    /// Was das Ziel bekommen hat — der EINE bewusste Ausgang.
    #[must_use]
    pub fn received(&self) -> Option<&[u8]> {
        self.received.as_deref()
    }
}

impl ReaderExportTarget for CanaryExportTarget {
    fn kind(&self) -> ReaderExportTargetKindV1 {
        ReaderExportTargetKindV1::UserChosenFile
    }

    fn is_occupied(&self) -> bool {
        false
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<(), ReaderExportTargetError> {
        assert!(!self.host_path.is_empty(), "die Attrappe traegt einen Pfad");
        self.received = Some(plaintext.to_vec());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Die Kulisse
// ---------------------------------------------------------------------------

/// Die Adresse, unter der DIESER Zeuge den versiegelten Index ablegt.
///
/// Siehe den Modulkopf: `ea-reader` fuehrt dafuer keine Konstante.
pub const INDEX_BLOB_KEY_IN_THIS_WITNESS_V1: &str = "search-index";

/// Die Adresse des absichtlich UNVERSCHLUESSELTEN Kontrollstroms.
pub const CONTROL_BLOB_KEY_V1: &str = "kanarie-kontrollstrom";

/// Die Autoritaet, an die der Reader seine Lesestapel richtet.
pub const CANARY_SYNC_AUTHORITY_V1: &str = "sync.einsatzarchiv.invalid";

/// Ein vollstaendiger Reader-Lauf ueber dem Kanarieneinsatz.
pub struct ReaderCanaryHarness {
    store: InMemoryReaderBlobStore,
    entry_hash: EntryHash,
    plaintext_len: usize,
    /// Ob jeder Marker im Klartext steckt, den der Tresor herausgibt — je Feld
    /// getrennt, damit die Positivkontrolle das FELD nennt und nie die Bytes.
    markers_readable_through_the_vault: Vec<(&'static str, bool)>,
    markers_in_the_encoded_payload: Vec<(&'static str, bool)>,
    exported_bytes: Vec<u8>,
    audit_lines: Vec<Vec<u8>>,
    error_reports: Vec<(String, Vec<u8>)>,
    server_metadata: Vec<(String, Vec<u8>)>,
    search_hit_incident_number: String,
    indexed_packages: usize,
}

impl ReaderCanaryHarness {
    /// Faehrt den Kanarieneinsatz durch Tresor, Verifikation, Entschluesselung,
    /// Cache, Zustandsspeicher, Index, Sync-Request, Sitzung und Einzelexport.
    ///
    /// # Panics
    /// An jeder Stelle, an der der Reader diesen Bestand nicht traegt — dann
    /// ist die Kulisse kaputt und nicht die Zusage.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn run() -> Self {
        let plaintext = canary_incident_plaintext();
        let markers_in_the_encoded_payload = READER_CANARY_MARKERS
            .iter()
            .map(|(field, marker)| (*field, ea_testkit::contains_canary(&plaintext, marker)))
            .collect();

        let complete = verify_support::complete_valid_archive_with_plaintext(&plaintext);
        assert_eq!(
            complete.anchor_bytes,
            fixtures::complete_archive_anchor_bytes(),
            "der Kanarienbestand MUSS an derselben Registrierungslinie haengen wie der \
             Kulissen-Tresor, sonst faellt er an Gate `trust` und der Zeuge maesse nichts"
        );
        let source = &complete.fixture;
        let vault = fixtures::session_vault();
        let entry_hash = fixtures::entry_hash(source);

        // --- Der Tresor als OPFS-Blob -------------------------------------
        let mut store = InMemoryReaderBlobStore::new();
        store
            .put(
                &blob_key(READER_VAULT_BLOB_KEY_V1),
                &fixtures::session_sealed_vault().to_deterministic_cbor(),
            )
            .expect("der versiegelte Tresor liegt im Speicher");

        // --- Verifikation vor Entschluesselung ----------------------------
        let classification = fixtures::classify(source, &vault);
        let entry = classification
            .verified_entry(entry_hash)
            .expect("der Kanarienbestand traegt einen Zeugen");
        let grant = classification
            .verified_grant(entry_hash)
            .expect("und einen eigenen Grant");
        let record = decrypt_verified(
            entry,
            grant,
            &vault,
            &SchemaRegistry::v1(),
            fixtures::EFFECTIVE_NOW,
            &mut SilentObserver,
        )
        .expect("der Kanarieneinsatz traegt eine gueltige Schemabestimmung");
        assert_eq!(
            record.source_schema().0,
            "ea.incident",
            "die Kulisse MUSS eine fachliche Nutzlast tragen"
        );

        // --- Positivkontrolle: der Marker ist ueber den Tresor LESBAR ------
        let markers_readable_through_the_vault = record.with_plaintext(|opened| {
            READER_CANARY_MARKERS
                .iter()
                .map(|(field, marker)| (*field, ea_testkit::contains_canary(opened, marker)))
                .collect::<Vec<_>>()
        });
        let plaintext_len = record.with_plaintext(<[u8]>::len);

        // --- Der inhaltsadressierte Cache ---------------------------------
        let cache = ReaderObjectCache::open(&vault);
        for (_, bytes) in source.blobs() {
            cache
                .put_exact_object(&mut store, bytes)
                .expect("jedes Archivobjekt laesst sich cachen");
        }
        // Der SCHLIMMSTE Fall, dem der Cache je begegnen koennte: ihm werden
        // die entschluesselten Bytes selbst gereicht. Der Reader tut das
        // nirgends — genau deshalb steht es hier: eine Ablage, die auch DAS
        // versiegelt, versiegelt jedes Archivobjekt erst recht. Dieselbe
        // Bauform wie `entry_package_bytes_carrying` in
        // `crates/ea-reader/tests/cache_canaries.rs`.
        cache
            .put_exact_object(&mut store, &plaintext)
            .expect("auch der Klartext geht als Objekt in den Cache");

        // --- Der Zustandsspeicher ------------------------------------------
        ReaderEntryStateStore::open(&vault)
            .put_entry_state(
                &mut store,
                &ReaderEntryStateV1::new(
                    entry_hash,
                    ObjectHash::try_from(&[0x75_u8; 32][..]).expect("32 Byte"),
                    ChainSequence::new(verify_support::COMPLETE_GENESIS_SEQUENCE_V1),
                    VerificationStatus::Verified,
                    EntryStatus::Present,
                    ServerConfirmationV1::NotServerConfirmed,
                    None,
                ),
            )
            .expect("der Eintragszustand laesst sich ablegen");

        // --- Der verschluesselte Index --------------------------------------
        let mut search = ReaderSearch::empty();
        search
            .index(&record)
            .expect("ein Einsatzpaket bildet eine fachliche Indexzeile");
        let indexed_packages = search.indexed_packages();
        let hit = search
            .search(&ReaderQueryV1::keyword(canary_text("keyword")))
            .expect("die Suche ueber dem eigenen Marker laeuft");
        assert_eq!(
            hit.len(),
            1,
            "die Suche nach dem Stichwortmarker MUSS genau den Kanarieneinsatz finden"
        );
        let search_hit_incident_number = hit[0].human_incident_number().to_owned();
        let index_blob = search
            .seal(
                &vault.index_key(),
                &SecretBytes::new([0x5a_u8; AEAD_NONCE_SIZE]),
            )
            .expect("der Index versiegelt");
        store
            .put(
                &blob_key(INDEX_BLOB_KEY_IN_THIS_WITNESS_V1),
                index_blob.bytes(),
            )
            .expect("der versiegelte Index liegt im Speicher");

        // --- Die Servermetadaten -------------------------------------------
        let sync = ReaderSyncService::open(
            &vault,
            CANARY_SYNC_AUTHORITY_V1.to_owned(),
            fixtures::EFFECTIVE_NOW,
        );
        let cursor = sync
            .confirmed_cursor(&store)
            .expect("ein Speicher ohne Cursorblob steht auf Genesis");
        let request = sync
            .next_request(&cursor)
            .expect("der Lesestapel-Request laesst sich bilden");
        let server_metadata = vec![
            (
                "Lesestapel-Request (Methode, Autoritaet, Ziel, Kopfzeilen, Koerper)".to_owned(),
                render_request(&request),
            ),
            (
                "Debug des Lesestapel-Requests".to_owned(),
                format!("{request:?}").into_bytes(),
            ),
            (
                "Debug des bestaetigten Cursors".to_owned(),
                format!("{cursor:?}").into_bytes(),
            ),
        ];

        // --- Sitzung, Einzelexport und das signierte lokale Audit ----------
        let now = fixtures::EFFECTIVE_NOW;
        let mut session = ReaderSession::unlock(
            fixtures::session_vault(),
            fixtures::confirmation(ReaderConfirmationPurpose::Unlock, now),
            now,
        )
        .expect("eine frische Entsperrbestaetigung eroeffnet die Sitzung");
        let mut target = CanaryExportTarget::default();
        let log = ReaderAuditLogStore::open(&vault);
        let report = {
            let mut sink = ReaderAuditLogSink::new(&log, &mut store);
            ReaderExportService::open(&mut session, fixtures::audit_identity(), &mut sink, now)
                .export_one(
                    record,
                    Some(&mut target),
                    fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, now),
                )
                .expect("der Einzelexport an ein freies Ziel gelingt")
        };
        let audit_lines = log
            .events(&store)
            .expect("das lokale Protokoll ist ueber denselben Tresor lesbar");
        let exported_bytes = target
            .received()
            .expect("das Ziel hat die Bytes angenommen")
            .to_vec();

        // --- Die Fehlerberichte ---------------------------------------------
        let error_reports = collect_error_reports(&store, &report, &search, entry_hash);

        Self {
            store,
            entry_hash,
            plaintext_len,
            markers_readable_through_the_vault,
            markers_in_the_encoded_payload,
            exported_bytes,
            audit_lines,
            error_reports,
            server_metadata,
            search_hit_incident_number,
            indexed_packages,
        }
    }

    /// Der Eintragshash des Kanarieneintrags.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    /// Wie viele Pakete der Index aufgenommen hat.
    #[must_use]
    pub const fn indexed_packages(&self) -> usize {
        self.indexed_packages
    }

    /// Die Einsatznummer, die die SUCHE zurueckgegeben hat.
    #[must_use]
    pub fn search_hit_incident_number(&self) -> &str {
        &self.search_hit_incident_number
    }

    /// Je Feld: steckt sein Marker in den kodierten Klartextbytes?
    #[must_use]
    pub fn markers_in_the_encoded_payload(&self) -> &[(&'static str, bool)] {
        &self.markers_in_the_encoded_payload
    }

    /// Je Feld: gibt der ENTSPERRTE Tresor seinen Marker wieder heraus?
    #[must_use]
    pub fn markers_readable_through_the_vault(&self) -> &[(&'static str, bool)] {
        &self.markers_readable_through_the_vault
    }

    /// Die Bytes, die das bewusst gewaehlte Exportziel bekommen hat — der EINE
    /// Ausgang, an dem Klartext den Reader verlassen DARF.
    #[must_use]
    pub fn exported_bytes(&self) -> &[u8] {
        &self.exported_bytes
    }

    /// Die Laenge des Klartexts, wie der Tresor ihn herausgab.
    #[must_use]
    pub const fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    /// STROM 1: jeder rohe OPFS-Blob, benannt nach seiner Adresse, plus die
    /// Adressliste selbst.
    ///
    /// Die Adressliste ist ein eigener Strom, weil sie den Byteport im
    /// KLARTEXT verlaesst: ein fachlicher Bestandteil in einer Adresse waere
    /// ein Leck, das keine Pruefung des Blobinhalts faengt.
    #[must_use]
    pub fn raw_opfs_bytes(&self) -> Vec<(String, Vec<u8>)> {
        let keys = self.store.keys().expect("die Adressliste ist lesbar");
        let mut streams: Vec<(String, Vec<u8>)> = keys
            .iter()
            .map(|key| {
                let bytes = self
                    .store
                    .get(key)
                    .expect("jeder gelistete Blob ist lesbar")
                    .expect("und vorhanden");
                (format!("OPFS-Blob {}", key.as_str()), bytes)
            })
            .collect();
        streams.push((
            "die Adressliste des Byteports".to_owned(),
            keys.iter()
                .map(ReaderBlobKey::as_str)
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes(),
        ));
        streams
    }

    /// STROM 4: die signierten Zeilen des lokalen Audits, je Zeile die exakten
    /// Bytes und der signaturgedeckte Kern.
    #[must_use]
    pub fn structured_log_lines(&self) -> Vec<(String, Vec<u8>)> {
        let mut streams = Vec::new();
        for (index, line) in self.audit_lines.iter().enumerate() {
            streams.push((format!("Auditzeile {index} (signiert)"), line.clone()));
            let event = decode_local_audit_event(line).expect("jede Zeile ist ein Ereignis");
            streams.push((
                format!("Auditzeile {index} (Kern)"),
                event.exact_core().to_vec(),
            ));
            streams.push((
                format!("Auditzeile {index} (Debug)"),
                format!("{event:?}").into_bytes(),
            ));
        }
        streams
    }

    /// Die dekodierten Auditzeilen.
    ///
    /// # Panics
    /// Wenn eine Zeile kein gueltiges signiertes Ereignis ist.
    #[must_use]
    pub fn audit_events(&self) -> Vec<ea_format::LocalAuditEventV1> {
        self.audit_lines
            .iter()
            .map(|line| decode_local_audit_event(line).expect("jede Zeile ist ein Ereignis"))
            .collect()
    }

    /// STROM 5: jede Fehler- und Debug-Ausgabe, die der Reader auf diesen Wegen
    /// ueberhaupt bilden kann.
    #[must_use]
    pub fn error_reports(&self) -> &[(String, Vec<u8>)] {
        &self.error_reports
    }

    /// STROM 6: was der Reader dem Server ueber sich mitteilt.
    #[must_use]
    pub fn server_metadata(&self) -> &[(String, Vec<u8>)] {
        &self.server_metadata
    }

    /// Legt den Klartext ABSICHTLICH unverschluesselt in den Byteport — die
    /// Gegenkontrolle der Suche.
    ///
    /// Der Strom traegt BEIDE Herkuenfte, aus denen Marker in diesem Lauf
    /// ueberhaupt stammen: die kodierte Nutzlast und den Wirtspfad des
    /// Exportziels. Ein Kontrollstrom, dem der Dateinamensmarker fehlte,
    /// belegte fuer genau dieses Feld nichts — und das Feld traegt eine eigene
    /// Zusage (`web-reader-design.md` §8.2: nie ein Klartext-Dateiname).
    ///
    /// # Panics
    /// Wenn der Speicher die Ablage verweigert.
    pub fn plant_the_unencrypted_control_stream(&mut self) {
        let mut control = canary_incident_plaintext();
        control.extend_from_slice(CANARY_EXPORT_FILENAME_V1.as_bytes());
        self.store
            .put(&blob_key(CONTROL_BLOB_KEY_V1), &control)
            .expect("der Kontrollstrom laesst sich ablegen");
    }
}

/// Eine Blobadresse.
///
/// # Panics
/// Wenn die Adresse nicht wohlgeformt ist.
fn blob_key(value: &str) -> ReaderBlobKey {
    ReaderBlobKey::new(value).expect("eine feste Adresse dieser Kulisse ist wohlgeformt")
}

/// Der Request als Bytestrom: alles, was der Wirt zu sehen bekaeme.
fn render_request(request: &ea_reader::ReaderRequestV1) -> Vec<u8> {
    let mut rendered = String::new();
    let _ = writeln!(
        rendered,
        "{:?} {} {}",
        request.method, request.authority, request.target
    );
    for (name, value) in &request.headers {
        let _ = writeln!(rendered, "{name}: {value}");
    }
    let mut bytes = rendered.into_bytes();
    bytes.extend_from_slice(&request.body);
    bytes
}

/// Jede Fehler- und Debug-Ausgabe, die auf diesen Wegen entstehen kann.
///
/// Sie ist der „Absturzausgang" dieses Kerns: der Workspace hat keinen
/// Absturzberichtsdienst, und was in eine Panik, eine Fehlerzeile oder eine
/// Browserkonsole geriete, entsteht aus `Debug` und `Display` und nirgends
/// sonst — dieselbe Begruendung, die
/// `tests/ea-system-tests/tests/support/mod.rs` fuer den Writer aufschreibt.
fn collect_error_reports(
    store: &InMemoryReaderBlobStore,
    report: &ea_reader::ReaderExportReport,
    search: &ReaderSearch,
    entry_hash: EntryHash,
) -> Vec<(String, Vec<u8>)> {
    let mut reports: Vec<(String, Vec<u8>)> = Vec::new();
    let mut push = |label: &str, text: String| reports.push((label.to_owned(), text.into_bytes()));

    push("Debug des Exportberichts", format!("{report:?}"));
    push(
        "Debug des Suchtreffers",
        format!("{:?}", search.hit_for(entry_hash)),
    );
    push(
        "Debug des Schwellenzustands",
        format!("{:?}", search.pressure()),
    );

    // Ein FREMDER Tresor auf denselben Blobs: die drei Speicher weisen ab, und
    // ihre Fehlerzeilen sind genau das, was ein Bediener zu sehen bekaeme.
    let foreign = fixtures::vault_pinning(fixtures::complete_archive_anchor_bytes().to_vec());
    let cache_error = ReaderObjectCache::open(&foreign)
        .get_exact_object(store, ea_crypto::object_hash(b"kanarie"))
        .err();
    push(
        "Cachefehler unter fremdem Tresor",
        format!("{cache_error:?}"),
    );
    let state_error = ReaderEntryStateStore::open(&foreign)
        .get_entry_state(store, entry_hash)
        .err();
    push(
        "Zustandsspeicherfehler unter fremdem Tresor",
        format!("{state_error:?}"),
    );
    let audit_error = ReaderAuditLogStore::open(&foreign).events(store).err();
    push(
        "Protokollfehler unter fremdem Tresor",
        format!("{audit_error:?}"),
    );
    let index_error = ReaderSearch::open(
        &store
            .get(&blob_key(INDEX_BLOB_KEY_IN_THIS_WITNESS_V1))
            .expect("lesbar")
            .expect("vorhanden"),
        &foreign.index_key(),
    )
    .err();
    push(
        "Indexfehler unter fremdem Tresor",
        format!("{index_error:?}"),
    );
    if let Some(error) = index_error {
        push("Anzeige des Indexfehlers", format!("{error}"));
    }

    // Der Schemaweg: ein Genesis-Paket traegt keine fachliche Indexzeile.
    let refused = indexable_record(&fixtures::decrypted_genesis_record()).err();
    push("Schemaweigerung des Index", format!("{refused:?}"));

    // Der Exportweg ohne Ziel — die Abweisung VOR der Grenze, ueber einem
    // zweiten, gleich gebauten Datensatz.
    let vault = fixtures::session_vault();
    let plaintext = canary_incident_plaintext();
    let complete = verify_support::complete_valid_archive_with_plaintext(&plaintext);
    let classification = fixtures::classify(&complete.fixture, &vault);
    let second_hash = fixtures::entry_hash(&complete.fixture);
    let second = decrypt_verified(
        classification.verified_entry(second_hash).expect("Zeuge"),
        classification.verified_grant(second_hash).expect("Grant"),
        &vault,
        &SchemaRegistry::v1(),
        fixtures::EFFECTIVE_NOW,
        &mut SilentObserver,
    )
    .expect("derselbe Bau entschluesselt ein zweites Mal");
    push(
        "Debug des entschluesselten Datensatzes",
        format!("{second:?}"),
    );
    let now = fixtures::EFFECTIVE_NOW;
    let mut session = ReaderSession::unlock(
        fixtures::session_vault(),
        fixtures::confirmation(ReaderConfirmationPurpose::Unlock, now),
        now,
    )
    .expect("die Sitzung eroeffnet");
    let mut sink = ea_reader::InMemoryReaderAuditSink::new();
    let refused_export: Result<_, ReaderExportError> =
        ReaderExportService::open(&mut session, fixtures::audit_identity(), &mut sink, now)
            .export_one(
                second,
                None,
                fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, now),
            );
    let export_error = refused_export.expect_err("ohne Ziel wird abgewiesen");
    push("Debug der Exportabweisung", format!("{export_error:?}"));
    push("Anzeige der Exportabweisung", format!("{export_error}"));
    assert!(
        sink.events().is_empty(),
        "eine Abweisung VOR der Grenze schreibt keine Zeile"
    );

    // Der Tresorweg: ein fremder PRF-Ausgang oeffnet nichts.
    let vault_error = ReaderVault::unlock(
        fixtures::session_sealed_vault(),
        &fixtures::authenticator_with_a_foreign_prf_output(),
    )
    .err();
    push("Tresorfehler", format!("{vault_error:?}"));

    // Der Byteport: eine unzulaessige Adresse.
    let key_error = ReaderBlobKey::new("../ausbruch").err();
    push("Adressfehler des Byteports", format!("{key_error:?}"));

    reports
}

// ---------------------------------------------------------------------------
// Der QUELLENSCAN der vier Stroeme ohne Rust-Darstellung
// ---------------------------------------------------------------------------

/// Die Wurzel des Arbeitsbaums.
///
/// # Panics
/// Wenn das Manifestverzeichnis nicht zwei Ebenen unter der Wurzel liegt.
#[must_use]
pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tests/ea-system-tests liegt zwei Ebenen unter der Wurzel")
        .to_path_buf()
}

/// Jede HANDGESCHRIEBENE Quelle der Browseranwendung und der wasm-Bruecke.
///
/// Ausgenommen sind die zwei Generatorausgaenge (`bridge/generated-contracts.ts`
/// und `bridge/pkg/`) und die Testdateien — dieselbe Sammelregel, die
/// `apps/web/src/features/export/SingleExport.test.tsx` fuer WR-082 auf der
/// TypeScript-Seite fuehrt. Testdateien bleiben draussen, weil ihre
/// Zusicherungen die verbotenen Namen NENNEN muessen.
///
/// # Panics
/// Wenn ein Verzeichnis nicht lesbar ist.
#[must_use]
pub fn hand_written_browser_sources() -> Vec<(String, String)> {
    let root = repository_root();
    let mut sources = Vec::new();
    for (subtree, extensions) in [
        ("apps/web/src", ["ts", "tsx"].as_slice()),
        ("crates/ea-reader-wasm/src", ["rs"].as_slice()),
    ] {
        let base = root.join(subtree);
        collect_sources(&base, extensions, &root, &mut sources);
    }
    sources.retain(|(path, _)| {
        !path.ends_with(".test.ts")
            && !path.ends_with(".test.tsx")
            && path != "apps/web/src/bridge/generated-contracts.ts"
            && !path.starts_with("apps/web/src/bridge/pkg/")
    });
    sources.sort_by(|left, right| left.0.cmp(&right.0));
    sources
}

fn collect_sources(
    directory: &Path,
    extensions: &[&str],
    root: &Path,
    sources: &mut Vec<(String, String)>,
) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} ist nicht lesbar: {error}", directory.display()));
    for entry in entries {
        let entry = entry.expect("jeder Verzeichniseintrag ist lesbar");
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, extensions, root, sources);
            continue;
        }
        let matches = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extensions.contains(&extension));
        if !matches {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("jede gesammelte Quelle liegt unter der Wurzel")
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} ist nicht lesbar: {error}", path.display()));
        sources.push((relative, text));
    }
}

/// Die Namen, mit denen entschluesselter Inhalt in eine
/// Zwischenablage-Automatik geriete.
pub const CLIPBOARD_NEEDLES_V1: [&str; 5] = [
    "navigator.clipboard",
    "execCommand(",
    "ClipboardItem",
    "web_sys::Clipboard",
    "clipboardData",
];

/// Die Namen, mit denen etwas in einen Service-Worker-Cache geschrieben wuerde
/// — oder mit denen der Worker sich ueberhaupt in eine Antwort einhaengte.
pub const SERVICE_WORKER_CACHE_NEEDLES_V1: [&str; 6] = [
    "cache.put(",
    "cache.add(",
    "cache.addAll(",
    "caches.match(",
    "addEventListener('fetch'",
    "onfetch",
];

/// Die Namen jeder Telemetrieform, die dieser Baum kennen koennte.
///
/// `Sentry.` und `@sentry/` mit ihrer Schreibung und nicht `sentry` klein:
/// die Teilzeichenkette `sEntryH` steckt in `previousEntryHash` und truebe
/// jeden Treffer (gemessen am 2026-09-05).
pub const TELEMETRY_NEEDLES_V1: [&str; 8] = [
    "sendBeacon",
    "@sentry/",
    "Sentry.",
    "gtag(",
    "posthog",
    "mixpanel",
    "datadogRum",
    "plausible(",
];

/// Der erste Treffer aus `needles` in `text` — EINMAL geschrieben und zweimal
/// benutzt: ueber jeder Quelle und ueber der Positivkontrolle.
#[must_use]
pub fn first_forbidden_call(text: &str, needles: &[&'static str]) -> Option<&'static str> {
    needles.iter().copied().find(|needle| text.contains(needle))
}

/// Jede Stelle, an der eine Quelle die Cache-API ueberhaupt anspricht.
#[must_use]
pub fn cache_api_call_sites(sources: &[(String, String)]) -> Vec<(String, String)> {
    let mut sites = Vec::new();
    for (path, text) in sources {
        for line in text.lines() {
            if line.contains("caches.") {
                sites.push((path.clone(), line.trim().to_owned()));
            }
        }
    }
    sites
}

/// Die drei Cache-Aufrufe, die der Service Worker fuehren DARF: er legt den
/// Namensraum der neuen Fassung an, listet die alten und raeumt sie ab. Kein
/// Schreiben, kein Lesen einer Antwort.
pub const ALLOWED_CACHE_CALLS_V1: [&str; 3] = ["caches.open(", "caches.keys()", "caches.delete("];

/// Die eine Aktion, die eine Exportzeile traegt.
#[must_use]
pub fn is_plaintext_export(action: &LocalAuditActionV1) -> bool {
    matches!(action, LocalAuditActionV1::PlaintextExport(_))
}
