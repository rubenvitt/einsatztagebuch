//! Archivfixtures fuer `ea-archive` und alles, was darauf aufbaut.
//!
//! Dieses Modul wird per `#[path]` in Testtargets eingebunden, nie in das
//! Lib-Target. Damit bleibt `ed25519-dalek` aus dem Lib-Graphen, es entsteht
//! kein Feature-Flag und `clippy --all-features` sieht keinen Fixture-Code im
//! Lib-Target.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; ein Target, das nur
//! einen Teil der Helfer nutzt, erzeugt sonst `dead_code`-Warnungen, die unter
//! `-D warnings` brechen. Daher `allow(dead_code)` auf Modulebene, genau wie im
//! Trust-Support.
#![allow(dead_code)]

/// Das Trust-Support-Modul aus `ea-trust`, unveraendert weiterverwendet.
///
/// Liefert `RegistryLineBuilder`, `ActionSpec`, `HeadOptions`, `BuiltHead`,
/// `Pin`, `source()` und `verified()`. Hier wird nichts davon nachgebaut.
#[path = "../../../ea-trust/tests/support/mod.rs"]
pub mod trust_support;

/// Das Format-Support-Modul aus `ea-format`, unveraendert weiterverwendet.
///
/// Liefert die signierten Wirebytes der Objektfamilien. Hier wird kein COSE
/// nachgebaut.
#[path = "../../../ea-format/tests/support/mod.rs"]
pub mod format_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use ea_archive::{ArchiveBlob, ArchiveError, ArchiveSource};
use ea_crypto::CoseSigner;
use ea_format::{
    EAG_PREFIX_V1, ECP_PREFIX_V1, EDS_PREFIX_V1, EIP_PREFIX_V1, ESR_PREFIX_V1, ETB_PREFIX_V1,
    EntryPackageV1, ExactObjectBytes, SignedManifestV1, encode_entry_package,
};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistrySelectionCommit,
    StateStoreError, TrustObjectSource, TrustStateKey, TrustStateSnapshot, TrustStateStore,
    load_trust_state,
};
use ea_types::UnixMillis;

/// Die sechs 9-Byte-Exact-Object-Praefixe aus `crates/ea-format/src/parser.rs`.
pub const EXACT_OBJECT_PREFIXES_V1: [[u8; 9]; 6] = [
    EIP_PREFIX_V1,
    EAG_PREFIX_V1,
    ESR_PREFIX_V1,
    ECP_PREFIX_V1,
    ETB_PREFIX_V1,
    EDS_PREFIX_V1,
];

/// Traegt `bytes` eines der sechs Exact-Object-Praefixe?
///
/// Nur zur Absicherung der Fixtures selbst. Die verbindliche Klassifikation
/// des Bestands entsteht im Inventar, nicht hier.
#[must_use]
pub fn has_exact_object_prefix(bytes: &[u8]) -> bool {
    EXACT_OBJECT_PREFIXES_V1
        .iter()
        .any(|prefix| bytes.starts_with(prefix))
}

/// Ein Bestand im Speicher: geordnete Paare aus Pfadhinweis und Bytes.
///
/// Bewusst eine `Vec` und keine Abbildung ueber den Pfad: ein Bestand darf
/// dieselben Bytes mehrfach und unter beliebigen Hinweisen tragen, und genau
/// das muss pruefbar bleiben.
#[derive(Clone, Default)]
pub struct ArchiveFixture {
    blobs: Vec<(String, Vec<u8>)>,
}

impl ArchiveFixture {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Legt ein Archivobjekt ab.
    pub fn push_object(&mut self, path_hint: &str, object: ExactObjectBytes) -> &mut Self {
        self.push_exact_bytes(path_hint, object.into_vec())
    }

    /// Legt bereits kodierte Objektbytes ab.
    ///
    /// Fuer die Fixtures aus [`format_support`], die `Vec<u8>` liefern, weil
    /// `ExactObjectBytes::new` `pub(crate)` in `ea-format` ist.
    pub fn push_exact_bytes(&mut self, path_hint: &str, bytes: Vec<u8>) -> &mut Self {
        assert!(
            has_exact_object_prefix(&bytes),
            "push_object expects exact object bytes: {path_hint}"
        );
        self.blobs.push((path_hint.to_owned(), bytes));
        self
    }

    /// Legt Beiwerk ab — Bytes ohne Exact-Object-Praefix.
    pub fn push_non_object(&mut self, path_hint: &str, bytes: &[u8]) -> &mut Self {
        assert!(
            !has_exact_object_prefix(bytes),
            "push_non_object expects bytes without an exact object prefix: {path_hint}"
        );
        self.blobs.push((path_hint.to_owned(), bytes.to_vec()));
        self
    }

    #[must_use]
    pub fn blobs(&self) -> &[(String, Vec<u8>)] {
        &self.blobs
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Derselbe Bestand unter vertauschten Pfaden und in anderer Reihenfolge.
    ///
    /// Die Bytes bleiben als Multimenge identisch; nur die Hinweise wandern um
    /// eine Stelle weiter und der Durchlauf laeuft rueckwaerts. Da Pfade nie
    /// klassifizieren, muss jede Aussage ueber den Bestand unveraendert
    /// bleiben. Deterministisch statt zufaellig, damit ein Fehlschlag
    /// reproduzierbar ist.
    #[must_use]
    pub fn randomized_paths(&self) -> Self {
        let count = self.blobs.len();
        if count == 0 {
            return Self::default();
        }
        let mut blobs: Vec<(String, Vec<u8>)> = (0..count)
            .map(|index| {
                (
                    self.blobs[(index + 1) % count].0.clone(),
                    self.blobs[index].1.clone(),
                )
            })
            .collect();
        blobs.reverse();
        Self { blobs }
    }
}

impl ArchiveSource for ArchiveFixture {
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

/// Ein Bestand mitsamt den Bytes, aus denen er gebaut wurde.
///
/// Der Trust Anchor liegt BEWUSST neben dem Bestand und nicht darin: er ist
/// nach `design.md` §11.4 nie Teil der Inventarklassifikation, sondern wird
/// der Verifikation als Parameter uebergeben.
pub struct BuiltArchive {
    pub fixture: ArchiveFixture,
    pub anchor_bytes: Vec<u8>,
    pub eip: Vec<u8>,
    pub eag: Vec<u8>,
    pub esr: Vec<u8>,
    pub ecp: Vec<u8>,
    pub eds: Vec<u8>,
    pub trust_object_count: usize,
    pub non_object_count: usize,
}

/// Baut einen Bestand aus einer Registrierungslinie, den vier Objektfamilien
/// und Beiwerk.
///
/// Die Vertrauensablage stammt vollstaendig aus [`trust_support`]; die
/// signierten Objekte stammen vollstaendig aus [`format_support`]. Die
/// Verteilung der Trust-Objekte auf Unterverzeichnisse ist beliebig, weil der
/// Pfad ein Hinweis ist und nie klassifiziert — das Inventar muss dieselbe
/// Aussage liefern, egal wo die Bytes liegen.
#[must_use]
pub fn canonical_archive() -> BuiltArchive {
    let mut line = trust_support::RegistryLineBuilder::new();
    line.push(
        trust_support::ActionSpec::Device {
            kind: ea_format::CertificateKindV1::Writer,
            marker: 0x11,
            effective_from: None,
        },
        trust_support::HeadOptions::default(),
    );

    let mut fixture = ArchiveFixture::new();
    let mut trust_object_count = 0;
    let source = line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .expect("the fixture trust line must enumerate");
    for hash in hashes {
        let bytes = source
            .read_exact_trust_object(hash)
            .expect("the fixture trust line must read")
            .expect("an enumerated trust object must be readable");
        fixture.push_exact_bytes(
            &format!(
                "{}{}.etb",
                ea_archive::REGISTRY_EVENTS_DIR_V1,
                hex::encode(hash.as_bytes())
            ),
            bytes.to_vec(),
        );
        trust_object_count += 1;
    }

    let (entry, eip) = signed_entry_package();
    let eds = format_support::valid_eds_from_entry(&entry, &eip);
    let eag = format_support::valid_initial_eag();
    let esr = format_support::valid_esr();
    let ecp = format_support::valid_ecp();

    fixture.push_exact_bytes(
        &format!("{}000000000001_entry.eip", ea_archive::ENTRIES_DIR_V1),
        eip.clone(),
    );
    fixture.push_exact_bytes(
        &format!("{}entry_grant.eag", ea_archive::GRANTS_DIR_V1),
        eag.clone(),
    );
    fixture.push_exact_bytes(
        &format!("{}entry.esr", ea_archive::RECEIPTS_DIR_V1),
        esr.clone(),
    );
    fixture.push_exact_bytes(
        &format!(
            "{}000000000001_checkpoint.ecp",
            ea_archive::CHECKPOINTS_DIR_V1
        ),
        ecp.clone(),
    );
    fixture.push_exact_bytes(
        &format!(
            "{}000000000001_entry.eds",
            ea_archive::DESTROYED_ENTRIES_DIR_V1
        ),
        eds.clone(),
    );

    // Beiwerk nach §11.4: traegt kein Exact-Object-Praefix und zaehlt nur in
    // nonObjectFileCount.
    let mut non_object_count = 0;
    for (path_hint, bytes) in [
        (
            ea_archive::README_FORMAT_FILE_V1,
            &b"Einsatzarchiv v1\n"[..],
        ),
        (ea_archive::COMPATIBILITY_MATRIX_FILE_V1, &b"{}\n"[..]),
    ] {
        fixture.push_non_object(path_hint, bytes);
        non_object_count += 1;
    }

    BuiltArchive {
        fixture,
        anchor_bytes: line.exact_anchor_bytes().to_vec(),
        eip,
        eag,
        esr,
        ecp,
        eds,
        trust_object_count,
        non_object_count,
    }
}

/// Die Stelle im `.eip` aus [`signed_entry_package`], an der genau ein Byte
/// verkippt wird, um einen Parse-Fehlschlag zu erzeugen.
///
/// Byte 50 ist das CBOR-`null` (`0xf6`) eines optionalen Feldes im
/// Manifestkern. `0xf6 ^ 0x01` ergibt `0xf7` (`undefined`): ein wohlgeformtes
/// CBOR-Element, das die aeussere Strukturpruefung passiert und erst an der
/// Formpruefung des Manifestkerns scheitert. Genau deshalb ist der Fehler
/// [`MUTATED_EIP_FORMAT_ERROR_CODE_V1`] und kein `EA-CBOR-*`.
///
/// Bewusst eine feste Stelle und keine Suche: eine Suche wuerde bei einer
/// Layoutaenderung in `ea-format` stillschweigend eine andere Fehlerklasse
/// treffen. Diese Konstante bricht stattdessen laut.
pub const MUTATED_EIP_BODY_OFFSET_V1: usize = 50;

/// Der Fehlercode, den [`eip_with_one_mutated_body_byte`] erzeugt.
pub const MUTATED_EIP_FORMAT_ERROR_CODE_V1: &str = "EA-FORMAT-SHAPE";

/// Das kanonische `.eip` mit genau EINEM verkippten Byte im CBOR-Rumpf.
///
/// Das Exact-Object-Praefix bleibt unangetastet: die Bytes sind damit
/// weiterhin ein Archivobjekt im Sinne von `design.md` §11.4 und muessen als
/// Quarantaenefall mit Grund `malformed` erscheinen, nicht als Beiwerk.
#[must_use]
pub fn eip_with_one_mutated_body_byte() -> Vec<u8> {
    let (_, eip) = signed_entry_package();
    let mut mutated = eip.clone();
    mutated[MUTATED_EIP_BODY_OFFSET_V1] ^= 0x01;

    assert_eq!(
        mutated.len(),
        eip.len(),
        "the mutation must not change the byte length"
    );
    assert_eq!(
        mutated
            .iter()
            .zip(eip.iter())
            .filter(|(left, right)| left != right)
            .count(),
        1,
        "exactly one byte must differ"
    );
    assert!(
        mutated.starts_with(&EIP_PREFIX_V1),
        "the mutation must leave the exact object prefix intact"
    );
    let error = ea_format::decode_exact_object(&mutated)
        .expect_err("the mutated entry package must fail to parse");
    assert_eq!(
        error.code(),
        MUTATED_EIP_FORMAT_ERROR_CODE_V1,
        "the pinned mutation offset must keep producing the pinned format error"
    );
    mutated
}

/// Ein signiertes `.eip` mitsamt dem Wert, aus dem das `.eds` gebaut wird.
///
/// Baut genau wie `format_support::valid_eip`, gibt aber zusaetzlich den
/// `EntryPackageV1` heraus, den `valid_eds_from_entry` verlangt.
#[must_use]
pub fn signed_entry_package() -> (EntryPackageV1, Vec<u8>) {
    let ciphertext = vec![0x5a; 16];
    let manifest = format_support::manifest_for_ciphertext(&ciphertext)
        .expect("the fixture manifest must encode");
    let signed =
        SignedManifestV1::new(manifest, &ciphertext).expect("the fixture manifest must sign");
    let signature = signer()
        .sign_record(signed.exact_bytes())
        .expect("the fixture signer must sign");
    let entry = EntryPackageV1::new(signed, ciphertext, signature)
        .expect("the fixture entry package must assemble");
    let eip = encode_entry_package(&entry)
        .expect("the fixture entry package must encode")
        .into_vec();
    (entry, eip)
}

fn signer() -> CoseSigner {
    format_support::signer()
}

/// Die Trust-Objektbytes eines Bestands, in der Reihenfolge des Bestands.
///
/// Klassifiziert wird auch hier am Praefix, nie am Pfad — die Fixtures legen
/// Trust-Objekte bewusst unter wechselnden Hinweisen ab.
#[must_use]
pub fn trust_object_bytes(fixture: &ArchiveFixture) -> Vec<Vec<u8>> {
    fixture
        .blobs()
        .iter()
        .filter(|(_, bytes)| bytes.starts_with(&ETB_PREFIX_V1))
        .map(|(_, bytes)| bytes.clone())
        .collect()
}

/// Die Stelle im `.etb`, an der genau ein Byte verkippt wird, um einen
/// Parse-Fehlschlag zu erzeugen.
///
/// Ein Exact-Objekt ist `[b"EA1\0", typ, version, [], rumpf]`: Byte 0 ist der
/// Arraykopf, die Bytes 1..9 sind das Praefix, Byte 9 ist der Arraykopf des
/// Rumpfes `[subtyp, nutzlast, [signaturen]]`, Byte 10 der Textkopf des
/// Subtyps. Byte 11 ist damit dessen ERSTES Zeichen; `^ 0x01` macht daraus
/// einen anderen Kleinbuchstaben und damit einen unbekannten Subtyp.
///
/// Bewusst eine feste Stelle und keine Suche, genau wie bei
/// [`MUTATED_EIP_BODY_OFFSET_V1`]: eine Suche wuerde bei einer Layoutaenderung
/// stillschweigend eine andere Fehlerklasse treffen.
pub const MUTATED_ETB_SUBTYPE_OFFSET_V1: usize = 11;

/// Der Fehlercode, den [`etb_with_one_mutated_subtype_byte`] erzeugt.
///
/// Ein unbekannter Subtyp ist ein Etikettenfehler, kein Formfehler: die Bytes
/// sind wohlgeformtes CBOR, sie benennen nur eine Objektart, die es nicht gibt.
pub const MUTATED_ETB_FORMAT_ERROR_CODE_V1: &str = "EA-FORMAT-TAG-MISMATCH";

/// Ein `.etb` mit genau EINEM verkippten Byte im Subtyp.
///
/// Das Exact-Object-Praefix bleibt unangetastet: die Bytes sind weiterhin ein
/// Archivobjekt nach `design.md` §11.4 und muessen als Quarantaenefall mit
/// Grund `malformed` erscheinen — und gerade NICHT im Trust-Port.
#[must_use]
pub fn etb_with_one_mutated_subtype_byte(template: &[u8]) -> Vec<u8> {
    assert!(
        template.starts_with(&ETB_PREFIX_V1),
        "the template must be an exact trust object"
    );
    let mut mutated = template.to_vec();
    assert_eq!(
        mutated[9], 0x83,
        "the trust body must be a three-element array"
    );
    assert!(
        (0x61..=0x77).contains(&mutated[10]),
        "the subtype must be a short CBOR text string"
    );
    mutated[MUTATED_ETB_SUBTYPE_OFFSET_V1] ^= 0x01;

    assert_eq!(
        mutated.len(),
        template.len(),
        "the mutation must not change the byte length"
    );
    assert!(
        mutated.starts_with(&ETB_PREFIX_V1),
        "the mutation must leave the exact object prefix intact"
    );
    let error = ea_format::decode_exact_object(&mutated)
        .expect_err("the mutated trust object must fail to parse");
    assert_eq!(
        error.code(),
        MUTATED_ETB_FORMAT_ERROR_CODE_V1,
        "the pinned mutation offset must keep producing the pinned format error"
    );
    mutated
}

/// Ein Bestand, der `count` Abwandlungen EINES Trust-Objekts liefert.
///
/// Erzeugt die Bytes waehrend des Durchlaufs, statt sie alle abzulegen — genau
/// wie `RepeatingSource` in `tests/inventory.rs`. Verkippt werden die letzten
/// drei Bytes, also die rohe Ed25519-Signatur am Ende der COSE-Struktur: das
/// laesst die Bytes parsbar (die Signatur wird beim Parsen nicht kryptografisch
/// geprueft), gibt aber jeder Abwandlung einen eigenen Objekthash.
pub struct VariedTrustObjectSource {
    template: Vec<u8>,
    count: usize,
}

impl VariedTrustObjectSource {
    /// # Panics
    ///
    /// Wenn `template` kein Exact-Trust-Objekt ist oder `count` mehr
    /// Abwandlungen verlangt, als drei Bytes unterscheiden koennen.
    #[must_use]
    pub fn new(template: Vec<u8>, count: usize) -> Self {
        assert!(
            template.starts_with(&ETB_PREFIX_V1),
            "the template must be an exact trust object"
        );
        assert!(
            count <= 1 << 24,
            "three counter bytes distinguish at most 2^24 variants"
        );
        Self { template, count }
    }
}

impl ArchiveSource for VariedTrustObjectSource {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        let tail = self.template.len() - 3;
        let mut bytes = self.template.clone();
        for index in 0..self.count {
            bytes[tail..].copy_from_slice(&[
                self.template[tail] ^ u8::try_from((index >> 16) & 0xff).unwrap(),
                self.template[tail + 1] ^ u8::try_from((index >> 8) & 0xff).unwrap(),
                self.template[tail + 2] ^ u8::try_from(index & 0xff).unwrap(),
            ]);
            visitor(ArchiveBlob::new(ea_archive::REGISTRY_EVENTS_DIR_V1, &bytes))?;
        }
        Ok(())
    }
}

/// Der Zustandsspeicher der Fixtures: laedt genau einen Stand und schreibt nie.
///
/// `verify_trust` verlangt einen [`TrustStateSnapshot`], und der entsteht
/// ausschliesslich ueber [`load_trust_state`]. Der Trust-Support baut dafuer
/// einen eigenen, privaten Speicher; hier steht der kleinste, der die
/// Archivtests bedient. Alle Schreibwege sind bewusst unerreichbar: ein
/// Archivtest darf keinen Zustand fortschreiben.
struct FixtureStateStore {
    key: TrustStateKey,
    record: Option<PersistedTrustRecord>,
}

impl TrustStateStore for FixtureStateStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Unavailable);
        }
        self.record.take().ok_or(StateStoreError::Unavailable)
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
}

/// Der Zeitboden der Fixtures, gleich dem des Trust-Supports.
pub const FIXTURE_TIME_FLOOR_V1: i64 = 1_700_000_000_000;

/// Ein Zustandsstand OHNE gepinnten Registrierungskopf.
///
/// Der Schluessel stammt aus [`trust_support::state_key`], damit die
/// Organisationskennung zum Anker der Fixtures passt — `verify_trust` weist
/// jeden Stand ab, dessen Organisation nicht die des Ankers ist.
#[must_use]
pub fn unpinned_snapshot() -> TrustStateSnapshot {
    let key = trust_support::state_key();
    let mut store = FixtureStateStore {
        key,
        record: Some(PersistedTrustRecord::new(
            17,
            TrustedTimeState::initial(UnixMillis::new(FIXTURE_TIME_FLOOR_V1)),
            None,
        )),
    };
    load_trust_state(&mut store, key).expect("the fixture state store must load exactly once")
}

/// Eine DETERMINISTISCHE Attrappe des schreibenden Ports.
///
/// Sie haelt Bytes, Dateiflushes, Verzeichnisflushes und die Sperre im
/// Speicher. Damit belegt `crates/ea-archive` seinen Staging-Vertrag OHNE
/// Dateisystem — genau wie die Crate selbst kein `std::fs` traegt.
///
/// Der eingespielte Fehlerpunkt ist ein ZAEHLER und kein Schalter: so faellt
/// genau der n-te Flush aus, und der Test kann sagen, WELCHE Stufe nicht
/// getragen hat.
pub struct InMemoryArchiveBackend {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Die LEER angelegten Layoutverzeichnisse.
    ///
    /// Eine Attrappe ohne Dateisystem kennt ein Verzeichnis nur, wenn es
    /// jemand angelegt hat: `format/transformations/` und `recovery-reports/`
    /// tragen nie eine Datei, aus der man sie ableiten koennte. Aufgezeichnet
    /// wird deshalb, was `create_directory_if_absent` anlegt — ein Leser
    /// entsteht erst mit dem ersten Porttest, der ihn braucht.
    directories: Mutex<BTreeSet<String>>,
    synced_files: Mutex<BTreeSet<String>>,
    synced_directories: Mutex<BTreeSet<String>>,
    file_sync_calls: AtomicUsize,
    failing_file_sync_call: Option<usize>,
    /// Ein `Arc`, damit der RAII-Waechter GENAU DIESE Flagge zuruecksetzt.
    /// Ein eigener Zustand im Waechter waere eine zweite Wahrheit, und der
    /// zweite Sperrversuch nach `drop` schlage dann falsch fehl.
    locked: Arc<AtomicBool>,
}

impl InMemoryArchiveBackend {
    /// Eine Attrappe, deren Flushes alle tragen.
    #[must_use]
    pub fn new() -> Self {
        Self::with_failing_file_sync(None)
    }

    /// Eine Attrappe, deren `failing`-ter Dateiflush fehlschlaegt (1-basiert).
    #[must_use]
    pub fn with_failing_file_sync(failing: Option<usize>) -> Self {
        Self {
            files: Mutex::new(BTreeMap::new()),
            directories: Mutex::new(BTreeSet::new()),
            synced_files: Mutex::new(BTreeSet::new()),
            synced_directories: Mutex::new(BTreeSet::new()),
            file_sync_calls: AtomicUsize::new(0),
            failing_file_sync_call: failing,
            locked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Traegt die Attrappe diese Adresse?
    #[must_use]
    pub fn exists(&self, relative: &str) -> bool {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(relative)
    }

    /// Die Bytes unter dieser Adresse.
    #[must_use]
    pub fn read(&self, relative: &str) -> Option<Vec<u8>> {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(relative)
            .cloned()
    }

    /// Wurde diese Datei geflusht?
    #[must_use]
    pub fn file_synced(&self, relative: &str) -> bool {
        self.synced_files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(relative)
    }

    /// Wurde dieses Verzeichnis geflusht?
    #[must_use]
    pub fn directory_synced(&self, directory: &str) -> bool {
        self.synced_directories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(directory)
    }

    fn insert_if_absent(
        &self,
        relative: &str,
        bytes: &[u8],
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        let mut files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
        match files.get(relative) {
            Some(existing) if existing == bytes => Ok(()),
            Some(_) => Err(ea_archive::ArchiveBackendError::ByteConflict),
            None => {
                files.insert(relative.to_owned(), bytes.to_vec());
                Ok(())
            }
        }
    }
}

impl Default for InMemoryArchiveBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Gibt die Sperre der Attrappe frei.
struct InMemoryLockRelease {
    locked: Arc<AtomicBool>,
}

impl ea_archive::WriterLockRelease for InMemoryLockRelease {
    fn release(&self) {
        self.locked.store(false, Ordering::SeqCst);
    }
}

impl ea_archive::ArchiveBackend for InMemoryArchiveBackend {
    fn create_if_absent(
        &self,
        relative: &ea_archive::ArchivePath,
        bytes: &ExactObjectBytes,
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        self.insert_if_absent(relative.as_str(), bytes.as_bytes())
    }

    fn create_non_object_if_absent(
        &self,
        relative: &ea_archive::ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        self.insert_if_absent(relative.as_str(), bytes)
    }

    fn staged_paths(&self) -> Result<Vec<String>, ea_archive::ArchiveBackendError> {
        Ok(self
            .files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .filter(|relative| ea_archive::is_staging_path(relative))
            .cloned()
            .collect())
    }

    /// Entfernt eine Adresse, wenn sie belegt ist.
    ///
    /// Die Spiegelseite von `create_if_absent` in dieser Attrappe: eine
    /// fehlende Adresse ist ein Erfolg, eine belegte verschwindet ganz.
    fn remove_if_present(
        &self,
        relative: &ea_archive::ArchivePath,
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(relative.as_str());
        Ok(())
    }

    fn sync_file(
        &self,
        relative: &ea_archive::ArchivePath,
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        let call = self.file_sync_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.failing_file_sync_call == Some(call) {
            return Err(ea_archive::ArchiveBackendError::FlushFailed);
        }
        if !self.exists(relative.as_str()) {
            return Err(ea_archive::ArchiveBackendError::Io);
        }
        self.synced_files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(relative.as_str().to_owned());
        Ok(())
    }

    fn sync_directory(
        &self,
        relative: &ea_archive::ArchivePath,
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        self.synced_directories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(relative.directory().to_owned());
        Ok(())
    }

    fn atomic_rename_same_fs(
        &self,
        from: &ea_archive::ArchivePath,
        to: &ea_archive::ArchivePath,
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        // Die Attrappe kennt genau EIN Dateisystem, also ist jeder Rename
        // dateisystemintern. Der Fall verschiedener Dateisysteme gehoert dem
        // Wirtbackend und wird dort geprueft.
        //
        // NICHT KLOBBERND, genau wie der Wirt: eine bestehende Zieladresse
        // MUSS bytegleich sein, sonst ist es ein Bytekonflikt. Waere die
        // Attrappe hier grosszuegiger als der Wirt, pruefte
        // `transaction_stages.rs` den Vertrag des Ports nicht mehr, sondern
        // die Nachsicht der Attrappe.
        let mut files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes = files
            .remove(from.as_str())
            .ok_or(ea_archive::ArchiveBackendError::Io)?;
        match files.get(to.as_str()) {
            Some(existing) if existing != &bytes => {
                // Die Quelladresse bleibt liegen: sie ist ein
                // Gesundheitsbefund (temporaere Datei) und keine
                // Veroeffentlichung.
                files.insert(from.as_str().to_owned(), bytes);
                Err(ea_archive::ArchiveBackendError::ByteConflict)
            }
            _ => {
                files.insert(to.as_str().to_owned(), bytes);
                Ok(())
            }
        }
    }

    fn create_directory_if_absent(
        &self,
        directory: &str,
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        // Dieselbe Ablehnung wie im Wirt: waere die Attrappe grosszuegiger,
        // pruefte ein Test die Attrappe und nicht den Port.
        if !ea_archive::LAYOUT_PATHS_V1.contains(&directory) || !directory.ends_with('/') {
            return Err(ea_archive::ArchiveBackendError::Path);
        }
        self.directories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(directory.to_owned());
        Ok(())
    }

    fn acquire_writer_lock(
        &self,
    ) -> Result<ea_archive::WriterLock, ea_archive::ArchiveBackendError> {
        // Der Waechter haelt eine geteilte Referenz auf DIESE Flagge, damit
        // `drop` sie tatsaechlich freigibt.
        if self.locked.swap(true, Ordering::SeqCst) {
            return Err(ea_archive::ArchiveBackendError::AlreadyLocked);
        }
        Ok(ea_archive::WriterLock::new(Arc::new(InMemoryLockRelease {
            locked: Arc::clone(&self.locked),
        })))
    }
}
