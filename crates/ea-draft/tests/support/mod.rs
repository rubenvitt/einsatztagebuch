//! Die Fixture der Entwurfstests.
//!
//! Jede Fixture legt ihre EIGENE temporaere Wurzel an — nach dem Muster von
//! `tools/xtask/tests/stage_gate.rs`:29-44, das Prozesskennung und Nanosekunden
//! mischt — und nimmt zusaetzlich eine prozessweite Sperre, damit die Tests
//! sich selbst serialisieren und kein `--test-threads`-Flag brauchen.

// Die Fixture wird von DREI Testzielen eingebunden, und keines braucht ihre
// ganze Flaeche. Beide Erlaubnisse gelten deshalb nur hier und nicht in der
// Crate.
#![allow(dead_code, unused_imports)]

// Die ECHTE Registry-Linie der Fixture. Sie liegt hier und nicht in den
// einzelnen Testzielen, weil `support` sie braucht und ein `#[path]` in jedem
// Ziel die drei Ziele aus Task 6 mitaendern muesste, die davon nichts wissen.
#[path = "../../../ea-trust/tests/support/mod.rs"]
mod trust_support;

use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use ea_crypto::{AEAD_NONCE_SIZE, CanonicalPublicCoseKey, SecretBytes, aead_open};
use ea_draft::{
    AutosaveDraftRepository, CsvImporter, DiscardFaultPoint, DiscardPhase, DiscardService,
    DraftError, IncidentNumberRegister, MasterDataRepository, OperatorProfileRepository,
    PreparedFinalizationMarker, RestartState,
};
use ea_format::{
    CertificateKindV1, ImportReportV1, ImportSourceKindV1, KeyProtectionProfileV1, OperatorRoleV1,
};
use ea_key_provider::{InMemoryKeyProvider, KeyHandle, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose,
};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError,
    TrustStateKey, TrustStateStore, prepare_local_time, select_registry_head,
    verify_registry_candidate,
};
use ea_types::{
    ChainSequence, DeviceId, Hash32, Id16, KeyThumbprint, ObjectHash, OperatorSubjectId,
    OrganizationId, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};

use self::trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

pub use ea_draft::DraftRepository;

/// Die EINGEFRORENE Bedienerprofil-Momentaufnahme dieser Fixture.
///
/// Die sechs Werte stehen in genau der Reihenfolge, in der Stufe 1 sie kodiert
/// (`crates/ea-schema/src/encode.rs`:429-445). Sie sind synthetisch und
/// unveraenderlich: Task 11 rechnet die Profilzusage gegen diese Zeile nach,
/// und ein wandernder Wert machte den Nachweis wertlos.
const FIXTURE_ORGANIZATION_ID: [u8; 16] = [0x11; 16];
const FIXTURE_OPERATOR_SUBJECT_ID: [u8; 16] = [0x22; 16];
const FIXTURE_DISPLAY_NAME: &str = "Ada Lovelace";
const FIXTURE_FUNCTION_LABEL: &str = "Einsatzleitung";
const FIXTURE_PROFILE_COMMITMENT_SALT: [u8; 32] = [0x33; 32];
const FIXTURE_OPERATOR_BINDING_OBJECT_HASH: [u8; 32] = [0x44; 32];

/// Der Startwert des In-Prozess-Providers. Er ist zugleich die Kontoinstanz.
const FIXTURE_PROVIDER_SEED: [u8; 32] = [0x5a; 32];

const DATABASE_FILE: &str = "writer.sqlite3";

/// Die prozessweite Sperre.
///
/// Der Anker des Briefs (`tools/xtask/tests/stage_gate.rs`:29-44) traegt die
/// Wurzelbildung, keine Sperre; die Sperre ist die AUSGESPROCHENE Absicht des
/// Briefs — die Tests serialisieren sich selbst — und steht deshalb hier.
static HARNESS_LOCK: Mutex<()> = Mutex::new(());

fn take_harness_lock() -> MutexGuard<'static, ()> {
    HARNESS_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn fixture_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("ea-draft-{label}-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

/// Oeffnet die verschluesselte Datenbank unter `root`.
///
/// Der Datenbankschluessel entsteht IM Schluesselspeicher und wird nie
/// ausserhalb gehalten; `KeyProvider::generate` verlangt das erreichte
/// Schutzprofil ausdruecklich und weicht nie aus.
fn open_database(root: &Path, provider: &InMemoryKeyProvider) -> Arc<EncryptedDatabase> {
    let handle = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .expect("der In-Prozess-Provider erreicht OsWrapped");
    Arc::new(
        EncryptedDatabase::open(&root.join(DATABASE_FILE), provider, &handle)
            .expect("die verschluesselte Datenbank muss sich oeffnen lassen"),
    )
}

/// Die geoeffnete Fixture.
pub struct DraftHarness {
    /// Die prozessweite Sperre. `None`, wenn sie beim umschliessenden
    /// [`ClosedDraftHarness`] liegt — ein zweites Nehmen aus demselben Faden
    /// waere ein Selbstblockieren.
    _lock: Option<MutexGuard<'static, ()>>,
    root: PathBuf,
    provider: Arc<InMemoryKeyProvider>,
    database: Arc<EncryptedDatabase>,
    /// Die Ablage. Oeffentliches Feld, weil die Tests sie unmittelbar rufen.
    pub repo: AutosaveDraftRepository,
}

impl DraftHarness {
    #[must_use]
    pub fn new() -> Self {
        Self::open("plain", take_harness_lock(), None)
    }

    /// Die Variante, die EINE Profilzeile aus der eingefrorenen
    /// Momentaufnahme setzt.
    ///
    /// Die Zeile wird mit rohem SQL gesetzt und nicht ueber
    /// `OperatorProfileRepository`: dort gibt es keinen Schreibarm, und genau
    /// das soll so bleiben.
    #[must_use]
    pub fn with_seeded_operator_profile() -> Self {
        let harness = Self::open("profile", take_harness_lock(), None);
        harness
            .database
            .execute(
                "INSERT INTO operator_profile (singleton, organization_id, \
                 operator_subject_id, display_name, function_label, profile_commitment_salt, \
                 operator_binding_object_hash) VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    StoreValue::Blob(FIXTURE_ORGANIZATION_ID.to_vec()),
                    StoreValue::Blob(FIXTURE_OPERATOR_SUBJECT_ID.to_vec()),
                    StoreValue::Text(FIXTURE_DISPLAY_NAME.to_owned()),
                    StoreValue::Text(FIXTURE_FUNCTION_LABEL.to_owned()),
                    StoreValue::Blob(FIXTURE_PROFILE_COMMITMENT_SALT.to_vec()),
                    StoreValue::Blob(FIXTURE_OPERATOR_BINDING_OBJECT_HASH.to_vec()),
                ],
            )
            .expect("die Profilzeile muss sich setzen lassen");
        harness
    }

    fn open(
        label: &str,
        lock: MutexGuard<'static, ()>,
        existing: Option<(PathBuf, Arc<InMemoryKeyProvider>)>,
    ) -> Self {
        let (root, provider) = existing.unwrap_or_else(|| {
            (
                fixture_root(label),
                Arc::new(InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED)),
            )
        });
        let database = open_database(&root, &provider);
        let repo = AutosaveDraftRepository::new(
            Arc::clone(&database),
            Arc::clone(&provider) as Arc<dyn KeyProvider>,
        );
        Self {
            _lock: Some(lock),
            root,
            provider,
            database,
            repo,
        }
    }

    /// Baut dieselbe Fixture NEU, ohne die Sperre erneut zu nehmen.
    fn reopened(root: PathBuf, provider: Arc<InMemoryKeyProvider>) -> Self {
        let database = open_database(&root, &provider);
        let repo = AutosaveDraftRepository::new(
            Arc::clone(&database),
            Arc::clone(&provider) as Arc<dyn KeyProvider>,
        );
        Self {
            _lock: None,
            root,
            provider,
            database,
            repo,
        }
    }

    /// Schliesst die Ablage.
    ///
    /// Nimmt `self` und gibt eine geschlossene Fixture zurueck: ein Feld aus
    /// einem noch benutzten Wert herauszubewegen ist hier nicht moeglich, und
    /// nur ein vollstaendiges Fallenlassen schliesst die SQLite-Verbindung
    /// wirklich.
    #[must_use]
    pub fn close_repo(self) -> ClosedDraftHarness {
        let Self {
            _lock,
            root,
            provider,
            database,
            repo,
        } = self;
        drop(repo);
        drop(database);
        ClosedDraftHarness {
            _lock,
            root,
            provider,
            reopened: None,
            raw: OnceLock::new(),
        }
    }

    /// Die Zahl der Zeilen der Entwurfstabelle.
    #[must_use]
    pub fn active_draft_row_count(&self) -> u64 {
        let row = self
            .database
            .query_row("SELECT count(*) FROM draft", &[] as &[StoreValue])
            .expect("die Entwurfstabelle muss zaehlbar sein")
            .expect("count(*) liefert immer eine Zeile");
        u64::try_from(row.integer(0).unwrap()).unwrap()
    }

    /// Das Register verbrauchter Einsatznummern.
    #[must_use]
    pub fn incident_number_register(&self) -> IncidentNumberRegister {
        IncidentNumberRegister::new(Arc::clone(&self.database))
    }

    /// Die NUR LESENDE Ablage der Profilzeile.
    #[must_use]
    pub fn operator_profile_repo(&self) -> OperatorProfileRepository {
        OperatorProfileRepository::new(Arc::clone(&self.database))
    }

    /// Die Organisation der Fixture.
    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        OrganizationId::try_from(FIXTURE_ORGANIZATION_ID.as_slice()).unwrap()
    }

    /// Das Subjekt der eingefrorenen Momentaufnahme.
    #[must_use]
    pub fn operator_subject_id(&self) -> OperatorSubjectId {
        OperatorSubjectId::try_from(FIXTURE_OPERATOR_SUBJECT_ID.as_slice()).unwrap()
    }

    /// Der Bindungsobjekthash, den die gesetzte Profilzeile traegt.
    #[must_use]
    pub fn bound_operator_binding_object_hash(&self) -> ObjectHash {
        ObjectHash::try_from(FIXTURE_OPERATOR_BINDING_OBJECT_HASH.as_slice()).unwrap()
    }

    /// Die unberuehrten Bytes der Hauptdatei.
    #[must_use]
    pub fn raw_database_bytes(&self) -> Vec<u8> {
        fs::read(self.root.join(DATABASE_FILE)).expect("die Hauptdatei muss lesbar sein")
    }

    /// Die gespeicherte Nutzlastspalte — DURCH SQLCipher hindurch gelesen.
    ///
    /// Sie isoliert die ZWEITE Verschluesselungsschicht. Die Rohbytes der Datei
    /// sagen ueber sie nichts: sie liegen ohnehin unter SQLCipher, und ein
    /// Entwurf, der unverschluesselt in der Spalte steht, bliebe darin
    /// unsichtbar. Erst diese Spalte macht die AEAD des Entwurfs messbar.
    #[must_use]
    pub fn stored_payload_ciphertext(&self) -> Vec<u8> {
        let row = self
            .database
            .query_row(
                "SELECT payload_ciphertext FROM draft WHERE singleton = 0",
                &[] as &[StoreValue],
            )
            .expect("die Entwurfszeile muss lesbar sein")
            .expect("nach einer Speicherung liegt genau eine Entwurfszeile");
        row.blob(0).unwrap().to_vec()
    }
}

/// Die geschlossene Fixture — dieselbe Wurzel, derselbe Schluesselspeicher.
pub struct ClosedDraftHarness {
    _lock: Option<MutexGuard<'static, ()>>,
    root: PathBuf,
    provider: Arc<InMemoryKeyProvider>,
    reopened: Option<DraftHarness>,
    raw: OnceLock<Vec<u8>>,
}

impl ClosedDraftHarness {
    /// Oeffnet dieselbe Datenbank auf derselben Wurzel erneut.
    pub fn reopen(&mut self) -> &DraftHarness {
        self.reopened = Some(DraftHarness::reopened(
            self.root.clone(),
            Arc::clone(&self.provider),
        ));
        self.reopened.as_ref().unwrap()
    }

    /// Die Zahl der Zeilen der Entwurfstabelle — nach dem Wiederoeffnen.
    #[must_use]
    pub fn active_draft_row_count(&self) -> u64 {
        self.reopened
            .as_ref()
            .expect("active_draft_row_count verlangt eine wiedergeoeffnete Datenbank")
            .active_draft_row_count()
    }

    /// Die gespeicherte Nutzlastspalte — nach dem Wiederoeffnen.
    #[must_use]
    pub fn stored_payload_ciphertext(&self) -> Vec<u8> {
        self.reopened
            .as_ref()
            .expect("stored_payload_ciphertext verlangt eine wiedergeoeffnete Datenbank")
            .stored_payload_ciphertext()
    }

    /// Die unberuehrten Bytes der Hauptdatei.
    ///
    /// Einmal gelesen und danach gehalten, weil der Brief eine Ausleihe
    /// verlangt und `&self` kein Feld beschreiben darf.
    #[must_use]
    pub fn raw_database_bytes(&self) -> &[u8] {
        self.raw.get_or_init(|| {
            fs::read(self.root.join(DATABASE_FILE)).expect("die Hauptdatei muss lesbar sein")
        })
    }
}

// ---------------------------------------------------------------------------
// Task 7 — die Fixture der Verwerfens- und Neustartpruefung
// ---------------------------------------------------------------------------

/// Die Zeit des Head, gegen die dieser Task jede Gueltigkeit bewertet.
///
/// Sie liegt bewusst WEIT hinter [`STALE_HEAD_NOW_MS`], damit ein Nachweis, der
/// gegen den frueheren Stand ausgestellt wurde, gegen diesen Stand ECHT
/// abgelaufen ist — `issued_at + MAX_INACTIVITY_MS` liegt dann in der
/// Vergangenheit. Ohne diesen Abstand liesse sich „nicht frisch" nur ueber
/// `invalidate_on_lock` herstellen, und die Zeitbedingung von
/// `OperatorSessionProof::is_valid_for` bliebe ungemessen.
const HEAD_NOW_MS: i64 = 1_000_000;
/// Die Zeit des frueheren Head, aus dem der abgelaufene Nachweis stammt.
const STALE_HEAD_NOW_MS: i64 = 1_000;
const FIXTURE_NOT_AFTER_MS: i64 = 10_000_000;
const PROPOSED_SEQUENCE: u64 = 30;
const BINDING_MARKER: u8 = 0x71;

/// Der Bedienerinstanzschluessel der Fixture — ein ECHTES Ed25519-Paar.
const INSTANCE_SECRET: [u8; 32] = [
    0x4a, 0x1c, 0x2e, 0x93, 0x77, 0x05, 0xbb, 0x61, 0x18, 0x8f, 0xd2, 0x40, 0x36, 0xa7, 0x5c, 0xe1,
    0x09, 0x94, 0x6d, 0x3b, 0xcf, 0x82, 0x17, 0x50, 0xe4, 0x2a, 0x68, 0xd9, 0x0b, 0x73, 0xf6, 0x84,
];

/// Der Inhalt, der den ORIGINALENTWURF von einem leeren unterscheidbar macht.
///
/// `RestartState::OriginalDraftUnchanged` und `RestartState::NewBlankDraft`
/// sind am Entwurf ablesbar, weil der eine Inhalt traegt und der andere nicht.
/// Ein LEERER Originalentwurf waere von einem frischen leeren Entwurf
/// ununterscheidbar — genau das ist die Zusage des unwiderruflichen Verwerfens
/// —, und deshalb heisst die Fixture `with_nonempty_draft`.
const ORIGINAL_NOTES: &str = "ORIGINALENTWURF-KANARIENVOGEL";

/// Die Nebendateien, die SQLite neben der Hauptdatei fuehrt.
const DATABASE_SIDECARS: [&str; 2] = ["writer.sqlite3-wal", "writer.sqlite3-shm"];
/// Die Sperrdatei von [`ea_draft::DraftLock`] neben der Datenbank.
const LOCK_FILE: &str = "writer.sqlite3.draft-lock";

struct ModelStore {
    key: TrustStateKey,
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: RegistryHeadPin,
}

impl TrustStateStore for ModelStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            Some(self.pinned_head),
        ))
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
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || expected_revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        self.revision += 1;
        self.trusted_time = commit.next_trusted_time().clone();
        self.pinned_head = *commit.next_head();
        Ok(PersistedTrustRecord::new(
            self.revision,
            self.trusted_time.clone(),
            Some(self.pinned_head),
        ))
    }
}

fn instance_signing_key() -> SigningKey {
    SigningKey::from_bytes(&INSTANCE_SECRET)
}

fn instance_public_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(instance_signing_key().verifying_key().to_bytes())
        .expect("der Instanzschluessel der Fixture ist ein gueltiger Ed25519-Schluessel")
}

fn head_options(effective_from: u64, valid_through: u64) -> HeadOptions {
    HeadOptions {
        effective_from: Some(effective_from),
        valid_through: Some(valid_through),
        not_after: UnixMillis::new(FIXTURE_NOT_AFTER_MS),
        ..HeadOptions::default()
    }
}

/// Baut die Registry-Linie und nennt die Bedienerbindung.
fn build_line() -> (RegistryLineBuilder, ObjectHash) {
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        head_options(1, 10),
    );
    let writer = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        head_options(11, 20),
    );
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer
                .direct_object_hash
                .expect("das Writer-Zertifikat der Fixture ist ein direktes Ziel"),
            role: OperatorRoleV1::Writer,
            marker: BINDING_MARKER,
            effective_from: None,
        },
        HeadOptions {
            binding_instance_key_thumbprint_override: Some(KeyThumbprint::from(
                Hash32::try_from(instance_public_key().thumbprint().as_bytes().as_slice())
                    .expect("ein Thumbprint ist 32 Byte lang"),
            )),
            ..head_options(21, 100)
        },
    );
    let binding_object_hash = binding
        .direct_object_hash
        .expect("die Bedienerbindung der Fixture ist ein direktes Ziel");
    (line, binding_object_hash)
}

/// Waehlt einen ECHTEN Head, dessen `PreexistingEffectiveNow` genau `now_ms`
/// ist.
///
/// Die Zeit ist der EINZIGE Unterschied zwischen dem Head, gegen den geprueft
/// wird, und dem, aus dem der abgelaufene Nachweis stammt.
fn selected_registry_head_at(now_ms: i64) -> SelectedRegistryHead {
    let (line, _) = build_line();
    let head_index = line.heads().len() - 1;
    let head = line.heads()[head_index];
    let key = trust_support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(now_ms));
    let trust = line.verified_with_record(Pin::Head(head_index), 17, trusted_time.clone(), key);
    let candidate =
        verify_registry_candidate(&trust, ChainSequence::new(PROPOSED_SEQUENCE)).unwrap();
    let mut store = ModelStore {
        key,
        revision: 17,
        trusted_time,
        pinned_head: RegistryHeadPin::new(head.version, head.object_hash),
    };
    let local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(now_ms), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
    else {
        panic!("die Fixture muss ihren eigenen aktuellen Head waehlen");
    };
    selected
}

struct FakeAccount {
    binding_hash: Hash32,
}

impl OsAccountProvider for FakeAccount {
    fn os_account_binding_hash(
        &self,
        _organization_id: OrganizationId,
        _device_id: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(self.binding_hash)
    }

    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(Some(instance_public_key()))
    }
}

/// Die Attrappe der nativen Praesenzpruefung — AUSSCHLIESSLICH die zwei
/// Plattformhaken; Kontoabgleich, Instanzschluesselpruefung und Ausstellung
/// liegen im Standardkoerper von `OperatorAuthenticator::reauthenticate`.
struct FakeAuthenticator {
    bound: BoundOperator,
}

impl OperatorAuthenticator for FakeAuthenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }

    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        Ok(instance_signing_key().sign(challenge).to_bytes())
    }
}

/// Stellt einen ECHTEN Praesenznachweis fuer `purpose` gegen `head` aus.
fn issue_proof(head: &SelectedRegistryHead, purpose: ReauthPurpose) -> OperatorSessionProof {
    let (_, binding_object_hash) = build_line();
    let bound = BoundOperator::resolve(head, binding_object_hash)
        .expect("die Bindung der Fixture ist an der gewaehlten Sequenz aktiv");
    let authenticator = FakeAuthenticator { bound };
    let account: Box<dyn OsAccountProvider> = Box::new(FakeAccount {
        binding_hash: trust_support::hash32(BINDING_MARKER.wrapping_add(2)),
    });
    authenticator
        .reauthenticate(account, purpose)
        .expect("die Fixture meldet den gebundenen Bediener wieder an")
}

/// Der ORIGINALENTWURF, wie er vor dem Verwerfen dalag.
///
/// Die Fixture haelt Chiffrat, Nonce und Griff — NICHT den Schluessel. Nur so
/// ist „kein entschluesselbarer `draftDEK` bleibt zurueck" ueberhaupt messbar:
/// die Fixture versucht nach dem Verwerfen, GENAU diese Bytes zu oeffnen.
struct OriginalDraft {
    draft_id: Id16,
    revision: u64,
    ciphertext: Vec<u8>,
    nonce: [u8; AEAD_NONCE_SIZE],
    dek: KeyHandle,
}

/// Die geoeffnete Datenbank samt Ablage.
struct OpenStore {
    database: Arc<EncryptedDatabase>,
    repo: Arc<AutosaveDraftRepository>,
}

/// Die Fixture der Verwerfens- und Neustartpruefung.
///
/// Sie liegt hinter einem [`RefCell`], weil ein Neustart die Datenbank
/// SCHLIESSEN und neu oeffnen muss und die Briefform `restart_and_resume` auch
/// auf einer nicht-`mut` Bindung ruft.
pub struct DiscardHarness {
    _lock: MutexGuard<'static, ()>,
    root: PathBuf,
    provider: Arc<InMemoryKeyProvider>,
    database_key: KeyHandle,
    head: SelectedRegistryHead,
    stale_head: SelectedRegistryHead,
    original: OriginalDraft,
    /// Die Momentaufnahme der Datenbankdateien VOR dem Verwerfen — die
    /// simulierte Sicherung. Der Schluesselspeicher ist ausdruecklich NICHT
    /// darin: ein geraetegebundener Eintrag ist aus der gewoehnlichen
    /// Anwendungs- und Systemsicherung ausgenommen (`design.md`:428, :1491).
    backup: Vec<(String, Vec<u8>)>,
    open: RefCell<Option<OpenStore>>,
}

impl DraftHarness {
    /// Saet EINEN gespeicherten Entwurf MIT Inhalt und haelt eine Kopie der
    /// Datenbankdateien als simulierte Sicherung.
    ///
    /// Gibt eine [`DiscardHarness`] zurueck und nicht wieder eine
    /// [`DraftHarness`]: nur ein Traeger, der die Datenbank vollstaendig
    /// FALLEN lassen kann, kann einen Neustart und eine
    /// Sicherungsrueckspielung ueberhaupt darstellen.
    #[must_use]
    pub fn with_nonempty_draft() -> DiscardHarness {
        DiscardHarness::new()
    }
}

impl DiscardHarness {
    fn new() -> Self {
        let lock = take_harness_lock();
        let root = fixture_root("discard");
        let provider = Arc::new(InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED));
        let database_key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");

        let open = Self::open_store(&root, &provider, &database_key);
        let draft = open.repo.load_or_create().unwrap();
        let saved = open.repo.save(draft.with_notes(ORIGINAL_NOTES)).unwrap();
        let (ciphertext, nonce) = stored_payload(&open.database);
        let original = OriginalDraft {
            draft_id: saved.draft_id(),
            revision: saved.revision(),
            ciphertext,
            nonce,
            dek: open.repo.draft_dek_handle(&saved).unwrap(),
        };
        drop(open);

        // Die Sicherung wird an der GESCHLOSSENEN Datenbank genommen. Eine
        // Kopie einer offenen WAL-Datenbank waere ein halber Zustand, und der
        // Test wollte dann nicht das Verwerfen messen, sondern die Kopie.
        let backup = capture_database_files(&root);
        let open = Self::open_store(&root, &provider, &database_key);

        Self {
            _lock: lock,
            root,
            provider,
            database_key,
            head: selected_registry_head_at(HEAD_NOW_MS),
            stale_head: selected_registry_head_at(STALE_HEAD_NOW_MS),
            original,
            backup,
            open: RefCell::new(Some(open)),
        }
    }

    fn open_store(
        root: &Path,
        provider: &Arc<InMemoryKeyProvider>,
        database_key: &KeyHandle,
    ) -> OpenStore {
        // DERSELBE Griff, nicht ein neu erzeugter: ein zweites `generate`
        // schriebe frisches Material an dieselbe Adresse.
        let database = Arc::new(
            EncryptedDatabase::open(&root.join(DATABASE_FILE), provider.as_ref(), database_key)
                .expect("dieselbe Datenbank muss sich mit demselben Schluessel wieder oeffnen"),
        );
        let repo = Arc::new(AutosaveDraftRepository::new(
            Arc::clone(&database),
            Arc::clone(provider) as Arc<dyn KeyProvider>,
        ));
        OpenStore { database, repo }
    }

    fn repo(&self) -> Arc<dyn DraftRepository> {
        let borrowed = self.open.borrow();
        let open = borrowed
            .as_ref()
            .expect("die Fixture haelt eine geoeffnete Datenbank");
        Arc::clone(&open.repo) as Arc<dyn DraftRepository>
    }

    /// Schliesst die Datenbank vollstaendig — beide Halter des `Arc` fallen.
    fn close(&self) {
        *self.open.borrow_mut() = None;
    }

    fn reopen(&self) {
        self.close();
        *self.open.borrow_mut() = Some(Self::open_store(
            &self.root,
            &self.provider,
            &self.database_key,
        ));
    }

    /// Der Dienst unter Pruefung.
    ///
    /// Er BORGT die Zeit des gewaehlten Head und haelt keine Momentaufnahme
    /// davon, und er ist an die ECHTE Bindung der Fixture gebaut — dieselbe,
    /// gegen die `issue_proof` jeden Nachweis ausstellt. Sie kommt aus
    /// `build_line()` und ausdruecklich NICHT aus
    /// [`FIXTURE_OPERATOR_BINDING_OBJECT_HASH`]: der eingefrorene Wert der
    /// Profilzeile ist nicht der Bindungsobjekthash der gebauten Linie, und ihn
    /// hier einzusetzen liesse JEDEN Nachweis der Fixture an der
    /// Bindungspruefung scheitern — die vier Briefzusicherungen ueber
    /// `EA-DRAFT-REAUTH-REQUIRED`, `EA-DRAFT-REAUTH-PURPOSE-MISMATCH` und
    /// `EA-DRAFT-PREPARED-FINALIZATION-PRESENT` maessen dann nicht mehr, was
    /// sie behaupten.
    #[must_use]
    pub fn discard_service(&self) -> DiscardService<'_> {
        self.discard_service_for_binding(self.bound_binding_object_hash())
    }

    /// Der ECHTE Bindungsobjekthash der Fixture.
    #[must_use]
    pub fn bound_binding_object_hash(&self) -> ObjectHash {
        let (_, binding_object_hash) = build_line();
        binding_object_hash
    }

    /// Ein Bindungsobjekthash, der zu KEINER Bindung dieser Linie gehoert.
    ///
    /// Er ist die FREMDE Bindung der Bindungspruefung: ein Dienst, der fuer ihn
    /// handelt, darf keinen Nachweis der Fixture annehmen, so frisch und so
    /// zweckgleich er auch sei.
    #[must_use]
    pub fn foreign_binding_object_hash(&self) -> ObjectHash {
        ObjectHash::try_from([0xf0; 32].as_slice()).unwrap()
    }

    /// Derselbe Dienst, aber gebaut FUER `binding_object_hash`.
    #[must_use]
    pub fn discard_service_for_binding(
        &self,
        binding_object_hash: ObjectHash,
    ) -> DiscardService<'_> {
        DiscardService::new(
            self.repo(),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            binding_object_hash,
            self.head.preexisting_effective_now(),
        )
    }

    /// Ein ECHTER, FRISCHER Praesenznachweis fuer `purpose`.
    #[must_use]
    pub fn proof_for(&self, purpose: ReauthPurpose) -> OperatorSessionProof {
        issue_proof(&self.head, purpose)
    }

    /// Ein ECHTER, aber ABGELAUFENER Nachweis fuer `DiscardDraft`.
    ///
    /// Er ist gegen den frueheren Head ausgestellt; sein Fuenfminutenfenster
    /// endet lange vor der Zeit des gewaehlten Head. Das ist der Fall, den
    /// `OperatorAuthenticator::reauthenticate` ausdruecklich beschreibt: ein
    /// `Ok` heisst nicht „der Nachweis gilt jetzt".
    #[must_use]
    pub fn expired_proof(&self) -> OperatorSessionProof {
        issue_proof(&self.stale_head, ReauthPurpose::DiscardDraft)
    }

    /// Fuehrt ein Verwerfen, das an GENAU `point` abbricht.
    pub fn discard_with_fault(&mut self, point: DiscardFaultPoint) -> Result<(), DraftError> {
        let outcome = self
            .discard_service()
            .begin_discard_interrupted_at(self.proof_for(ReauthPurpose::DiscardDraft), point);
        if point == DiscardFaultPoint::BackupRestoreAfterKeyDeletion {
            // Der Punkt IST die Rueckspielung: der Schluessel ist fort, und der
            // Bediener legt die Datenbankdateien seiner Sicherung zurueck.
            self.put_back_backup();
        }
        outcome
    }

    /// Fuehrt ein SAUBERES Verwerfen, das nach genau `phase` haelt.
    pub fn discard_up_to(&mut self, phase: DiscardPhase) -> Result<(), DraftError> {
        let point = match phase {
            DiscardPhase::Editable => DiscardFaultPoint::BeforeIntentCommit,
            DiscardPhase::IntentDurable => DiscardFaultPoint::AfterIntentCommit,
            DiscardPhase::KeyAbsent => DiscardFaultPoint::AfterAbsenceConfirmation,
            DiscardPhase::DraftRemoved => DiscardFaultPoint::AfterDraftRemoval,
        };
        self.discard_service()
            .begin_discard_interrupted_at(self.proof_for(ReauthPurpose::DiscardDraft), point)
    }

    /// Oeffnet die Ablage NEU und laeuft den Neustartpfad.
    pub fn restart_and_resume(&self) -> Result<RestartState, DraftError> {
        let proof = self.proof_for(ReauthPurpose::DiscardDraft);
        self.restart_and_resume_with(&proof)
    }

    /// Derselbe Neustartpfad, aber mit einem VORGEGEBENEN Nachweis.
    pub fn restart_and_resume_with(
        &self,
        proof: &OperatorSessionProof,
    ) -> Result<RestartState, DraftError> {
        self.reopen();
        self.discard_service().resume_after_restart(proof)
    }

    /// Legt die aufgenommene Sicherung zurueck und laeuft den Neustartpfad
    /// erneut.
    pub fn restore_captured_backup(&mut self) -> Result<RestartState, DraftError> {
        self.put_back_backup();
        self.restart_and_resume()
    }

    fn put_back_backup(&mut self) {
        self.close();
        // Erst alles fort, was jetzt daliegt — sonst ueberlebte ein WAL, das
        // die Sicherung nicht kennt, und die „Rueckspielung" waere eine
        // Mischung aus zwei Zustaenden.
        for name in
            std::iter::once(DATABASE_FILE).chain(DATABASE_SIDECARS.into_iter().chain([LOCK_FILE]))
        {
            let _ = fs::remove_file(self.root.join(name));
        }
        for (name, bytes) in &self.backup {
            fs::write(self.root.join(name), bytes).expect("die Sicherung muss schreibbar sein");
        }
    }

    /// Setzt die vorbereitete Abschlussmarke durch `DraftRepository`.
    pub fn set_prepared_finalization_marker(&mut self) {
        self.repo()
            .replace_prepared_finalization_marker(Some(PreparedFinalizationMarker::new(
                b"VORBEREITETER-ABSCHLUSS".to_vec(),
            )))
            .expect("die Abschlussmarke muss sich setzen lassen");
    }

    /// Ob der ORIGINALENTWURF noch entschluesselbar ist.
    ///
    /// Die Frage ist ausdruecklich NICHT `KeyProvider::contains`: die Adresse
    /// eines Griffs ist Dienst und Konto und wird nicht verbraucht, also traegt
    /// sie nach dem Verwerfen den `draftDEK` des NEUEN leeren Entwurfs.
    /// Gemessen wird deshalb, was die Zusage wirklich behauptet — dass die
    /// Bytes des verworfenen Entwurfs nicht mehr zu oeffnen sind.
    #[must_use]
    pub fn draft_dek_is_present(&self) -> bool {
        let Ok(dek) = self.provider.unwrap_secret(&self.original.dek) else {
            return false;
        };
        aead_open(
            &dek,
            &SecretBytes::new(self.original.nonce),
            &self.original.ciphertext,
            &original_associated_data(self.original.draft_id, self.original.revision),
        )
        .is_ok()
    }

    /// Ob der Schluesselspeichereintrag des ORIGINALENTWURFS WIRKLICH fort ist.
    ///
    /// Das ist eine ANDERE Frage als [`Self::draft_dek_is_present`], und der
    /// Unterschied ist der Kern dieses Tasks. Die Adresse eines Griffs ist
    /// Dienst und Konto und wird nicht verbraucht: sobald der leere Entwurf
    /// entsteht, liegt an DERSELBEN Adresse wieder ein Eintrag, und die
    /// Unentschluesselbarkeit der alten Bytes waere dann auch ohne ein
    /// Loeschen erreicht — durch das Ueberschreiben allein. Nur ZWISCHEN dem
    /// Loeschen und dem Anlegen des leeren Entwurfs ist der dauerhafte Schritt
    /// „der `draftDEK` ist fort" ueberhaupt sichtbar, und genau dort fragt
    /// dieser Leser.
    #[must_use]
    pub fn draft_dek_entry_is_absent(&self) -> bool {
        !self
            .provider
            .contains(&self.original.dek)
            .expect("der In-Prozess-Provider antwortet immer")
    }

    /// Derselbe Dienst, aber mit einem Schluesselspeicher, der sein `delete`
    /// verschluckt.
    #[must_use]
    pub fn discard_service_with_deaf_keystore(&self) -> DiscardService<'_> {
        DiscardService::new(
            self.repo(),
            Arc::new(DeafDeleteProvider {
                inner: Arc::clone(&self.provider),
            }) as Arc<dyn KeyProvider>,
            self.bound_binding_object_hash(),
            self.head.preexisting_effective_now(),
        )
    }

    /// Oeffnet die Ablage NEU und laeuft den Neustartpfad gegen einen
    /// Schluesselspeicher, der ein zweites `delete` mit `NotFound` ABLEHNT.
    ///
    /// Das ist der Vertrag, den `KeyProvider::delete` WIRKLICH zusagt:
    /// „Loescht den Eintrag endgueltig" — keine Idempotenz. Nur gegen diesen
    /// Doppelgaenger ist messbar, dass der Neustartpfad einen schon abwesenden
    /// Eintrag nicht als Fehler nimmt und sich damit dauerhaft verklemmt.
    pub fn restart_and_resume_with_strict_keystore(&self) -> Result<RestartState, DraftError> {
        let proof = self.proof_for(ReauthPurpose::DiscardDraft);
        self.reopen();
        DiscardService::new(
            self.repo(),
            Arc::new(StrictDeleteProvider {
                inner: Arc::clone(&self.provider),
            }) as Arc<dyn KeyProvider>,
            self.bound_binding_object_hash(),
            self.head.preexisting_effective_now(),
        )
        .resume_after_restart(&proof)
    }

    /// Ersetzt den Entwurf durch einen leeren — DIREKT ueber die Ablage.
    ///
    /// Nicht ueber den Dienst: der Nachweis, den Task 6 ausdruecklich diesem
    /// Task uebergeben hat, betrifft den TRAIT-Arm und nicht den Dienst.
    pub fn replace_with_blank(&self) -> Result<(), DraftError> {
        self.repo().replace_with_blank().map(|_| ())
    }

    /// Die Zahl der Zeilen der Entwurfstabelle.
    #[must_use]
    pub fn draft_row_count(&self) -> i64 {
        let borrowed = self.open.borrow();
        let open = borrowed
            .as_ref()
            .expect("die Fixture haelt eine geoeffnete Datenbank");
        open.database
            .query_row("SELECT count(*) FROM draft", &[] as &[StoreValue])
            .expect("die Entwurfstabelle muss zaehlbar sein")
            .expect("count(*) liefert immer eine Zeile")
            .integer(0)
            .expect("count(*) ist eine Zahl")
    }

    /// Ob KEINE Verwerfensabsicht mehr gebucht ist.
    #[must_use]
    pub fn pending_discard_is_absent(&self) -> bool {
        self.repo()
            .pending_discard()
            .expect("die Uebergangstabelle muss lesbar sein")
            .is_none()
    }
}

/// Ein Schluesselspeicher, der sein `delete` VERSCHLUCKT und `Ok` meldet.
///
/// Er existiert, damit die Abwesenheitsbestaetigung des Dienstes TRAGEND ist
/// und nicht dekorativ: gegen einen wahrhaftigen Provider kann sie nie
/// fehlschlagen, also waere sie ohne diesen Doppelgaenger eine Zeile, die kein
/// Test je ausfuehrt. Genau der Fall — ein Provider, der ein Loeschen meldet und
/// nicht loescht — ist der, gegen den sie steht.
struct DeafDeleteProvider {
    inner: Arc<InMemoryKeyProvider>,
}

impl KeyProvider for DeafDeleteProvider {
    fn generate(
        &self,
        purpose: SecretPurpose,
        protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, ea_key_provider::KeyError> {
        self.inner.generate(purpose, protection)
    }

    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ea_crypto::ContentType,
        certificate_hash: ea_types::CertificateHash,
        payload: &[u8],
    ) -> Result<ea_key_provider::CoseSign1Bytes, ea_key_provider::KeyError> {
        self.inner
            .sign(handle, content_type, certificate_hash, payload)
    }

    fn wrap_secret(
        &self,
        purpose: SecretPurpose,
        secret: SecretBytes<32>,
    ) -> Result<KeyHandle, ea_key_provider::KeyError> {
        self.inner.wrap_secret(purpose, secret)
    }

    fn unwrap_secret(
        &self,
        handle: &KeyHandle,
    ) -> Result<SecretBytes<32>, ea_key_provider::KeyError> {
        self.inner.unwrap_secret(handle)
    }

    fn unwrap_database_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ea_crypto::SecretVec, ea_key_provider::KeyError> {
        self.inner.unwrap_database_key(handle)
    }

    /// Meldet Erfolg und tut NICHTS.
    fn delete(&self, _handle: &KeyHandle) -> Result<(), ea_key_provider::KeyError> {
        Ok(())
    }

    fn contains(&self, handle: &KeyHandle) -> Result<bool, ea_key_provider::KeyError> {
        self.inner.contains(handle)
    }

    fn reached_protection_profile(
        &self,
        handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, ea_key_provider::KeyError> {
        self.inner.reached_protection_profile(handle)
    }
}

/// Ein Schluesselspeicher, der ein `delete` auf einem ABWESENDEN Eintrag mit
/// [`KeyError::NotFound`] ABLEHNT.
///
/// Er ist der NATIVE Speicher, wie sein Vertrag ihn erlaubt.
/// `KeyProvider::delete` sagt „Loescht den Eintrag endgueltig" und sagt
/// AUSDRUECKLICH keine Idempotenz zu; dass `InMemoryKeyProvider::delete`
/// bedingungslos `Ok` meldet, ist die Eigenschaft EINER Implementierung. Gegen
/// diesen Doppelgaenger ist messbar, dass ein Neustart nach einem Absturz
/// ZWISCHEN Loeschen und Entfernen sich nicht dauerhaft verklemmt — ohne ihn
/// waere die Zusage „ein zweites resume ist ein no-op" nur gegen den einen
/// gutmuetigen Provider gemessen.
struct StrictDeleteProvider {
    inner: Arc<InMemoryKeyProvider>,
}

impl KeyProvider for StrictDeleteProvider {
    fn generate(
        &self,
        purpose: SecretPurpose,
        protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, ea_key_provider::KeyError> {
        self.inner.generate(purpose, protection)
    }

    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ea_crypto::ContentType,
        certificate_hash: ea_types::CertificateHash,
        payload: &[u8],
    ) -> Result<ea_key_provider::CoseSign1Bytes, ea_key_provider::KeyError> {
        self.inner
            .sign(handle, content_type, certificate_hash, payload)
    }

    fn wrap_secret(
        &self,
        purpose: SecretPurpose,
        secret: SecretBytes<32>,
    ) -> Result<KeyHandle, ea_key_provider::KeyError> {
        self.inner.wrap_secret(purpose, secret)
    }

    fn unwrap_secret(
        &self,
        handle: &KeyHandle,
    ) -> Result<SecretBytes<32>, ea_key_provider::KeyError> {
        self.inner.unwrap_secret(handle)
    }

    fn unwrap_database_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ea_crypto::SecretVec, ea_key_provider::KeyError> {
        self.inner.unwrap_database_key(handle)
    }

    /// Lehnt ein Loeschen ins Leere ab — wie ein nativer Speicher es darf.
    fn delete(&self, handle: &KeyHandle) -> Result<(), ea_key_provider::KeyError> {
        if !self.inner.contains(handle)? {
            return Err(ea_key_provider::KeyError::NotFound);
        }
        self.inner.delete(handle)
    }

    fn contains(&self, handle: &KeyHandle) -> Result<bool, ea_key_provider::KeyError> {
        self.inner.contains(handle)
    }

    fn reached_protection_profile(
        &self,
        handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, ea_key_provider::KeyError> {
        self.inner.reached_protection_profile(handle)
    }
}

/// Liest Chiffrat und Nonce der Entwurfszeile DURCH SQLCipher hindurch.
fn stored_payload(database: &EncryptedDatabase) -> (Vec<u8>, [u8; AEAD_NONCE_SIZE]) {
    let row = database
        .query_row(
            "SELECT payload_ciphertext, payload_nonce FROM draft WHERE singleton = 0",
            &[] as &[StoreValue],
        )
        .expect("die Entwurfszeile muss lesbar sein")
        .expect("nach einer Speicherung liegt genau eine Entwurfszeile");
    let ciphertext = row.blob(0).unwrap().to_vec();
    let nonce: [u8; AEAD_NONCE_SIZE] = row.blob(1).unwrap().try_into().unwrap();
    (ciphertext, nonce)
}

/// Nimmt jede vorhandene Datenbankdatei auf.
fn capture_database_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    std::iter::once(DATABASE_FILE)
        .chain(DATABASE_SIDECARS)
        .filter_map(|name| {
            fs::read(root.join(name))
                .ok()
                .map(|bytes| (name.to_owned(), bytes))
        })
        .collect()
}

/// Die AEAD-Zusatzdaten des Entwurfs — `draft_id || zielfassung_be`.
///
/// Sie stehen hier NACHGEBILDET, weil sie in `ea-draft` privat sind. Waeren sie
/// oeffentlich, koennte ein Aufrufer sie unterschieben; die Fixture bildet sie
/// deshalb nach, statt die Grenze zu oeffnen.
fn original_associated_data(draft_id: Id16, revision: u64) -> Vec<u8> {
    let mut associated = Vec::with_capacity(24);
    associated.extend_from_slice(draft_id.as_bytes());
    associated.extend_from_slice(&revision.to_be_bytes());
    associated
}

// ---------------------------------------------------------------------------
// Die Fixture der Stammdaten- und Importpruefung.
// ---------------------------------------------------------------------------

/// Die Fixture des CSV-Imports und der Stammdatenmomentaufnahmen.
///
/// Sie oeffnet die verschluesselte Datenbank EINMAL und gibt sie an Importeur
/// und Ablage weiter. Ein Neustart wird hier nicht dargestellt: kein Test
/// dieses Tasks braucht einen, und ein Traeger, der die Datenbank fallen lassen
/// koennte, waere Flaeche ohne Nachfrage.
pub struct ImportHarness {
    _lock: MutexGuard<'static, ()>,
    /// Die temporaere Wurzel. Sie bleibt gehalten, damit der Pfad ueber die
    /// Lebensdauer der Fixture stabil ist.
    root: PathBuf,
    /// Der Schluesselspeicher. Er bleibt gehalten, weil der Datenbankschluessel
    /// IN ihm entstanden ist und nirgends sonst liegt.
    provider: Arc<InMemoryKeyProvider>,
    database: Arc<EncryptedDatabase>,
}

impl ImportHarness {
    #[must_use]
    pub fn new() -> Self {
        let lock = take_harness_lock();
        let root = fixture_root("import");
        let provider = Arc::new(InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED));
        let database = open_database(&root, &provider);
        Self {
            _lock: lock,
            root,
            provider,
            database,
        }
    }

    /// Der Importeur auf DERSELBEN Datenbank.
    #[must_use]
    pub fn importer(&self) -> CsvImporter {
        CsvImporter::new(Arc::clone(&self.database))
    }

    /// Die Stammdatenablage auf DERSELBEN Datenbank.
    #[must_use]
    pub fn master_data_repo(&self) -> MasterDataRepository {
        MasterDataRepository::new(Arc::clone(&self.database))
    }

    /// Trockenlauf UND Buchung in einem Schritt, fuer die Tests, denen der
    /// Trockenlauf selbst nichts sagt.
    ///
    /// Gibt den Bericht zurueck, weil die Provenienzpruefung genau seinen
    /// `importProtocolHash` gegen die Momentaufnahme stellt. Ohne `must_use`:
    /// den meisten Tests sagt der Bericht nichts, sie wollen nur den Zustand.
    pub fn import_persons(&self, csv: &[u8]) -> ImportReportV1 {
        self.import(ImportSourceKindV1::Persons, csv)
    }

    pub fn import_vehicles(&self, csv: &[u8]) -> ImportReportV1 {
        self.import(ImportSourceKindV1::Vehicles, csv)
    }

    fn import(&self, kind: ImportSourceKindV1, csv: &[u8]) -> ImportReportV1 {
        let importer = self.importer();
        let report = importer
            .dry_run(kind, csv)
            .expect("die Fixture-Eingabe muss annehmbar sein");
        importer
            .commit(&report, csv)
            .expect("ein fehlerfreier Bericht muss buchbar sein");
        report
    }

    /// Die Zahl der Zeilen des Einsatznummernregisters.
    ///
    /// Der Importpfad darf sie NIE erhoehen: eine Einsatznummer entsteht unter
    /// der ausschliesslichen Writer-Sperre beim Abschluss und nirgends sonst.
    #[must_use]
    pub fn consumed_incident_number_count(&self) -> u64 {
        let row = self
            .database
            .query_row(
                "SELECT count(*) FROM incident_number_register",
                &[] as &[StoreValue],
            )
            .expect("das Register muss zaehlbar sein")
            .expect("count(*) liefert immer eine Zeile");
        u64::try_from(row.integer(0).unwrap()).unwrap()
    }

    /// Der Pfad der Fixture-Wurzel.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Der Schluesselspeicher der Fixture.
    #[must_use]
    pub fn provider(&self) -> &Arc<InMemoryKeyProvider> {
        &self.provider
    }
}
