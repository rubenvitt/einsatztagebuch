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

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use ea_draft::{AutosaveDraftRepository, IncidentNumberRegister, OperatorProfileRepository};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_types::{ObjectHash, OperatorSubjectId, OrganizationId};

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
