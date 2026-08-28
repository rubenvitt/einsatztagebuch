//! Die Fixture der Finalisierungstests.
//!
//! Drei Zusagen tragen dieses Modul:
//!
//! 1. **Jeder Test serialisiert sich selbst.** Eine prozessweite Sperre plus
//!    eine eigene Temporaerwurzel je Test, nach dem Muster von
//!    `tools/xtask/tests/stage_gate.rs`. Die Wurzel entsteht aus einem
//!    MONOTONEN Zaehler und nicht aus Nanosekunden — derselbe beobachtete
//!    Kollisionsfall wie in `crates/ea-archive-fs/tests/support/mod.rs`. Kein
//!    Test dieses Ziels braucht `--test-threads=1`.
//! 2. **Kein zweiter Kryptobaukasten.** Registrierungslinie, Anker, Objekte
//!    und Signaturen kommen unveraendert aus dem `#[path]`-eingebundenen
//!    Supportmodul von `ea-trust`.
//! 3. **EINE Linie fuer alles.** Registry, Bedienerbindung, Profilzeile,
//!    Archivprofil und Schluesselspeicher gehoeren derselben Organisation und
//!    demselben Head. Zwei Linien hiessen zwei Wahrheiten, und eine von beiden
//!    waere zufaellig die falsche.
//!
//! # Was diese Fixture ANDERS macht als ihre Vorbilder
//!
//! Das Writer-Zertifikat traegt den oeffentlichen Signaturschluessel DIESES
//! Providers, und die Bedienerbindung traegt die aus DIESER Profilzeile
//! nachgerechnete Zusage. Ohne beides pruefte die Finalisierung gegen
//! synthetische Werte, und ihre zwei tragenden Vergleiche waeren Dekoration.
#![allow(dead_code)]

#[path = "../../../ea-trust/tests/support/mod.rs"]
pub mod trust_support;

use std::{
    cell::RefCell,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use ea_archive::{ArchiveBackendProfileV1, BoundArchiveProfilePolicyV1, LocalPathProfileV1};
use ea_archive_fs::{CapabilityTestVectorV1, LocalPathBackend};
use ea_crypto::CanonicalPublicCoseKey;
use ea_draft::{
    AutosaveDraftRepository, DraftRepository, IncidentNumberRegister, OperatorProfileRepository,
};
use ea_format::{CertificateKindV1, KeyProtectionProfileV1, OperatorRoleV1};
use ea_key_provider::{InMemoryKeyProvider, KeyHandle, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose,
};
use ea_schema::{
    KeywordV1, LocationV1, NativeSourceV1, OccurredAtV1, PatientCount, StructuredAddressV1,
};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError,
    TrustStateKey, TrustStateStore, prepare_local_time, select_registry_head,
    verify_registry_candidate,
};
use ea_types::{
    ChainSequence, DeviceId, EntryHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId,
    UnixMillis,
};
use ea_writer::{
    FinalizationFaultPoint, FinalizationInputV1, ReachedState, WriterBindingV1, WriterError,
    WriterService,
};
use ed25519_dalek::{Signer as _, SigningKey};

use trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

/// Der Bedienerinstanzschluessel der Fixture — ein ECHTES Ed25519-Paar.
const INSTANCE_SECRET: [u8; 32] = [
    0x2f, 0x8d, 0x11, 0x4c, 0x63, 0xa0, 0xde, 0x57, 0x94, 0x21, 0xbb, 0x0e, 0x77, 0xf3, 0x48, 0x9c,
    0x15, 0x6a, 0xd2, 0x30, 0xcb, 0x84, 0x39, 0x62, 0xe1, 0x0d, 0x5f, 0xa7, 0x48, 0x76, 0x91, 0x23,
];
/// Der Signaturschluessel des Writer-Zertifikats der ZWEITEN Linie.
///
/// Er existiert ALLEIN, damit eine zweite Bedienerbindung mit einem anderen
/// Objekthash entsteht (siehe
/// [`WriterHarness::proof_of_another_operator_binding`]). Ein anderer
/// Signaturschluessel ist die kleinste Abweichung, die den Zertifikatshash und
/// damit den Bindungshash verschiebt, ohne irgendeine markerabgeleitete
/// Groesse anzuruehren.
const OTHER_WRITER_SECRET: [u8; 32] = [
    0x51, 0xac, 0x0d, 0x74, 0x2e, 0xb8, 0x96, 0x1f, 0x43, 0xd5, 0x60, 0x8a, 0x27, 0xce, 0x19, 0xb3,
    0x7d, 0x04, 0xe2, 0x5b, 0x98, 0x36, 0xaf, 0x11, 0x6c, 0xd9, 0x40, 0x83, 0x2a, 0xf7, 0x65, 0x1e,
];
const BINDING_MARKER: u8 = 0x22;
const WRITER_MARKER: u8 = 0x61;
const RECOVERY_MARKER: u8 = 0x62;
const READER_ONE_MARKER: u8 = 0x63;
const READER_TWO_MARKER: u8 = 0x64;
const SECOND_RECOVERY_MARKER: u8 = 0x65;

/// Der Ausstellungszeitpunkt jedes Head-Ereignisses und der Bezugspunkt des
/// Vertrauensalters — 2026-01-01T00:00:00Z.
///
/// Eine ECHTE Zeit und kein kleiner Zaehler: das oertliche Kalenderjahr des
/// Einsatzes geht in den Registerschluessel der Einsatznummer ein
/// (`design.md`:361-373), und mit einer Zeit nahe der Epoche waere dieses Jahr
/// 1970 — ein Schluessel, den kein Test absichtlich waehlen wuerde.
const FIXTURE_ISSUED_AT_MS: i64 = 1_767_225_600_000;
/// Die Betriebssystemuhr der Fixture, und damit `effectiveNow` des Head: eine
/// Stunde nach der Ausstellung.
const FIXTURE_NOW_MS: i64 = FIXTURE_ISSUED_AT_MS + 3_600_000;
/// `notAfter` des Head. Hinter [`FIXTURE_NOW_MS`], damit der glatte Pfad einen
/// FRISCHEN Head hat, und innerhalb von `maxRegistryAgeMs = 86_400_000`, damit
/// die Kandidatenpruefung ihn annimmt.
const FIXTURE_NOT_AFTER_MS: i64 = FIXTURE_ISSUED_AT_MS + 86_399_000;
/// Eine Auffrischungsfrist UNTER dem Alter des Head zur beobachteten Zeit
/// (eine Minute gegen eine Stunde) — der einzige Weg zu einer ueberschrittenen
/// Frist bei einem FRISCHEN Head.
const FIXTURE_SHORT_TRUST_REFRESH_MS: u64 = 60_000;
/// Das oertliche Kalenderjahr des Einsatzes in `Europe/Berlin`.
pub const FIXTURE_LOCAL_CIVIL_YEAR: i32 = 2026;
/// Die Einsatznummer der Fixture.
pub const FIXTURE_INCIDENT_NUMBER: &str = "2026-000042";
/// Die Sequenz, die die Fixture beansprucht. Ein LEERER Bestand hat keinen
/// verifizierten Kopf, also ist die einzige gueltige Sequenz die NULL.
const PROPOSED_SEQUENCE: u64 = 0;
const FIXTURE_PROVIDER_SEED: [u8; 32] = [0x7c; 32];

/// Die Profilzeile der Fixture — EINGEFROREN.
const FIXTURE_DISPLAY_NAME: &str = "Ada Lovelace";
const FIXTURE_FUNCTION_LABEL: &str = "Einsatzleitung";
const FIXTURE_PROFILE_COMMITMENT_SALT: [u8; 32] = [0x33; 32];

const DATABASE_FILE: &str = "writer.sqlite3";
/// Die Beiwerkdateien der SQLite-Datenbank und die Sperrdatei des Entwurfs.
///
/// Dieselbe Liste und dieselbe Begruendung wie in
/// `crates/ea-draft/tests/support/mod.rs`: eine Rueckspielung, die ein WAL
/// stehen laesst, das die Sicherung nicht kennt, waere eine Mischung aus zwei
/// Zustaenden und keine Rueckspielung.
const DATABASE_SIDECARS: [&str; 2] = ["writer.sqlite3-wal", "writer.sqlite3-shm"];
const LOCK_FILE: &str = "writer.sqlite3.draft-lock";

static HARNESS_LOCK: Mutex<()> = Mutex::new(());
static ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn take_lock() -> MutexGuard<'static, ()> {
    HARNESS_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn fixture_root(label: &str) -> PathBuf {
    let sequence = ROOT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!(
        "ea-writer-{label}-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("die Temporaerwurzel muss anlegbar sein");
    root
}

fn signing_key(secret: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&secret)
}

fn public_key(secret: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(signing_key(secret).verifying_key().to_bytes())
        .expect("der Instanzschluessel der Fixture ist gueltig")
}

/// Die NACHGERECHNETE Profilzusage dieser Profilzeile.
///
/// Sie entsteht ueber DIESELBE Domaine und DIESELBE Feldreihenfolge wie im
/// Writer (`design.md`:242-252) — aber ueber einen eigenen Kodierer, damit die
/// Zusicherung eine zweite Rechnung ist und nicht dieselbe zweimal.
fn expected_profile_commitment(organization: OrganizationId) -> Hash32 {
    let mut bytes = Vec::new();
    minicbor::Encoder::new(&mut bytes)
        .array(5)
        .and_then(|encoder| encoder.bytes(organization.as_bytes()))
        .and_then(|encoder| encoder.bytes(&[BINDING_MARKER; 16]))
        .and_then(|encoder| encoder.str(FIXTURE_DISPLAY_NAME))
        .and_then(|encoder| encoder.str(FIXTURE_FUNCTION_LABEL))
        .and_then(|encoder| encoder.bytes(&FIXTURE_PROFILE_COMMITMENT_SALT))
        .expect("das Urbild der Profilzusage kodiert");
    ea_crypto::operator_profile_digest(&bytes)
}

/// Eine Profilzusage, die zu KEINER Profilzeile dieser Fixture passt.
///
/// KEIN Nullhash: `Hash32::ZERO` waere auch der Wert eines vergessenen Feldes,
/// und ein Waechter, der gegen ihn anspricht, spraeche vielleicht gegen eine
/// Auslassung an und nicht gegen eine Abweichung.
fn foreign_profile_commitment() -> Hash32 {
    let mut bytes = [0x5a_u8; 32];
    bytes[0] = 0xa5;
    Hash32::try_from(bytes.as_slice()).expect("32 Byte sind 32 Byte")
}

fn head_options(effective_from: u64, valid_through: u64) -> HeadOptions {
    HeadOptions {
        effective_from: Some(effective_from),
        valid_through: Some(valid_through),
        issued_at: UnixMillis::new(FIXTURE_ISSUED_AT_MS),
        not_before: UnixMillis::new(FIXTURE_ISSUED_AT_MS - 10),
        not_after: UnixMillis::new(FIXTURE_NOT_AFTER_MS),
        ..HeadOptions::default()
    }
}

/// Ein X25519-Empfaengerschluessel je Empfaenger.
///
/// VERSCHIEDENE Schluessel: der Vorgabewert der Stufe-1-Fixture ist fuer JEDEN
/// Reader und JEDEN Recovery-Empfaenger derselbe, und `GrantPlanV1::new`
/// verbietet doppelte Empfaenger. Mit dem Vorgabewert waere der Plan „ein
/// Recovery plus zwei Reader" nicht baubar.
fn kem_key(marker: u8) -> CanonicalPublicCoseKey {
    let mut bytes = [0_u8; 32];
    bytes[0] = marker;
    bytes[31] = 0x40;
    CanonicalPublicCoseKey::x25519(bytes).expect("ein X25519-Schluessel ist 32 Byte lang")
}

/// Was aus der gebauten Linie herausgereicht wird.
struct BuiltLine {
    line: RegistryLineBuilder,
    binding_object_hash: ObjectHash,
    writer_certificate_hash: ObjectHash,
}

/// Wie eine Fixture von der glatten Linie abweicht.
#[derive(Clone, Copy, Default)]
pub struct LineVariantV1 {
    /// Der ZWEITE Reader traegt keinen KEM-Abdruck.
    pub reader_without_kem_key: bool,
    /// Ein ZWEITER Recovery-Empfaenger ist aktiv.
    pub second_recovery_recipient: bool,
    /// Die Policy traegt `operatingProfile = 1` — Evidence Grade.
    pub evidence_grade: bool,
    /// Die Policy traegt `registryExpiryBehavior = 1` — signiertes `block`.
    pub signed_block_expiry: bool,
    /// Die Policy traegt eine Auffrischungsfrist UNTER dem Alter, das der Head
    /// der Fixture zur beobachteten Zeit schon hat.
    ///
    /// Ohne sie ist eine ueberschrittene Frist bei einem FRISCHEN Head
    /// arithmetisch unerreichbar: die Vorgabe `86_400_000` liegt ueber der
    /// Lebensdauer des Head (`notAfter = issuedAt + 86_399_000`), und `Fresh`
    /// verlangt eine Zeit vor `notAfter`.
    pub short_reader_trust_refresh: bool,
    /// Die Bedienerbindung traegt eine ANDERE Profilzusage als die, die sich
    /// aus der Profilzeile dieser Fixture nachrechnen laesst.
    ///
    /// Der einzige Weg zu `EA-OPERATOR-PROFILE-COMMITMENT`: die Zusage steht in
    /// der SIGNIERTEN Bindung, und der Writer rechnet sie in Schritt 4 aus der
    /// lokalen Profilzeile nach. Stimmen beide ueberein — und in der glatten
    /// Fixture tun sie das per Konstruktion —, ist der Waechter eine Zeile, die
    /// kein Test je ausfuehrt.
    pub foreign_operator_profile_commitment: bool,
    /// KEIN Recovery-Empfaenger ist aktiv.
    ///
    /// Das NULL-Bein der dritten Produktinvariante. Die beiden anderen Beine
    /// sind ueber `second_recovery_recipient` (zu viele) und ueber den
    /// vollstaendigen Plan (genau einer je aktivem Empfaenger) bezeugt; ohne
    /// diesen Knopf gibt es keinen Aufbau, in dem der Waechter
    /// `NoActiveRecoveryRecipient` ueberhaupt erreichbar ist.
    pub without_recovery_recipient: bool,
}

/// Baut die EINE Registrierungslinie der Fixture.
fn build_line(
    writer_public_key: &CanonicalPublicCoseKey,
    profile_hashes: Vec<Hash32>,
    variant: LineVariantV1,
) -> BuiltLine {
    let mut line = RegistryLineBuilder::new();
    line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            policy_allowed_archive_profile_hashes_override: Some(profile_hashes),
            policy_operating_profile_override: variant.evidence_grade.then_some(1),
            policy_registry_expiry_behavior_override: variant.signed_block_expiry.then_some(1),
            policy_reader_trust_refresh_ms_override: variant
                .short_reader_trust_refresh
                .then_some(FIXTURE_SHORT_TRUST_REFRESH_MS),
            ..head_options(0, 10)
        },
    );
    let writer = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: WRITER_MARKER,
            effective_from: Some(0),
        },
        HeadOptions {
            signing_public_key_override: Some(writer_public_key.clone()),
            ..head_options(0, 20)
        },
    );
    if !variant.without_recovery_recipient {
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::RecoveryRecipient,
                marker: RECOVERY_MARKER,
                effective_from: Some(0),
            },
            HeadOptions {
                kem_public_key_override: Some(kem_key(RECOVERY_MARKER)),
                ..head_options(0, 30)
            },
        );
    }
    line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: READER_ONE_MARKER,
            effective_from: Some(0),
        },
        HeadOptions {
            kem_public_key_override: Some(kem_key(READER_ONE_MARKER)),
            ..head_options(0, 40)
        },
    );
    line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Reader,
            marker: READER_TWO_MARKER,
            effective_from: Some(0),
        },
        HeadOptions {
            kem_public_key_override: Some(kem_key(READER_TWO_MARKER)),
            omit_kem_public_key: variant.reader_without_kem_key,
            ..head_options(0, 50)
        },
    );
    if variant.second_recovery_recipient {
        line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::RecoveryRecipient,
                marker: SECOND_RECOVERY_MARKER,
                effective_from: Some(0),
            },
            HeadOptions {
                kem_public_key_override: Some(kem_key(SECOND_RECOVERY_MARKER)),
                ..head_options(0, 60)
            },
        );
    }
    let writer_certificate_hash = writer
        .direct_object_hash
        .expect("das Writer-Zertifikat ist ein direktes Ziel");
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer_certificate_hash,
            role: OperatorRoleV1::Writer,
            marker: BINDING_MARKER,
            effective_from: Some(0),
        },
        HeadOptions {
            binding_instance_key_thumbprint_override: Some(KeyThumbprint::from(
                Hash32::try_from(
                    public_key(INSTANCE_SECRET)
                        .thumbprint()
                        .as_bytes()
                        .as_slice(),
                )
                .expect("ein Thumbprint ist 32 Byte lang"),
            )),
            binding_operator_profile_commitment_override: Some(
                if variant.foreign_operator_profile_commitment {
                    foreign_profile_commitment()
                } else {
                    expected_profile_commitment(trust_support::organization())
                },
            ),
            ..head_options(0, 100)
        },
    );
    BuiltLine {
        binding_object_hash: binding
            .direct_object_hash
            .expect("die Bedienerbindung ist ein direktes Ziel"),
        writer_certificate_hash,
        line,
    }
}

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

fn select_head(line: &RegistryLineBuilder, now_ms: i64) -> SelectedRegistryHead {
    let head_index = line.heads().len() - 1;
    let head = line.heads()[head_index];
    let key = trust_support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(now_ms));
    let trust = line.verified_with_record(Pin::Head(head_index), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(PROPOSED_SEQUENCE))
        .expect("der Kandidat der Fixture muss verifizieren");
    let mut store = ModelStore {
        key,
        revision: 17,
        trusted_time,
        pinned_head: RegistryHeadPin::new(head.version, head.object_hash),
    };
    let local_time = prepare_local_time(&mut store, &candidate, UnixMillis::new(now_ms), &[])
        .expect("die lokale Zeit der Fixture muss vorbereitbar sein");
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None)
            .expect("die Auswahl der Fixture muss gelingen")
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
        Ok(Some(public_key(INSTANCE_SECRET)))
    }
}

struct FakeAuthenticator {
    bound: BoundOperator,
    signing_key: SigningKey,
    challenges: RefCell<Vec<Vec<u8>>>,
}

impl OperatorAuthenticator for FakeAuthenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }

    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        self.challenges.borrow_mut().push(challenge.to_vec());
        Ok(self.signing_key.sign(challenge).to_bytes())
    }
}

/// Das lokale Archivprofil der Fixture.
fn local_profile() -> ArchiveBackendProfileV1 {
    ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
        filesystem_row_id: "fixture-writer-fs".to_owned(),
        capability_test_vector_id: "cap-v1-writer".to_owned(),
    })
}

fn capability_test_vector() -> CapabilityTestVectorV1 {
    CapabilityTestVectorV1::new("stage2:writer-fixture", b"ea-writer capability probe")
        .expect("der Testvektor der Fixture ist gueltig")
}

/// Die geoeffnete verschluesselte Ablage.
///
/// Als eigener Wert, weil die Rueckspielung einer Sicherung sie SCHLIESSEN
/// muss: eine Datei unter einer offenen SQLite-Verbindung zu ersetzen waere
/// keine Rueckspielung, sondern ein halber Zustand.
struct OpenStore {
    database: Arc<EncryptedDatabase>,
    repository: Arc<dyn DraftRepository>,
}

/// Die geoeffnete Fixture.
pub struct WriterHarness {
    _lock: MutexGuard<'static, ()>,
    root: PathBuf,
    provider: Arc<InMemoryKeyProvider>,
    database_key: KeyHandle,
    draft_dek_handle: KeyHandle,
    open: Option<OpenStore>,
    /// Die Datenbankdateien, wie sie NACH dem Setzen der Profilzeile und dem
    /// Speichern des Entwurfs dalagen — an der GESCHLOSSENEN Datenbank
    /// genommen.
    backup: Vec<(String, Vec<u8>)>,
    backend: LocalPathBackend,
    head: SelectedRegistryHead,
    binding: WriterBindingV1,
    line: RegistryLineBuilder,
}

impl WriterHarness {
    /// Eine Fixture mit gesetzter Profilzeile, gefuelltem Entwurf und LEEREM
    /// Bestand.
    #[must_use]
    pub fn with_incident() -> Self {
        Self::with_variant(LineVariantV1::default())
    }

    /// Der Fehler, mit dem die KANDIDATENPRUEFUNG diese Variante ablehnt.
    ///
    /// `None`, wenn die Variante eine gueltige Linie ergibt. Sie existiert,
    /// weil eine Variante, die Stufe 1 schon am Vertrauenspfad abweist, den
    /// Writer nie erreicht — und das ist eine Aussage, die belegt gehoert und
    /// nicht als Panik in einer Fixture.
    #[must_use]
    pub fn candidate_rejection(variant: LineVariantV1) -> Option<&'static str> {
        let provider = InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED);
        provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");
        let writer_public = CanonicalPublicCoseKey::ed25519(
            provider
                .signing_public_key_for_test(SecretPurpose::WriterSigningKey)
                .expect("der erzeugte Signaturschluessel ist lesbar"),
        )
        .expect("ein erzeugter Ed25519-Schluessel ist gueltig");
        let profile_hash = local_profile()
            .profile_hash()
            .expect("das Profil der Fixture ist kodierbar");
        let built = build_line(&writer_public, vec![profile_hash], variant);
        let head_index = built.line.heads().len() - 1;
        let key = trust_support::state_key();
        let trusted_time = TrustedTimeState::initial(UnixMillis::new(FIXTURE_NOW_MS));
        let trust = built
            .line
            .verified_with_record(Pin::Head(head_index), 17, trusted_time, key);
        verify_registry_candidate(&trust, ChainSequence::new(PROPOSED_SEQUENCE))
            .err()
            .map(|error| error.code())
    }

    /// Eine Fixture, deren Registrierungslinie GENAU in einem Punkt abweicht.
    #[must_use]
    pub fn with_variant(variant: LineVariantV1) -> Self {
        let lock = take_lock();
        ea_writer::reset_entropy_draws();
        let root = fixture_root("finalize");
        let provider = Arc::new(InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED));

        // Der Writer-Signaturschluessel entsteht IM Schluesselspeicher, und das
        // Zertifikat der Linie traegt genau seinen oeffentlichen Teil.
        let writer_signing_handle = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");
        let writer_public = CanonicalPublicCoseKey::ed25519(
            provider
                .signing_public_key_for_test(SecretPurpose::WriterSigningKey)
                .expect("der erzeugte Signaturschluessel ist lesbar"),
        )
        .expect("ein erzeugter Ed25519-Schluessel ist gueltig");

        // Der Profilhash kommt vom PROFIL und nicht von einem geoeffneten
        // Bestand: `open` verlangt die Policy, die ihn schon enthalten muss.
        let profile_hash = local_profile()
            .profile_hash()
            .expect("das Profil der Fixture ist kodierbar");
        // Die Linie und der Head entstehen ZUERST; die Policybindung des
        // Backends kommt danach aus GENAU der signierten Policy des gewaehlten
        // Head. Eine zweite, danebenlaufende Policy waere die Luecke, die die
        // Profilpruefung wertlos macht.
        let built = build_line(&writer_public, vec![profile_hash], variant);
        let head = select_head(&built.line, FIXTURE_NOW_MS);
        let backend = LocalPathBackend::open(
            root.join("archive"),
            local_profile(),
            &BoundArchiveProfilePolicyV1::from_policy(head.policy_fields()),
        )
        .expect("der Bestand der Fixture muss sich oeffnen lassen");

        // DER Griff, EINMAL erzeugt: ein zweites `generate` schriebe frisches
        // Material an dieselbe Adresse, und die Datenbank waere nach einer
        // Rueckspielung nicht mehr zu oeffnen.
        let database_key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der In-Prozess-Provider erreicht OsWrapped");
        let open = open_store(&root, &provider, &database_key);
        seed_operator_profile(&open.database, &built);
        let draft = open
            .repository
            .load_or_create()
            .expect("der Entwurf der Fixture muss entstehen");
        let saved = open
            .repository
            .save(draft.with_notes("CANARY-INCIDENT-TEXT"))
            .expect("die Fixture muss speichern koennen");
        // Die ADRESSE des `draftDEK` — Anbieter, Konto und Zweck — und kein
        // Abbild des Geheimnisses. Sie ist nach Schritt 13 dieselbe (der
        // Entwurfsspeicher bildet sie aus genau diesen drei Teilen), also ist
        // sie der Griff, unter dem gemessen wird, was der Writer nach dem
        // Abschluss noch hergeben kann.
        let draft_dek_handle = open
            .repository
            .draft_dek_handle(&saved)
            .expect("der Griff auf den draftDEK der Fixture muss lesbar sein");

        // Die Sicherung wird an der GESCHLOSSENEN Datenbank genommen, NACH der
        // Profilzeile und dem Entwurf: eine Kopie einer offenen WAL-Datenbank
        // waere ein halber Zustand, und die Rueckspielung rollte weiter zurueck
        // als der Test behauptet.
        drop(open);
        let backup = capture_database_files(&root);
        let open = open_store(&root, &provider, &database_key);

        let binding = WriterBindingV1 {
            binding_object_hash: built.binding_object_hash,
            writer_certificate_hash: built.writer_certificate_hash.into(),
            writer_key_thumbprint: writer_public.thumbprint(),
            writer_signing_handle,
            // Die Kettenkennung kommt aus DEM GEWAEHLTEN HEAD und nicht aus
            // einem eigenen Literal. Ein eigenes Literal war genau der Zustand,
            // den die Finalisierung inzwischen fail-closed abweist: die Bindung
            // behauptete eine Kette, die die Vertrauenslinie dieser Fixture
            // nicht fuehrt, und auf einem LEEREN Bestand faellt das nirgends
            // auf — dort gibt es keinen Knoten, an dem eine fremde Kennung
            // erkennbar waere.
            chain_id: head.chain_id(),
            archive_profile_hash: profile_hash,
        };

        Self {
            _lock: lock,
            root,
            provider,
            database_key,
            draft_dek_handle,
            open: Some(open),
            backup,
            backend,
            head,
            binding,
            line: built.line,
        }
    }

    /// Die geoeffnete Ablage.
    fn store(&self) -> &OpenStore {
        self.open
            .as_ref()
            .expect("die Ablage der Fixture ist offen")
    }

    /// Die BEOBACHTETE Zeit des glatten Pfades — die Betriebssystemuhr der
    /// Fixture, dieselbe, die den Head ausgewaehlt hat.
    #[must_use]
    pub const fn observed_now(&self) -> UnixMillis {
        UnixMillis::new(FIXTURE_NOW_MS)
    }

    /// Eine beobachtete Zeit EINE Millisekunde hinter `notAfter` des gebundenen
    /// Head.
    ///
    /// Der Head war bei seiner AUSWAHL frisch — anders gaebe
    /// `select_registry_head` ihn gar nicht heraus — und ist zu dieser Zeit
    /// veraltet. Genau dieser Verlauf ist der Fall, den
    /// `registryExpiryBehavior` regelt.
    #[must_use]
    pub const fn observed_now_after_expiry(&self) -> UnixMillis {
        UnixMillis::new(FIXTURE_NOT_AFTER_MS + 1)
    }

    /// Das Alter, das der gebundene Head zur beobachteten Zeit hat —
    /// NACHGERECHNET aus den zwei Zeiten und nicht als Zahl wiederholt.
    #[must_use]
    pub fn expected_trust_age_ms(&self, observed_now: UnixMillis) -> u64 {
        u64::try_from(observed_now.get() - self.head.issued_at().get())
            .expect("die beobachtete Zeit liegt hinter der Ausstellung")
    }

    /// Der Dienst dieser Fixture.
    ///
    /// `source` kommt von aussen, weil [`Self::source`] einen kurzlebigen
    /// Adapter auf das Backend liefert: haelte die Fixture ihn, waere sie
    /// selbstreferenziell. Der Test haelt ihn, und der Dienst leiht ihn.
    #[must_use]
    pub fn service<'a>(&'a self, source: &'a dyn ea_archive::ArchiveSource) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.store().repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            &self.backend,
            source,
            &self.head,
            &[],
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            self.binding,
        )
    }

    /// Derselbe Dienst mit einer ABWEICHENDEN Geraetebindung.
    ///
    /// Sie ist der einzige Weg, eine Bindung zu messen, die nicht zu dieser
    /// Vertrauenslinie gehoert: die Fixture bildet ihre Bindung aus GENAU dem
    /// gewaehlten Head, und eine unstimmige entsteht darum nur absichtlich.
    #[must_use]
    pub fn service_with_binding<'a>(
        &'a self,
        source: &'a dyn ea_archive::ArchiveSource,
        binding: WriterBindingV1,
    ) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.store().repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            &self.backend,
            source,
            &self.head,
            &[],
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            binding,
        )
    }

    /// Derselbe Dienst mit erreichbaren SERVER-CHECKPOINTAUSSAGEN.
    ///
    /// Der glatte Pfad gibt `&[]` weiter. Ohne eine Aussage ueber DIESE Kette
    /// ist Schritt 2 `NotAssessable` (`ea_chain::assess_rollback`), und der
    /// Rollbackwaechter kann gar nicht ansprechen — er waere eine Zeile, die
    /// kein Test je ausfuehrt. Erst eine Aussage macht ihn messbar, und erst
    /// eine STIMMIGE Aussage daneben macht die Messung falsifizierbar.
    #[must_use]
    pub fn service_with_checkpoints<'a>(
        &'a self,
        source: &'a dyn ea_archive::ArchiveSource,
        checkpoint_claims: &'a [ea_chain::CheckpointClaim],
    ) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.store().repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            &self.backend,
            source,
            &self.head,
            checkpoint_claims,
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            self.binding,
        )
    }

    /// Ein VOLLER Abschluss gegen einen Schluesselspeicher, dessen `delete`
    /// sein `Ok` meldet und NICHTS tut.
    ///
    /// Der Dienst bekommt den tauben Doppelgaenger, die Entwurfsablage behaelt
    /// den wahrhaftigen Provider — dieselbe Aufteilung wie in
    /// `DraftHarness::discard_service_with_deaf_keystore`: gemessen wird die
    /// Abwesenheitsbestaetigung des DIENSTES, und dafuer muss der Entwurf
    /// vorher normal lesbar und speicherbar sein.
    ///
    /// Kein dreizehnter Abbruchpunkt: `FinalizationFaultPoint` beschreibt
    /// STELLEN der Reihenfolge, und ein luegender Schluesselspeicher ist keine
    /// Stelle, sondern ein Verhalten eines Ports. `stage-2-fault-points.json`
    /// bleibt bei zwoelf.
    pub fn finalize_with_deaf_keystore(&self) -> Result<ea_writer::FinalizeOutcome, WriterError> {
        let source = self.source();
        let deaf: Arc<dyn KeyProvider> = Arc::new(DeafDeleteProvider {
            inner: Arc::clone(&self.provider),
        });
        let service = WriterService::new(
            Arc::clone(&self.store().repository),
            deaf,
            &self.backend,
            &source,
            &self.head,
            &[],
            IncidentNumberRegister::new(Arc::clone(&self.store().database)),
            OperatorProfileRepository::new(Arc::clone(&self.store().database)),
            self.binding,
        );
        let proof = self.proof_for(ReauthPurpose::Finalize);
        let preview = service.preview(&proof, valid_incident(), self.observed_now())?;
        service.finalize(&proof, valid_incident(), &preview, self.observed_now())
    }

    /// Der Lesezugriff auf den Bestand.
    #[must_use]
    pub fn source(&self) -> ea_archive_fs::LocalPathArchiveSource<'_> {
        self.backend.as_archive_source()
    }

    #[must_use]
    pub const fn backend(&self) -> &LocalPathBackend {
        &self.backend
    }

    #[must_use]
    pub const fn head(&self) -> &SelectedRegistryHead {
        &self.head
    }

    #[must_use]
    pub const fn binding(&self) -> WriterBindingV1 {
        self.binding
    }

    /// Der Vertrauensanker DIESER Linie.
    ///
    /// Er wird herausgegeben, weil ein Verifikationslauf UEBER den erzeugten
    /// Bestand gegen GENAU diesen Anker laufen muss; ein zweiter, daneben
    /// gebauter Anker waere eine zweite Wahrheit.
    #[must_use]
    pub fn anchor(&self) -> ea_trust::TrustAnchorV1 {
        ea_trust::decode_trust_anchor(self.line.exact_anchor_bytes())
            .expect("der Anker der Fixture muss dekodieren")
    }

    #[must_use]
    pub fn repository(&self) -> Arc<dyn DraftRepository> {
        Arc::clone(&self.store().repository)
    }

    #[must_use]
    pub fn provider(&self) -> Arc<InMemoryKeyProvider> {
        Arc::clone(&self.provider)
    }

    #[must_use]
    pub fn database(&self) -> Arc<EncryptedDatabase> {
        Arc::clone(&self.store().database)
    }

    /// Ein ECHTER Praesenznachweis fuer `purpose`, gegen den gewaehlten Head.
    #[must_use]
    pub fn proof_for(&self, purpose: ReauthPurpose) -> OperatorSessionProof {
        issue_proof(&self.head, self.binding.binding_object_hash, purpose)
    }

    /// Ein ECHTER, aber ABGELAUFENER Nachweis fuer `Finalize`.
    ///
    /// Er ist gegen DIESELBE Linie und DIESELBE Bindung ausgestellt — nur
    /// gegen einen FRUEHER gewaehlten Head. Sein Fuenfminutenfenster beginnt
    /// bei [`FIXTURE_ISSUED_AT_MS`] und endet lange vor der `effectiveNow` des
    /// gebundenen Head (eine Stunde spaeter). Die Bindung stimmt also, der
    /// Zweck stimmt, und ALLEIN die Zeit entscheidet — dieselbe Bauart wie
    /// `DraftHarness::expired_proof` auf der Verwerfensseite.
    #[must_use]
    pub fn expired_proof(&self) -> OperatorSessionProof {
        let earlier_head = select_head(&self.line, FIXTURE_ISSUED_AT_MS);
        issue_proof(
            &earlier_head,
            self.binding.binding_object_hash,
            ReauthPurpose::Finalize,
        )
    }

    /// Ein ECHTER, TAUFRISCHER Nachweis fuer `purpose` — aber fuer eine
    /// ANDERE Bedienerbindung.
    ///
    /// # Warum eine zweite Linie und nicht ein erfundener Hash
    ///
    /// `OperatorSessionProof` entsteht ausschliesslich ueber
    /// `OperatorAuthenticator::reauthenticate` aus einem `BoundOperator`, und
    /// der wiederum nur ueber `BoundOperator::resolve` aus einem Head, in dem
    /// die Bindung AKTIV ist. Ein Nachweis mit erfundenem Bindungshash ist
    /// nicht konstruierbar — und ein Dienst, der auf einen erfundenen Hash
    /// gebunden waere, faellt schon an `active_operator_binding_fields` und
    /// bezeugte damit einen ANDEREN Waechter unter demselben Code.
    ///
    /// Diese zweite Linie weicht in GENAU EINEM Punkt ab: ihr
    /// Writer-Zertifikat traegt einen anderen Signaturschluessel. Damit weicht
    /// der Zertifikatshash ab, damit die `certificateHash` der Bindung, damit
    /// ihr Objekthash. Alles Markerabgeleitete — `osAccountBindingHash`, die
    /// Instanzschluesselzusage, die Profilzusage — bleibt gleich, also meldet
    /// sich derselbe Bediener wirklich an, und der Nachweis ist echt.
    #[must_use]
    pub fn proof_of_another_operator_binding(
        &self,
        purpose: ReauthPurpose,
    ) -> OperatorSessionProof {
        let profile_hash = local_profile()
            .profile_hash()
            .expect("das Profil der Fixture ist kodierbar");
        let other = build_line(
            &public_key(OTHER_WRITER_SECRET),
            vec![profile_hash],
            LineVariantV1::default(),
        );
        let other_head = select_head(&other.line, FIXTURE_NOW_MS);
        issue_proof(&other_head, other.binding_object_hash, purpose)
    }

    /// Wie viele Grants der Plan tragen MUSS: ein Recovery plus jeder aktive
    /// Reader — ABGELEITET aus der synthetisierten Registry und nicht als Zahl
    /// wiederholt.
    #[must_use]
    pub fn expected_grant_count(&self) -> usize {
        self.head
            .active_certificates()
            .filter(|(_, fields)| {
                matches!(
                    fields.certificate_kind,
                    CertificateKindV1::Reader | CertificateKindV1::RecoveryRecipient
                )
            })
            .count()
    }

    #[must_use]
    pub fn expected_registry_version(&self) -> ea_types::RegistryVersion {
        self.head.registry_version()
    }

    /// Ob eine Einsatznummer im Register dieses Jahres schon verbraucht ist.
    #[must_use]
    pub fn incident_number_is_taken(&self, number: &str) -> bool {
        IncidentNumberRegister::new(Arc::clone(&self.store().database))
            .contains(
                trust_support::organization(),
                FIXTURE_LOCAL_CIVIL_YEAR,
                number,
            )
            .expect("das Register muss lesbar sein")
    }

    /// Nimmt die Profilzeile aus der verschluesselten Ablage.
    ///
    /// Der einzige Weg zu `EA-OPERATOR-PROFILE-MISSING`: die Fixture SETZT die
    /// Zeile beim Oeffnen (`seed_operator_profile`), weil ohne sie kein
    /// einziger glatter Pfad liefe. Ein Bestand ohne Zeile ist die Lage nach
    /// einer zurueckgespielten Sicherung, die aelter ist als die Bedieneranlage
    /// — und Schritt 4 MUSS dort abbrechen statt eine Momentaufnahme aus
    /// Vorgabewerten zu bauen.
    pub fn remove_operator_profile(&self) {
        self.store()
            .database
            .execute("DELETE FROM operator_profile", &[])
            .expect("die Profilzeile muss sich entfernen lassen");
    }

    /// Beansprucht die Nummer der Fixture VORAB im Register.
    ///
    /// Sie isoliert die Anspruchspruefung von der Kettenfortschreibung: ein
    /// zweiter Abschluss im selben Bestand faellt schon an Schritt 3, weil der
    /// gebundene Head fuer die verbrauchte Sequenz gewaehlt ist.
    pub fn preclaim_incident_number(&self) {
        IncidentNumberRegister::new(Arc::clone(&self.store().database))
            .claim(
                trust_support::organization(),
                FIXTURE_LOCAL_CIVIL_YEAR,
                FIXTURE_INCIDENT_NUMBER,
            )
            .expect("die Vorabbeanspruchung muss tragen");
    }

    /// Die Zahl der GESTAGTEN, noch nicht veroeffentlichten Objekte.
    #[must_use]
    pub fn staged_object_count(&self) -> usize {
        ["entries/", "grants/"]
            .into_iter()
            .flat_map(|directory| self.backend.relative_paths_below_for_test(directory))
            .filter(|path| path.ends_with(".staging"))
            .count()
    }

    /// Ob der aktive Entwurf LEER ist.
    #[must_use]
    pub fn draft_is_blank(&self) -> bool {
        self.store()
            .repository
            .load_or_create()
            .map(|draft| draft.notes().is_empty())
            .unwrap_or(false)
    }

    /// Ob der `draftDEK` des aktiven Entwurfs noch da ist.
    #[must_use]
    pub fn draft_dek_is_present(&self) -> bool {
        self.store().repository.load_or_create().is_ok()
    }

    /// Ob der SCHLUESSELSPEICHER den `draftDEK` dieser Fixture nicht mehr
    /// fuehrt.
    ///
    /// Eine ANDERE Frage als [`Self::draft_dek_is_present`], und die Trennung
    /// ist der Punkt: jene liest die ABLAGE (`load_or_create` scheitert, wenn
    /// die Entwurfszeile ihr Geheimnis nicht mehr findet), diese fragt den
    /// SCHLUESSELSPEICHER unter der Adresse, die die Fixture beim Saeen
    /// genommen hat. Nach einer Rueckspielung sind die beiden Antworten
    /// dasselbe Ereignis von zwei Seiten — und nur diese Seite ist keine
    /// Wiederholung der Bedingung, die den Fall ueberhaupt erkannt hat.
    ///
    /// # Das Fenster, in dem dieser Leser etwas sagt
    ///
    /// Die Adresse ist (Speicher, Konto, `DraftDek`) und damit EIN Platz, den
    /// Schritt 13 mit dem Schluessel des neuen LEEREN Entwurfs wieder belegt.
    /// „Fort" ist deshalb die Aussage des Fensters ZWISCHEN dem Loeschen und
    /// dem leeren Entwurf — nach einem vollendeten Abschluss ist der Platz
    /// wieder belegt, und das ist die Nachbedingung und kein Verstoss. Was nach
    /// einem vollendeten Abschluss gemessen gehoert, ist
    /// [`Self::writer_keys_cannot_decrypt`].
    #[must_use]
    pub fn draft_dek_entry_is_absent(&self) -> bool {
        !self
            .provider
            .contains(&self.draft_dek_handle)
            .expect("der In-Prozess-Provider antwortet immer")
    }

    /// Die VEROEFFENTLICHTEN Eintraege — ohne jede Staging-Adresse.
    ///
    /// `"x.eip.staging".ends_with(".eip")` ist falsch, also trennt schon der
    /// Filter das Veroeffentlichte vom Vorbereiteten.
    #[must_use]
    pub fn published_entry_paths(&self) -> Vec<String> {
        self.backend
            .relative_paths_below_for_test("entries/")
            .into_iter()
            .filter(|path| path.ends_with(".eip"))
            .collect()
    }

    /// Die VEROEFFENTLICHTEN Grants — ohne jede Staging-Adresse.
    #[must_use]
    pub fn published_grant_paths(&self) -> Vec<String> {
        self.backend
            .relative_paths_below_for_test("grants/")
            .into_iter()
            .filter(|path| path.ends_with(".eag"))
            .collect()
    }

    /// Fuehrt eine Finalisierung, die an GENAU `point` abbricht.
    ///
    /// Fuer [`FinalizationFaultPoint::BackupRestoreAfterKeyDeletion`] ist der
    /// Abbruch nur die HAELFTE: der Punkt IST die Rueckspielung, und ohne sie
    /// waere er derselbe Programmpunkt wie
    /// [`FinalizationFaultPoint::AfterAbsenceConfirmation`] und damit eine
    /// Verdopplung statt einer zweiten Messung. Dieselbe Bauart wie
    /// `DraftHarness::discard_with_fault` in `ea-draft`.
    pub fn finalize_with_fault(
        &mut self,
        point: FinalizationFaultPoint,
    ) -> Result<ReachedState, WriterError> {
        let reached = {
            let source = self.source();
            let service = self.service(&source);
            let proof = self.proof_for(ReauthPurpose::Finalize);
            service.finalize_interrupted_at(&proof, valid_incident(), self.observed_now(), point)
        };
        if point == FinalizationFaultPoint::BackupRestoreAfterKeyDeletion {
            self.restore_captured_backup();
        }
        reached
    }

    /// Laesst BEIDE Sperrdateien liegen, als waere der Prozess unter ihnen
    /// gestorben.
    ///
    /// `SIGKILL` oder Stromausfall mitten in der Finalisierung hinterlaesst
    /// genau das: die Sperrdatei des Bestands und die des Entwurfs stehen da,
    /// aber kein Prozess haelt eine Sperre darauf. Der Neustartpfad
    /// [`ea_writer::WriterService::recover_pending`] nimmt BEIDE Sperren, in
    /// dieser Reihenfolge — solange sie am DASEIN der Dateien haengen, kommt
    /// er an keiner von beiden vorbei.
    ///
    /// AUSDRUECKLICH nicht [`Self::restore_captured_backup`]: das raeumt die
    /// Sperrdateien ab und stellte damit genau die Lage her, die hier gemessen
    /// werden soll, gerade NICHT her.
    pub fn leave_stale_lock_files(&self) {
        fs::write(
            self.backend.root().join(ea_archive_fs::CONTROL_FILES_V1[0]),
            b"",
        )
        .expect("die Sperrdatei des Bestands muss anlegbar sein");
        fs::write(self.root.join(LOCK_FILE), b"")
            .expect("die Sperrdatei des Entwurfs muss anlegbar sein");
    }

    /// Ob BEIDE Sperrdateien (noch) liegen.
    #[must_use]
    pub fn both_lock_files_are_present(&self) -> bool {
        self.backend
            .root()
            .join(ea_archive_fs::CONTROL_FILES_V1[0])
            .exists()
            && self.root.join(LOCK_FILE).exists()
    }

    /// Legt die aufgenommene Sicherung zurueck.
    ///
    /// Der Schluesselspeichereintrag kehrt NICHT zurueck: er ist geraetegebunden
    /// und liegt nicht in diesen Dateien. Genau diese Asymmetrie ist der Punkt.
    pub fn restore_captured_backup(&mut self) {
        // Erst schliessen: eine Datei unter einer offenen Verbindung zu
        // ersetzen ist keine Rueckspielung. Und erst alles fort, was jetzt
        // daliegt, sonst ueberlebte ein WAL, das die Sicherung nicht kennt.
        self.open = None;
        for name in std::iter::once(DATABASE_FILE)
            .chain(DATABASE_SIDECARS)
            .chain([LOCK_FILE])
        {
            let _ = fs::remove_file(self.root.join(name));
        }
        for (name, bytes) in &self.backup {
            fs::write(self.root.join(name), bytes).expect("die Sicherung muss schreibbar sein");
        }
        self.open = Some(open_store(&self.root, &self.provider, &self.database_key));
    }

    /// Ob eine liegende Abschlussmarke in der Ablage steht.
    #[must_use]
    pub fn prepared_marker_is_present(&self) -> bool {
        self.store()
            .repository
            .prepared_finalization_marker()
            .expect("die Ablage muss lesbar sein")
            .is_some()
    }

    /// Ob KEIN Geheimnis, das dieser Schluesselspeicher hergibt, den committed
    /// Eintrag oeffnet.
    ///
    /// # Was hier GEMESSEN wird
    ///
    /// Der Ciphertext des veroeffentlichten `.eip` wird mit JEDEM Geheimnis
    /// probiert, das der Provider dieses Writers ausgibt: der `draftDEK` unter
    /// seiner unveraenderten Adresse (nach Schritt 13 der des LEEREN Entwurfs),
    /// der Writer-Signaturschluessel und der Datenbankschluessel. Die
    /// Zusicherung ist FALSIFIZIERBAR: laege die CEK dieses Eintrags an einer
    /// dieser Adressen, oeffnete `aead_open` und die Antwort waere `false`.
    /// Damit sie nicht leer ist, MUSS mindestens ein Geheimnis wirklich bis
    /// `aead_open` gekommen sein.
    ///
    /// # Was hier NICHT gemessen wird
    ///
    /// „Kein privater Reader- oder Recovery-Schluessel auf dem Writer" ist eine
    /// Aussage des TYPSYSTEMS und nicht dieser Messung: `SecretPurpose` hat vier
    /// Varianten, und keine davon ist ein KEM-Empfaengerzweck
    /// (`crates/ea-key-provider/src/contract.rs`, `KeyPurpose` fuehrt sie als
    /// FREMDES Material). Ein solcher Schluessel ist an diesem Port nicht
    /// speicherbar.
    #[must_use]
    pub fn writer_keys_cannot_decrypt(&self, entry_hash: EntryHash) -> bool {
        let path = self
            .published_entry_paths()
            .into_iter()
            .find(|path| path.contains(&hex(entry_hash.as_bytes())))
            .expect("der committed Eintrag muss unter seinem Layoutnamen liegen");
        let bytes = self
            .backend
            .read_for_test(&path)
            .expect("das committed .eip muss lesbar sein");
        let parsed =
            ea_format::decode_exact_object(&bytes).expect("das committed .eip muss dekodieren");
        let ea_format::ParsedArchiveObject::Entry(entry) = &parsed else {
            panic!("unter entries/ liegt ein Eintragspaket");
        };
        // `assert_eq!` verlangt `Debug`, und Stufe 1 leitet fuer `EntryHash`
        // keines ab — ein Hash gehoert in keine Protokollzeile.
        assert!(
            entry.value().entry_hash() == entry_hash,
            "gemessen wird GENAU der Eintrag, dessen Hash der Abschluss gemeldet hat"
        );
        let nonce = ea_crypto::SecretBytes::new(entry.value().manifest().fields().nonce);
        let aad = ea_crypto::payload_aad(entry.value().manifest().exact_bytes());

        // POSITIVKONTROLLE: mit dem RICHTIGEN Schluessel oeffnet derselbe
        // Aufruf ueber dieselbe Nonce und dieselben Zusatzdaten. Ohne sie waere
        // ein fehlgeschlagenes `aead_open` unten auch dann gruen, wenn Nonce,
        // Zusatzdaten oder der Ciphertextschnitt gar nicht die dieses Eintrags
        // waeren — die Zusicherung koennte nicht mehr fehlschlagen.
        let control_key = ea_crypto::SecretBytes::new([0x5c; 32]);
        let control = ea_crypto::aead_seal(
            &control_key,
            &nonce,
            ea_crypto::SecretVec::new(b"KONTROLLE".to_vec()),
            &aad,
        )
        .expect("die Kontrolle muss versiegeln");
        assert!(
            ea_crypto::aead_open(&control_key, &nonce, &control, &aad).is_ok(),
            "Nonce und Zusatzdaten dieses Eintrags sind benutzbar"
        );

        // JEDE der vier Adressen dieses Schluesselspeichers, und nicht nur die
        // drei, die diese Finalisierung benutzt: `SecretPurpose` ist
        // geschlossen, also ist die Aufzaehlung vollstaendig, und ein
        // Schluessel, der die CEK an einer unbenutzten Adresse aufbewahrte,
        // faellt genauso auf.
        let account = self.database_key.account_instance();
        let keystore = self.database_key.keystore_provider();
        // Die abgeleitete Adresse IST die des Entwurfsschluessels. Ohne diese
        // Gleichheit koennte die Aufzaehlung an vier leeren Adressen probieren
        // und waere gruen, ohne etwas zu beruehren.
        assert!(
            KeyHandle::new(keystore, account, SecretPurpose::DraftDek) == self.draft_dek_handle,
            "die abgeleiteten Adressen sind die des Entwurfsspeichers"
        );
        let mut secrets = Vec::new();
        for purpose in [
            SecretPurpose::WriterSigningKey,
            SecretPurpose::OperatorInstanceKey,
            SecretPurpose::DraftDek,
            SecretPurpose::LocalDatabaseKey,
        ] {
            let handle = KeyHandle::new(keystore, account, purpose);
            if let Ok(secret) = self.provider.unwrap_secret(&handle) {
                secrets.push(secret);
            }
            if let Ok(database_key) = self.provider.unwrap_database_key(&handle) {
                database_key.with_exposed(|raw| {
                    if let Ok(exact) = <[u8; 32]>::try_from(raw) {
                        secrets.push(ea_crypto::SecretBytes::new(exact));
                    }
                });
            }
        }
        assert!(
            !secrets.is_empty(),
            "die Zusicherung waere leer: kein einziges Geheimnis ist bis aead_open gekommen"
        );
        secrets.iter().all(|secret| {
            ea_crypto::aead_open(secret, &nonce, entry.value().ciphertext(), &aad).is_err()
        })
    }

    #[must_use]
    pub const fn root(&self) -> &PathBuf {
        &self.root
    }

    #[must_use]
    pub const fn line(&self) -> &RegistryLineBuilder {
        &self.line
    }
}

/// Stellt einen ECHTEN Praesenznachweis fuer `binding_object_hash` gegen `head`
/// aus.
///
/// EINE Stelle fuer alle drei Nachweise der Fixture — der frische, der
/// abgelaufene und der einer fremden Bindung. Waeren es drei Kopien, koennte
/// eine von ihnen leise etwas anderes tun als „derselbe Bediener meldet sich
/// wieder an", und genau das ist der Unterschied, den die drei Zusicherungen
/// messen.
fn issue_proof(
    head: &SelectedRegistryHead,
    binding_object_hash: ObjectHash,
    purpose: ReauthPurpose,
) -> OperatorSessionProof {
    let bound = BoundOperator::resolve(head, binding_object_hash)
        .expect("die Bindung ist an der gewaehlten Sequenz aktiv");
    let authenticator = FakeAuthenticator {
        bound,
        signing_key: signing_key(INSTANCE_SECRET),
        challenges: RefCell::new(Vec::new()),
    };
    let account: Box<dyn OsAccountProvider> = Box::new(FakeAccount {
        binding_hash: trust_support::hash32(BINDING_MARKER.wrapping_add(2)),
    });
    authenticator
        .reauthenticate(account, purpose)
        .expect("der gebundene Bediener meldet sich wieder an")
}

/// Ein Schluesselspeicher, der sein `delete` VERSCHLUCKT und `Ok` meldet.
///
/// Er existiert, damit die Abwesenheitsbestaetigung in Schritt 9 TRAGEND ist
/// und nicht dekorativ: gegen einen wahrhaftigen Provider kann sie nie
/// fehlschlagen, also waere `WriterError::KeyDeletionNotConfirmed` ohne diesen
/// Doppelgaenger eine Zeile, die kein Test je ausfuehrt. Wortgleich zum
/// Doppelgaenger der VERWERFENSSEITE (`crates/ea-draft/tests/support/mod.rs`) —
/// dieselbe Zusage, dieselbe Bauart, und die Asymmetrie zwischen den beiden
/// Seiten war der Befund.
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
        secret: ea_crypto::SecretBytes<32>,
    ) -> Result<KeyHandle, ea_key_provider::KeyError> {
        self.inner.wrap_secret(purpose, secret)
    }

    fn unwrap_secret(
        &self,
        handle: &KeyHandle,
    ) -> Result<ea_crypto::SecretBytes<32>, ea_key_provider::KeyError> {
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

/// Oeffnet Datenbank und Ablage mit DEMSELBEN Griff.
fn open_store(
    root: &std::path::Path,
    provider: &Arc<InMemoryKeyProvider>,
    database_key: &KeyHandle,
) -> OpenStore {
    let database = Arc::new(
        EncryptedDatabase::open(&root.join(DATABASE_FILE), provider.as_ref(), database_key)
            .expect("die verschluesselte Datenbank muss sich oeffnen lassen"),
    );
    let repository: Arc<dyn DraftRepository> = Arc::new(AutosaveDraftRepository::new(
        Arc::clone(&database),
        Arc::clone(provider) as Arc<dyn KeyProvider>,
    ));
    OpenStore {
        database,
        repository,
    }
}

/// Nimmt die Datenbankdateien, wie sie JETZT dalegen.
fn capture_database_files(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    std::iter::once(DATABASE_FILE)
        .chain(DATABASE_SIDECARS)
        .filter_map(|name| {
            fs::read(root.join(name))
                .ok()
                .map(|bytes| (name.to_owned(), bytes))
        })
        .collect()
}

/// Setzt die EINE Profilzeile mit rohem SQL.
///
/// Ueber `OperatorProfileRepository` gibt es keinen Schreibarm, und genau das
/// soll so bleiben: Stufe 2 konsumiert Bedieneridentitaet und stellt sie nicht
/// aus.
fn seed_operator_profile(database: &EncryptedDatabase, built: &BuiltLine) {
    database
        .execute(
            "INSERT INTO operator_profile (singleton, organization_id, operator_subject_id, \
             display_name, function_label, profile_commitment_salt, \
             operator_binding_object_hash) VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                StoreValue::Blob([BINDING_MARKER; 16].to_vec()),
                StoreValue::Text(FIXTURE_DISPLAY_NAME.to_owned()),
                StoreValue::Text(FIXTURE_FUNCTION_LABEL.to_owned()),
                StoreValue::Blob(FIXTURE_PROFILE_COMMITMENT_SALT.to_vec()),
                StoreValue::Blob(built.binding_object_hash.as_bytes().to_vec()),
            ],
        )
        .expect("die Profilzeile muss sich setzen lassen");
}

/// Kleinbuchstaben-Hex, wie jeder Dateiname des Layouts.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Ein gueltiger Einsatz — dieselben Werte bei jedem Aufruf.
///
/// Die Typen sind nicht `Clone` (Stufe 1 gibt sie bewusst nicht heraus), also
/// baut jeder Aufruf sie NEU. Zwei Aufrufe ergeben denselben Inhalt und damit
/// dieselbe Vorschau — das ist die Voraussetzung dafuer, dass `finalize` den
/// `previewHash` nachrechnen kann.
#[must_use]
pub fn valid_incident() -> FinalizationInputV1 {
    incident_numbered(FIXTURE_INCIDENT_NUMBER)
}

/// Ein GUELTIGER Einsatz mit einer ANDEREN Einsatznummer.
///
/// Er unterscheidet sich in genau einem Feld, und dieses Feld geht ueber den
/// `recordDigest` in den `previewHash` ein — er ist damit der Aufbau, mit dem
/// sich eine Vorschau von einem Inhalt unterscheiden laesst.
#[must_use]
pub fn other_incident() -> FinalizationInputV1 {
    incident_numbered("2026-000043")
}

fn incident_numbered(number: &str) -> FinalizationInputV1 {
    FinalizationInputV1 {
        timezone: "Europe/Berlin".to_owned(),
        source: NativeSourceV1::new("ea.writer.fixture", 1)
            .expect("die Quelle der Fixture ist gueltig"),
        human_incident_number: number.to_owned(),
        occurred_at: OccurredAtV1::new(UnixMillis::new(FIXTURE_NOW_MS - 3_600_000), None)
            .expect("das Intervall der Fixture ist gueltig"),
        keyword: KeywordV1::free_text("Verkehrsunfall")
            .expect("das Stichwort der Fixture ist gueltig"),
        location: LocationV1::structured(
            StructuredAddressV1::new(
                Some("Hauptstrasse".to_owned()),
                Some("1".to_owned()),
                Some("12345".to_owned()),
                Some("Musterstadt".to_owned()),
                None,
                Some("DE".to_owned()),
            )
            .expect("die Adresse der Fixture ist gueltig"),
            None,
        )
        .expect("der Ort der Fixture ist gueltig"),
        personnel: Vec::new(),
        personnel_empty_reason: Some("keine Personalzuordnung erfasst".to_owned()),
        vehicles: Vec::new(),
        vehicles_empty_reason: Some("keine Fahrzeugzuordnung erfasst".to_owned()),
        patient_count: PatientCount::Known(0),
        notes: None,
        external_organizations: Vec::new(),
    }
}
