//! Die Fixture der Wirtbackendtests.
//!
//! Drei Zusagen tragen dieses Modul:
//!
//! 1. **Jeder Test serialisiert sich selbst.** Eine prozessweite Sperre plus
//!    eine eigene Temporaerwurzel je Test, nach dem Muster von
//!    `tools/xtask/tests/stage_gate.rs`. Die Wurzel entsteht aus einem
//!    MONOTONEN Zaehler und nicht aus Nanosekunden: der beobachtete
//!    Kollisionsfall in `crates/ea-local-store/tests/encrypted_open.rs` hing
//!    genau an der Nanosekundenbildung.
//! 2. **Kein zweiter Kryptobaukasten.** Registrierungslinie, Anker, Objekte und
//!    Signaturen kommen unveraendert aus den `#[path]`-eingebundenen
//!    Supportmodulen von `ea-verify`, `ea-archive`, `ea-trust` und `ea-format`.
//! 3. **Der Bedienernachweis ist ECHT.** Er entsteht durch
//!    `OperatorAuthenticator::reauthenticate` gegen einen gewaehlten
//!    Registrierungskopf, wie in `crates/ea-audit/tests/support/mod.rs`. Ein
//!    frei gebauter Nachweis uebersprang genau die Pruefungen, die ihm seinen
//!    Wert geben.
//!
//! `#[path]`-Includes werden je Testtarget uebersetzt; daher
//! `allow(dead_code)` auf Modulebene, genau wie in den eingebundenen Modulen.
#![allow(dead_code)]

/// Das Supportmodul aus `ea-verify`, unveraendert weiterverwendet.
///
/// Bindet seinerseits das Archiv-, Trust- und Formatfixture ein und liefert die
/// vollstaendigen Bestaende mitsamt Anker. Hier wird nichts davon nachgebaut.
#[path = "../../../ea-verify/tests/support/mod.rs"]
pub mod verify_support;

use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use ea_archive::{
    ArchiveBackendProfileV1, ArchivePath, BoundArchiveProfilePolicyV1, ControlledNetworkProfileV1,
    ENTRIES_DIR_V1, GRANTS_DIR_V1, LocalPathProfileV1,
};
use ea_archive_fs::{
    ArchiveHealthCheckV1, ArchiveHealthReport, CapabilityReportV1, CapabilityTestVectorV1,
    FreeSpaceV1, HealthFinding, LocalCommitComponentV1, LocalPathBackend, MigrationFaultPoint,
    MigrationSourceV1, PlannedPublicationV1, ProfileMigrator, PublicationQueue,
    PublicationTargetV1,
};
use ea_audit::{
    AuditError, LocalAuditRepository, LocalAuditService, SignedLocalAuditEvent,
    SignedLocalAuditService,
};
use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, CanonicalPublicCoseKey, SecretBytes};
use ea_format::{
    CertificateKindV1, ExactObjectBytes, FreeTextPolicyFieldsV1, GrantV1, KeyProtectionProfileV1,
    OperatorRoleV1, Parsed, ParsedArchiveObject, PolicyFieldsV1, RetentionPolicyFieldsV1,
    decode_exact_object, encode_grant,
};
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
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
    ChainSequence, DeviceId, EventId, Hash32, KeyThumbprint, ObjectHash, OrganizationId, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};

use verify_support::archive_support::{
    self,
    format_support::{self},
    trust_support::{self, ActionSpec, HeadOptions, Pin, RegistryLineBuilder},
};

/// Der Bedienerinstanzschluessel der Fixture — ein ECHTES Ed25519-Paar.
const INSTANCE_SECRET: [u8; 32] = [
    0x4a, 0x1c, 0x2e, 0x93, 0x77, 0x05, 0xbb, 0x61, 0x18, 0x8f, 0xd2, 0x40, 0x36, 0xa7, 0x5c, 0xe1,
    0x09, 0x94, 0x6d, 0x3b, 0xcf, 0x82, 0x17, 0x50, 0xe4, 0x2a, 0x68, 0xd9, 0x0b, 0x73, 0xf6, 0x84,
];
const BINDING_MARKER: u8 = 0x71;
/// Die Betriebssystemuhr der Fixture.
///
/// GLEICH `verify_support::FIXTURE_OS_WALL_CLOCK_V1`, und das ist keine
/// Bequemlichkeit: der Nachweis wird gegen die
/// `PreexistingEffectiveNow` DIESER Linie geprueft, und derselbe Wert waehlt in
/// `verify_archive` den Kopf der Bestandsfixture. Zwei Uhren hiessen zwei
/// Zeitfenster, und eines von beiden waere zufaellig das falsche.
const FIXTURE_NOW_MS: i64 = verify_support::FIXTURE_OS_WALL_CLOCK_V1;
const PROPOSED_SEQUENCE: u64 = 30;
const FIXTURE_NOT_AFTER_MS: i64 = 10_000_000;
const FIXTURE_PROVIDER_SEED: [u8; 32] = [0x6b; 32];

/// Die prozessweite Sperre. JEDER Test dieses Ziels nimmt sie.
static HARNESS_LOCK: Mutex<()> = Mutex::new(());

/// Der MONOTONE Zaehler der Temporaerwurzeln.
///
/// Bewusst kein Nanosekundenstempel: zwei Wurzeln, die im selben Tick
/// entstehen, kollidieren, und genau dieser Fehlschlag ist in
/// `crates/ea-local-store/tests/encrypted_open.rs` beobachtet worden.
static ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Nimmt die prozessweite Sperre und legt eine frische Temporaerwurzel an.
///
/// # Panics
///
/// Wenn das Betriebssystem die Wurzel nicht anlegen kann.
pub fn temp_root(label: &str) -> (MutexGuard<'static, ()>, PathBuf) {
    let guard = HARNESS_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let sequence = ROOT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!(
        "ea-archive-fs-{label}-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("die Temporaerwurzel muss anlegbar sein");
    (guard, root)
}

fn signing_key(secret: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&secret)
}

fn public_key(secret: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(signing_key(secret).verifying_key().to_bytes())
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

/// Baut die Registrierungslinie und nennt Bindung und Writer-Zertifikat.
fn build_line() -> (RegistryLineBuilder, ObjectHash, ObjectHash) {
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
                Hash32::try_from(
                    public_key(INSTANCE_SECRET)
                        .thumbprint()
                        .as_bytes()
                        .as_slice(),
                )
                .expect("ein Thumbprint ist 32 Byte lang"),
            )),
            ..head_options(21, 100)
        },
    );
    let binding_object_hash = binding
        .direct_object_hash
        .expect("die Bedienerbindung der Fixture ist ein direktes Ziel");
    let writer_object_hash = writer
        .direct_object_hash
        .expect("das Writer-Zertifikat der Fixture ist ein direktes Ziel");
    (line, binding_object_hash, writer_object_hash)
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

fn selected_registry_head() -> SelectedRegistryHead {
    let (line, _, _) = build_line();
    let head_index = line.heads().len() - 1;
    let head = line.heads()[head_index];
    let key = trust_support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(FIXTURE_NOW_MS));
    let trust = line.verified_with_record(Pin::Head(head_index), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(PROPOSED_SEQUENCE))
        .expect("der Kandidat der Fixture muss verifizieren");
    let mut store = ModelStore {
        key,
        revision: 17,
        trusted_time,
        pinned_head: RegistryHeadPin::new(head.version, head.object_hash),
    };
    let local_time =
        prepare_local_time(&mut store, &candidate, UnixMillis::new(FIXTURE_NOW_MS), &[])
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
    instance_public_key: Option<CanonicalPublicCoseKey>,
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
        Ok(self.instance_public_key.clone())
    }
}

/// Die Attrappe der nativen Praesenzpruefung.
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

/// Ein ECHTER Praesenznachweis fuer `purpose`, gegen den gewaehlten Head.
#[must_use]
pub fn operator_proof(purpose: ReauthPurpose) -> OperatorSessionProof {
    let head = selected_registry_head();
    let (_, binding_object_hash, _) = build_line();
    let bound = BoundOperator::resolve(&head, binding_object_hash)
        .expect("die Bindung der Fixture ist an der gewaehlten Sequenz aktiv");
    let authenticator = FakeAuthenticator {
        bound,
        signing_key: signing_key(INSTANCE_SECRET),
        challenges: RefCell::new(Vec::new()),
    };
    let account: Box<dyn OsAccountProvider> = Box::new(FakeAccount {
        binding_hash: trust_support::hash32(BINDING_MARKER.wrapping_add(2)),
        instance_public_key: Some(public_key(INSTANCE_SECRET)),
    });
    authenticator
        .reauthenticate(account, purpose)
        .expect("die Fixture meldet den gebundenen Bediener wieder an")
}

/// Ein Nachweis fuer den Profilwechsel.
#[must_use]
pub fn profile_migration_proof() -> OperatorSessionProof {
    operator_proof(ReauthPurpose::ArchiveProfileMigration)
}

/// Ein Nachweis fuer den ABSCHLUSS — der falsche Zweck fuer einen Profilwechsel.
#[must_use]
pub fn finalize_proof() -> OperatorSessionProof {
    operator_proof(ReauthPurpose::Finalize)
}

/// Die ANHAENGENDE Auditablage der Fixture, im Speicher.
///
/// Sie implementiert [`LocalAuditRepository`] und nicht
/// [`LocalAuditService`]: `SignedLocalAuditEvent::sealed` ist `pub(crate)` in
/// `ea-audit`, ein fremder Dienst koennte das Ergebnis also gar nicht bauen.
/// Signieren und Buchen bleiben damit beim echten
/// [`SignedLocalAuditService`], und diese Attrappe belegt nur, dass die Zeile
/// TATSAECHLICH angekommen ist.
pub struct InMemoryAuditRepository {
    events: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
}

impl InMemoryAuditRepository {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for InMemoryAuditRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalAuditRepository for InMemoryAuditRepository {
    fn append(&self, event: &SignedLocalAuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*event.id().as_bytes(), event.exact_bytes().to_vec());
        Ok(())
    }

    fn event(&self, _id: EventId) -> Result<SignedLocalAuditEvent, AuditError> {
        // Nicht baubar von aussen, und fuer diese Tests nicht gebraucht: sie
        // lesen die Bytes ueber `AuditHarness::signed_event`.
        Err(AuditError::NotFound)
    }
}

/// Eine gebuchte Auditzeile, so wie diese Fixture sie beobachtet.
pub struct ObservedAuditEvent {
    exact_bytes: Vec<u8>,
}

impl ObservedAuditEvent {
    /// Die exakten `local-audit-event-v1`-Bytes.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

/// Der Auditapparat der Fixture: echter Dienst, beobachtbare Ablage.
pub struct AuditHarness {
    repository: Arc<InMemoryAuditRepository>,
    service: SignedLocalAuditService,
}

impl AuditHarness {
    #[must_use]
    pub fn new() -> Self {
        let provider = Arc::new(InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED));
        let signing_handle = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .expect("der Signaturgriff der Fixture muss entstehen");
        let (_, _, writer_certificate_object_hash) = build_line();
        let repository = Arc::new(InMemoryAuditRepository::new());
        let service = SignedLocalAuditService::new(
            Arc::clone(&repository) as Arc<dyn LocalAuditRepository>,
            Arc::clone(&provider) as Arc<dyn KeyProvider>,
            signing_handle,
            writer_certificate_object_hash,
            UnixMillis::new(FIXTURE_NOW_MS),
        );
        Self {
            repository,
            service,
        }
    }

    #[must_use]
    pub fn service(&self) -> &dyn LocalAuditService {
        &self.service
    }

    /// Die gebuchte Zeile unter dieser Kennung.
    #[must_use]
    pub fn signed_event(&self, id: EventId) -> Option<ObservedAuditEvent> {
        self.repository
            .events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id.as_bytes())
            .map(|exact_bytes| ObservedAuditEvent {
                exact_bytes: exact_bytes.clone(),
            })
    }

    /// Ist die Zeile unter dieser Kennung tatsaechlich gebucht?
    #[must_use]
    pub fn is_flushed(&self, id: EventId) -> bool {
        self.repository
            .events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(id.as_bytes())
    }
}

impl Default for AuditHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Das lokale Profil der Fixture.
#[must_use]
pub fn local_profile() -> ArchiveBackendProfileV1 {
    ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
        filesystem_row_id: "fixture-local-fs".to_owned(),
        capability_test_vector_id: "cap-v1-local".to_owned(),
    })
}

/// Ein ZWEITES lokales Profil — es unterscheidet sich in der Dateisystemzeile
/// und damit im Profilhash.
#[must_use]
pub fn target_local_profile() -> ArchiveBackendProfileV1 {
    ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
        filesystem_row_id: "fixture-target-fs".to_owned(),
        capability_test_vector_id: "cap-v1-local".to_owned(),
    })
}

/// Das kontrollierte Netzprofil der Fixture, VOLLSTAENDIG gepinnt.
#[must_use]
pub fn controlled_network_profile() -> ArchiveBackendProfileV1 {
    ArchiveBackendProfileV1::ControlledNetworkPath(ControlledNetworkProfileV1 {
        filesystem_row_id: "fixture-smb".to_owned(),
        protocol_id: "smb-3.1.1".to_owned(),
        server_product: "windows-server".to_owned(),
        server_version: "2022".to_owned(),
        mount_options: vec!["nobrl".to_owned(), "sync".to_owned()],
        failover_config_id: "failover-single-node".to_owned(),
        capability_test_vector_id: "cap-v1-smb".to_owned(),
        queue_max_objects: 64,
        queue_max_bytes: 1_048_576,
        resume_backoff_initial_ms: 10,
        resume_backoff_max_ms: 100,
        resume_max_attempts: 3,
    })
}

/// Der Profilhash eines Profils.
///
/// # Panics
///
/// Wenn das Profil nicht kodierbar ist.
#[must_use]
pub fn profile_hash(profile: &ArchiveBackendProfileV1) -> Hash32 {
    profile
        .profile_hash()
        .expect("das Profil der Fixture ist kodierbar")
}

/// Der Quellprofilhash der Migrationsfixture.
#[must_use]
pub fn source_profile_hash() -> Hash32 {
    profile_hash(&local_profile())
}

/// Der Zielprofilhash der Migrationsfixture.
#[must_use]
pub fn target_profile_hash() -> Hash32 {
    profile_hash(&target_local_profile())
}

/// Eine Policy, die genau `allowed` zulaesst.
fn policy_with(allowed: Vec<Hash32>) -> PolicyFieldsV1 {
    PolicyFieldsV1 {
        organization_id: OrganizationId::try_from(&[0x21_u8; 16][..])
            .expect("16 Bytes sind eine Organisationskennung"),
        policy_version: 1,
        previous_policy_object_hash: None,
        operating_profile: 0,
        max_registry_age_ms: 86_400_000,
        max_future_clock_skew_ms: 300_000,
        registry_expiry_behavior: 0,
        evidence_max_delay_ms: 60_000,
        reader_inactivity_ms: 900_000,
        reader_trust_refresh_ms: 86_400_000,
        reader_history_access_allowed: true,
        allowed_archive_profile_hashes: allowed,
        backup_frequency_ms: 86_400_000,
        restore_test_interval_ms: 2_592_000_000,
        retention_policy: RetentionPolicyFieldsV1 {
            minimum_retention_ms: None,
            destruction_enabled: false,
            eds_privacy_decision_document_hash: None,
        },
        free_text_policy: FreeTextPolicyFieldsV1 {
            free_text_allowed: false,
            rule_set_version: "1".to_owned(),
            local_pattern_warning_enabled: true,
        },
        allowed_crypto_suite_ids: vec!["EINSATZARCHIV-SUITE-1".to_owned()],
        allowed_format_versions: vec![1],
        effective_from_sequence: ChainSequence::new(0),
    }
}

/// Die gebundene Zulassung, die Quell- UND Zielprofil traegt.
#[must_use]
pub fn policy_allowing_source_and_target() -> BoundArchiveProfilePolicyV1 {
    let mut allowed = vec![source_profile_hash(), target_profile_hash()];
    allowed.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    BoundArchiveProfilePolicyV1::from_policy(&policy_with(allowed))
}

/// Die gebundene Zulassung, die NUR das Quellprofil traegt.
#[must_use]
pub fn policy_allowing_only_source() -> BoundArchiveProfilePolicyV1 {
    BoundArchiveProfilePolicyV1::from_policy(&policy_with(vec![source_profile_hash()]))
}

/// Die gebundene Zulassung, die das kontrollierte Netzprofil traegt.
#[must_use]
pub fn policy_allowing_controlled_network() -> BoundArchiveProfilePolicyV1 {
    BoundArchiveProfilePolicyV1::from_policy(&policy_with(vec![profile_hash(
        &controlled_network_profile(),
    )]))
}

/// Eine leere Zulassung: nichts ist erlaubt.
#[must_use]
pub fn policy_allowing_nothing() -> BoundArchiveProfilePolicyV1 {
    BoundArchiveProfilePolicyV1::from_policy(&policy_with(Vec::new()))
}

/// Der Capability-Testvektor der Fixture.
#[must_use]
pub fn capability_test_vector() -> CapabilityTestVectorV1 {
    CapabilityTestVectorV1::new("cap-v1-local", &[0x5a; 64])
        .expect("der Testvektor der Fixture ist gueltig")
}

/// Eine Ablage, die ihre Bytes mit ChaCha20-Poly1305 verschluesselt ablegt.
///
/// NUR FUER TESTS und ausdruecklich KEIN freigegebener Ruheort-Behaelter: der
/// Schluessel ist ein Fixturewert, und die Nonce wird DETERMINISTISCH aus der
/// Adresse abgeleitet. Zwei verschiedene Klartexte unter derselben Adresse
/// benutzten damit dieselbe Nonce — in einem Produktionsbehaelter waere das ein
/// Defekt. Die Fixture legt jede Adresse genau einmal ab.
///
/// Sie existiert, damit die Zusage „verschluesselte lokale Commit-Komponente"
/// MESSBAR ist: `bytes_at_rest` gibt den Chiffretext, `get` den Klartext.
pub struct AeadCommitStore {
    root: PathBuf,
    cek: SecretBytes<CEK_SIZE>,
}

impl AeadCommitStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            cek: SecretBytes::new([0x2b; CEK_SIZE]),
        }
    }

    fn absolute(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// Die deterministische Nonce dieser Adresse.
    fn nonce(relative: &str) -> SecretBytes<AEAD_NONCE_SIZE> {
        let digest = ea_crypto::object_hash(relative.as_bytes());
        let mut nonce = [0_u8; AEAD_NONCE_SIZE];
        nonce.copy_from_slice(&digest.as_bytes()[..AEAD_NONCE_SIZE]);
        SecretBytes::new(nonce)
    }
}

impl ea_archive_fs::AtRestEncryptedStoreV1 for AeadCommitStore {
    fn put(&self, relative: &str, bytes: &[u8]) -> Result<(), ea_archive::ArchiveBackendError> {
        let ciphertext = ea_crypto::aead_seal(
            &self.cek,
            &Self::nonce(relative),
            ea_crypto::SecretVec::new(bytes.to_vec()),
            relative.as_bytes(),
        )
        .map_err(|_| ea_archive::ArchiveBackendError::Io)?;
        let absolute = self.absolute(relative);
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent).map_err(|_| ea_archive::ArchiveBackendError::Io)?;
        }
        fs::write(absolute, ciphertext).map_err(|_| ea_archive::ArchiveBackendError::Io)
    }

    fn get(&self, relative: &str) -> Option<Vec<u8>> {
        let ciphertext = fs::read(self.absolute(relative)).ok()?;
        let opened = ea_crypto::aead_open(
            &self.cek,
            &Self::nonce(relative),
            &ciphertext,
            relative.as_bytes(),
        )
        .ok()?;
        Some(opened.with_exposed(<[u8]>::to_vec))
    }

    fn bytes_at_rest(&self, relative: &str) -> Option<Vec<u8>> {
        fs::read(self.absolute(relative)).ok()
    }

    fn remove(&self, relative: &str) {
        let _ = fs::remove_file(self.absolute(relative));
    }
}

/// Eine Ablage, die ihre Bytes im KLARTEXT ablegt.
///
/// Sie rundet fehlerfrei — `get` gibt genau zurueck, was `put` bekam — und wird
/// trotzdem abgewiesen: die Messung liest den Ruheort und findet dort den
/// Klartext der Sonde. Ohne diese Ablage waere „verschluesselt" nicht von
/// „unverschluesselt" unterscheidbar.
pub struct PlaintextCommitStore {
    root: PathBuf,
}

impl PlaintextCommitStore {
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl ea_archive_fs::AtRestEncryptedStoreV1 for PlaintextCommitStore {
    fn put(&self, relative: &str, bytes: &[u8]) -> Result<(), ea_archive::ArchiveBackendError> {
        let absolute = self.root.join(relative);
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent).map_err(|_| ea_archive::ArchiveBackendError::Io)?;
        }
        fs::write(absolute, bytes).map_err(|_| ea_archive::ArchiveBackendError::Io)
    }

    fn get(&self, relative: &str) -> Option<Vec<u8>> {
        fs::read(self.root.join(relative)).ok()
    }

    fn bytes_at_rest(&self, relative: &str) -> Option<Vec<u8>> {
        fs::read(self.root.join(relative)).ok()
    }

    fn remove(&self, relative: &str) {
        let _ = fs::remove_file(self.root.join(relative));
    }
}

/// Die VERSCHLUESSELTE lokale Commit-Komponente der Fixture.
#[must_use]
pub fn encrypted_local_commit(root: PathBuf) -> LocalCommitComponentV1 {
    LocalCommitComponentV1::new(root.clone(), Box::new(AeadCommitStore::new(root)))
}

/// Eine lokale Commit-Komponente, deren Ablage KLARTEXT schreibt.
#[must_use]
pub fn plaintext_local_commit(root: PathBuf) -> LocalCommitComponentV1 {
    LocalCommitComponentV1::new(root.clone(), Box::new(PlaintextCommitStore::new(root)))
}

/// Zwei SIGNIERTE Grants, die sich in mindestens einem Byte unterscheiden.
///
/// Sie muessen sich unterscheiden, weil `GrantV1::new` die Ausstellersignatur
/// prueft (`crates/ea-format/src/eag.rs`) — ein Literal genuegt also nicht, und
/// zwei bytegleiche Grants koennten den Bytekonflikt nicht belegen.
fn parsed_grant(bytes: &[u8]) -> Parsed<GrantV1> {
    match decode_exact_object(bytes).expect("die Grantbytes der Fixture parsen") {
        ParsedArchiveObject::Grant(grant) => grant,
        _ => panic!("die Fixture legt einen Grant ab"),
    }
}

#[must_use]
pub fn signed_grant_a() -> ExactObjectBytes {
    let parsed = parsed_grant(&format_support::valid_initial_eag());
    encode_grant(parsed.value()).expect("der Grant der Fixture kodiert")
}

#[must_use]
pub fn signed_grant_b() -> ExactObjectBytes {
    let parsed = parsed_grant(&format_support::valid_historical_eag());
    encode_grant(parsed.value()).expect("der Grant der Fixture kodiert")
}

/// Die Zieladresse, unter der die Capability-Tests staged.
#[must_use]
pub fn staged_path() -> ArchivePath {
    ArchivePath::in_dir(GRANTS_DIR_V1, "staged.eag").expect("die Adresse ist gueltig")
}

/// Eine Adresse, die die Fixture als „auf einem anderen Dateisystem" markiert.
#[must_use]
pub fn foreign_filesystem_path() -> ArchivePath {
    ArchivePath::in_dir(ENTRIES_DIR_V1, "foreign.eip").expect("die Adresse ist gueltig")
}

/// Ein Ziel, das seine Verbindung auf Kommando verliert und wiedererlangt.
///
/// DETERMINISTISCH und ohne Netz: der Vertrag, den `design.md` §11.5 an die
/// Publikationswarteschlange stellt, ist eine Zustandsaussage und keine
/// Netzmessung. Die native Zertifizierung eines echten Netzbackends bleibt
/// Stufe 7.
pub struct DisconnectingTarget {
    connected: Mutex<bool>,
    published: Mutex<Vec<(String, Vec<u8>)>>,
}

impl DisconnectingTarget {
    #[must_use]
    pub fn disconnected() -> Self {
        Self {
            connected: Mutex::new(false),
            published: Mutex::new(Vec::new()),
        }
    }
}

impl PublicationTargetV1 for DisconnectingTarget {
    fn is_connected(&self) -> bool {
        *self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn reconnect(&self) {
        *self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
    }

    fn publish_one(
        &self,
        relative: &ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        if !self.is_connected() {
            return Err(ea_archive::ArchiveBackendError::Io);
        }
        self.published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((relative.as_str().to_owned(), bytes.to_vec()));
        Ok(())
    }
}

/// Ein Ziel, das ERREICHBAR ist und die Publikation dennoch HART ablehnt.
///
/// Der Unterschied zu [`DisconnectingTarget`] ist der ganze Punkt: verlorene
/// Erreichbarkeit ist ein ZUSTAND (`Upload ausstehend`), ein Hartfehler ist ein
/// FEHLER. Beide muessen den aufgeschobenen Plan aufbewahren, sonst meldet der
/// naechste `resume` `synchronisiert`, obwohl nie etwas ankam.
///
/// Zwei Fixtureeigenschaften sind tragend:
///
/// 1. Der Ausfall liegt am ZWEITEN Objekt des Plans. Nur so belegt der
///    Wiederanlauf, dass der GANZE Plan aufbewahrt wurde und nicht bloss sein
///    unveroeffentlichter Rest.
/// 2. `publish_one` ist fuer bytegleiche Wiederholungen idempotent, weil das
///    reale Ziel Create-if-absent traegt. Ein blind anhaengender Zaehler
///    machte den Wiederanlauf zu einem Fixturebefund (doppeltes erstes Objekt)
///    statt zu einer Messung; abweichende Bytes an einer bereits belegten
///    Adresse laesst die Attrappe deshalb NICHT durchgehen.
pub struct HardFailingTarget {
    connected: Mutex<bool>,
    fails_hard: Mutex<bool>,
    published: Mutex<Vec<(String, Vec<u8>)>>,
}

impl HardFailingTarget {
    /// Anfangs getrennt, nach der Wiederverbindung ablehnend.
    #[must_use]
    pub fn disconnected_and_failing() -> Arc<Self> {
        Arc::new(Self {
            connected: Mutex::new(false),
            fails_hard: Mutex::new(true),
            published: Mutex::new(Vec::new()),
        })
    }

    /// Von Anfang an ERREICHBAR und ablehnend.
    ///
    /// Fuer den Weg ueber `publish`: dort nimmt die Warteschlange den Plan
    /// FRISCH an und laeuft ohne jede Trennung in den Hartfehler.
    #[must_use]
    pub fn connected_and_failing() -> Arc<Self> {
        Arc::new(Self {
            connected: Mutex::new(true),
            fails_hard: Mutex::new(true),
            published: Mutex::new(Vec::new()),
        })
    }

    /// Das Ziel nimmt ab jetzt an.
    pub fn repair(&self) {
        *self
            .fails_hard
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = false;
    }

    /// Die Adressen, die das Ziel TATSAECHLICH tragt, in Ankunftsreihenfolge.
    #[must_use]
    pub fn published_order(&self) -> Vec<String> {
        self.published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }
}

/// Der Griff, mit dem die Warteschlange dasselbe Ziel haelt wie die Fixture.
///
/// Die Warteschlange BESITZT ihr Ziel (`Box<dyn PublicationTargetV1>`); ohne
/// diesen Griff koennte der Test es nach dem Bau nicht mehr reparieren.
struct SharedHardFailingTarget(Arc<HardFailingTarget>);

impl PublicationTargetV1 for SharedHardFailingTarget {
    fn is_connected(&self) -> bool {
        *self
            .0
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn reconnect(&self) {
        *self
            .0
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
    }

    fn publish_one(
        &self,
        relative: &ArchivePath,
        bytes: &[u8],
    ) -> Result<(), ea_archive::ArchiveBackendError> {
        if !self.is_connected() {
            return Err(ea_archive::ArchiveBackendError::Io);
        }
        let mut published = self
            .0
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let address = relative.as_str().to_owned();
        if let Some((_, existing)) = published.iter().find(|(path, _)| path == &address) {
            assert_eq!(
                existing.as_slice(),
                bytes,
                "die Wiederaufnahme MUSS byteidentisch sein"
            );
            return Ok(());
        }
        if *self
            .0
            .fails_hard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            && !published.is_empty()
        {
            // Erreichbar und ablehnend, am ZWEITEN Objekt des Plans.
            //
            // `FlushFailed` und nicht `Io`, obwohl der Arm eine
            // Flush-Operation beschreibt: `Io` ist genau der Fehler, den die
            // Trennung liefert (siehe oben), und der Test MUSS den Hartfehler
            // vom Trennungspfad unterscheiden koennen. Der Arm ist hier
            // Stellvertreter fuer „das Ziel lehnt ab"; welchen Fehler ein
            // echtes Netzziel liefert, entscheidet Task 11.
            return Err(ea_archive::ArchiveBackendError::FlushFailed);
        }
        published.push((address, bytes.to_vec()));
        Ok(())
    }
}

/// Eine Warteschlange, deren Ziel nach der Wiederverbindung HART ablehnt.
///
/// Der Plan liegt nach dem Bau als `Upload ausstehend` in der Warteschlange und
/// das Ziel ist WIEDER erreichbar: der naechste `resume` laeuft also in den
/// Hartfehler und nicht in die Trennung.
///
/// # Panics
///
/// Wenn die Warteschlange nicht entsteht oder den Plan nicht aufschiebt.
#[must_use]
pub fn queue_with_a_reconnected_but_failing_target() -> (PublicationQueue, Arc<HardFailingTarget>) {
    let target = HardFailingTarget::disconnected_and_failing();
    let queue = PublicationQueue::new(
        Box::new(SharedHardFailingTarget(Arc::clone(&target))),
        controlled_network_profile(),
        &policy_allowing_controlled_network(),
    )
    .expect("die Warteschlange der Fixture muss entstehen");
    let state = queue
        .publish(two_grants_and_one_entry())
        .expect("die Warteschlange nimmt den Plan an");
    assert_eq!(
        state.sync_status(),
        ea_archive_fs::SyncStatus::UploadPending,
        "die Fixture MUSS eine WARTENDE Publikation hinterlassen"
    );
    let _ = queue.reconnect();
    (queue, target)
}

/// Eine Warteschlange, deren Ziel ERREICHBAR ist und HART ablehnt.
///
/// Sie ist LEER: der Plan wird ihr im Test frisch uebergeben. Nur so laeuft
/// der Weg ueber `publish` und nicht der ueber `resume`.
///
/// # Panics
///
/// Wenn die Warteschlange nicht entsteht.
#[must_use]
pub fn queue_on_a_connected_but_failing_target() -> (PublicationQueue, Arc<HardFailingTarget>) {
    let target = HardFailingTarget::connected_and_failing();
    let queue = PublicationQueue::new(
        Box::new(SharedHardFailingTarget(Arc::clone(&target))),
        controlled_network_profile(),
        &policy_allowing_controlled_network(),
    )
    .expect("die Warteschlange der Fixture muss entstehen");
    (queue, target)
}

/// Eine Warteschlange auf einem Ziel, das anfangs getrennt ist.
#[must_use]
pub fn queue_with_disconnecting_adapter() -> PublicationQueue {
    PublicationQueue::new(
        Box::new(DisconnectingTarget::disconnected()),
        controlled_network_profile(),
        &policy_allowing_controlled_network(),
    )
    .expect("die Warteschlange der Fixture muss entstehen")
}

/// Zwei Grants und ein Eintrag — in genau dieser Reihenfolge.
///
/// Grants VOR `.eip`: die Reihenfolge entscheidet Task 11, diese Fixture
/// belegt nur, dass die Warteschlange die uebergebene Reihenfolge bewahrt.
#[must_use]
pub fn two_grants_and_one_entry() -> PlannedPublicationV1 {
    let (_, eip) = archive_support::signed_entry_package();
    PlannedPublicationV1::new(vec![
        (
            ArchivePath::in_dir(GRANTS_DIR_V1, "a.eag").expect("die Adresse ist gueltig"),
            signed_grant_a().into_vec(),
        ),
        (
            ArchivePath::in_dir(GRANTS_DIR_V1, "b.eag").expect("die Adresse ist gueltig"),
            signed_grant_b().into_vec(),
        ),
        (
            ArchivePath::in_dir(ENTRIES_DIR_V1, "000001.eip").expect("die Adresse ist gueltig"),
            eip,
        ),
    ])
}

/// Die vollstaendige Migrationsfixture: Quellbestand, Zielwurzel, Policy,
/// Audit und ein gueltiger Nachweis.
pub struct MigrationHarness {
    _lock: MutexGuard<'static, ()>,
    root: PathBuf,
    source: LocalPathBackend,
    target: LocalPathBackend,
    policy: BoundArchiveProfilePolicyV1,
    audit: AuditHarness,
    anchor_bytes: Vec<u8>,
    /// Der gewaehlte Registrierungskopf. Er MUSS leben, solange der Migrator
    /// lebt: dessen Nachweispruefung leiht sich seine
    /// `PreexistingEffectiveNow`.
    head: SelectedRegistryHead,
    /// Die offenen Publikationen des QUELLPROFILS.
    ///
    /// Sie gehoeren der Fixture und nicht `migrator()`, weil der Migrator sie
    /// borgt und laenger leben wuerde als eine im Aufruf gebaute
    /// Warteschlange.
    ///
    /// FIXTUREVEREINFACHUNG, ausgeschrieben: ein `localPath`-Quellprofil hat
    /// gar keine Warteschlange (seine Queuegrenzen sind null). Die
    /// Warteschlange hier traegt deshalb das kontrollierte Netzprofil und
    /// steht fuer „das Quellprofil hat noch etwas offen" — die Zusage, die
    /// geprueft wird, ist der SCHRITT und nicht das Profil, an dem er haengt.
    pending: Vec<PublicationQueue>,
    /// Die Attrappen der HART ablehnenden Ziele, damit der Test sie nach dem
    /// Bau noch reparieren kann.
    hard_targets: Vec<Arc<HardFailingTarget>>,
}

impl MigrationHarness {
    /// Baut die Fixture mit `policy` als wirksamer Zulassung.
    ///
    /// # Panics
    ///
    /// Wenn die Temporaerwurzeln oder die Bestaende nicht anlegbar sind.
    #[must_use]
    pub fn new(policy: BoundArchiveProfilePolicyV1) -> Self {
        let (lock, root) = temp_root("migration");
        let source_root = root.join("source");
        let target_root = root.join("target");
        fs::create_dir_all(&source_root).expect("die Quellwurzel muss anlegbar sein");
        fs::create_dir_all(&target_root).expect("die Zielwurzel muss anlegbar sein");

        let complete = verify_support::complete_valid_archive();
        let source = LocalPathBackend::open(
            source_root,
            local_profile(),
            &BoundArchiveProfilePolicyV1::from_policy(&policy_with(vec![source_profile_hash()])),
        )
        .expect("der Quellbestand muss sich oeffnen lassen");
        for (path_hint, bytes) in complete.fixture.blobs() {
            source.materialize_for_test(path_hint, bytes);
        }
        let target = LocalPathBackend::open(
            target_root,
            target_local_profile(),
            &BoundArchiveProfilePolicyV1::from_policy(&policy_with(vec![target_profile_hash()])),
        )
        .expect("der Zielbestand muss sich oeffnen lassen");

        Self {
            _lock: lock,
            root,
            source,
            target,
            policy,
            audit: AuditHarness::new(),
            anchor_bytes: complete.anchor_bytes.clone(),
            head: selected_registry_head(),
            pending: Vec::new(),
            hard_targets: Vec::new(),
        }
    }

    /// Legt EINE noch nicht beendete Publikation des Quellprofils an.
    ///
    /// Das Ziel ist getrennt, der Plan liegt also nach `publish` als
    /// `Upload ausstehend` in der Warteschlange — genau der Zustand, den ein
    /// Profilwechsel nicht zuruecklassen darf.
    ///
    /// # Panics
    ///
    /// Wenn die Warteschlange nicht entsteht oder den Plan nicht annimmt.
    #[must_use]
    pub fn with_a_pending_source_publication(mut self) -> Self {
        let queue = queue_with_disconnecting_adapter();
        let state = queue
            .publish(two_grants_and_one_entry())
            .expect("die Warteschlange nimmt den Plan an");
        assert_eq!(
            state.sync_status(),
            ea_archive_fs::SyncStatus::UploadPending,
            "die Fixture MUSS eine WARTENDE Publikation hinterlassen"
        );
        self.pending.push(queue);
        self
    }

    /// Legt EINE aufgeschobene Publikation an, deren Ziel ERREICHBAR ist und
    /// dennoch HART ablehnt.
    ///
    /// Genau diese Kette ist der Pruefstein: der Wechsel bricht ab, der Plan
    /// MUSS aber in der Warteschlange bleiben, sonst faende ein zweiter
    /// Versuch eine leere Warteschlange, meldete `synchronisiert` und liefe
    /// durch, ohne dass die geplanten Objekte je beim Ziel angekommen sind.
    ///
    /// # Panics
    ///
    /// Wenn die Warteschlange nicht entsteht oder den Plan nicht aufschiebt.
    #[must_use]
    pub fn with_a_hard_failing_source_publication(mut self) -> Self {
        let (queue, target) = queue_with_a_reconnected_but_failing_target();
        self.pending.push(queue);
        self.hard_targets.push(target);
        self
    }

    /// Repariert jedes HART ablehnende Ziel dieser Fixture.
    pub fn repair_hard_failing_targets(&self) {
        for target in &self.hard_targets {
            target.repair();
        }
    }

    /// Die Adressen, die die HART ablehnenden Ziele tatsaechlich tragen.
    #[must_use]
    pub fn published_by_hard_failing_targets(&self) -> Vec<String> {
        self.hard_targets
            .iter()
            .flat_map(|target| target.published_order())
            .collect()
    }

    /// Stellt die Verbindung jeder offenen Warteschlange wieder her.
    pub fn reconnect_pending_publications(&self) {
        for queue in &self.pending {
            let _ = queue.reconnect();
        }
    }

    /// Der Migrator dieser Fixture, mit gueltigem Profilwechselnachweis.
    #[must_use]
    pub fn migrator(&self) -> ProfileMigrator<'_> {
        ProfileMigrator::new(
            MigrationSourceV1::new(&self.source, self.pending.iter().collect()),
            &self.target,
            &self.policy,
            self.audit.service(),
            &self.anchor_bytes,
            self.head.preexisting_effective_now(),
            profile_migration_proof(),
        )
        .expect("der Migrator der Fixture muss entstehen")
    }

    #[must_use]
    pub const fn audit(&self) -> &AuditHarness {
        &self.audit
    }

    #[must_use]
    pub const fn source(&self) -> &LocalPathBackend {
        &self.source
    }

    #[must_use]
    pub const fn target(&self) -> &LocalPathBackend {
        &self.target
    }

    #[must_use]
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

/// Die Fixture mit einer Policy, die Quell- UND Zielprofil traegt.
#[must_use]
pub fn migration_harness() -> MigrationHarness {
    MigrationHarness::new(policy_allowing_source_and_target())
}

/// Die Fixture mit einer noch nicht beendeten Publikation des Quellprofils.
#[must_use]
pub fn migration_harness_with_a_pending_publication() -> MigrationHarness {
    MigrationHarness::new(policy_allowing_source_and_target()).with_a_pending_source_publication()
}

/// Die Fixture mit einer Publikation, deren erreichbares Ziel HART ablehnt.
#[must_use]
pub fn migration_harness_with_a_hard_failing_publication() -> MigrationHarness {
    MigrationHarness::new(policy_allowing_source_and_target())
        .with_a_hard_failing_source_publication()
}

/// Die Fixture mit einer Policy, die das ZIELPROFIL nicht traegt.
#[must_use]
pub fn migration_harness_with_unlisted_target_profile() -> MigrationHarness {
    MigrationHarness::new(policy_allowing_only_source())
}

/// Alle Fehlerpunkte, in Deklarationsreihenfolge.
#[must_use]
pub fn all_fault_points() -> &'static [MigrationFaultPoint] {
    &MigrationFaultPoint::ALL
}

/// Ein Plan, der die Queuegrenze des Profils UEBERSCHREITET.
///
/// Die Grenze der Fixture ist `queue_max_objects = 64`; der Plan traegt mehr.
#[must_use]
pub fn planned_publication_beyond_the_queue_bound() -> PlannedPublicationV1 {
    let bytes = signed_grant_a().into_vec();
    let objects = (0..65)
        .map(|index| {
            (
                ArchivePath::in_dir(GRANTS_DIR_V1, &format!("bound-{index:04}.eag"))
                    .expect("die Adresse ist gueltig"),
                bytes.clone(),
            )
        })
        .collect();
    PlannedPublicationV1::new(objects)
}

/// Ein vollstaendiges Szenario des Gesundheitschecks.
///
/// Es haelt den materialisierten Bestand, das ERWARTETE Inventar, den freien
/// Speicher, den Capability-Bericht und — sofern das Szenario ihn braucht —
/// den Verifikationsbericht. `run` fuehrt genau die Erkenner aus.
pub struct HealthScenario {
    _lock: MutexGuard<'static, ()>,
    backend: LocalPathBackend,
    expected_inventory: ea_format::ArchiveInventoryListV1,
    free_space: FreeSpaceV1,
    capabilities: CapabilityReportV1,
    /// Der Verifikationsbericht — jedes Szenario traegt einen.
    ///
    /// Die fuenf Szenarien, deren Befund NICHT aus der Verifikation kommt,
    /// bringen einen fuer sie befundfreien Bericht mit; sie bilden ihn VOR dem
    /// eingespielten Schaden, weil `verify_archive` an einem beschaedigten
    /// Bestand hart fehlschlagen kann und die Fixture dann an ihrem eigenen
    /// `expect` scheiterte statt am Erkenner.
    verification: ea_verify::VerificationReportV1,
}

impl HealthScenario {
    /// Fuehrt den Gesundheitscheck aus.
    ///
    /// # Panics
    ///
    /// Wenn der Bestand nicht lesbar ist.
    #[must_use]
    pub fn run(&self) -> ArchiveHealthReport {
        ArchiveHealthCheckV1::new(
            &self.backend,
            &self.expected_inventory,
            self.free_space,
            &self.capabilities,
            &self.verification,
        )
        .run()
        .expect("der Gesundheitscheck muss laufen")
    }
}

/// Der erste Inventareintrag, der KEINE Beiwerkdatei ist.
///
/// Seit Task 10 traegt jeder Bestand das Formatbeiwerk, und `README-FORMAT.txt`
/// sortiert byteweise VOR jedem Layoutverzeichnis (`0x52` vor `0x61`) —
/// `entries()[0]` waere damit die Formatbeschreibung und nicht mehr ein
/// Archivobjekt. Die Szenarien „fehlende Datei" und „geaenderte Datei" wollen
/// aber genau ein ARCHIVOBJEKT beschaedigen; sonst messen sie die
/// Dauerhaftigkeit des Beiwerks und nicht die des Bestands.
///
/// # Panics
///
/// Wenn der Bestand ausser dem Beiwerk nichts traegt.
fn first_non_beiwerk_entry(inventory: &ea_format::ArchiveInventoryListV1) -> String {
    inventory
        .entries()
        .iter()
        .map(ea_format::ArchiveInventoryEntryV1::relative_path)
        .find(|relative| {
            !ea_archive_fs::FORMAT_PACKAGE_FILES_V1
                .iter()
                .any(|(beiwerk, _)| beiwerk == relative)
        })
        .expect("die Fixture MUSS mindestens ein Archivobjekt tragen")
        .to_owned()
}

/// Ein Bestand mit den Bytes von `blobs`, auf einer frischen Wurzel.
fn materialized(
    label: &str,
    blobs: &[(String, Vec<u8>)],
) -> (MutexGuard<'static, ()>, LocalPathBackend) {
    let (guard, root) = temp_root(label);
    let backend = LocalPathBackend::open(
        root.join("archive"),
        local_profile(),
        &BoundArchiveProfilePolicyV1::from_policy(&policy_with(vec![source_profile_hash()])),
    )
    .expect("der Bestand muss sich oeffnen lassen");
    for (path_hint, bytes) in blobs {
        backend.materialize_for_test(path_hint, bytes);
    }
    (guard, backend)
}

/// Der Capability-Bericht eines gesunden Wirtdateisystems.
fn proven_capabilities(backend: &LocalPathBackend) -> CapabilityReportV1 {
    backend
        .run_capability_test(&capability_test_vector())
        .expect("der Capability-Test muss laufen")
}

/// Reichlich freier Speicher.
const fn ample_free_space() -> FreeSpaceV1 {
    FreeSpaceV1 {
        required_bytes: 1_024,
        available_bytes: 1_048_576,
    }
}

/// Ein Verifikationslauf ueber `backend` gegen `anchor_bytes`.
fn verification_of(
    backend: &LocalPathBackend,
    anchor_bytes: &[u8],
) -> ea_verify::VerificationReportV1 {
    let anchor = ea_trust::decode_trust_anchor(anchor_bytes).expect("der Anker muss dekodieren");
    ea_verify::verify_archive(
        &backend.as_archive_source(),
        &anchor,
        ea_verify::VerifyOptions::new(UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1)),
    )
    .expect("der Verifikationslauf muss ein Ergebnis liefern")
}

/// Das Szenario eines UNVERSEHRTEN Bestands.
#[must_use]
pub fn intact_health_scenario() -> HealthScenario {
    let complete = verify_support::complete_valid_archive();
    let (lock, backend) = materialized("health-intact", complete.fixture.blobs());
    let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
    let capabilities = proven_capabilities(&backend);
    let verification = verification_of(&backend, &complete.anchor_bytes);
    HealthScenario {
        _lock: lock,
        backend,
        expected_inventory,
        free_space: ample_free_space(),
        capabilities,
        verification,
    }
}

/// Ein Szenario mit einem Rest unter der Kratzwurzel des Capability-Tests.
///
/// Ein abgebrochener Capability-Test laesst genau solche Bytes liegen. Sie sind
/// weder aus dem Inventar noch aus der Lesesicht ausgeblendet, also MUSS der
/// Gesundheitscheck sie melden.
#[must_use]
pub fn health_scenario_with_capability_scratch_leftover() -> HealthScenario {
    let complete = verify_support::complete_valid_archive();
    let (lock, backend) = materialized("health-scratch", complete.fixture.blobs());
    let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
    let capabilities = proven_capabilities(&backend);
    let verification = verification_of(&backend, &complete.anchor_bytes);
    backend.materialize_for_test(
        &format!(
            "{}/aborted-run/leftover.bin",
            ea_archive_fs::CAPABILITY_SCRATCH_DIR_V1
        ),
        b"Rest eines abgebrochenen Capability-Tests",
    );
    HealthScenario {
        _lock: lock,
        backend,
        expected_inventory,
        free_space: ample_free_space(),
        capabilities,
        verification,
    }
}

/// Ein Szenario, dessen FORMATBEIWERK ein veraendertes Byte traegt.
///
/// Es hebt genau die Kehrseite auf, die das Oeffnen unter der Sperre erlaubt:
/// ein Bestand mit abweichendem Beiwerkbyte laesst sich weiter oeffnen, und
/// deshalb MUSS der Gesundheitscheck die Abweichung befunden. Das Beiwerk ist
/// inventarisiert; der Befund ist damit `ModifiedFile` und braucht keinen
/// eigenen elften Erkenner.
///
/// Der Bestand wird nach dem Schaden ERNEUT geoeffnet — auf diesem Backend
/// laeuft der Check, und dass das zweite Oeffnen ueberhaupt traegt, ist die
/// halbe Aussage.
#[must_use]
pub fn health_scenario_with_a_tampered_beiwerk_byte() -> HealthScenario {
    let complete = verify_support::complete_valid_archive();
    let (lock, backend) = materialized("health-beiwerk", complete.fixture.blobs());
    let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
    let capabilities = proven_capabilities(&backend);
    let verification = verification_of(&backend, &complete.anchor_bytes);
    backend.overwrite_for_test(
        ea_archive::README_FORMAT_FILE_V1,
        b"eine andere Formatbeschreibung",
    );
    let reopened = LocalPathBackend::open(
        backend.root().to_path_buf(),
        local_profile(),
        &BoundArchiveProfilePolicyV1::from_policy(&policy_with(vec![source_profile_hash()])),
    )
    .expect("ein veraendertes Beiwerkbyte darf den Bestand nicht unoeffenbar machen");
    HealthScenario {
        _lock: lock,
        backend: reopened,
        expected_inventory,
        free_space: ample_free_space(),
        capabilities,
        verification,
    }
}

/// Das Szenario, das GENAU `finding` erzeugt.
///
/// # Panics
///
/// Wenn die Fixture ihren eigenen Bestand nicht materialisieren kann.
#[must_use]
pub fn health_scenario_for(finding: HealthFinding) -> HealthScenario {
    match finding {
        HealthFinding::MissingFile => {
            let complete = verify_support::complete_valid_archive();
            let (lock, backend) = materialized("health-missing", complete.fixture.blobs());
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            // ERST das Inventar UND den Verifikationsbericht, DANN das
            // Loeschen: die Erwartung entsteht vor dem Schaden, und der
            // Bericht des UNVERSEHRTEN Bestands ist fuer dieses Szenario
            // befundfrei — der Befund kommt allein vom Inventarvergleich.
            let verification = verification_of(&backend, &complete.anchor_bytes);
            backend.remove_for_test(&first_non_beiwerk_entry(&expected_inventory));
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                capabilities,
                verification,
            }
        }
        HealthFinding::ModifiedFile => {
            let complete = verify_support::complete_valid_archive();
            let (lock, backend) = materialized("health-modified", complete.fixture.blobs());
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            let verification = verification_of(&backend, &complete.anchor_bytes);
            backend.overwrite_for_test(
                &first_non_beiwerk_entry(&expected_inventory),
                b"andere Bytes",
            );
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                capabilities,
                verification,
            }
        }
        HealthFinding::OrphanGrantOrTemporaryFile => {
            let complete = verify_support::complete_valid_archive();
            let (lock, backend) = materialized("health-orphan", complete.fixture.blobs());
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            let verification = verification_of(&backend, &complete.anchor_bytes);
            backend.overwrite_for_test("entries/000000000001_entry.eip.staging", b"halb fertig");
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                capabilities,
                verification,
            }
        }
        HealthFinding::InsufficientFreeSpace => {
            let complete = verify_support::complete_valid_archive();
            let (lock, backend) = materialized("health-space", complete.fixture.blobs());
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            let verification = verification_of(&backend, &complete.anchor_bytes);
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: FreeSpaceV1 {
                    required_bytes: 1_048_576,
                    available_bytes: 1_024,
                },
                capabilities,
                verification,
            }
        }
        HealthFinding::UnsuitableFilesystemSemantics => {
            let complete = verify_support::complete_valid_archive();
            let (lock, backend) = materialized("health-semantics", complete.fixture.blobs());
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let verification = verification_of(&backend, &complete.anchor_bytes);
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                // KEINE Faehigkeit belegt — genau das ist ungeeignete
                // Dateisystemsemantik.
                capabilities: CapabilityReportV1::unproven(),
                verification,
            }
        }
        HealthFinding::HashSignatureOrChainError => {
            let mutated = verify_support::archive_with_one_mutated_entry(
                verify_support::MUTATED_EIP_SIGNATURE_OFFSET_V1,
            );
            let (lock, backend) = materialized("health-signature", mutated.fixture.blobs());
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            let verification = verification_of(&backend, &mutated.anchor_bytes);
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                capabilities,
                verification,
            }
        }
        HealthFinding::UnexpectedSequenceForkOrRollback => {
            let forked = verify_support::archive_with_swapped_predecessors();
            let (lock, backend) = materialized("health-fork", forked.fixture.blobs());
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            let verification = verification_of(&backend, &forked.anchor_bytes);
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                capabilities,
                verification,
            }
        }
        HealthFinding::MissingMandatoryGrant => {
            let without = verify_support::archive_without_a_recovery_grant();
            let (lock, backend) = materialized("health-grant", without.fixture.blobs());
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            let verification = verification_of(&backend, &without.anchor_bytes);
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                capabilities,
                verification,
            }
        }
        HealthFinding::IncompleteTrustData => {
            // Ein Bestand OHNE ein einziges Trust-Objekt: ohne Vertrauenskette
            // waehlt `verify_archive` keinen Registrierungskopf, und dann ist
            // ueber kein Objekt etwas gesagt.
            let complete = verify_support::complete_valid_archive();
            let without_trust = complete
                .fixture
                .blobs()
                .iter()
                .filter(|(path_hint, _)| !path_hint.starts_with("trust/"))
                .cloned()
                .collect::<Vec<_>>();
            let (lock, backend) = materialized("health-trust", &without_trust);
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            let verification = verification_of(&backend, &complete.anchor_bytes);
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                capabilities,
                verification,
            }
        }
        HealthFinding::InvalidOrUnauthorizedStub => {
            // Ein `.eds` OHNE Vernichtungsautorisierung: der Stummel ist da,
            // seine Autorisierung nicht.
            let complete = verify_support::complete_valid_archive();
            let mut blobs = complete.fixture.blobs().to_vec();
            let (entry, eip) = archive_support::signed_entry_package();
            blobs.push((
                format!("{}unauthorized.eds", ea_archive::DESTROYED_ENTRIES_DIR_V1),
                format_support::valid_eds_from_entry(&entry, &eip),
            ));
            let (lock, backend) = materialized("health-stub", &blobs);
            let expected_inventory = backend.inventory().expect("das Inventar muss entstehen");
            let capabilities = proven_capabilities(&backend);
            let verification = verification_of(&backend, &complete.anchor_bytes);
            HealthScenario {
                _lock: lock,
                backend,
                expected_inventory,
                free_space: ample_free_space(),
                capabilities,
                verification,
            }
        }
    }
}

/// Die Wurzel des ARBEITSBAUMS, erreicht aus `CARGO_MANIFEST_DIR`.
///
/// Dasselbe Muster wie `tools/xtask/tests/stage_gate.rs`: eine relative
/// Kletterei plus `canonicalize`, damit ein Test die eingecheckten Bytes lesen
/// kann, ohne einen Pfad zu erfinden.
///
/// # Panics
///
/// Wenn die Wurzel von `crates/ea-archive-fs` aus nicht erreichbar ist.
#[must_use]
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("die Arbeitsbaumwurzel muss von crates/ea-archive-fs aus erreichbar sein")
}

/// Die EINGECHECKTEN Bytes von `relative`, wurzelrelativ.
///
/// Der Vergleichswert der Beiwerktests kommt damit aus dem Arbeitsbaum und
/// nicht aus demselben `include_bytes!`, das die Produktion benutzt — sonst
/// waere die Gleichheit eine Tautologie und ein falscher Einbettungspfad
/// unsichtbar.
///
/// # Panics
///
/// Wenn die Datei nicht lesbar ist.
#[must_use]
pub fn repository_bytes(relative: &str) -> Vec<u8> {
    let path = workspace_root().join(relative);
    fs::read(&path).unwrap_or_else(|error| panic!("{relative} muss lesbar sein: {error}"))
}

/// Alle Pfade unter `schemas/`, RELATIV zu `schemas/`, ohne die
/// Kompatibilitaetsmatrix.
///
/// Die Matrix bleibt draussen, weil sie im Bestand nicht unter
/// `format/schemas/` liegt, sondern an ihrer eigenen Layoutadresse
/// (`ea_archive::COMPATIBILITY_MATRIX_FILE_V1`).
///
/// Die Liste entsteht durch einen LAUF ueber das Verzeichnis und nicht als
/// Literal: ein spaeter hinzugefuegtes Schema faellt damit in den Tests auf,
/// statt still in jedem neuen Bestand zu fehlen.
///
/// # Panics
///
/// Wenn `schemas/` nicht lesbar ist.
#[must_use]
pub fn repository_schema_paths() -> Vec<String> {
    let root = workspace_root().join("schemas");
    let mut found = Vec::new();
    collect_files_below(&root, "", &mut found);
    found.retain(|relative| relative != "compatibility-matrix.json");
    found.sort();
    found
}

/// Sammelt alle Dateien unter `directory` rekursiv, als `/`-getrennte Pfade.
fn collect_files_below(directory: &std::path::Path, prefix: &str, found: &mut Vec<String>) {
    let read = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} muss lesbar sein: {error}", directory.display()));
    for entry in read {
        let entry = entry.expect("jeder Verzeichniseintrag muss lesbar sein");
        let name = entry
            .file_name()
            .into_string()
            .expect("jeder Dateiname im Arbeitsbaum ist UTF-8");
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type().expect("der Eintragstyp muss lesbar sein");
        if kind.is_dir() {
            collect_files_below(&entry.path(), &relative, found);
        } else if kind.is_file() {
            found.push(relative);
        }
    }
}

/// Die Bytekarte einer Lesequelle: relativer Pfad -> Abdruck der Bytes.
///
/// Sie ist der Vergleichsmassstab des Buendelexports und laeuft ueber den PORT
/// und nicht ueber ein Dateisystem — nur so vergleicht dieselbe Funktion das
/// Verzeichnis mit dem Buendel. Der Abdruck ist [`ea_crypto::object_hash`] und
/// damit ein domainseparierter SHA-256 ueber die exakten Bytes; er wird als
/// rohes `[u8; 32]` gehalten, weil die Hashtypen der Stufe 1 absichtlich kein
/// `Debug` tragen und ein Kartenvergleich sonst nicht assertierbar waere.
///
/// # Panics
///
/// Wenn die Quelle sich nicht vollstaendig durchlaufen laesst.
#[must_use]
pub fn digest_map_of(source: &dyn ea_archive::ArchiveSource) -> BTreeMap<String, [u8; 32]> {
    let mut map = BTreeMap::new();
    source
        .visit_blobs(&mut |blob: ea_archive::ArchiveBlob<'_>| {
            map.insert(
                blob.path_hint().to_owned(),
                *ea_crypto::object_hash(blob.bytes()).as_bytes(),
            );
            Ok(())
        })
        .expect("die Quelle muss sich durchlaufen lassen");
    map
}

/// Die Pfadhinweise einer Lesequelle, in Durchlaufreihenfolge.
///
/// # Panics
///
/// Wie [`digest_map_of`].
#[must_use]
pub fn path_hints_of(source: &dyn ea_archive::ArchiveSource) -> Vec<String> {
    let mut hints = Vec::new();
    source
        .visit_blobs(&mut |blob: ea_archive::ArchiveBlob<'_>| {
            hints.push(blob.path_hint().to_owned());
            Ok(())
        })
        .expect("die Quelle muss sich durchlaufen lassen");
    hints
}

/// Die Fixture des Ein-Datei-Buendelexports.
///
/// Beide Seiten kommen aus DEMSELBEN [`LocalPathBackend`] ueber einer eigenen
/// Temporaerwurzel: die Schreibseite fuer den Export, die Lesesicht
/// desselben Backends als Verzeichnisvergleich. Sie greift ausdruecklich NICHT
/// nach `FsArchiveSource` — der Typ lebt in `ea-recovery`, und die
/// Abhaengigkeitsrichtung ist `apps/cli` -> `ea-recovery`, niemals
/// `ea-archive-fs` -> `ea-recovery`.
///
/// Das Buendelziel liegt AUSSERHALB der Bestandswurzel. Laege es darin, waere
/// es selbst eine Bytesequenz des Bestands, und der zweite Export truege den
/// ersten.
pub struct BundleHarness {
    _lock: MutexGuard<'static, ()>,
    root: PathBuf,
    backend: LocalPathBackend,
    anchor: ea_trust::TrustAnchorV1,
}

impl BundleHarness {
    /// Ein vollstaendiger, abgeschlossener Bestand auf einer frischen Wurzel.
    ///
    /// # Panics
    ///
    /// Wenn die Wurzel oder der Bestand nicht anlegbar ist.
    #[must_use]
    pub fn finalized_archive() -> Self {
        let complete = verify_support::complete_valid_archive();
        let (lock, root) = temp_root("bundle");
        let backend = LocalPathBackend::open(
            root.join("archive"),
            local_profile(),
            &BoundArchiveProfilePolicyV1::from_policy(&policy_with(vec![source_profile_hash()])),
        )
        .expect("der Bestand muss sich oeffnen lassen");
        for (path_hint, bytes) in complete.fixture.blobs() {
            backend.materialize_for_test(path_hint, bytes);
        }
        Self {
            _lock: lock,
            root,
            backend,
            anchor: complete.anchor(),
        }
    }

    /// Derselbe Bestand, dessen erster Eintrag ABGESCHNITTEN ist.
    ///
    /// Die Bytes behalten ihr Exact-Object-Praefix — sie bleiben also ein
    /// Archivobjekt und werden nicht still zu Beiwerk —, und der Parser
    /// scheitert dahinter. Der Lauf liefert damit einen BERICHT MIT BEFUND und
    /// keinen harten Fehlschlag: genau der Zustand, an dem der Export abbrechen
    /// MUSS.
    ///
    /// # Panics
    ///
    /// Wenn der Bestand keinen Eintrag traegt.
    #[must_use]
    pub fn with_truncated_entry(self) -> Self {
        let inventory = self
            .backend
            .inventory()
            .expect("das Inventar muss entstehen");
        let entry = inventory
            .entries()
            .iter()
            .map(ea_format::ArchiveInventoryEntryV1::relative_path)
            .find(|relative| relative.ends_with(".eip"))
            .expect("die Fixture MUSS einen Eintrag tragen")
            .to_owned();
        let bytes = self
            .backend
            .read_for_test(&entry)
            .expect("der Eintrag muss lesbar sein");
        assert!(
            bytes.len() > 16,
            "ein Eintrag MUSS laenger sein als sein Praefix"
        );
        self.backend
            .overwrite_for_test(&entry, &bytes[..bytes.len() / 2]);
        self
    }

    #[must_use]
    pub const fn backend(&self) -> &LocalPathBackend {
        &self.backend
    }

    #[must_use]
    pub const fn anchor(&self) -> &ea_trust::TrustAnchorV1 {
        &self.anchor
    }

    /// Die Betriebssystemuhr der Fixture.
    ///
    /// GENAU die der Bestandsfixture: sie waehlt den Registrierungskopf, und
    /// eine zweite Uhr waehlte zufaellig einen anderen.
    #[must_use]
    pub const fn os_wall_clock(&self) -> UnixMillis {
        UnixMillis::new(verify_support::FIXTURE_OS_WALL_CLOCK_V1)
    }

    /// Die Verifikationsstellschrauben des Vergleichslaufs.
    ///
    /// OHNE Empfaengerschluessel — genau wie der Lauf INNERHALB des Exports.
    /// Zwei verschiedene Stellschrauben ergaeben zwei verschiedene Berichte,
    /// und die Berichtsgleichheit waere nicht mehr die gemessene Aussage.
    #[must_use]
    pub const fn options(&self) -> ea_verify::VerifyOptions<'static> {
        ea_verify::VerifyOptions::new(self.os_wall_clock())
    }

    /// Die Lesesicht des Verzeichnisses als [`ea_archive::ArchiveSource`].
    #[must_use]
    pub const fn directory_source(&self) -> ea_archive_fs::LocalPathArchiveSource<'_> {
        self.backend.as_archive_source()
    }

    /// Die Bytekarte des Verzeichnisses.
    #[must_use]
    pub fn digest_map(&self) -> BTreeMap<String, [u8; 32]> {
        digest_map_of(&self.directory_source())
    }

    #[must_use]
    pub fn bundle_path(&self) -> PathBuf {
        self.bundle_path_named("bundle")
    }

    #[must_use]
    pub fn bundle_path_named(&self, name: &str) -> PathBuf {
        self.root.join(format!(
            "{name}.{}",
            ea_archive_fs::BUNDLE_FILE_EXTENSION_V1
        ))
    }

    /// Exportiert und liefert die Containerbytes.
    ///
    /// # Panics
    ///
    /// Wenn der Export nicht gelingt oder die Zieldatei nicht lesbar ist.
    #[must_use]
    pub fn exported_bytes(&self) -> Vec<u8> {
        let target = self.bundle_path_named("exported");
        ea_archive_fs::write_archive_bundle(
            self.backend(),
            self.anchor(),
            self.os_wall_clock(),
            &target,
        )
        .expect("der Export muss gelingen");
        fs::read(&target).expect("die Zieldatei muss lesbar sein")
    }

    /// Derselbe Bestand, dem das FORMATBEIWERK fehlt.
    ///
    /// Er ist der einzige Weg, Schritt 1 des Exports ueberhaupt zu beobachten:
    /// [`LocalPathBackend::open`] materialisiert das Beiwerk selbst, und auf
    /// einem so erzeugten Bestand ist der Schritt ein Leerlauf, den kein Test
    /// von seiner Abwesenheit unterscheiden koennte. Hier liegt beim Oeffnen
    /// eine FREMDE Schreibersperre, das Beiwerk wird deshalb
    /// [`FormatPackageOutcomeV1::Deferred`] — und danach wird die Sperre
    /// weggenommen, damit der Export sie nehmen kann.
    ///
    /// # Panics
    ///
    /// Wenn das Beiwerk NICHT aufgeschoben wurde — dann messte der Test nichts.
    #[must_use]
    pub fn without_the_format_package() -> Self {
        let complete = verify_support::complete_valid_archive();
        let (lock, root) = temp_root("bundle-deferred");
        let archive_root = root.join("archive");
        fs::create_dir_all(&archive_root).expect("die Bestandswurzel muss anlegbar sein");
        let lock_file = archive_root.join(ea_archive_fs::CONTROL_FILES_V1[0]);
        fs::write(&lock_file, b"").expect("die Sperrdatei muss anlegbar sein");
        let backend = LocalPathBackend::open(
            archive_root,
            local_profile(),
            &BoundArchiveProfilePolicyV1::from_policy(&policy_with(vec![source_profile_hash()])),
        )
        .expect("der Bestand muss sich oeffnen lassen");
        assert_eq!(
            backend.format_package_outcome(),
            ea_archive_fs::FormatPackageOutcomeV1::Deferred,
            "die Fixture MUSS einen Bestand OHNE Beiwerk hinterlassen"
        );
        fs::remove_file(&lock_file).expect("die Sperrdatei muss entfernbar sein");
        for (path_hint, bytes) in complete.fixture.blobs() {
            backend.materialize_for_test(path_hint, bytes);
        }
        Self {
            _lock: lock,
            root,
            backend,
            anchor: complete.anchor(),
        }
    }

    /// Ein Kopf, der `count` Blobs BEHAUPTET, und ein leerer Index.
    ///
    /// Er belegt, dass der Leser die Blobgrenze aus dem KOPF durchsetzt, bevor
    /// er einen Index anfasst — sonst muesste ein Angreifer erst 1 048 577
    /// Indexsaetze mitliefern, um die Grenze ueberhaupt zu erreichen.
    #[must_use]
    pub fn synthetic_index_claiming(count: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ea_archive_fs::BUNDLE_HEADER_BYTES_V1);
        bytes.extend_from_slice(&ea_archive_fs::BUNDLE_MAGIC_V1);
        bytes.extend_from_slice(
            &u64::try_from(count)
                .expect("die Blobzahl der Fixture passt in u64")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes
    }
}
