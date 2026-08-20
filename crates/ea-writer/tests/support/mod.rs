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
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
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
    ChainId, ChainSequence, DeviceId, Hash32, KeyThumbprint, ObjectHash, OrganizationId, UnixMillis,
};
use ea_writer::{FinalizationInputV1, WriterBindingV1, WriterService};
use ed25519_dalek::{Signer as _, SigningKey};

use trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

/// Der Bedienerinstanzschluessel der Fixture — ein ECHTES Ed25519-Paar.
const INSTANCE_SECRET: [u8; 32] = [
    0x2f, 0x8d, 0x11, 0x4c, 0x63, 0xa0, 0xde, 0x57, 0x94, 0x21, 0xbb, 0x0e, 0x77, 0xf3, 0x48, 0x9c,
    0x15, 0x6a, 0xd2, 0x30, 0xcb, 0x84, 0x39, 0x62, 0xe1, 0x0d, 0x5f, 0xa7, 0x48, 0x76, 0x91, 0x23,
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
            binding_operator_profile_commitment_override: Some(expected_profile_commitment(
                trust_support::organization(),
            )),
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

/// Die geoeffnete Fixture.
pub struct WriterHarness {
    _lock: MutexGuard<'static, ()>,
    root: PathBuf,
    provider: Arc<InMemoryKeyProvider>,
    database: Arc<EncryptedDatabase>,
    repository: Arc<dyn DraftRepository>,
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

        let database = open_database(&root, &provider);
        seed_operator_profile(&database, &built);
        let repository: Arc<dyn DraftRepository> = Arc::new(AutosaveDraftRepository::new(
            Arc::clone(&database),
            Arc::clone(&provider) as Arc<dyn KeyProvider>,
        ));
        let draft = repository
            .load_or_create()
            .expect("der Entwurf der Fixture muss entstehen");
        repository
            .save(draft.with_notes("CANARY-INCIDENT-TEXT"))
            .expect("die Fixture muss speichern koennen");

        let binding = WriterBindingV1 {
            binding_object_hash: built.binding_object_hash,
            writer_certificate_hash: built.writer_certificate_hash.into(),
            writer_key_thumbprint: writer_public.thumbprint(),
            writer_signing_handle,
            chain_id: ChainId::try_from(&[0x50; 16][..]).expect("16 Byte"),
            archive_profile_hash: profile_hash,
            head_issued_at: UnixMillis::new(FIXTURE_ISSUED_AT_MS),
        };

        Self {
            _lock: lock,
            root,
            provider,
            database,
            repository,
            backend,
            head,
            binding,
            line: built.line,
        }
    }

    /// Der Dienst dieser Fixture.
    ///
    /// `source` kommt von aussen, weil [`Self::source`] einen kurzlebigen
    /// Adapter auf das Backend liefert: haelte die Fixture ihn, waere sie
    /// selbstreferenziell. Der Test haelt ihn, und der Dienst leiht ihn.
    #[must_use]
    pub fn service<'a>(&'a self, source: &'a dyn ea_archive::ArchiveSource) -> WriterService<'a> {
        WriterService::new(
            Arc::clone(&self.repository),
            Arc::clone(&self.provider) as Arc<dyn KeyProvider>,
            &self.backend,
            source,
            &self.head,
            &[],
            IncidentNumberRegister::new(Arc::clone(&self.database)),
            OperatorProfileRepository::new(Arc::clone(&self.database)),
            self.binding,
        )
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

    #[must_use]
    pub fn repository(&self) -> Arc<dyn DraftRepository> {
        Arc::clone(&self.repository)
    }

    #[must_use]
    pub fn provider(&self) -> Arc<InMemoryKeyProvider> {
        Arc::clone(&self.provider)
    }

    #[must_use]
    pub fn database(&self) -> Arc<EncryptedDatabase> {
        Arc::clone(&self.database)
    }

    /// Ein ECHTER Praesenznachweis fuer `purpose`, gegen den gewaehlten Head.
    #[must_use]
    pub fn proof_for(&self, purpose: ReauthPurpose) -> OperatorSessionProof {
        let bound = BoundOperator::resolve(&self.head, self.binding.binding_object_hash)
            .expect("die Bindung der Fixture ist an der gewaehlten Sequenz aktiv");
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
            .expect("die Fixture meldet den gebundenen Bediener wieder an")
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

    /// Beansprucht die Nummer der Fixture VORAB im Register.
    ///
    /// Sie isoliert die Anspruchspruefung von der Kettenfortschreibung: ein
    /// zweiter Abschluss im selben Bestand faellt schon an Schritt 3, weil der
    /// gebundene Head fuer die verbrauchte Sequenz gewaehlt ist.
    pub fn preclaim_incident_number(&self) {
        IncidentNumberRegister::new(Arc::clone(&self.database))
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
        self.repository
            .load_or_create()
            .map(|draft| draft.notes().is_empty())
            .unwrap_or(false)
    }

    /// Ob der `draftDEK` des aktiven Entwurfs noch da ist.
    #[must_use]
    pub fn draft_dek_is_present(&self) -> bool {
        self.repository.load_or_create().is_ok()
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

fn open_database(root: &std::path::Path, provider: &InMemoryKeyProvider) -> Arc<EncryptedDatabase> {
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

/// Ein gueltiger Einsatz — dieselben Werte bei jedem Aufruf.
///
/// Die Typen sind nicht `Clone` (Stufe 1 gibt sie bewusst nicht heraus), also
/// baut jeder Aufruf sie NEU. Zwei Aufrufe ergeben denselben Inhalt und damit
/// dieselbe Vorschau — das ist die Voraussetzung dafuer, dass `finalize` den
/// `previewHash` nachrechnen kann.
#[must_use]
pub fn valid_incident() -> FinalizationInputV1 {
    FinalizationInputV1 {
        timezone: "Europe/Berlin".to_owned(),
        source: NativeSourceV1::new("ea.writer.fixture", 1)
            .expect("die Quelle der Fixture ist gueltig"),
        human_incident_number: FIXTURE_INCIDENT_NUMBER.to_owned(),
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
