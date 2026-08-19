//! Die Fixture der Auditests.
//!
//! Sie baut eine ECHTE Registry-Linie, waehlt einen ECHTEN Head und loest die
//! Bedienerbindung durch `SelectedRegistryHead::active_operator_binding_fields`
//! auf — wie `crates/ea-operator/tests/session_contract.rs`. Eine frei gebaute
//! Bindung oder ein frei gebauter Nachweis wuerde genau die Pruefungen
//! ueberspringen, die dem Praesenznachweis seinen Wert geben.

#![allow(dead_code)]

use std::{
    cell::RefCell,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use ea_audit::{
    LocalAuditRepository, LocalAuditService, SignedLocalAuditService, SqliteLocalAuditRepository,
};
use ea_crypto::CanonicalPublicCoseKey;
use ea_format::{CertificateKindV1, KeyProtectionProfileV1, OperatorRoleV1};
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::EncryptedDatabase;
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
    ChainSequence, DeviceId, Hash32, KeyThumbprint, ObjectHash, OrganizationId, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};

use crate::trust_support::{self, ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

/// Der Bedienerinstanzschluessel der Fixture — ein ECHTES Ed25519-Paar.
const INSTANCE_SECRET: [u8; 32] = [
    0x4a, 0x1c, 0x2e, 0x93, 0x77, 0x05, 0xbb, 0x61, 0x18, 0x8f, 0xd2, 0x40, 0x36, 0xa7, 0x5c, 0xe1,
    0x09, 0x94, 0x6d, 0x3b, 0xcf, 0x82, 0x17, 0x50, 0xe4, 0x2a, 0x68, 0xd9, 0x0b, 0x73, 0xf6, 0x84,
];
const BINDING_MARKER: u8 = 0x71;
const FIXTURE_NOW_MS: i64 = 1_000;
const PROPOSED_SEQUENCE: u64 = 30;
const FIXTURE_NOT_AFTER_MS: i64 = 10_000_000;
const FIXTURE_PROVIDER_SEED: [u8; 32] = [0x6b; 32];
const DATABASE_FILE: &str = "writer.sqlite3";

static HARNESS_LOCK: Mutex<()> = Mutex::new(());

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

/// Baut die Linie und nennt Bindung und Writer-Zertifikat.
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

fn selected_registry_head() -> SelectedRegistryHead {
    let (line, _, _) = build_line();
    let head_index = line.heads().len() - 1;
    let head = line.heads()[head_index];
    let key = trust_support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(FIXTURE_NOW_MS));
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
        prepare_local_time(&mut store, &candidate, UnixMillis::new(FIXTURE_NOW_MS), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(selected) =
        select_registry_head(candidate, local_time, None).unwrap()
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
///
/// Sie implementiert AUSSCHLIESSLICH die beiden Plattformhaken; Kontoabgleich,
/// Instanzschluesselpruefung und Ausstellung liegen im Standardkoerper von
/// `OperatorAuthenticator::reauthenticate`.
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

/// Die Fixture.
pub struct AuditHarness {
    _lock: MutexGuard<'static, ()>,
    root: PathBuf,
    provider: Arc<InMemoryKeyProvider>,
    database_key: ea_key_provider::KeyHandle,
    binding_object_hash: ObjectHash,
    service: SignedLocalAuditService,
    reopened: OnceLock<SqliteLocalAuditRepository>,
}

impl AuditHarness {
    #[must_use]
    pub fn new() -> Self {
        let lock = HARNESS_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("ea-audit-{}-{nanos}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let provider = Arc::new(InMemoryKeyProvider::new_for_test(FIXTURE_PROVIDER_SEED));
        let database_key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let database = Arc::new(
            EncryptedDatabase::open(&root.join(DATABASE_FILE), provider.as_ref(), &database_key)
                .expect("die verschluesselte Datenbank muss sich oeffnen lassen"),
        );
        let signing_handle = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();

        let (_, binding_object_hash, writer_certificate_object_hash) = build_line();
        let repository: Arc<dyn LocalAuditRepository> =
            Arc::new(SqliteLocalAuditRepository::new(Arc::clone(&database)));
        let service = SignedLocalAuditService::new(
            repository,
            Arc::clone(&provider) as Arc<dyn KeyProvider>,
            signing_handle,
            writer_certificate_object_hash,
            UnixMillis::new(FIXTURE_NOW_MS),
        );

        Self {
            _lock: lock,
            root,
            provider,
            database_key,
            binding_object_hash,
            service,
            reopened: OnceLock::new(),
        }
    }

    #[must_use]
    pub fn audit_service(&self) -> &dyn LocalAuditService {
        &self.service
    }

    /// Ein ECHTER Praesenznachweis, gegen den gewaehlten Head ausgestellt.
    ///
    /// Die Bindung wird unmittelbar vorher neu aufgeloest, wie
    /// `BoundOperator::resolve` es verlangt: ein Nachweis gilt fuenf Minuten ab
    /// der Zeit DIESER Aufloesung.
    #[must_use]
    pub fn operator_session(&self) -> OperatorSessionProof {
        let head = selected_registry_head();
        let bound = BoundOperator::resolve(&head, self.binding_object_hash)
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
            .reauthenticate(account, ReauthPurpose::Finalize)
            .expect("die Fixture meldet den gebundenen Bediener wieder an")
    }

    /// Oeffnet die Datenbank ERNEUT und liest die Auditzeilen der neuen
    /// Verbindung.
    #[must_use]
    pub fn reopen_audit(&self) -> &dyn LocalAuditRepository {
        self.reopened.get_or_init(|| {
            // DERSELBE Griff, nicht ein neu erzeugter: ein zweites `generate`
            // schriebe frisches Material an dieselbe Adresse und waere nur
            // deshalb unauffaellig, weil die Epoche des In-Prozess-Providers
            // ohne ein `delete` unveraendert bleibt. Der Test soll das
            // Wiederoeffnen belegen und nicht diese Feinheit.
            let database = Arc::new(
                EncryptedDatabase::open(
                    &self.root.join(DATABASE_FILE),
                    self.provider.as_ref(),
                    &self.database_key,
                )
                .expect(
                    "dieselbe Datenbank muss sich mit demselben Schluessel wieder oeffnen lassen",
                ),
            );
            SqliteLocalAuditRepository::new(database)
        })
    }
}
