//! Die Kulisse des Wirksamkeitszeugen.
//!
//! Vier Zusagen tragen dieses Modul:
//!
//! 1. **Kein zweiter Kryptobaukasten.** Registrierungslinie, Anker, Objekte
//!    und Signaturen kommen unveraendert aus dem `#[path]`-eingebundenen
//!    Supportmodul von `ea-trust` — demselben, das
//!    `tests/ea-system-tests/tests/task8_trust_time.rs` einbindet. Hier wird
//!    nichts davon nachgebaut.
//! 2. **Der Zustandsspeicher lebt ueber den ganzen Zeugen.** Er wird EINMAL
//!    gebaut und ueber alle Anwendungen hinweg weitergereicht; erst dadurch
//!    ist die Einmaligkeit einer Uhrfreigabe ueberhaupt messbar. Eine
//!    Attrappe, die `clock_release_consumed` fest mit `false` beantwortet,
//!    koennte eine Wiedereinspielung nicht von einem Erstverbrauch
//!    unterscheiden.
//! 3. **Der Bedienernachweis ist ECHT.** Er entsteht durch
//!    `OperatorAuthenticator::reauthenticate` gegen einen gewaehlten
//!    Registrierungskopf. Ein frei gebauter Nachweis uebersprang genau die
//!    Pruefungen, die ihm seinen Wert geben.
//! 4. **Der Auditdienst ist der PRODUKTIVE.** `SignedLocalAuditService`
//!    signiert und bucht; die Attrappe implementiert nur
//!    [`LocalAuditRepository`], weil `SignedLocalAuditEvent::sealed`
//!    `pub(crate)` in `ea-audit` ist und ein fremder Dienst das Ergebnis gar
//!    nicht bauen koennte.
//!
//! `#[path]`-Includes werden je Testziel uebersetzt; daher `allow(dead_code)`
//! auf Modulebene, genau wie im eingebundenen Modul.
#![allow(dead_code)]

/// Das Supportmodul aus `ea-trust`, unveraendert weiterverwendet.
#[path = "../../../../crates/ea-trust/tests/support/mod.rs"]
pub mod trust_support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use ea_audit::{AuditError, LocalAuditRepository, SignedLocalAuditEvent, SignedLocalAuditService};
use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{
    CoseSign1Bytes, KeyError, KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose,
};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose,
};
use ea_time::TrustedTimeState;
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin,
    RegistrySelectionCommit, SelectedRegistryHead, StateStoreError, TrustStateKey, TrustStateStore,
};
use ea_types::{
    CertificateHash, DeviceId, EventId, Hash32, ObjectHash, OrganizationId, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};

/// Der Kontobindungshash, den die Bindung nennt und das Konto zurueckmeldet.
pub const OS_ACCOUNT_MARKER: u8 = 0x77;

/// Der Instanzschluessel der Bedienerin dieser Kulisse.
///
/// Ein eigener Vektor: die Bootstrap-Adminbindungen der `ea-trust`-Linie
/// nennen einen ausgedachten Instanzabdruck, den KEIN echter Schluessel
/// trifft — gegen sie liesse sich `reauthenticate` nicht durchfuehren.
pub const INSTANCE_SECRET: [u8; 32] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5, 0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe,
];

#[must_use]
pub fn signing_key(secret: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&secret)
}

#[must_use]
pub fn public_key(secret: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(signing_key(secret).verifying_key().to_bytes())
        .expect("der Fixturschluessel bleibt kanonisch")
}

// ===========================================================================
// Die Zustandsablage
// ===========================================================================

/// Der Speicher, der Kopf, Zeit UND Freigabesperre fuehrt.
///
/// Er wird pro Zeuge EINMAL gebaut und ueber alle Anwendungen hinweg
/// weitergereicht: Nonce-Sperre, Zeitboden und gebundener Kopf sind genau
/// dann beobachtbar, wenn sie einen Aufruf ueberleben.
pub struct WorkflowStore {
    key: TrustStateKey,
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
    consumed: Vec<([u8; 16], [u8; 16], [u8; 32])>,
    selection_commits: usize,
    independent_commits: usize,
}

impl WorkflowStore {
    #[must_use]
    pub fn new(
        key: TrustStateKey,
        revision: u64,
        trusted_time: TrustedTimeState,
        pinned_head: Option<RegistryHeadPin>,
    ) -> Self {
        Self {
            key,
            revision,
            trusted_time,
            pinned_head,
            consumed: Vec::new(),
            selection_commits: 0,
            independent_commits: 0,
        }
    }

    #[must_use]
    pub const fn key(&self) -> TrustStateKey {
        self.key
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn trusted_time(&self) -> &TrustedTimeState {
        &self.trusted_time
    }

    #[must_use]
    pub const fn pinned_head(&self) -> Option<RegistryHeadPin> {
        self.pinned_head
    }

    #[must_use]
    pub const fn selection_commits(&self) -> usize {
        self.selection_commits
    }

    #[must_use]
    pub const fn independent_commits(&self) -> usize {
        self.independent_commits
    }

    /// Wie viele Freigaben dauerhaft verbraucht sind.
    ///
    /// Zaehlt AUSSCHLIESSLICH; die Nonce selbst verlaesst diesen Typ nie.
    #[must_use]
    pub fn consumed_releases(&self) -> usize {
        self.consumed.len()
    }

    fn record(&self) -> PersistedTrustRecord {
        PersistedTrustRecord::new(self.revision, self.trusted_time.clone(), self.pinned_head)
    }
}

impl TrustStateStore for WorkflowStore {
    fn load(&mut self, key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key {
            return Err(StateStoreError::Conflict);
        }
        Ok(self.record())
    }

    fn commit_independent_time(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || expected_revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        if commit.next_trusted_time().floor() < self.trusted_time.floor() {
            return Err(StateStoreError::MonotonicityViolation);
        }
        self.independent_commits += 1;
        self.revision += 1;
        self.trusted_time = commit.next_trusted_time().clone();
        Ok(self.record())
    }

    fn clock_release_consumed(
        &mut self,
        key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Ok(self.consumed.contains(&(
            *key.organization_id().as_bytes(),
            *key.target_device_id().as_bytes(),
            *key.nonce(),
        )))
    }

    /// Kopf, Zeit UND Sperre in EINEM Zug — genau die Atomizitaet, die
    /// `RegistrySelectionCommit` zusagt.
    fn commit_registry_selection(
        &mut self,
        key: TrustStateKey,
        expected_revision: u64,
        commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        if key != self.key || expected_revision != self.revision {
            return Err(StateStoreError::Conflict);
        }
        if commit.next_trusted_time().floor() < self.trusted_time.floor() {
            return Err(StateStoreError::MonotonicityViolation);
        }
        if let Some(replay) = commit.replay_key() {
            let tuple = (
                *replay.organization_id().as_bytes(),
                *replay.target_device_id().as_bytes(),
                *replay.nonce(),
            );
            if self.consumed.contains(&tuple) {
                return Err(StateStoreError::ReplayAlreadyConsumed);
            }
            self.consumed.push(tuple);
        }
        self.selection_commits += 1;
        self.revision += 1;
        self.trusted_time = commit.next_trusted_time().clone();
        self.pinned_head = Some(*commit.next_head());
        Ok(self.record())
    }
}

// ===========================================================================
// Der Schluesselport und die Auditablage
// ===========================================================================

/// Der PRODUKTIVE Signierport ueber EINEM Ed25519-Schluessel.
///
/// `InMemoryKeyProvider` leitet seine Schluessel aus einem Startwert ab und
/// traefe den Geraeteschluessel der Linie nicht; `ea_crypto::CoseSigner` ist
/// an dieser Stelle ausdruecklich verboten
/// (`crates/ea-key-provider/src/contract.rs`).
pub struct FixtureKeyProvider {
    secret: [u8; 32],
}

impl FixtureKeyProvider {
    #[must_use]
    pub const fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    #[must_use]
    pub fn handle(&self) -> KeyHandle {
        KeyHandle::new(
            KeystoreProvider::InMemory,
            trust_support::hash32(0x11),
            SecretPurpose::WriterSigningKey,
        )
    }
}

impl KeyProvider for FixtureKeyProvider {
    fn generate(
        &self,
        _purpose: SecretPurpose,
        _protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, KeyError> {
        Err(KeyError::ForbiddenPurpose)
    }

    fn sign(
        &self,
        _handle: &KeyHandle,
        content_type: ContentType,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        let key = signing_key(self.secret);
        let protected = ProtectedHeader::normal(
            content_type,
            public_key(self.secret).thumbprint(),
            certificate_hash,
        );
        let signature = key.sign(&protected.sig_structure_bytes(payload));
        CoseSign1Bytes::compose(&protected, payload, &signature.to_bytes())
    }

    fn wrap_secret(
        &self,
        _purpose: SecretPurpose,
        _secret: SecretBytes<32>,
    ) -> Result<KeyHandle, KeyError> {
        Err(KeyError::ForbiddenPurpose)
    }

    fn unwrap_secret(&self, _handle: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        Err(KeyError::ForbiddenPurpose)
    }

    fn unwrap_database_key(&self, _handle: &KeyHandle) -> Result<SecretVec, KeyError> {
        Err(KeyError::ForbiddenPurpose)
    }

    fn delete(&self, _handle: &KeyHandle) -> Result<(), KeyError> {
        Err(KeyError::ForbiddenPurpose)
    }

    fn contains(&self, _handle: &KeyHandle) -> Result<bool, KeyError> {
        Ok(true)
    }

    fn reached_protection_profile(
        &self,
        _handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        Ok(KeyProtectionProfileV1::OsWrapped)
    }
}

/// Die ANHAENGENDE Auditablage der Kulisse, im Speicher.
pub struct MemoryAuditRepository {
    events: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
}

impl MemoryAuditRepository {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
        }
    }

    #[must_use]
    pub fn booked(&self) -> usize {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl Default for MemoryAuditRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalAuditRepository for MemoryAuditRepository {
    fn append(&self, event: &SignedLocalAuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*event.id().as_bytes(), event.exact_bytes().to_vec());
        Ok(())
    }

    fn event(&self, _id: EventId) -> Result<SignedLocalAuditEvent, AuditError> {
        Err(AuditError::NotFound)
    }
}

/// Der Auditapparat: echter Dienst, beobachtbare Ablage.
pub struct AuditHarness {
    repository: Arc<MemoryAuditRepository>,
    service: SignedLocalAuditService,
}

impl AuditHarness {
    /// `effective_now` ist die `raw_now` DER Bewertung, ueber die die Zeile
    /// spricht — bei der Uhrfreigabe die der GESPERRTEN Bewertung und nicht
    /// die des gewaehlten Kopfes.
    #[must_use]
    pub fn new(signer_certificate_object_hash: ObjectHash, effective_now: UnixMillis) -> Self {
        let repository = Arc::new(MemoryAuditRepository::new());
        let provider = Arc::new(FixtureKeyProvider::new(
            trust_support::device_signing_secret(),
        ));
        let handle = provider.handle();
        let service = SignedLocalAuditService::new(
            Arc::clone(&repository) as Arc<dyn LocalAuditRepository>,
            provider as Arc<dyn KeyProvider>,
            handle,
            signer_certificate_object_hash,
            effective_now,
        );
        Self {
            repository,
            service,
        }
    }

    #[must_use]
    pub const fn service(&self) -> &SignedLocalAuditService {
        &self.service
    }

    #[must_use]
    pub fn booked(&self) -> usize {
        self.repository.booked()
    }
}

// ===========================================================================
// Der Bedienernachweis
// ===========================================================================

struct Account;

impl OsAccountProvider for Account {
    fn os_account_binding_hash(
        &self,
        _organization_id: OrganizationId,
        _device_id: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(trust_support::hash32(OS_ACCOUNT_MARKER))
    }

    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(Some(public_key(INSTANCE_SECRET)))
    }
}

struct Authenticator {
    bound: BoundOperator,
}

impl OperatorAuthenticator for Authenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }

    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        Ok(signing_key(INSTANCE_SECRET).sign(challenge).to_bytes())
    }
}

/// Ein ECHTER Praesenznachweis fuer `purpose`, gegen den gewaehlten Kopf.
///
/// # Panics
///
/// Wenn die Bindung an der gewaehlten Sequenz nicht aktiv ist oder die
/// Wiederanmeldung scheitert — beides waere ein Fehler der Kulisse und kein
/// Befund des Zeugen.
#[must_use]
pub fn operator_proof(
    head: &SelectedRegistryHead,
    binding_object_hash: ObjectHash,
    purpose: ReauthPurpose,
) -> OperatorSessionProof {
    let bound = BoundOperator::resolve(head, binding_object_hash)
        .expect("die Adminbindung der Kulisse ist an der gewaehlten Sequenz aktiv");
    Authenticator { bound }
        .reauthenticate(Box::new(Account), purpose)
        .expect("die Kulisse meldet die gebundene Adminbedienerin wieder an")
}
