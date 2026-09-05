//! Die Kulisse der Zeremonienzeugen.
//!
//! Vier Zusagen tragen dieses Modul:
//!
//! 1. **Kein zweiter Kryptobaukasten.** Registrierungslinie, Anker, Objekte und
//!    Signaturen kommen unveraendert aus dem `#[path]`-eingebundenen
//!    Supportmodul von `ea-trust`. Hier wird nichts davon nachgebaut.
//! 2. **Der Bedienernachweis ist ECHT.** Er entsteht durch
//!    `OperatorAuthenticator::reauthenticate` gegen einen gewaehlten
//!    Registrierungskopf, wie in `crates/ea-archive-fs/tests/support/mod.rs`.
//!    Ein frei gebauter Nachweis uebersprang genau die Pruefungen, die ihm
//!    seinen Wert geben.
//! 3. **Der Auditdienst ist ECHT.** Die Attrappe implementiert
//!    [`LocalAuditRepository`] und nicht [`LocalAuditService`]:
//!    `SignedLocalAuditEvent::sealed` ist `pub(crate)` in `ea-audit`, ein
//!    fremder Dienst koennte das Ergebnis also gar nicht bauen. Signieren und
//!    Buchen bleiben beim echten [`SignedLocalAuditService`]; diese Attrappe
//!    belegt nur, dass die Zeile TATSAECHLICH angekommen ist — und laesst den
//!    ersten Anhaengevorgang auf Wunsch scheitern.
//! 4. **Der Schluesselport ist der PRODUKTIVE.** Der Wurzelprovider dieses
//!    Moduls implementiert `ea_key_provider::KeyProvider` ueber
//!    `CoseSign1Bytes::compose` und haelt den Wurzelschluessel der
//!    `ea-trust`-Fixture. `InMemoryKeyProvider` leitet seine Schluessel aus
//!    einem Startwert ab und traefe den Wurzelschluessel der Linie nicht.
//!
//! `#[path]`-Includes werden je Testziel uebersetzt; daher `allow(dead_code)`
//! auf Modulebene, genau wie im eingebundenen Modul.
#![allow(dead_code)]

/// Das Supportmodul aus `ea-trust`, unveraendert weiterverwendet.
#[path = "../../../ea-trust/tests/support/mod.rs"]
pub mod trust_support;

use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use ea_admin::RootCeremonyService;
use ea_audit::{
    AuditError, LocalAuditRepository, LocalAuditService, SignedLocalAuditEvent,
    SignedLocalAuditService,
};
use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_format::{
    CertificateKindV1, KeyProtectionProfileV1, OperatorRoleV1, TrustPayloadV1, TrustSubtypeV1,
};
use ea_key_provider::{
    CoseSign1Bytes, KeyError, KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose,
};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose,
};
use ea_time::TrustedTimeState;
use ea_trust::{
    AdminAuthorizationReplayKey, ClockReleaseReplayKey, IndependentTimeCommit,
    PersistedTrustRecord, RegistryHeadPin, RegistrySelectionCommit, RegistrySelectionOutcome,
    SelectedRegistryHead, StateStoreError, TrustStateKey, TrustStateStore, VerifiedTrust,
    prepare_local_time, select_registry_head, verify_registry_candidate,
};
use ea_types::{
    CertificateHash, ChainSequence, DeviceId, EventId, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};

use trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

/// Der Bedienerinstanzschluessel der Fixture — ein ECHTES Ed25519-Paar.
const INSTANCE_SECRET: [u8; 32] = [
    0x4a, 0x1c, 0x2e, 0x93, 0x77, 0x05, 0xbb, 0x61, 0x18, 0x8f, 0xd2, 0x40, 0x36, 0xa7, 0x5c, 0xe1,
    0x09, 0x94, 0x6d, 0x3b, 0xcf, 0x82, 0x17, 0x50, 0xe4, 0x2a, 0x68, 0xd9, 0x0b, 0x73, 0xf6, 0x84,
];

/// Ein ANDERER Wurzelschluessel: derselbe Port, aber nicht der Schluessel, den
/// die Linie als Wurzel fuehrt.
const FOREIGN_ROOT_SECRET: [u8; 32] = [
    0x1f, 0x3d, 0x55, 0x02, 0xa9, 0xc4, 0x6e, 0x17, 0x8b, 0x20, 0x74, 0xdd, 0x91, 0x0c, 0x38, 0xf2,
    0x46, 0xe7, 0xb1, 0x5a, 0x23, 0x9d, 0x60, 0xcc, 0x08, 0x71, 0x4f, 0xa3, 0xd6, 0x12, 0x89, 0x35,
];

const BINDING_MARKER: u8 = 0x71;

/// Die Betriebssystemuhr der Fixture.
///
/// Sie liegt IM Fenster der Administrationsautorisierung: `HeadOptions`
/// vergibt `issuedAt = 100`, und die Fixture setzt `expiresAt = issuedAt +
/// 1_000`. Derselbe Wert ist die `PreexistingEffectiveNow` des gewaehlten
/// Kopfes, gegen die `OperatorSessionProof::is_valid_for` bewertet — zwei Uhren
/// hiessen zwei Zeitfenster, und eines von beiden waere zufaellig das falsche.
pub const FIXTURE_NOW_MS: i64 = 1_000;

/// Die Sequenz, an der die Fixture ihren Kopf waehlt — im Fenster des
/// LETZTEN Uebergangs, der die Bedienerbindung traegt.
const PROPOSED_SEQUENCE: u64 = 30;

const FIXTURE_NOT_AFTER_MS: i64 = 10_000_000;

/// Die Sequenz, an der die Autorisierung des Ziels gebraucht wird.
///
/// Die Wirksamkeit des ERSTEN Uebergangs. Das Ziel der Zeremonie ist sein
/// direktes Ziel, und das ist keine Bequemlichkeit: `VerifiedTrust::previous_head`
/// ist der aus dem Anker bewiesene Bootstrap-Stand — Registrierung NULL —, und
/// die Autorisierung eines Ziels nennt genau den Stand, auf dem sie beruht.
/// Ein spaeterer Uebergang beruhte auf einem spaeteren Kopf und braeuchte
/// dessen Auswahl als `head`-Argument.
pub const TARGET_SEQUENCE: u64 = 1;

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

fn policy_action() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

/// Alles, was ein Zeuge ueber die gebaute Linie wissen muss.
pub struct CeremonyLine {
    pub line: RegistryLineBuilder,
    /// Die Nutzlast des Ziels — genau die, die der letzte Uebergang
    /// Wurzel-signiert hat.
    pub target_payload: TrustPayloadV1,
    pub target_object_hash: ObjectHash,
    pub binding_object_hash: ObjectHash,
    pub writer_certificate_object_hash: ObjectHash,
    pub root_certificate_hash: CertificateHash,
}

/// Baut die Registrierungslinie der Zeremonie.
///
/// Deterministisch: feste Geheimnisse, feste Marken, feste Fenster. Zwei
/// Aufrufe liefern dieselbe Linie, denselben Zielhash und dieselbe Nutzlast.
///
/// Drei Uebergaenge. Das direkte Ziel des ERSTEN ist das Objekt, das die
/// Zeremonie veroeffentlicht; die beiden weiteren tragen das
/// Writer-Zertifikat und die Bedienerbindung, gegen die der Praesenznachweis
/// ausgestellt wird.
///
/// # Panics
///
/// Wenn die Fixture ihre eigenen direkten Ziele nicht baut.
#[must_use]
pub fn ceremony_line() -> CeremonyLine {
    let mut line = RegistryLineBuilder::new();
    let root_certificate_hash = CertificateHash::from(line.current_root_hash());
    let (target_head, target_payload) =
        line.push_returning_direct_payload(policy_action(), head_options(1, 10));
    let target_object_hash = target_head
        .direct_object_hash
        .expect("ein Policy-Uebergang traegt ein direktes Ziel");
    let writer = line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x61,
            effective_from: None,
        },
        head_options(11, 20),
    );
    let writer_certificate_object_hash = writer
        .direct_object_hash
        .expect("das Writer-Zertifikat der Fixture ist ein direktes Ziel");
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer_certificate_object_hash,
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
                .expect("ein Thumbprint ist 32 Byte"),
            )),
            ..head_options(21, 100)
        },
    );
    let binding_object_hash = binding
        .direct_object_hash
        .expect("die Bedienerbindung der Fixture ist ein direktes Ziel");
    CeremonyLine {
        target_object_hash,
        target_payload: target_payload.expect("eine Policy traegt ein direktes Ziel"),
        binding_object_hash,
        writer_certificate_object_hash,
        root_certificate_hash,
        line,
    }
}

/// Der gepruefte Bestand dieser Linie, ohne Pin.
#[must_use]
pub fn verified(line: &RegistryLineBuilder) -> VerifiedTrust {
    line.verified(Pin::None)
}

/// Der Speicher, aus dem die Kopfauswahl ihren persistierten Stand liest.
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

/// Waehlt den letzten Kopf der Linie an [`PROPOSED_SEQUENCE`].
///
/// # Panics
///
/// Wenn die Fixture ihren eigenen aktuellen Kopf nicht waehlt.
#[must_use]
pub fn selected_head(line: &RegistryLineBuilder) -> SelectedRegistryHead {
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
        panic!("die Fixture muss ihren eigenen aktuellen Kopf waehlen");
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

/// Ein ECHTER Praesenznachweis fuer `purpose`, gegen den gewaehlten Kopf.
///
/// # Panics
///
/// Wenn die Bindung an der gewaehlten Sequenz nicht aktiv ist oder die
/// Wiederanmeldung scheitert.
#[must_use]
pub fn operator_proof(
    head: &SelectedRegistryHead,
    binding_object_hash: ObjectHash,
    purpose: ReauthPurpose,
) -> OperatorSessionProof {
    let bound = BoundOperator::resolve(head, binding_object_hash)
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

/// Der Schluesselport der Fixture: EIN Ed25519-Schluessel hinter der
/// oeffentlichen Portschnittstelle.
///
/// Er implementiert `KeyProvider` vollstaendig und komponiert seine
/// COSE-Bytes ueber `CoseSign1Bytes::compose` — dieselbe Fassade, die ein
/// nativer Provider benutzt. Er haelt den Wurzelschluessel der
/// `ea-trust`-Fixture, weil die Zeremonie das autorisierte Ziel Byte fuer Byte
/// reproduzieren koennen muss; `InMemoryKeyProvider` leitet seine Schluessel
/// aus einem Startwert ab und traefe ihn nie.
pub struct FixtureKeyProvider {
    secret: [u8; 32],
}

impl FixtureKeyProvider {
    /// Der Provider, der den Wurzelschluessel DIESER Linie haelt.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            secret: trust_support::root_signing_secret(),
        }
    }

    /// Ein Provider mit einem FREMDEN Schluessel — derselbe Port, ein anderer
    /// Unterzeichner.
    #[must_use]
    pub const fn foreign() -> Self {
        Self {
            secret: FOREIGN_ROOT_SECRET,
        }
    }

    /// Die Adresse des Eintrags dieses Providers.
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
        let public = CanonicalPublicCoseKey::ed25519(key.verifying_key().to_bytes())
            .map_err(KeyError::Crypto)?;
        let protected =
            ProtectedHeader::normal(content_type, public.thumbprint(), certificate_hash);
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

/// Die ANHAENGENDE Auditablage der Fixture, im Speicher.
///
/// `failures_remaining` laesst die naechsten `n` Anhaengevorgaenge scheitern.
/// Genau eine Fehlzahl macht die Fail-closed-Zusage messbar: der erste
/// Anhaengevorgang — die Zeile mit dem Ausgang `completed` — scheitert, der
/// zweite — die Zeile mit dem Ausgang `failed` — gelingt und ist danach
/// ablesbar.
pub struct InMemoryAuditRepository {
    events: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
    order: Mutex<Vec<[u8; 16]>>,
    failures_remaining: Mutex<usize>,
}

impl InMemoryAuditRepository {
    #[must_use]
    pub fn new(failures_remaining: usize) -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
            order: Mutex::new(Vec::new()),
            failures_remaining: Mutex::new(failures_remaining),
        }
    }

    /// Die gebuchten Zeilen in der Reihenfolge ihres Anhaengens.
    #[must_use]
    pub fn booked(&self) -> Vec<Vec<u8>> {
        let events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        self.order
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(|id| events.get(id).cloned())
            .collect()
    }
}

impl LocalAuditRepository for InMemoryAuditRepository {
    fn append(&self, event: &SignedLocalAuditEvent) -> Result<(), AuditError> {
        {
            let mut remaining = self
                .failures_remaining
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *remaining > 0 {
                *remaining -= 1;
                return Err(AuditError::NotFound);
            }
        }
        let id = *event.id().as_bytes();
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, event.exact_bytes().to_vec());
        self.order
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(id);
        Ok(())
    }

    fn event(&self, _id: EventId) -> Result<SignedLocalAuditEvent, AuditError> {
        // Von aussen nicht baubar und fuer diese Zeugen nicht gebraucht: sie
        // lesen die Bytes ueber `InMemoryAuditRepository::booked`.
        Err(AuditError::NotFound)
    }
}

/// Der Auditapparat der Fixture: echter Dienst, beobachtbare Ablage.
pub struct AuditHarness {
    repository: Arc<InMemoryAuditRepository>,
    service: SignedLocalAuditService,
}

impl AuditHarness {
    /// Baut den Dienst je Kopfauswahl — `SignedLocalAuditService::new` bindet
    /// `effective_now` BEIM BAUEN.
    #[must_use]
    pub fn new(
        head: &SelectedRegistryHead,
        signer_certificate_object_hash: ObjectHash,
        failures: usize,
    ) -> Self {
        let repository = Arc::new(InMemoryAuditRepository::new(failures));
        let provider = Arc::new(FixtureKeyProvider::root());
        let handle = provider.handle();
        let service = SignedLocalAuditService::new(
            Arc::clone(&repository) as Arc<dyn LocalAuditRepository>,
            provider as Arc<dyn KeyProvider>,
            handle,
            signer_certificate_object_hash,
            head.preexisting_effective_now().value(),
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

    #[must_use]
    pub fn booked(&self) -> Vec<Vec<u8>> {
        self.repository.booked()
    }
}

/// Eine Zeile, wie sie in einer Tabelle laege. Der Primaerschluessel IST die
/// Sperre — genau wie bei `clock_release_replays`.
type ReplayRow = ([u8; 16], [u8; 16], [u8; 32]);

fn replay_row(key: &AdminAuthorizationReplayKey) -> ReplayRow {
    (
        *key.organization_id().as_bytes(),
        *key.authorization_id().as_bytes(),
        *key.nonce(),
    )
}

/// Der Speicher HINTER dem Speicherwert.
///
/// Er lebt ausserhalb jedes [`PersistentStore`] — so wie eine Tabelle
/// ausserhalb des Prozesses liegt, der sie beschreibt. Ein zweiter Lauf oeffnet
/// einen NEUEN [`PersistentStore`] ueber DIESES Backing.
#[derive(Default)]
pub struct ReplayTable(Vec<ReplayRow>);

impl ReplayTable {
    /// Ob die Tabelle noch keine verbrauchte Autorisierung fuehrt.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Ein Speicherwert ueber einer laufuebergreifenden Tabelle.
pub struct PersistentStore {
    table: Arc<Mutex<ReplayTable>>,
}

impl PersistentStore {
    #[must_use]
    pub fn open(table: &Arc<Mutex<ReplayTable>>) -> Self {
        Self {
            table: Arc::clone(table),
        }
    }
}

impl TrustStateStore for PersistentStore {
    fn load(&mut self, _key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
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

    /// Pruefen und Setzen in EINEM Zug — die Form, die `replay_nonces` als
    /// `INSERT … ON CONFLICT DO NOTHING` traegt.
    fn admin_authorization_consumed(
        &mut self,
        key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        let row = replay_row(key);
        if table.0.contains(&row) {
            return Ok(true);
        }
        table.0.push(row);
        Ok(false)
    }
}

/// Ein Speicher, der die Sperre NICHT fuehrt.
pub struct StoreWithoutReplayLock;

impl TrustStateStore for StoreWithoutReplayLock {
    fn load(&mut self, _key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
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

/// Der Dienst der Fixture ueber `provider`.
#[must_use]
pub fn ceremony_service<'a>(
    head: &'a SelectedRegistryHead,
    provider: &'a FixtureKeyProvider,
    audit: &'a AuditHarness,
    ceremony: &CeremonyLine,
) -> RootCeremonyService<'a> {
    RootCeremonyService::new(
        head,
        provider,
        provider.handle(),
        ceremony.root_certificate_hash,
        audit.service(),
        ceremony.binding_object_hash,
    )
}

/// Der Subtyp des Ziels dieser Fixture.
#[must_use]
pub const fn target_subtype() -> TrustSubtypeV1 {
    TrustSubtypeV1::Policy
}
