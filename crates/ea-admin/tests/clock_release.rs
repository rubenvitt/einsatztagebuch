//! Die Zeugen der Uhrfreigabe: Ausstellung, Verbrauch, Bedienfuehrung.
//!
//! Drei Zusagen tragen diese Datei:
//!
//! 1. **Kein zweiter Kryptobaukasten.** Registrierungslinie, Anker, Objekte und
//!    Signaturen kommen unveraendert aus dem `#[path]`-eingebundenen
//!    Supportmodul von `ea-trust`. Hier wird nichts davon nachgebaut.
//! 2. **Der Bedienernachweis ist ECHT.** Er entsteht durch
//!    `OperatorAuthenticator::reauthenticate` gegen einen gewaehlten
//!    Registrierungskopf. Ein frei gebauter Nachweis uebersprang genau die
//!    Pruefungen, die ihm seinen Wert geben.
//! 3. **Der Auditdienst ist der PRODUKTIVE.** `SignedLocalAuditService`
//!    signiert und bucht; die Attrappe implementiert nur
//!    [`LocalAuditRepository`], weil `SignedLocalAuditEvent::sealed`
//!    `pub(crate)` in `ea-audit` ist.
//!
//! Der handgeschriebene Kodierer am Ende der Datei ist der Kodierer aus
//! `crates/ea-trust/tests/clock_release.rs:83-200`, unveraendert uebernommen.
//! Er baut die Abweichungen, die ein GETYPTER Aufrufer nicht bauen kann: einen
//! Begruendungscode ausserhalb `0..2`, eine TSA-Referenz, einen abgesenkten
//! Floor und die vier Fenstergrenzen.
#![allow(clippy::too_many_lines)]

/// Das Supportmodul aus `ea-trust`, unveraendert weiterverwendet.
#[path = "../../ea-trust/tests/support/mod.rs"]
mod trust_support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use ea_admin::clock_release::{
    ClockReleaseAvailability, ClockReleaseRequest, ClockReleaseService, ClockReleaseWorkflowError,
    apply_clock_release,
};
use ea_audit::{AuditError, LocalAuditRepository, SignedLocalAuditEvent, SignedLocalAuditService};
use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, ProtectedHeader, SecretBytes, SecretVec,
};
use ea_format::{
    ClockReleaseJustificationV1, KeyProtectionProfileV1, OperatorRoleV1, decode_clock_release_audit,
};
use ea_key_provider::{
    CoseSign1Bytes, KeyError, KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose,
};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose,
};
use ea_time::{IndependentTimeInput, IndependentTimeKind, TrustedTimeState};
use ea_trust::{
    ClockReleaseReplayKey, IndependentTimeCommit, PersistedTrustRecord, RegistryCandidate,
    RegistryHeadPin, RegistrySelectionCommit, RegistrySelectionOutcome, SelectedRegistryHead,
    StateStoreError, TrustStateKey, TrustStateStore, VerifiedTrust, prepare_local_time,
    select_registry_head, verify_registry_candidate,
};
use ea_types::{
    CertificateHash, ChainSequence, DeviceId, EventId, Hash32, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};
use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::{Encoder, data::Tag};

use trust_support::{ActionSpec, HeadOptions, Pin, RegistryLineBuilder};

// ===========================================================================
// Die Zahlen der Kulisse
// ===========================================================================

/// Die Marke, unter der die Linie ihr Adminzertifikat und seine Bindung baut.
const ADMIN_MARKER: u8 = 0x11;
/// Das Geraet des Adminzertifikats — `ActionSpec::AdminIssue` bildet es als
/// `marker + 0x40` (`crates/ea-trust/tests/support/mod.rs`).
const ADMIN_DEVICE: u8 = ADMIN_MARKER.wrapping_add(0x40);
/// Der Kontobindungshash, den die Bindung nennt und das Konto meldet.
const OS_ACCOUNT_MARKER: u8 = 0x77;
/// Die gebundene Wachrichtlinie erlaubt 50 ms Vorlauf.
const GUARD_SKEW_MS: u64 = 50;
/// Der persistierte Zeit-Floor.
const FLOOR_MS: i64 = 3_100;
/// Die gepruefte Zeit der persistierten unabhaengigen Referenz.
const REFERENCE_MS: i64 = 3_000;
/// Eine Wanduhr INNERHALB der Grenze: `3_000 <= 3_000 + 50`.
const UNBLOCKED_WALL_MS: i64 = 3_000;
/// Eine Wanduhr JENSEITS der Grenze: `3_201 > 3_000 + 50`.
const BLOCKED_WALL_MS: i64 = 3_201;
/// `raw_now` der gesperrten Bewertung: `max(3_100, 3_201)`.
const BLOCKED_NOW_MS: i64 = BLOCKED_WALL_MS;
/// `raw_now` der ungesperrten Bewertung: `max(3_100, 3_000)`.
const HEAD_NOW_MS: i64 = FLOOR_MS;
/// Die untere Grenze des Freigabefensters.
const ISSUED_AT_MS: i64 = 3_150;
/// Die obere Grenze des Freigabefensters.
const EXPIRES_AT_MS: i64 = 3_250;
/// Der persistierte Anfangsstand der Zustandsablage.
const INITIAL_REVISION: u64 = 17;
/// Die Sequenz, an der die Zeugen den aktuellen Kopf vorschlagen.
const PROPOSED_SEQUENCE: u64 = 25;
/// Der Index des Kopfes, an dem die Kulisse pinnt.
const GUARD_HEAD_INDEX: usize = 3;

/// Der Instanzschluessel der Bedienerin dieser Kulisse.
///
/// Ein eigener Vektor: die Bootstrap-Adminbindungen der `ea-trust`-Linie
/// nennen einen ausgedachten Instanzabdruck, den KEIN echter Schluessel
/// trifft — gegen sie liesse sich `reauthenticate` nicht durchfuehren.
const INSTANCE_SECRET: [u8; 32] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5, 0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe,
];

fn signing_key(secret: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&secret)
}

fn public_key(secret: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(signing_key(secret).verifying_key().to_bytes())
        .expect("der Fixturschluessel bleibt kanonisch")
}

fn admin_device_id() -> DeviceId {
    DeviceId::try_from(&[ADMIN_DEVICE; 16][..]).expect("16 Byte sind eine Geraetekennung")
}

fn state_key() -> TrustStateKey {
    TrustStateKey {
        organization_id: trust_support::organization(),
        device_id: admin_device_id(),
    }
}

fn reference_hash() -> ObjectHash {
    ObjectHash::from(trust_support::hash32(0xc5))
}

fn trusted_time() -> TrustedTimeState {
    trusted_time_of(IndependentTimeKind::Receipt)
}

fn trusted_time_of(kind: IndependentTimeKind) -> TrustedTimeState {
    TrustedTimeState::from_persisted(
        UnixMillis::new(FLOOR_MS),
        Some(IndependentTimeInput::new(
            kind,
            reference_hash(),
            UnixMillis::new(REFERENCE_MS),
        )),
    )
    .expect("die persistierte Referenz liegt nicht hinter dem Floor")
}

/// Derselbe Zustand OHNE unabhaengige Referenz.
fn trusted_time_without_reference() -> TrustedTimeState {
    TrustedTimeState::initial(UnixMillis::new(FLOOR_MS))
}

// ===========================================================================
// Die Registrierungslinie
// ===========================================================================

fn policy_action() -> ActionSpec {
    ActionSpec::Policy {
        policy_version: None,
        previous_policy_hash: None,
        effective_from: None,
    }
}

fn head_options(effective_from: u64, valid_through: u64) -> HeadOptions {
    HeadOptions {
        effective_from: Some(effective_from),
        valid_through: Some(valid_through),
        ..HeadOptions::default()
    }
}

/// Alles, was ein Zeuge ueber die gebaute Linie wissen muss.
struct Line {
    line: RegistryLineBuilder,
    admin_certificate_object_hash: ObjectHash,
    admin_binding_object_hash: ObjectHash,
}

/// Baut die Linie der Uhrfreigabe.
///
/// Vier Koepfe: Anfangspolicy, Adminzertifikat, Adminbindung und die
/// Wachrichtlinie, an der die Kulisse pinnt. Der Kandidat IST dieser Kopf —
/// `select_registry_head` nimmt damit den `is_current`-Zweig, und der
/// Zeit-Floor kann strukturell nur bestaetigt und nie abgesenkt werden.
fn build_line(guard_not_after: i64) -> Line {
    let mut line = RegistryLineBuilder::new();
    line.push(policy_action(), head_options(1, 9));
    let admin = line.push(
        ActionSpec::AdminIssue {
            marker: ADMIN_MARKER,
            effective_from: None,
        },
        head_options(10, 19),
    );
    let admin_certificate_object_hash = admin
        .direct_object_hash
        .expect("das Adminzertifikat der Fixture ist ein direktes Ziel");
    let binding = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: admin_certificate_object_hash,
            role: OperatorRoleV1::OrganizationAdmin,
            marker: ADMIN_MARKER,
            effective_from: None,
        },
        HeadOptions {
            binding_instance_key_thumbprint_override: Some(
                public_key(INSTANCE_SECRET).thumbprint(),
            ),
            binding_os_account_hash_override: Some(trust_support::hash32(OS_ACCOUNT_MARKER)),
            ..head_options(20, 29)
        },
    );
    let admin_binding_object_hash = binding
        .direct_object_hash
        .expect("die Adminbindung der Fixture ist ein direktes Ziel");
    line.push(
        policy_action(),
        HeadOptions {
            policy_max_future_clock_skew_ms_override: Some(GUARD_SKEW_MS),
            not_after: UnixMillis::new(guard_not_after),
            ..head_options(20, 39)
        },
    );
    Line {
        line,
        admin_certificate_object_hash,
        admin_binding_object_hash,
    }
}

/// Der Vorgabewert von `HeadOptions::not_after`.
const DEFAULT_NOT_AFTER_MS: i64 = 10_000;

// ===========================================================================
// Die Zustandsablage
// ===========================================================================

/// Der Speicher, der die Auswahl UND die Freigabesperre fuehrt.
///
/// Er lebt ueber mehrere Anwendungen hinweg: erst so ist die Einmaligkeit
/// einer Freigabe ueberhaupt messbar.
struct Store {
    key: TrustStateKey,
    revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
    consumed: Vec<([u8; 16], [u8; 16], [u8; 32])>,
    registry_commits: usize,
}

impl Store {
    fn new(pinned_head: RegistryHeadPin, trusted_time: TrustedTimeState) -> Self {
        Self {
            key: state_key(),
            revision: INITIAL_REVISION,
            trusted_time,
            pinned_head: Some(pinned_head),
            consumed: Vec::new(),
            registry_commits: 0,
        }
    }

    fn record(&self) -> PersistedTrustRecord {
        PersistedTrustRecord::new(self.revision, self.trusted_time.clone(), self.pinned_head)
    }
}

impl TrustStateStore for Store {
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
        if let Some(replay) = commit.replay_key() {
            self.consumed.push((
                *replay.organization_id().as_bytes(),
                *replay.target_device_id().as_bytes(),
                *replay.nonce(),
            ));
        }
        self.registry_commits += 1;
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
struct AdminKeyProvider {
    secret: [u8; 32],
}

impl AdminKeyProvider {
    fn handle(&self) -> KeyHandle {
        KeyHandle::new(
            KeystoreProvider::InMemory,
            trust_support::hash32(0x11),
            SecretPurpose::WriterSigningKey,
        )
    }
}

impl KeyProvider for AdminKeyProvider {
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
struct MemoryAuditRepository {
    events: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
}

impl MemoryAuditRepository {
    fn new() -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
        }
    }

    fn booked(&self) -> usize {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
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
struct AuditHarness {
    repository: Arc<MemoryAuditRepository>,
    service: SignedLocalAuditService,
}

impl AuditHarness {
    /// `effective_now` ist die `raw_now` der GESPERRTEN Bewertung und nicht die
    /// des gewaehlten Kopfes: die Auditzeile spricht ueber den Augenblick, in
    /// dem die Uhr blockiert.
    fn new(signer_certificate_object_hash: ObjectHash, effective_now: UnixMillis) -> Self {
        let repository = Arc::new(MemoryAuditRepository::new());
        let provider = Arc::new(AdminKeyProvider {
            secret: trust_support::device_signing_secret(),
        });
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
fn operator_proof(
    head: &SelectedRegistryHead,
    binding_object_hash: ObjectHash,
    purpose: ReauthPurpose,
) -> OperatorSessionProof {
    let bound = BoundOperator::resolve(head, binding_object_hash)
        .expect("die Adminbindung ist an der gewaehlten Sequenz aktiv");
    Authenticator { bound }
        .reauthenticate(Box::new(Account), purpose)
        .expect("die Kulisse meldet die gebundene Adminbedienerin wieder an")
}

// ===========================================================================
// Die Kulisse
// ===========================================================================

/// Linie, Speicher und der gewaehlte Kopf, gegen den die Freigabe entsteht.
struct Scene {
    parts: Line,
    store: Store,
    guard_head: SelectedRegistryHead,
}

fn scene() -> Scene {
    scene_with(DEFAULT_NOT_AFTER_MS)
}

/// Baut die Kulisse und waehlt den aktuellen Kopf, WAEHREND die Uhr NICHT
/// gesperrt ist.
///
/// Das ist der Kopf, in dessen Zeitrahmen der Freigabenachweis ausgestellt und
/// seine Frische gemessen wird; die gesperrte Bewertung liegt daneben und
/// traegt eine eigene `raw_now`.
fn scene_with(guard_not_after: i64) -> Scene {
    let parts = build_line(guard_not_after);
    let head = parts.line.heads()[GUARD_HEAD_INDEX];
    let mut store = Store::new(
        RegistryHeadPin::new(head.version, head.object_hash),
        trusted_time(),
    );
    let trust = trust_of(&parts.line, &store);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(PROPOSED_SEQUENCE))
        .expect("der aktuelle Kopf der Kulisse verifiziert");
    let local_time = prepare_local_time(
        &mut store,
        &candidate,
        UnixMillis::new(UNBLOCKED_WALL_MS),
        &[],
    )
    .expect("die lokale Zeit der Kulisse ist vorbereitbar");
    let RegistrySelectionOutcome::Selected(guard_head) =
        select_registry_head(candidate, local_time, None).expect("die ungesperrte Auswahl gelingt")
    else {
        panic!("die Kulisse waehlt ihren eigenen aktuellen Kopf");
    };
    Scene {
        parts,
        store,
        guard_head,
    }
}

fn trust_of(line: &RegistryLineBuilder, store: &Store) -> VerifiedTrust {
    line.verified_with_record(
        Pin::Head(GUARD_HEAD_INDEX),
        store.revision,
        store.trusted_time.clone(),
        state_key(),
    )
}

impl Scene {
    fn candidate(&self) -> RegistryCandidate {
        let trust = trust_of(&self.parts.line, &self.store);
        verify_registry_candidate(&trust, ChainSequence::new(PROPOSED_SEQUENCE))
            .expect("der gesperrte Kandidat der Kulisse verifiziert")
    }

    fn audit(&self) -> AuditHarness {
        AuditHarness::new(
            self.parts.admin_certificate_object_hash,
            UnixMillis::new(BLOCKED_NOW_MS),
        )
    }

    fn service<'a>(&'a self, audit: &'a AuditHarness) -> ClockReleaseService<'a> {
        ClockReleaseService::new(
            &self.guard_head,
            &audit.service,
            self.parts.admin_binding_object_hash,
        )
    }

    fn proof(&self, purpose: ReauthPurpose) -> OperatorSessionProof {
        operator_proof(
            &self.guard_head,
            self.parts.admin_binding_object_hash,
            purpose,
        )
    }

    /// Wendet Freigabebytes gegen die eigene Linie an.
    fn apply(
        &mut self,
        bytes: &[u8],
    ) -> Result<RegistrySelectionOutcome, ClockReleaseWorkflowError> {
        self.apply_at(PROPOSED_SEQUENCE, BLOCKED_WALL_MS, bytes)
    }

    fn apply_at(
        &mut self,
        proposed_sequence: u64,
        wall_clock: i64,
        bytes: &[u8],
    ) -> Result<RegistrySelectionOutcome, ClockReleaseWorkflowError> {
        let trust = trust_of(&self.parts.line, &self.store);
        apply_clock_release(
            &mut self.store,
            &trust,
            ChainSequence::new(proposed_sequence),
            UnixMillis::new(wall_clock),
            &[],
            bytes,
        )
    }

    /// Wendet Freigabebytes gegen eine ABWEICHENDE Linie an — dieselbe
    /// Praefixgeschichte, ein zusaetzlicher Kopf.
    fn apply_against(
        &mut self,
        line: &RegistryLineBuilder,
        proposed_sequence: u64,
        bytes: &[u8],
    ) -> Result<RegistrySelectionOutcome, ClockReleaseWorkflowError> {
        let trust = trust_of(line, &self.store);
        apply_clock_release(
            &mut self.store,
            &trust,
            ChainSequence::new(proposed_sequence),
            UnixMillis::new(BLOCKED_WALL_MS),
            &[],
            bytes,
        )
    }

    /// Die Felder der Freigabe, die zu dieser Kulisse passen.
    fn fields(&self) -> AuditFields {
        let head = self.parts.line.heads()[GUARD_HEAD_INDEX];
        AuditFields {
            organization_id: trust_support::organization(),
            target_device_id: admin_device_id(),
            admin_binding_hash: Some(self.parts.admin_binding_object_hash),
            signer_certificate_hash: self.parts.admin_certificate_object_hash,
            action: 6,
            outcome: 1,
            effective_now: UnixMillis::new(BLOCKED_NOW_MS),
            trusted_time_floor: UnixMillis::new(FLOOR_MS),
            observed_os_wall_clock: UnixMillis::new(BLOCKED_WALL_MS),
            max_future_clock_skew_ms: GUARD_SKEW_MS,
            registry_version: head.version,
            registry_head_hash: head.object_hash,
            guard_policy_object_hash: self.guard_head.policy_object_hash(),
            independent_reference_kind: 0,
            independent_reference_hash: reference_hash(),
            independent_reference_time: UnixMillis::new(REFERENCE_MS),
            justification: 0,
            issued_at: UnixMillis::new(ISSUED_AT_MS),
            expires_at: UnixMillis::new(EXPIRES_AT_MS),
            nonce: [0xd0; 32],
        }
    }
}

fn request<'a>(
    candidate: &'a RegistryCandidate,
    trusted_time: &'a TrustedTimeState,
    wall_clock: i64,
) -> ClockReleaseRequest<'a> {
    ClockReleaseRequest {
        candidate,
        trusted_time,
        observed_os_wall_clock: UnixMillis::new(wall_clock),
        justification: ClockReleaseJustificationV1::OperatorVerifiedWallClock,
        issued_at: UnixMillis::new(ISSUED_AT_MS),
        expires_at: UnixMillis::new(EXPIRES_AT_MS),
    }
}

fn code(result: Result<RegistrySelectionOutcome, ClockReleaseWorkflowError>) -> &'static str {
    result
        .err()
        .expect("der Dreischritt muss geschlossen scheitern")
        .code()
}

// ===========================================================================
// Zeuge 1: Einmaligkeit
// ===========================================================================

#[test]
fn a_release_is_issued_once_consumed_once_and_replayed_never() {
    let mut scene = scene();
    assert_eq!(
        scene.guard_head.preexisting_effective_now().value(),
        UnixMillis::new(HEAD_NOW_MS)
    );
    let audit = scene.audit();
    let proof = scene.proof(ReauthPurpose::ClockSkewRelease);
    let time = scene.store.trusted_time.clone();

    let issued = {
        let candidate = scene.candidate();
        scene
            .service(&audit)
            .issue(request(&candidate, &time, BLOCKED_WALL_MS), &proof)
            .expect("die Kulisse stellt eine Freigabe aus")
    };
    assert_eq!(audit.repository.booked(), 1);
    assert_eq!(format!("{issued:?}"), "IssuedClockRelease(<signed>)");

    let commits_before = scene.store.registry_commits;
    let floor_before = scene.store.trusted_time.floor();
    let outcome = scene
        .apply(issued.exact_bytes())
        .expect("die Freigabe traegt genau eine gesperrte Auswahl");
    assert!(matches!(outcome, RegistrySelectionOutcome::Selected(_)));
    assert_eq!(scene.store.registry_commits, commits_before + 1);
    assert!(scene.store.trusted_time.floor() >= floor_before);

    assert_eq!(
        code(scene.apply(issued.exact_bytes())),
        "EA-TRUST-CLOCK-RELEASE-REPLAY"
    );
}

// ===========================================================================
// Zeuge 2: die exakte, EINSCHLIESSENDE Befristung
// ===========================================================================

#[test]
fn the_release_window_is_inclusive_at_both_boundaries() {
    // `raw_now` ist in allen vier Laeufen 3_201; nur das Fenster wandert.
    for (issued_at, expires_at) in [
        (BLOCKED_NOW_MS, EXPIRES_AT_MS),
        (ISSUED_AT_MS, BLOCKED_NOW_MS),
    ] {
        let mut scene = scene();
        let bytes = signed_clock_release(&AuditFields {
            issued_at: UnixMillis::new(issued_at),
            expires_at: UnixMillis::new(expires_at),
            ..scene.fields()
        });
        assert!(
            scene.apply(&bytes).is_ok(),
            "raw_now auf einer Fenstergrenze liegt INNERHALB"
        );
    }

    for (issued_at, expires_at) in [
        (BLOCKED_NOW_MS + 1, EXPIRES_AT_MS),
        (ISSUED_AT_MS, BLOCKED_NOW_MS - 1),
    ] {
        let mut scene = scene();
        let bytes = signed_clock_release(&AuditFields {
            issued_at: UnixMillis::new(issued_at),
            expires_at: UnixMillis::new(expires_at),
            ..scene.fields()
        });
        assert_eq!(code(scene.apply(&bytes)), "EA-TRUST-CLOCK-RELEASE-EXPIRED");
    }
}

// ===========================================================================
// Zeuge 3: der Zeit-Floor wird nie abgesenkt
// ===========================================================================

#[test]
fn a_release_never_lowers_the_trusted_time_floor() {
    let mut scene = scene();
    let lowered = signed_clock_release(&AuditFields {
        trusted_time_floor: UnixMillis::new(REFERENCE_MS),
        ..scene.fields()
    });
    assert_eq!(
        code(scene.apply(&lowered)),
        "EA-TRUST-CLOCK-RELEASE-MISMATCH"
    );
    assert_eq!(scene.store.trusted_time.floor(), UnixMillis::new(FLOOR_MS));

    let exact = signed_clock_release(&scene.fields());
    scene
        .apply(&exact)
        .expect("die exakte Freigabe traegt die Auswahl");
    assert!(scene.store.trusted_time.floor() >= UnixMillis::new(FLOOR_MS));
}

// ===========================================================================
// Zeuge 4: die sechs „hebelt nicht aus"-Negative
// ===========================================================================

#[test]
fn a_release_never_waives_registry_not_after() {
    // Der gewaehlte Kopf laeuft zwischen der ungesperrten (3_100) und der
    // gesperrten (3_201) Bewertung ab.
    let mut scene = scene_with(3_150);
    let bytes = signed_clock_release(&scene.fields());
    let commits_before = scene.store.registry_commits;
    assert_eq!(code(scene.apply(&bytes)), "EA-TRUST-STALE");
    // Die Freigabe war GUELTIG — `require_release_pairing` hat sie
    // angenommen — und wurde trotzdem weder verbraucht noch wirksam.
    assert_eq!(scene.store.registry_commits, commits_before);
    assert!(scene.store.consumed.is_empty());
}

#[test]
fn a_release_never_waives_registry_not_before() {
    let mut scene = scene();
    let mut successor = scene.parts.line.clone();
    let future = successor.push(
        policy_action(),
        HeadOptions {
            issued_at: UnixMillis::new(5_000),
            not_before: UnixMillis::new(5_000),
            not_after: UnixMillis::new(9_000),
            ..head_options(PROPOSED_SEQUENCE, 59)
        },
    );
    let bytes = signed_clock_release(&AuditFields {
        registry_version: future.version,
        registry_head_hash: future.object_hash,
        ..scene.fields()
    });
    let commits_before = scene.store.registry_commits;
    let pin_before = scene.store.pinned_head;
    let outcome = scene
        .apply_against(&successor, PROPOSED_SEQUENCE, &bytes)
        .expect("ein noch nicht gueltiger Nachfolger ist kein Fehlschlag, sondern ein Ausgang");
    assert!(matches!(
        outcome,
        RegistrySelectionOutcome::PendingFuture(_)
    ));
    assert_eq!(scene.store.registry_commits, commits_before);
    assert!(scene.store.pinned_head == pin_before);
    assert!(scene.store.consumed.is_empty());
}

#[test]
fn a_release_never_waives_an_exhausted_sequence_lease() {
    let mut scene = scene();
    let bytes = signed_clock_release(&scene.fields());
    let commits_before = scene.store.registry_commits;
    assert_eq!(
        code(scene.apply_at(45, BLOCKED_WALL_MS, &bytes)),
        "EA-TRUST-SEQUENCE-LEASE"
    );
    // Der Befund faellt VOR der Freigabe. Genau deshalb steht hier die
    // zweite Haelfte des Zeugen: die Nonce ist unverbraucht, und eine
    // Fassade, die die Freigabe zuerst prueft und den Rest abkuerzt, haette
    // sie bereits ausgegeben.
    assert_eq!(scene.store.registry_commits, commits_before);
    assert!(scene.store.consumed.is_empty());
}

#[test]
fn a_release_never_waives_a_missing_activation_authorization() {
    let mut scene = scene();
    let mut successor = scene.parts.line.clone();
    let future = successor.push(
        policy_action(),
        HeadOptions {
            omit_event_authorization: true,
            ..head_options(PROPOSED_SEQUENCE, 59)
        },
    );
    let bytes = signed_clock_release(&AuditFields {
        registry_version: future.version,
        registry_head_hash: future.object_hash,
        ..scene.fields()
    });
    let commits_before = scene.store.registry_commits;
    assert_eq!(
        code(scene.apply_against(&successor, PROPOSED_SEQUENCE, &bytes)),
        "EA-TRUST-ACTIVATION-MISSING"
    );
    assert_eq!(scene.store.registry_commits, commits_before);
    assert!(scene.store.consumed.is_empty());
}

/// Eine ABGELAUFENE Administrationsautorisierung.
///
/// Das Fenster der Autorisierung ist ein EIGENER Ablauf: er hat mit dem
/// Freigabefenster (`issued_at`/`expires_at` des Kontexts) und mit `notAfter`
/// des Kopfes nichts zu tun. `verify_authorization_binds_target` misst ihn
/// gegen die `issued_at` des Registrierungsereignisses
/// (`crates/ea-trust/src/registry.rs`), und genau dieser Vergleich darf von
/// einer gueltigen Freigabe nicht beruehrt werden.
///
/// Die Vorgabe der Fixture (`(issued_at, issued_at + 1000)`) kann die Lage
/// strukturell nicht bauen: beide Werte speisen sich aus derselben
/// `HeadOptions::issued_at`. Deshalb der additive Schalter
/// `authorization_window_override`, der das Fenster ALS GANZES vor die
/// Benutzungszeit legt — ein blosses Vorziehen des Endes faellt schon an der
/// Formgrenze, die `issued_at < expires_at` erzwingt.
#[test]
fn a_release_never_waives_an_expired_activation_authorization() {
    let mut scene = scene();
    let mut successor = scene.parts.line.clone();
    let future = successor.push(
        policy_action(),
        HeadOptions {
            // Die Vorgabe von `HeadOptions::issued_at` ist 100 und ist zugleich
            // die Benutzungszeit; ein Fenster, das bei 99 endet, ist zu ihr um
            // genau eine Millisekunde abgelaufen.
            authorization_window_override: Some((UnixMillis::new(90), UnixMillis::new(99))),
            ..head_options(PROPOSED_SEQUENCE, 59)
        },
    );
    let bytes = signed_clock_release(&AuditFields {
        registry_version: future.version,
        registry_head_hash: future.object_hash,
        ..scene.fields()
    });
    let commits_before = scene.store.registry_commits;
    assert_eq!(
        code(scene.apply_against(&successor, PROPOSED_SEQUENCE, &bytes)),
        "EA-TRUST-AUTH-EXPIRED"
    );
    assert_eq!(scene.store.registry_commits, commits_before);
    assert!(scene.store.consumed.is_empty());
}

#[test]
fn a_release_never_waives_a_broken_authorization_signature() {
    let mut scene = scene();
    let mut successor = scene.parts.line.clone();
    let future = successor.push(
        policy_action(),
        HeadOptions {
            corrupt_event_authorization_signature: true,
            ..head_options(PROPOSED_SEQUENCE, 59)
        },
    );
    let bytes = signed_clock_release(&AuditFields {
        registry_version: future.version,
        registry_head_hash: future.object_hash,
        ..scene.fields()
    });
    let commits_before = scene.store.registry_commits;
    assert_eq!(
        code(scene.apply_against(&successor, PROPOSED_SEQUENCE, &bytes)),
        "EA-TRUST-SIGNATURE"
    );
    assert_eq!(scene.store.registry_commits, commits_before);
    assert!(scene.store.consumed.is_empty());
}

// ===========================================================================
// Zeuge 5: jede Kontextabweichung wird abgewiesen
// ===========================================================================

/// Eine benannte Abweichung: ihr Etikett und der Bauplan ihrer Felder.
type Deviation = (&'static str, Box<dyn Fn(&Scene) -> AuditFields>);

#[test]
fn every_signed_context_deviation_is_rejected() {
    let deviations: Vec<Deviation> = vec![
        (
            "wall clock",
            Box::new(|scene: &Scene| AuditFields {
                observed_os_wall_clock: UnixMillis::new(BLOCKED_WALL_MS + 1),
                effective_now: UnixMillis::new(BLOCKED_WALL_MS + 1),
                ..scene.fields()
            }),
        ),
        (
            "registry version",
            Box::new(|scene: &Scene| AuditFields {
                registry_version: RegistryVersion::new(99),
                ..scene.fields()
            }),
        ),
        (
            "registry head hash",
            Box::new(|scene: &Scene| AuditFields {
                registry_head_hash: trust_support::object_hash_marker(0xee),
                ..scene.fields()
            }),
        ),
        (
            "guard policy",
            Box::new(|scene: &Scene| AuditFields {
                guard_policy_object_hash: trust_support::object_hash_marker(0xef),
                ..scene.fields()
            }),
        ),
        (
            "independent reference",
            Box::new(|scene: &Scene| AuditFields {
                independent_reference_hash: trust_support::object_hash_marker(0xf0),
                ..scene.fields()
            }),
        ),
    ];

    for (label, deviate) in deviations {
        let mut scene = scene();
        let bytes = signed_clock_release(&deviate(&scene));
        assert_eq!(
            code(scene.apply(&bytes)),
            "EA-TRUST-CLOCK-RELEASE-MISMATCH",
            "die Abweichung „{label}\" muss abgewiesen werden"
        );
    }
}

// ===========================================================================
// Zeuge 6: ohne unabhaengige Referenz gibt es GAR KEINE Freigabe
// ===========================================================================

#[test]
fn no_release_is_offered_without_an_independent_reference() {
    let scene = scene();
    let audit = scene.audit();
    let proof = scene.proof(ReauthPurpose::ClockSkewRelease);
    let bare = trusted_time_without_reference();
    let service = scene.service(&audit);

    assert_eq!(
        service
            .availability(&bare, UnixMillis::new(BLOCKED_WALL_MS))
            .expect("die Bedienfuehrung antwortet"),
        ClockReleaseAvailability::IndependentTimeUnavailable
    );
    assert_eq!(
        service
            .availability(&scene.store.trusted_time, UnixMillis::new(BLOCKED_WALL_MS))
            .expect("die Bedienfuehrung antwortet"),
        ClockReleaseAvailability::Offered
    );

    let candidate = scene.candidate();
    let error = service
        .issue(request(&candidate, &bare, BLOCKED_WALL_MS), &proof)
        .expect_err("ohne unabhaengige Referenz wird gar keine Freigabe gebaut");
    assert_eq!(error.code(), "EA-SKEW-INDEPENDENT-TIME-UNAVAILABLE");
    assert_ne!(error.code(), "EA-TRUST-CLOCK-RELEASE-MISMATCH");
    assert_eq!(audit.repository.booked(), 0);
}

// ===========================================================================
// Zeuge 7: der Begruendungscode ist der geschlossene Satz 0..2
// ===========================================================================

#[test]
fn a_justification_outside_the_closed_set_never_verifies() {
    let mut scene = scene();
    let fields = AuditFields {
        justification: 3,
        ..scene.fields()
    };
    let bytes = wire_invalid_clock_release(&fields);
    assert!(
        decode_clock_release_audit(&bytes).is_err(),
        "der Begruendungscode 3 muss die exakte Dekodierung brechen"
    );
    assert_eq!(code(scene.apply(&bytes)), "EA-TRUST-CLOCK-RELEASE-MISMATCH");
}

// ===========================================================================
// Zeuge 8: eine TSA-Referenz ergibt nie eine Freigabe
// ===========================================================================

#[test]
fn a_tsa_reference_never_mints_a_release() {
    let stage = scene();
    let audit = stage.audit();
    let proof = stage.proof(ReauthPurpose::ClockSkewRelease);
    let tsa_time = trusted_time_of(IndependentTimeKind::Tsa);
    let candidate = stage.candidate();
    let error = stage
        .service(&audit)
        .issue(request(&candidate, &tsa_time, BLOCKED_WALL_MS), &proof)
        .expect_err("eine TSA-Referenz traegt keine Freigabe");
    assert_eq!(error.code(), "EA-TRUST-TIME-SOURCE-UNSUPPORTED");
    assert_eq!(audit.repository.booked(), 0);
}

#[test]
fn a_tsa_reference_never_carries_a_release() {
    let mut stage = scene();
    let bytes = signed_clock_release(&AuditFields {
        independent_reference_kind: 2,
        ..stage.fields()
    });
    assert_eq!(
        code(stage.apply(&bytes)),
        "EA-TRUST-TIME-SOURCE-UNSUPPORTED"
    );
}

// ===========================================================================
// Zeuge 9: nur eine gesperrte Uhr paart mit einer Freigabe
// ===========================================================================

#[test]
fn only_a_blocked_clock_pairs_with_a_release() {
    let mut scene = scene();
    let audit = scene.audit();
    let proof = scene.proof(ReauthPurpose::ClockSkewRelease);
    let time = scene.store.trusted_time.clone();

    let service = scene.service(&audit);
    assert_eq!(
        service
            .availability(&time, UnixMillis::new(UNBLOCKED_WALL_MS))
            .expect("die Bedienfuehrung antwortet"),
        ClockReleaseAvailability::NotBlocked
    );
    let candidate = scene.candidate();
    assert_eq!(
        service
            .issue(request(&candidate, &time, UNBLOCKED_WALL_MS), &proof)
            .expect_err("eine nicht gesperrte Uhr hat keinen Freigabegegenstand")
            .code(),
        "EA-SKEW-NOT-BLOCKED"
    );

    let bytes = signed_clock_release(&scene.fields());
    assert_eq!(
        code(scene.apply_at(PROPOSED_SEQUENCE, UNBLOCKED_WALL_MS, &bytes)),
        "EA-TRUST-CLOCK-RELEASE-MISMATCH"
    );
}

// ===========================================================================
// Zeuge 10: die Zweckbindung des Bedienernachweises
// ===========================================================================

#[test]
fn only_a_fresh_clock_skew_release_proof_carries_the_issuance() {
    let scene = scene();
    let audit = scene.audit();
    let time = scene.store.trusted_time.clone();
    let candidate = scene.candidate();
    let service = scene.service(&audit);

    let foreign_purpose = scene.proof(ReauthPurpose::AdminRootCeremony);
    assert_eq!(
        service
            .issue(
                request(&candidate, &time, BLOCKED_WALL_MS),
                &foreign_purpose
            )
            .expect_err("ein Nachweis fuer die Wurzelzeremonie traegt keine Uhrfreigabe")
            .code(),
        "EA-SKEW-REAUTH-PURPOSE"
    );

    let release_purpose = scene.proof(ReauthPurpose::ClockSkewRelease);
    service
        .issue(
            request(&candidate, &time, BLOCKED_WALL_MS),
            &release_purpose,
        )
        .expect("der frische Uhrfreigabenachweis traegt sie");
    assert_eq!(audit.repository.booked(), 1);
}

#[test]
fn a_proof_of_another_binding_never_carries_the_issuance() {
    let scene = scene();
    let audit = scene.audit();
    let service = ClockReleaseService::new(
        &scene.guard_head,
        &audit.service,
        trust_support::object_hash_marker(0x5a),
    );
    let proof = scene.proof(ReauthPurpose::ClockSkewRelease);
    let time = scene.store.trusted_time.clone();
    let candidate = scene.candidate();
    assert_eq!(
        service
            .issue(request(&candidate, &time, BLOCKED_WALL_MS), &proof)
            .expect_err("ein Nachweis einer fremden Bindung traegt keine Uhrfreigabe")
            .code(),
        "EA-SKEW-REAUTH-BINDING"
    );
    assert_eq!(audit.repository.booked(), 0);
}

/// Ein ENTWERTETER Nachweis der eigenen Bindung traegt gar keinen Zweck mehr.
///
/// Der Unterschied zur Zweckabweichung ist der ganze Punkt dieses Zeugen.
/// `only_a_fresh_clock_skew_release_proof_carries_the_issuance` legt einen
/// Nachweis vor, der einen ANDEREN Zweck autorisiert — das ist
/// `EA-SKEW-REAUTH-PURPOSE`. Hier ist der Zweck der richtige und die Bindung
/// die eigene; entwertet ist der Nachweis durch eine native Sperre
/// (`OperatorSessionProof::invalidate_on_lock`), und `is_valid_for` faellt
/// deshalb fuer JEDEN der zehn Zwecke aus. Es autorisiert also kein anderer
/// Zweck, und der Ausgang ist die Wiederanmeldepflicht selbst.
///
/// Ueber die Uhr laeuft das nicht: die Frische wird gegen
/// `guard_head.preexisting_effective_now()` gemessen, und der Nachweis dieser
/// Buehne wird im selben Rahmen ausgestellt.
#[test]
fn a_proof_invalidated_by_the_os_lock_demands_a_reauthentication() {
    let scene = scene();
    let audit = scene.audit();
    let service = scene.service(&audit);
    let locked = scene
        .proof(ReauthPurpose::ClockSkewRelease)
        .invalidate_on_lock();
    let time = scene.store.trusted_time.clone();
    let candidate = scene.candidate();
    assert_eq!(
        service
            .issue(request(&candidate, &time, BLOCKED_WALL_MS), &locked)
            .expect_err("ein durch die OS-Sperre entwerteter Nachweis traegt keine Uhrfreigabe")
            .code(),
        "EA-SKEW-REAUTH-REQUIRED"
    );
    assert_eq!(audit.repository.booked(), 0);
}

// ===========================================================================
// Der handgeschriebene Kodierer
//
// Uebernommen aus `crates/ea-trust/tests/clock_release.rs:83-200`. Er baut
// AUSSCHLIESSLICH Faelle, die ein getypter Aufrufer nicht bauen kann.
// ===========================================================================

#[derive(Clone)]
struct AuditFields {
    organization_id: OrganizationId,
    target_device_id: DeviceId,
    admin_binding_hash: Option<ObjectHash>,
    signer_certificate_hash: ObjectHash,
    action: u8,
    outcome: u8,
    effective_now: UnixMillis,
    trusted_time_floor: UnixMillis,
    observed_os_wall_clock: UnixMillis,
    max_future_clock_skew_ms: u64,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    independent_reference_kind: u8,
    independent_reference_hash: ObjectHash,
    independent_reference_time: UnixMillis,
    justification: u8,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    nonce: [u8; 32],
}

fn encode_clock_release_core(fields: &AuditFields) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .array(12)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[0x01; 16])
        .unwrap()
        .bytes(fields.organization_id.as_bytes())
        .unwrap()
        .bytes(fields.target_device_id.as_bytes())
        .unwrap();
    if let Some(binding) = fields.admin_binding_hash {
        encoder.bytes(binding.as_bytes()).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder
        .bytes(fields.signer_certificate_hash.as_bytes())
        .unwrap()
        .u8(fields.action)
        .unwrap()
        .u8(fields.outcome)
        .unwrap()
        .i64(fields.effective_now.get())
        .unwrap()
        .array(2)
        .unwrap()
        .u8(2)
        .unwrap()
        .array(10)
        .unwrap()
        .i64(fields.trusted_time_floor.get())
        .unwrap()
        .i64(fields.observed_os_wall_clock.get())
        .unwrap()
        .u64(fields.max_future_clock_skew_ms)
        .unwrap()
        .u64(fields.registry_version.get())
        .unwrap()
        .bytes(fields.registry_head_hash.as_bytes())
        .unwrap()
        .bytes(fields.guard_policy_object_hash.as_bytes())
        .unwrap()
        .array(3)
        .unwrap()
        .u8(fields.independent_reference_kind)
        .unwrap()
        .bytes(fields.independent_reference_hash.as_bytes())
        .unwrap()
        .i64(fields.independent_reference_time.get())
        .unwrap()
        .u8(fields.justification)
        .unwrap()
        .i64(fields.issued_at.get())
        .unwrap()
        .i64(fields.expires_at.get())
        .unwrap()
        .bytes(&fields.nonce)
        .unwrap()
        .array(0)
        .unwrap();
    bytes
}

fn wrap_clock_release(exact_core: &[u8], exact_cose: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    Encoder::new(&mut bytes).array(2).unwrap();
    bytes.extend_from_slice(exact_core);
    bytes.extend_from_slice(exact_cose);
    bytes
}

/// Die signierte Zeile — der Kodierer prueft den Kern an der Signaturgrenze.
fn signed_clock_release(fields: &AuditFields) -> Vec<u8> {
    let exact_core = encode_clock_release_core(fields);
    let exact_cose =
        CoseSigner::from_secret(SecretBytes::new(trust_support::device_signing_secret()))
            .sign_local_audit(&exact_core)
            .expect("der Kern der Kulisse ist an der Signaturgrenze gueltig");
    wrap_clock_release(&exact_core, &exact_cose)
}

/// Eine signierte Zeile UNTER UMGEHUNG der Signaturgrenze.
///
/// Nur so entsteht ein Kern, den `encode_local_audit_core` bereits abweisen
/// wuerde — der Fall, den ein getypter Aufrufer gar nicht bauen kann.
fn wire_invalid_clock_release(fields: &AuditFields) -> Vec<u8> {
    let exact_core = encode_clock_release_core(fields);
    let key = signing_key(trust_support::device_signing_secret());
    let public = public_key(trust_support::device_signing_secret());
    let protected = ProtectedHeader::normal(
        ContentType::LocalAuditCbor,
        public.thumbprint(),
        CertificateHash::from(fields.signer_certificate_hash),
    );
    let signature = key
        .sign(&protected.sig_structure_bytes(&exact_core))
        .to_bytes();
    let mut exact_cose = Vec::new();
    Encoder::new(&mut exact_cose)
        .tag(Tag::new(18))
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&protected.to_deterministic_cbor())
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(&exact_core)
        .unwrap()
        .bytes(&signature)
        .unwrap();
    wrap_clock_release(&exact_core, &exact_cose)
}
