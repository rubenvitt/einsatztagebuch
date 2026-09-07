//! Die Kulisse des Systemzeugen des Writer-Uebergangs (Stufe 5, Task 5).
//!
//! Vier Zusagen tragen dieses Modul:
//!
//! 1. **EINE Linie, zwei Geraete, drei Tore.** Registrierungslinie, beide
//!    Writer-Geraete und der Bestand kommen unveraendert aus dem
//!    `#[path]`-eingebundenen Supportmodul von `ea-writer`
//!    (`TransitionHarness`). Die Verwaltung (`ea-admin`) und der Server
//!    (`ea-sync-server`) arbeiten GEGEN DIESE Linie; keine zweite wird gebaut.
//!    Die Zeremonienfixture von `ea-admin` (`writer_transition_ceremony_line`)
//!    kann hier nicht dienen: ihre Geraetezertifikate tragen synthetische
//!    Schluessel, auf ihr finalisiert kein Writer.
//! 2. **Die Zeremonie ist ECHT.** Das Transitionsobjekt entsteht ueber
//!    `RootCeremonyService::publish_authorized_target` mit dem
//!    Wurzelschluessel der Linie, einem echten Bedienernachweis
//!    (`OperatorAuthenticator::reauthenticate`) und dem produktiven
//!    `SignedLocalAuditService`; die Aktivierung bindet die BYTES, die dabei
//!    herauskamen, und der Change 3 wandert mit GENAU dem geplanten Ereignis
//!    in die Linie.
//! 3. **Kein zweiter Kryptobaukasten.** Der Schluesselport ueber dem
//!    Wurzelschluessel, die Auditablage und der Sperrspeicher sind die
//!    kleinsten Attrappen, die die Ports verlangen — nach dem Muster von
//!    `registry_effectiveness_support` und `crates/ea-admin/tests/support`.
//!    Sie werden hier NEU geschrieben und nicht per `#[path]` eingebunden,
//!    weil jedes jener Module seine EIGENE Kopie der `ea-trust`-Fixture
//!    einbindet: eine `RegistryLineBuilder` von dort waere ein anderer Typ als
//!    die der Writer-Linie, und die Linie muss die des Writers bleiben.
//! 4. **Der Server prueft, er speichert nicht.** `ea_sync_server::validate_commit`
//!    wird DIREKT gerufen — mit der Anfrage, die ein Writer schicken wuerde
//!    (`EntryCommitRequestV1` aus den veroeffentlichten Bytes), und dem ECHTEN
//!    `SelectedRegistryHead`. Die atomare Ablage samt Sequenzsperre bezeugt
//!    `crates/ea-sync-server/tests/commit_service.rs`; hier wird die REGEL
//!    gemessen, nicht die Ablage.
//!
//! `#[path]`-Includes werden je Testziel uebersetzt; daher `allow(dead_code)`
//! auf Modulebene, genau wie in den eingebundenen Modulen.
#![allow(dead_code)]

/// Die Fixture von `ea-writer` samt ihrer Kopie der `ea-trust`-Fixture.
#[path = "../../../../crates/ea-writer/tests/support/mod.rs"]
pub mod writer_support;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use ea_admin::{
    RegistryWindow, RootCeremonyService, VerifiedLocalDeviceIdentity,
    registry::RegistryEventFactory,
    writer_transition::{TrustedChainHead, WriterTransitionRequest, WriterTransitionService},
};
use ea_archive_fs::LocalPathBackend;
use ea_audit::{AuditError, LocalAuditRepository, SignedLocalAuditEvent, SignedLocalAuditService};
use ea_chain::CheckpointClaim;
use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec, object_hash,
};
use ea_draft::{IncidentNumberRegister, OperatorProfileRepository};
use ea_format::{
    DecodedTrustPayloadV1, EntryPackageV1, KeyProtectionProfileV1, ManifestCoreV1, Parsed,
    ParsedArchiveObject, RegistryEventFieldsV1, SignedManifestV1, decode_exact_object,
    encode_entry_package,
};
use ea_key_provider::{
    CoseSign1Bytes, InMemoryKeyProvider, KeyError, KeyHandle, KeyProvider, KeystoreProvider,
    SecretPurpose,
};
use ea_operator::ReauthPurpose;
use ea_sync_protocol::EntryCommitRequestV1;
use ea_sync_server::validation::{
    CommitValidationError, ValidatedCommitV1, parse_entry, validate_commit,
};
use ea_trust::{
    AdminAuthorizationReplayDimension, AdminAuthorizationReplayKey, ClockReleaseReplayKey,
    IndependentTimeCommit, PersistedTrustRecord, RegistrySelectionCommit, SelectedRegistryHead,
    StateStoreError, TrustStateKey, TrustStateStore, verify_intended_trust_target,
};
use ea_types::{
    CertificateHash, ChainSequence, EntryHash, EventId, ObjectHash, OrganizationId, UnixMillis,
};
use ea_writer::{FinalizeOutcome, WriterBindingV1, WriterService};
use ed25519_dalek::{Signer as _, SigningKey};

use writer_support::{TransitionHarness, trust_support};

/// Der `reason_code`, den die `ea-trust`-Fixture in JEDEN Uebergang schreibt
/// (`crates/ea-trust/tests/support/mod.rs`, Zweig `ActionSpec::WriterTransition`)
/// — und damit der, den die Autorisierung aus
/// `TransitionHarness::prepare_transition_authorization` deckt. Ein Antrag
/// mit einem anderen Wert ergaebe eine andere Nutzlast, und die Zeremonie
/// wiese ihn ab. Dieselbe Konstante wie `FIXTURE_TRANSITION_REASON_CODE` in
/// `crates/ea-admin/tests/support/mod.rs`.
pub const FIXTURE_TRANSITION_REASON_CODE: u64 = 1;

/// Die Laenge des Lease des Uebergangskopfes — dieselbe, die
/// `TransitionHarness::activate_transition` waehlt (`effective_from + 129`).
pub const TRANSITION_LEASE_LENGTH: u64 = 129;

/// Die Einsatznummern, die der ALTE Writer auf seiner Kopie des Bestands
/// vergibt. Seine erste (`FIXTURE_INCIDENT_NUMBER`, `2026-000042`) ist mit
/// dem Eintrag an Sequenz 0 verbraucht; der neue Writer fuehrt ein EIGENES
/// Register und kann `2026-000043` (`other_incident`) selbst vergeben.
pub const OLD_WRITER_STALE_NUMBERS: [&str; 2] = ["2026-000143", "2026-000144"];

// ===========================================================================
// Der Schluesselport der Wurzel, die Auditablage und der Sperrspeicher
// ===========================================================================

/// Der PRODUKTIVE Signierport ueber dem Wurzelschluessel der Linie.
///
/// `InMemoryKeyProvider` leitet seine Schluessel aus einem Startwert ab und
/// traefe die Wurzel der `ea-trust`-Fixture nie; die Zeremonie muss aber mit
/// GENAU dem Schluessel unterschreiben, dem der gewaehlte Kopf die Wurzel
/// zuschreibt. Wortgleich zu `FixtureKeyProvider` in
/// `registry_effectiveness_support`, nur mit dem Wurzelgeheimnis.
pub struct RootKeyProvider;

impl RootKeyProvider {
    /// Die Adresse des Wurzelgriffs — ein Griff, kein Material.
    #[must_use]
    pub fn handle(&self) -> KeyHandle {
        KeyHandle::new(
            KeystoreProvider::InMemory,
            trust_support::hash32(0x11),
            SecretPurpose::WriterSigningKey,
        )
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&trust_support::root_signing_secret())
    }

    fn public_key() -> CanonicalPublicCoseKey {
        CanonicalPublicCoseKey::ed25519(Self::signing_key().verifying_key().to_bytes())
            .expect("der Wurzelschluessel der Fixture bleibt kanonisch")
    }
}

impl KeyProvider for RootKeyProvider {
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
        let protected = ProtectedHeader::normal(
            content_type,
            Self::public_key().thumbprint(),
            certificate_hash,
        );
        let signature = Self::signing_key().sign(&protected.sig_structure_bytes(payload));
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
#[derive(Default)]
pub struct MemoryAuditRepository {
    events: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
}

impl MemoryAuditRepository {
    #[must_use]
    pub fn booked(&self) -> usize {
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

/// Der Auditapparat: produktiver Dienst, beobachtbare Ablage.
pub struct AuditHarness {
    repository: Arc<MemoryAuditRepository>,
    service: SignedLocalAuditService,
}

impl AuditHarness {
    /// Baut den Dienst je Kopfauswahl — `SignedLocalAuditService::new` bindet
    /// `effective_now` BEIM BAUEN.
    #[must_use]
    pub fn new(head: &SelectedRegistryHead, signer_certificate_object_hash: ObjectHash) -> Self {
        let repository = Arc::new(MemoryAuditRepository::default());
        let provider = Arc::new(RootKeyProvider);
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
    pub const fn service(&self) -> &SignedLocalAuditService {
        &self.service
    }

    #[must_use]
    pub fn booked(&self) -> usize {
        self.repository.booked()
    }
}

/// Der Sperrspeicher der Administrationsautorisierung: Pruefen und Setzen in
/// EINEM Zug, wie `PersistentStore` in `crates/ea-admin/tests/support`.
///
/// Alle uebrigen Ports antworten `Unavailable`: die Zeremonie waehlt keinen
/// Kopf und schreibt keine Zeit, und ein Speicher, der das stillschweigend
/// koennte, verdeckte einen Aufruf, den es nicht geben darf.
#[derive(Default)]
pub struct ReplayStore {
    consumed: Vec<(OrganizationId, AdminAuthorizationReplayDimension)>,
}

impl ReplayStore {
    /// Wie viele Sperrzeilen verbraucht sind — eine Autorisierung setzt ZWEI.
    #[must_use]
    pub fn consumed(&self) -> usize {
        self.consumed.len()
    }
}

impl TrustStateStore for ReplayStore {
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

    fn admin_authorization_consumed(
        &mut self,
        key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        let row = (key.organization_id(), key.dimension());
        if self.consumed.contains(&row) {
            return Ok(true);
        }
        self.consumed.push(row);
        Ok(false)
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

// ===========================================================================
// Die Verwaltungsseite: vorbereiten → Zeremonie → aktivieren → Change 3
// ===========================================================================

/// Was die Verwaltung herausgegeben hat, nachdem der Change 3 in der Linie
/// liegt.
pub struct AdminTransition {
    /// Der Antrag, den die Autorisierung deckt — `Copy`, damit ein Zeuge
    /// ihn am Nachfolgekopf noch einmal stellen kann.
    pub request: WriterTransitionRequest,
    /// Die Autorisierung des Uebergangs im Katalog der Linie.
    pub authorization_object_hash: ObjectHash,
    /// Die exakten Bytes, die die Zeremonie herausgegeben hat.
    pub published: Vec<u8>,
    /// `ea_crypto::object_hash(published)` — der Hash, den das Manifest des
    /// ersten neuen Eintrags tragen muss.
    pub transition_hash: ObjectHash,
    /// Das Aenderung-3-Ereignis, wie die Ereignisfabrik es geplant hat.
    pub event: RegistryEventFieldsV1,
    /// Der Kopf, den die Linie mit GENAU diesem Ereignis traegt.
    pub head: trust_support::BuiltHead,
}

/// Fuehrt den Uebergang vom laufenden auf den freigegebenen Writer ueber
/// `ea-admin` — gegen die Linie der Writer-Fixture.
///
/// `trusted_head` ist der abgeglichene Kettenkopf: der letzte Eintrag des
/// alten Writers, wie ihn `FinalizeOutcome` gemeldet hat. Der Abgleich gegen
/// Server, Reader oder Checkpoint ist hier die Meldung des Writers selbst —
/// im Systemzeugen liegen beide Seiten im selben Prozess.
///
/// # Panics
///
/// Wenn ein Schritt der Verwaltung nicht traegt — jeder ist eine Vorbedingung
/// des Zeugen, kein Befund.
pub fn run_admin_transition(
    harness: &mut TransitionHarness,
    trusted_head: TrustedChainHead,
) -> AdminTransition {
    let effective_from = trusted_head
        .chain_sequence
        .get()
        .checked_add(1)
        .expect("die Sequenz der Fixture liegt weit vor dem Ueberlauf");
    let (authorization_object_hash, fixture_payload) =
        harness.prepare_transition_authorization(effective_from, trusted_head.entry_hash);

    // Der Kopf VOR dem Uebergang, gewaehlt fuer die Wirksamkeitssequenz —
    // aus der Linie, die die Autorisierung schon fuehrt.
    let admin_head = harness.line_head(effective_from);
    assert!(
        admin_head.current_writer_certificate_hash() == Some(harness.old_writer_certificate_hash()),
        "vor dem Uebergang laeuft der alte Writer"
    );
    assert!(admin_head.effective_writer_transition().is_none());

    // 1. Vorbereiten — und die Nutzlast ist Byte fuer Byte die, die die
    //    Fixture fuer denselben Uebergang gebaut hat: EIN Kodierer.
    let request = WriterTransitionRequest {
        old_writer_certificate_hash: harness.old_writer_certificate_hash(),
        new_writer_certificate_hash: harness.new_writer_certificate_hash(),
        trusted_head,
        reason_code: FIXTURE_TRANSITION_REASON_CODE,
    };
    let service = WriterTransitionService::new(&admin_head);
    let prepared = service
        .prepare(&request, authorization_object_hash)
        .expect("der Uebergang vom laufenden auf den freigegebenen Writer ist vorbereitbar");
    assert!(
        prepared.payload() == &fixture_payload,
        "die Nutzlast des Dienstes ist die der Fixture — zwei Erzeuger, dieselben Bytes"
    );
    assert_eq!(
        prepared.effective_from_sequence(),
        ChainSequence::new(effective_from)
    );

    // 2. Die Wurzelzeremonie: echter Nachweis, echter Auditdienst,
    //    Wurzelschluessel der Linie, laufuebergreifende Sperre.
    let now = harness.old().observed_now();
    let trust = harness.old().line().verified(trust_support::Pin::None);
    let intent = verify_intended_trust_target(
        &trust,
        Some(&admin_head),
        prepared.payload(),
        now,
        admin_head.proposed_sequence(),
    )
    .expect("die vorbereitete Autorisierung deckt die vorbereitete Nutzlast");
    let provider = RootKeyProvider;
    let old_certificate_object_hash =
        certificate_object_hash(harness.old_writer_certificate_hash());
    let audit = AuditHarness::new(&admin_head, old_certificate_object_hash);
    let binding_object_hash = harness.old().binding().binding_object_hash;
    let ceremony = RootCeremonyService::new(
        &admin_head,
        &provider,
        provider.handle(),
        CertificateHash::from(harness.old().line().current_root_hash()),
        audit.service(),
        binding_object_hash,
    );
    let proof = harness.old().proof_for(ReauthPurpose::AdminRootCeremony);
    let mut store = ReplayStore::default();
    let authorization_bytes = harness
        .old()
        .line()
        .exact_object_bytes(authorization_object_hash)
        .to_vec();
    let published = ceremony
        .publish_authorized_target(
            &intent,
            prepared.payload().clone(),
            &authorization_bytes,
            &mut store,
            &proof,
        )
        .expect("die Zeremonie veroeffentlicht den Uebergang")
        .as_bytes()
        .to_vec();
    assert_eq!(audit.booked(), 1, "die Zeremonie bucht ihre Zeile");
    assert_eq!(
        store.consumed(),
        2,
        "die Autorisierung ist in beiden Dimensionen verbraucht"
    );
    let transition_hash = object_hash(&published);

    // 3. Aktivieren: die veroeffentlichten Bytes gegen die Vorbereitung, das
    //    Ereignis aus der Ereignisfabrik des Kopfes.
    let device_id = admin_head
        .active_certificate_fields(harness.old_writer_certificate_hash())
        .expect("der alte Writer ist am Kopf vor dem Uebergang aktiv")
        .device_id;
    let local_device = VerifiedLocalDeviceIdentity::verify(
        &admin_head,
        harness.old_writer_certificate_hash(),
        device_id,
    )
    .expect("der alte Writer ist die lokale Geraeteidentitaet der Verwaltung");
    let events = RegistryEventFactory::new(&admin_head, audit.service(), local_device);
    let window = RegistryWindow {
        effective_from_sequence: ChainSequence::new(effective_from),
        valid_through_sequence: ChainSequence::new(effective_from + TRANSITION_LEASE_LENGTH),
        not_after: transition_not_after(harness),
    };
    let activated = service
        .activate(&prepared, &published, &events, window)
        .expect("die veroeffentlichten Bytes sind der vorbereitete Uebergang");
    assert!(activated.transition_object_hash() == transition_hash);
    let event = activated.event().clone();
    assert_eq!(
        audit.booked(),
        1,
        "die Ereignisfabrik bucht keine zweite Zeile"
    );

    // 4. Der Change 3 in der Linie — mit GENAU dem geplanten Ereignis.
    let head = harness.activate_published_transition(&published, &event);
    let ParsedArchiveObject::Trust(parsed) =
        decode_exact_object(harness.old().line().exact_object_bytes(head.object_hash))
            .expect("der Kopf der Linie ist wohlgeformt")
    else {
        panic!("der Kopf der Linie ist ein Trust-Objekt");
    };
    let DecodedTrustPayloadV1::RegistryEvent(core) = parsed
        .value()
        .decoded_payload()
        .expect("der Kopf traegt eine Registrierungsnutzlast")
    else {
        panic!("der Kopf ist ein Registrierungsereignis");
    };
    assert!(
        core.fields() == &event,
        "das Ereignis, das der Kern annimmt, ist Feld fuer Feld das geplante"
    );

    AdminTransition {
        request,
        authorization_object_hash,
        published,
        transition_hash,
        event,
        head,
    }
}

/// `notAfter` des Uebergangskopfes: dieselbe Grenze wie die der uebrigen
/// Koepfe der Writer-Linie — eine Millisekunde vor der Zeit, zu der die
/// Fixture ihren Kopf als abgelaufen beobachtet.
fn transition_not_after(harness: &TransitionHarness) -> UnixMillis {
    UnixMillis::new(harness.old().observed_now_after_expiry().get() - 1)
}

/// Ein Zertifikatshash als Objekthash — dieselben 32 Byte.
#[must_use]
pub fn certificate_object_hash(certificate: CertificateHash) -> ObjectHash {
    ObjectHash::try_from(certificate.as_bytes().as_slice())
        .expect("ein Zertifikatshash ist ein 32-Byte-Objekthash")
}

// ===========================================================================
// Die Writer-Seite
// ===========================================================================

/// Der NEUE Writer finalisiert seinen `keyTransition` gegen `head`.
///
/// # Panics
///
/// Wenn Vorschau oder Abschluss nicht tragen.
#[must_use]
pub fn new_writer_finalizes_key_transition(
    harness: &TransitionHarness,
    head: &SelectedRegistryHead,
    claims: &[CheckpointClaim],
) -> FinalizeOutcome {
    let source = harness.old().source();
    let service = harness.new_writer_service(&source, head, claims);
    let proof = harness.new_writer_proof(head);
    let now = harness.old().observed_now();
    let preview = service
        .preview_key_transition(
            &proof,
            writer_support::key_transition_input(writer_support::CANARY_TRANSITION_REASON),
            now,
        )
        .expect("die Vorschau des Uebergangs muss entstehen");
    service
        .finalize_key_transition(
            &proof,
            writer_support::key_transition_input(writer_support::CANARY_TRANSITION_REASON),
            &preview,
            now,
        )
        .expect("der keyTransition muss abschliessen")
}

/// Der NEUE Writer finalisiert einen Einsatz gegen `head`.
///
/// # Panics
///
/// Wenn Vorschau oder Abschluss nicht tragen.
#[must_use]
pub fn new_writer_finalizes_incident(
    harness: &TransitionHarness,
    head: &SelectedRegistryHead,
    claims: &[CheckpointClaim],
    number: &str,
) -> FinalizeOutcome {
    let source = harness.old().source();
    let service = harness.new_writer_service(&source, head, claims);
    let proof = harness.new_writer_proof(head);
    let now = harness.old().observed_now();
    let preview = service
        .preview(&proof, writer_support::incident_numbered(number), now)
        .expect("die Vorschau des Einsatzes muss entstehen");
    service
        .finalize(
            &proof,
            writer_support::incident_numbered(number),
            &preview,
            now,
        )
        .expect("der Einsatz des neuen Writers muss abschliessen")
}

/// Der ALTE Writer auf seiner KOPIE des Bestands.
///
/// Die Kulisse des zurueckgespielten Writers, der weiterschreibt — siehe
/// `TransitionHarness::old_writer_archive_replica`. Die Kopie muss VOR dem
/// ersten Eintrag des neuen Writers genommen werden: sie soll den Bestand
/// zeigen, wie der alte Writer ihn zuletzt gesehen hat.
pub struct OldWriterReplica {
    backend: LocalPathBackend,
}

impl OldWriterReplica {
    #[must_use]
    pub fn taken_now(harness: &TransitionHarness) -> Self {
        Self {
            backend: harness.old_writer_archive_replica(),
        }
    }

    #[must_use]
    pub const fn backend(&self) -> &LocalPathBackend {
        &self.backend
    }

    /// Der alte Writer finalisiert einen Einsatz mit `number` gegen `head` —
    /// auf der Kopie, mit seiner eigenen Datenbank, seinem eigenen
    /// Schluesselspeicher und seiner eigenen Bindung.
    ///
    /// # Panics
    ///
    /// Wenn Vorschau oder Abschluss nicht tragen.
    #[must_use]
    pub fn old_writer_finalizes_incident(
        &self,
        harness: &TransitionHarness,
        head: &SelectedRegistryHead,
        claims: &[CheckpointClaim],
        number: &str,
    ) -> FinalizeOutcome {
        let source = self.backend.as_archive_source();
        let service = WriterService::new(
            harness.old().repository(),
            harness.old().provider() as Arc<dyn KeyProvider>,
            &self.backend,
            &source,
            head,
            claims,
            IncidentNumberRegister::new(harness.old().database()),
            OperatorProfileRepository::new(harness.old().database()),
            harness.old().binding(),
        );
        let proof = harness.old_writer_proof(head);
        let now = harness.old().observed_now();
        let preview = service
            .preview(&proof, writer_support::incident_numbered(number), now)
            .expect("auf dem stalen Kopf entsteht die Vorschau des alten Writers");
        service
            .finalize(
                &proof,
                writer_support::incident_numbered(number),
                &preview,
                now,
            )
            .expect("auf der Kopie des Bestands schliesst der alte Writer ab")
    }
}

// ===========================================================================
// Die Serverseite: aus veroeffentlichten Bytes eine Commit-Anfrage
// ===========================================================================

/// Ein veroeffentlichter Eintrag samt seiner initialen Grants — die Bytes,
/// die ein Writer dem Server schicken wuerde.
pub struct PublishedEntry {
    pub bytes: Vec<u8>,
    pub parsed: Parsed<EntryPackageV1>,
    /// Jeder unter `grants/` liegende Grant, der DIESEN Eintrag nennt.
    pub grants: Vec<Vec<u8>>,
}

impl PublishedEntry {
    /// Liest den Eintrag mit `entry_hash` und seine Grants aus `backend`.
    ///
    /// # Panics
    ///
    /// Wenn der Eintrag nicht liegt oder die liegenden Bytes nicht parsen.
    #[must_use]
    pub fn read(backend: &LocalPathBackend, entry_hash: EntryHash) -> Self {
        let hex = hex::encode(entry_hash.as_bytes());
        let path = backend
            .relative_paths_below_for_test("entries/")
            .into_iter()
            .find(|path| path.ends_with(".eip") && path.contains(&hex))
            .expect("der committed Eintrag muss unter seinem Layoutnamen liegen");
        let bytes = backend
            .read_for_test(&path)
            .expect("das committed .eip muss lesbar sein");
        let parsed = parse_entry(&bytes).expect("das committed .eip ist ein Eintragspaket");
        assert!(parsed.value().entry_hash() == entry_hash);
        let grants = backend
            .relative_paths_below_for_test("grants/")
            .into_iter()
            .filter(|path| path.ends_with(".eag"))
            .map(|path| {
                backend
                    .read_for_test(&path)
                    .expect("ein veroeffentlichter Grant muss lesbar sein")
            })
            .filter(|bytes| {
                let ParsedArchiveObject::Grant(grant) =
                    decode_exact_object(bytes).expect("ein veroeffentlichter Grant dekodiert")
                else {
                    return false;
                };
                grant.value().grant_body().fields().entry_hash == entry_hash
            })
            .collect();
        Self {
            bytes,
            parsed,
            grants,
        }
    }

    /// Die Commit-Anfrage dieses Eintrags — mit dem Plan, den `head` fuer
    /// seine aktiven Empfaenger verlangt (derselbe, den der Writer beim
    /// Abschluss gegen diesen Kopf gebaut hat).
    ///
    /// # Panics
    ///
    /// Wenn der Plan nicht baubar ist oder die Anfrage ihre Grenzen reisst.
    #[must_use]
    pub fn commit_request(&self, head: &SelectedRegistryHead) -> EntryCommitRequestV1 {
        EntryCommitRequestV1::new(
            self.bytes.clone(),
            ea_writer::build_grant_plan(head).expect("der Kopf verlangt einen baubaren Plan"),
            self.grants.clone(),
        )
        .expect("die Commit-Anfrage der Fixture ist gueltig")
    }

    /// Dieselbe Anfrage ueber ANDERE Eintragsbytes — dieselben Grants,
    /// derselbe Plan.
    #[must_use]
    pub fn commit_request_with_entry(
        &self,
        head: &SelectedRegistryHead,
        entry_bytes: Vec<u8>,
    ) -> EntryCommitRequestV1 {
        EntryCommitRequestV1::new(
            entry_bytes,
            ea_writer::build_grant_plan(head).expect("der Kopf verlangt einen baubaren Plan"),
            self.grants.clone(),
        )
        .expect("die Commit-Anfrage der Fixture ist gueltig")
    }
}

/// Schritt 2 des Servers: `validate_commit` gegen den ECHTEN Kopf, mit
/// Organisation und Kette aus der Linie beziehungsweise dem Kopf.
///
/// # Errors
///
/// Jeder Arm von [`CommitValidationError`] — der Befund des Zeugen.
pub fn validate_at_server(
    request: &EntryCommitRequestV1,
    entry: &Parsed<EntryPackageV1>,
    head: &SelectedRegistryHead,
    writer_certificate_hash: CertificateHash,
) -> Result<ValidatedCommitV1, CommitValidationError> {
    validate_commit(
        request,
        entry,
        trust_support::organization(),
        head.chain_id(),
        writer_certificate_hash,
        head,
    )
}

/// Dasselbe Manifest, aber mit einem anderen `writer_transition_event_hash`,
/// vom NEUEN Writer mit seinem echten Schluessel nachsigniert.
///
/// Ciphertext, Nonce, Plan-Hash, Registry-Bindung und Vorgaenger bleiben.
/// Nur das eine Feld weicht ab — und damit der `entryHash`: die Grants des
/// Originals nennen einen anderen Eintrag. Das ist fuer die Messung ohne
/// Belang, weil die Uebergangsregel VOR jeder Grant-Pruefung faellt
/// (`crates/ea-sync-server/src/validation.rs`, Reihenfolge von
/// `validate_commit`); ein Zeuge, der die Grants passend machte, maesse
/// nichts anderes.
///
/// # Panics
///
/// Wenn Manifest, Signatur oder Paket nicht entstehen.
#[must_use]
pub fn resigned_with_transition_hash(
    entry: &Parsed<EntryPackageV1>,
    provider: &InMemoryKeyProvider,
    binding: WriterBindingV1,
    writer_transition_event_hash: Option<ObjectHash>,
) -> Vec<u8> {
    let mut fields = entry.value().manifest().fields().clone();
    fields.writer_transition_event_hash = writer_transition_event_hash;
    let ciphertext = entry.value().ciphertext().to_vec();
    let manifest =
        ManifestCoreV1::new(fields, &ciphertext).expect("das nachgebaute Manifest kodiert");
    let signed = SignedManifestV1::new(manifest, &ciphertext).expect("das Manifest bindet");
    let signature = provider
        .sign(
            &binding.writer_signing_handle,
            ContentType::RecordDigest,
            binding.writer_certificate_hash,
            ea_crypto::record_digest(signed.exact_bytes()).as_bytes(),
        )
        .expect("der Schluesselspeicher des neuen Writers signiert")
        .as_bytes()
        .to_vec();
    let package = EntryPackageV1::new(signed, ciphertext, signature)
        .expect("das nachsignierte Eintragspaket setzt sich zusammen");
    encode_entry_package(&package)
        .expect("das nachsignierte Eintragspaket kodiert")
        .into_vec()
}

/// Der Code, mit dem ein Writer-Lauf NICHT stattgefunden hat.
///
/// `expect_err` verlangt `Debug` auf dem `Ok`-Typ, und eine Vorschau hat
/// bewusst keines.
pub fn blocked_with<T>(result: Result<T, ea_writer::WriterError>, why: &str) -> &'static str {
    match result {
        Ok(_) => panic!("{why}"),
        Err(error) => error.code(),
    }
}

/// Der Befund, mit dem der Server einen Commit NICHT angenommen hat.
///
/// `expect_err` verlangt `Debug` auf `ValidatedCommitV1` — das hat es —, aber
/// ein Ok-Wert traegt Hashes, die in keine Panikzeile gehoeren.
pub fn refused_with(
    result: Result<ValidatedCommitV1, CommitValidationError>,
    why: &str,
) -> CommitValidationError {
    match result {
        Ok(_) => panic!("{why}"),
        Err(error) => error,
    }
}
