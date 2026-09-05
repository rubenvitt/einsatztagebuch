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
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use ea_admin::{
    AdminBootstrapPairV1, AdminError, AnchorMedia, AnchorMediumId, BackedUpKeyClass,
    BootstrapCoordinator, BootstrapStateV1, BootstrapStep, BootstrapStore, BootstrapTranscriptV1,
    CeremonyRandomSource, ComponentBindingV1, GenesisEnvelopeV1, KeyBackupRecordV1,
    OuterKeyRecordV1, ProductionState, RecoveryTestObservation, RootCeremonyService,
    RootKeyMaterialV1, bind_genesis, confirm_pre_anchor_fingerprint,
    verify_fresh_machine_recovery_test,
};
use ea_audit::{
    AuditError, LocalAuditRepository, LocalAuditService, SignedLocalAuditEvent,
    SignedLocalAuditService,
};
use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_format::{CertificateKindV1, KeyProtectionProfileV1, OperatorRoleV1, TrustPayloadV1};
use ea_key_provider::{
    CoseSign1Bytes, KeyError, KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose,
};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose,
};
use ea_schema::{CommonHeaderV1, GenesisV1, NativeSourceV1, OperatorSnapshotV1};
use ea_time::TrustedTimeState;
use ea_trust::{
    AdminAuthorizationReplayDimension, AdminAuthorizationReplayKey, ClockReleaseReplayKey,
    IndependentTimeCommit, PersistedTrustRecord, RegistryHeadPin, RegistrySelectionCommit,
    RegistrySelectionOutcome, SelectedRegistryHead, StateStoreError, TrustStateKey,
    TrustStateStore, VerifiedAdminAuthorizationIntent, VerifiedTrust, decode_trust_anchor,
    prepare_local_time, select_registry_head, verify_intended_trust_target,
    verify_registry_candidate,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, EventId, Hash32, KeyThumbprint,
    ObjectHash, OperatorSubjectId, OrganizationId, RecordId, RegistryVersion, UnixMillis,
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

/// Die Marke der Bindung, unter der die Zeremonie handelt.
const BINDING_MARKER: u8 = 0x71;

/// Die Marke einer ZWEITEN, ebenfalls gebundenen Bedienerin derselben
/// Organisation. Ihr Nachweis ist frisch und tauglich — er gehoert nur nicht
/// zu der Bindung, fuer die der Dienst handelt.
const SECOND_BINDING_MARKER: u8 = 0x81;

/// Die Betriebssystemuhr der Fixture.
///
/// Sie liegt IM Fenster der Administrationsautorisierung: `HeadOptions`
/// vergibt `issuedAt = 100`, und die Fixture setzt `expiresAt = issuedAt +
/// 1_000`. Derselbe Wert ist die `PreexistingEffectiveNow` des gewaehlten
/// Kopfes, gegen die `OperatorSessionProof::is_valid_for` bewertet — zwei Uhren
/// hiessen zwei Zeitfenster, und eines von beiden waere zufaellig das falsche.
pub const FIXTURE_NOW_MS: i64 = 1_000;

/// Der Index des letzten Kopfes der Linie.
pub const LAST_HEAD: usize = 3;

/// Der Index des VORLETZTEN Kopfes — eine andere Registrierungsfassung,
/// gegen die derselbe Beweiszustand nicht gilt.
pub const EARLIER_HEAD: usize = 2;

/// Die Sequenz, an der die Fixture ihren Kopf waehlt — im Fenster des letzten
/// Uebergangs (41..100) und VOR dem Widerruf der zweiten Bindung.
pub const PROPOSED_SEQUENCE: u64 = 50;

/// Die Sequenz, ab der die zweite Bindung widerrufen ist.
const SECOND_BINDING_REVOKED_FROM: u64 = 60;

/// Eine Sequenz HINTER dem Widerruf — noch im Fenster desselben Kopfes.
pub const AFTER_REVOCATION_SEQUENCE: u64 = 70;

/// Eine Sequenz im Fenster des VORLETZTEN Kopfes (21..40).
pub const EARLIER_SEQUENCE: u64 = 30;

const FIXTURE_NOT_AFTER_MS: i64 = 10_000_000;

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
    /// Die UNSIGNIERTE Nutzlast des Ziels. Es liegt NICHT im Katalog: genau
    /// diesen Stand hat ein Wirt in der Hand, der eine Wurzelaenderung erst
    /// noch veroeffentlichen will.
    pub target_payload: TrustPayloadV1,
    /// Die Autorisierung des Ziels — sie liegt im Katalog, das Ziel nicht.
    pub authorization_object_hash: ObjectHash,
    /// Die Bindung, fuer die der Dienst handelt. Nie widerrufen.
    pub binding_object_hash: ObjectHash,
    /// Die Bindung einer ZWEITEN Bedienerin, ab
    /// [`SECOND_BINDING_REVOKED_FROM`] widerrufen.
    pub second_binding_object_hash: ObjectHash,
    pub writer_certificate_object_hash: ObjectHash,
    pub root_certificate_hash: CertificateHash,
}

/// Baut die Registrierungslinie der Zeremonie.
///
/// Deterministisch: feste Geheimnisse, feste Marken, feste Fenster. Zwei
/// Aufrufe liefern dieselbe Linie und dieselbe Nutzlast.
///
/// Vier Uebergaenge — Policy, Writer-Zertifikat und ZWEI Bedienerbindungen —,
/// und danach `prepare_unsigned`: die Autorisierung des Ziels wandert in den
/// Katalog, das Ziel selbst entsteht erst im Dienst. Ein Zeuge, der ein
/// bereits signiertes Objekt durchreichte, bezeugte den Fall nicht, fuer den
/// dieser Dienst gebaut ist.
///
/// # Panics
///
/// Wenn die Fixture ihre eigenen direkten Ziele nicht baut.
#[must_use]
pub fn ceremony_line() -> CeremonyLine {
    ceremony_line_for(&|_, _| policy_action())
}

/// Dieselbe Linie, aber mit einer frei gewaehlten Objektart als Ziel.
///
/// `target` bekommt den Objekthash des Writer-Zertifikats der Linie und den
/// der aktuellen Wurzelurkunde: eine Bedienerbindung muss ein Zertifikat
/// nennen, eine Wurzelrotation ihre Vorgaengerin.
///
/// # Panics
///
/// Wenn die Fixture ihre eigenen direkten Ziele nicht baut.
#[must_use]
pub fn ceremony_line_for(target: &dyn Fn(ObjectHash, ObjectHash) -> ActionSpec) -> CeremonyLine {
    let instance_thumbprint = KeyThumbprint::from(
        Hash32::try_from(
            public_key(INSTANCE_SECRET)
                .thumbprint()
                .as_bytes()
                .as_slice(),
        )
        .expect("ein Thumbprint ist 32 Byte"),
    );
    let mut line = RegistryLineBuilder::new();
    let root_object_hash = line.current_root_hash();
    let root_certificate_hash = CertificateHash::from(root_object_hash);
    line.push(policy_action(), head_options(1, 10));
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
            binding_instance_key_thumbprint_override: Some(instance_thumbprint),
            ..head_options(21, 40)
        },
    );
    let binding_object_hash = binding
        .direct_object_hash
        .expect("die Bedienerbindung der Fixture ist ein direktes Ziel");
    let second = line.push(
        ActionSpec::OperatorBinding {
            certificate_hash: writer_certificate_object_hash,
            role: OperatorRoleV1::Writer,
            marker: SECOND_BINDING_MARKER,
            effective_from: None,
        },
        HeadOptions {
            binding_instance_key_thumbprint_override: Some(instance_thumbprint),
            revoked_from_sequence: Some(ChainSequence::new(SECOND_BINDING_REVOKED_FROM)),
            ..head_options(41, 100)
        },
    );
    let second_binding_object_hash = second
        .direct_object_hash
        .expect("die zweite Bedienerbindung ist ein direktes Ziel");
    // Erst JETZT: die Autorisierung des Ziels, gebunden an den aktuellen Kopf.
    // Das Ziel selbst bleibt aus dem Katalog fort.
    let (authorization_object_hash, target_payload) = line.prepare_unsigned(
        target(writer_certificate_object_hash, root_object_hash),
        HeadOptions::default(),
    );
    CeremonyLine {
        target_payload,
        authorization_object_hash,
        binding_object_hash,
        second_binding_object_hash,
        writer_certificate_object_hash,
        root_certificate_hash,
        line,
    }
}

impl CeremonyLine {
    /// Eine Kopie der beabsichtigten Nutzlast.
    ///
    /// `publish_authorized_target` nimmt sie als Wert; ein Zeuge, der danach
    /// noch etwas ueber sie sagen will, braucht deshalb eine zweite.
    #[must_use]
    pub fn target_payload(&self) -> TrustPayloadV1 {
        self.target_payload.clone()
    }

    /// Die exakten Bytes der Autorisierung dieses Ziels.
    #[must_use]
    pub fn authorization_bytes(&self) -> &[u8] {
        self.line.exact_object_bytes(self.authorization_object_hash)
    }

    /// Der Beweiszustand VOR der Signatur, gegen `head`.
    ///
    /// # Panics
    ///
    /// Wenn die Autorisierung das beabsichtigte Ziel nicht deckt.
    #[must_use]
    pub fn intent(&self, head: &SelectedRegistryHead) -> VerifiedAdminAuthorizationIntent {
        let trust = verified(&self.line);
        verify_intended_trust_target(
            &trust,
            Some(head),
            &self.target_payload,
            UnixMillis::new(FIXTURE_NOW_MS),
            head.proposed_sequence(),
        )
        .expect("die Autorisierung deckt das beabsichtigte Ziel")
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
    selected_head_at(line, LAST_HEAD, PROPOSED_SEQUENCE)
}

/// Waehlt den Kopf mit dem Index `head_index` an `proposed_sequence`.
///
/// # Panics
///
/// Wenn die Fixture diesen Kopf nicht waehlt.
#[must_use]
pub fn selected_head_at(
    line: &RegistryLineBuilder,
    head_index: usize,
    proposed_sequence: u64,
) -> SelectedRegistryHead {
    let head = line.heads()[head_index];
    let key = trust_support::state_key();
    let trusted_time = TrustedTimeState::initial(UnixMillis::new(FIXTURE_NOW_MS));
    let trust = line.verified_with_record(Pin::Head(head_index), 17, trusted_time.clone(), key);
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(proposed_sequence))
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
/// `marker` ist die Marke, unter der die Fixture die Bindung gebaut hat; ihr
/// `os_account_binding_hash` ist `hash32(marker + 2)`
/// (`crates/ea-trust/tests/support/mod.rs`, Zweig `ActionSpec::OperatorBinding`).
/// Ohne sie meldete die Kontoattrappe das Konto einer fremden Bindung, und
/// `reauthenticate` braeche mit `AccountMismatch` ab.
///
/// # Panics
///
/// Wenn die Bindung an der gewaehlten Sequenz nicht aktiv ist oder die
/// Wiederanmeldung scheitert.
#[must_use]
pub fn operator_proof(
    head: &SelectedRegistryHead,
    binding_object_hash: ObjectHash,
    marker: u8,
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
        binding_hash: trust_support::hash32(marker.wrapping_add(2)),
        instance_public_key: Some(public_key(INSTANCE_SECRET)),
    });
    authenticator
        .reauthenticate(account, purpose)
        .expect("die Fixture meldet den gebundenen Bediener wieder an")
}

/// Der Nachweis der Bindung, fuer die der Dienst handelt.
#[must_use]
pub fn ceremony_proof(
    ceremony: &CeremonyLine,
    head: &SelectedRegistryHead,
    purpose: ReauthPurpose,
) -> OperatorSessionProof {
    operator_proof(head, ceremony.binding_object_hash, BINDING_MARKER, purpose)
}

/// Der Nachweis der ZWEITEN Bedienerin — frisch, tauglich, fremde Bindung.
#[must_use]
pub fn second_operator_proof(
    ceremony: &CeremonyLine,
    head: &SelectedRegistryHead,
    purpose: ReauthPurpose,
) -> OperatorSessionProof {
    operator_proof(
        head,
        ceremony.second_binding_object_hash,
        SECOND_BINDING_MARKER,
        purpose,
    )
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
    /// Der Abdruck, den der geschuetzte Kopf NENNT — falls er nicht der des
    /// Schluessels ist, mit dem unterschrieben wird.
    ///
    /// Die Attrappe eines Providers, der luegt. `CoseSign1Bytes::compose`
    /// liest seine Bytes nur gegen `parse_cose_sign1` zurueck, und das prueft
    /// keine Signatur — ein Abdruckvergleich allein faellt auf ihn herein.
    claimed_thumbprint: Option<KeyThumbprint>,
    /// Wie oft der Port um eine Signatur gebeten wurde.
    ///
    /// Ohne den Zaehler misst ein Zeuge namens „… erreicht den Schluesselport
    /// nie" seinen eigenen Namen nicht: er saehe nur, dass der Aufruf
    /// scheitert, nicht WO.
    signatures: AtomicUsize,
}

impl FixtureKeyProvider {
    /// Der Provider, der den Wurzelschluessel DIESER Linie haelt.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            secret: trust_support::root_signing_secret(),
            claimed_thumbprint: None,
            signatures: AtomicUsize::new(0),
        }
    }

    /// Ein Provider mit einem FREMDEN Schluessel — derselbe Port, ein anderer
    /// Unterzeichner.
    #[must_use]
    pub const fn foreign() -> Self {
        Self {
            secret: FOREIGN_ROOT_SECRET,
            claimed_thumbprint: None,
            signatures: AtomicUsize::new(0),
        }
    }

    /// Ein Provider, der den Abdruck der WURZEL nennt und mit einem fremden
    /// Schluessel unterschreibt.
    ///
    /// Der Fall, den ein reiner Abdruckvergleich nicht faengt.
    #[must_use]
    pub fn impersonating_root() -> Self {
        Self {
            secret: FOREIGN_ROOT_SECRET,
            claimed_thumbprint: Some(public_key(trust_support::root_signing_secret()).thumbprint()),
            signatures: AtomicUsize::new(0),
        }
    }

    /// Wie oft dieser Port bisher signiert hat.
    #[must_use]
    pub fn signatures_produced(&self) -> usize {
        self.signatures.load(Ordering::SeqCst)
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
        self.signatures.fetch_add(1, Ordering::SeqCst);
        let key = signing_key(self.secret);
        let public = CanonicalPublicCoseKey::ed25519(key.verifying_key().to_bytes())
            .map_err(KeyError::Crypto)?;
        let protected = ProtectedHeader::normal(
            content_type,
            self.claimed_thumbprint
                .unwrap_or_else(|| public.thumbprint()),
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
///
/// Die Dimension gehoert in den Schluessel: `authorizationId` und `nonce` sind
/// je fuer sich organisationsweit einmalig, und eine Ablage, die die Dimension
/// wegwirft, verwechselte eine 16-Byte-Kennung mit einer 32-Byte-Nonce.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ReplayDimensionRow {
    AuthorizationId([u8; 16]),
    Nonce([u8; 32]),
}

type ReplayRow = ([u8; 16], ReplayDimensionRow);

fn replay_row(key: &AdminAuthorizationReplayKey) -> ReplayRow {
    let dimension = match key.dimension() {
        AdminAuthorizationReplayDimension::AuthorizationId(id) => {
            ReplayDimensionRow::AuthorizationId(*id.as_bytes())
        }
        AdminAuthorizationReplayDimension::Nonce(nonce) => ReplayDimensionRow::Nonce(nonce),
    };
    (*key.organization_id().as_bytes(), dimension)
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

    /// Wie viele Sperrzeilen die Tabelle fuehrt.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
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

/// Ein Speicher, der die ERSTE Sperrdimension setzt und bei der zweiten
/// ausfaellt.
///
/// Kein konstruierter Sonderfall: `consume_replay_keys` setzt die beiden
/// Dimensionen NACHEINANDER, und eine Ablage kann zwischen zwei Anweisungen
/// wegbrechen. Danach ist die Autorisierung halb verbraucht — genau der
/// Zustand, ueber den die Auditzeile Auskunft geben muss.
pub struct StoreFailingOnTheSecondDimension {
    table: Arc<Mutex<ReplayTable>>,
    seen: usize,
}

impl StoreFailingOnTheSecondDimension {
    #[must_use]
    pub fn open(table: &Arc<Mutex<ReplayTable>>) -> Self {
        Self {
            table: Arc::clone(table),
            seen: 0,
        }
    }
}

impl TrustStateStore for StoreFailingOnTheSecondDimension {
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

    fn admin_authorization_consumed(
        &mut self,
        key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.seen += 1;
        if self.seen > 1 {
            return Err(StateStoreError::Unavailable);
        }
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .push(replay_row(key));
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

/// Der Dienst der Fixture ueber `provider`, gebunden an `binding_object_hash`.
#[must_use]
pub fn ceremony_service<'a>(
    head: &'a SelectedRegistryHead,
    provider: &'a FixtureKeyProvider,
    audit: &'a AuditHarness,
    ceremony: &CeremonyLine,
) -> RootCeremonyService<'a> {
    ceremony_service_for(
        head,
        provider,
        audit,
        ceremony,
        ceremony.binding_object_hash,
    )
}

/// Derselbe Dienst, aber fuer eine ausdruecklich genannte Bindung.
#[must_use]
pub fn ceremony_service_for<'a>(
    head: &'a SelectedRegistryHead,
    provider: &'a FixtureKeyProvider,
    audit: &'a AuditHarness,
    ceremony: &CeremonyLine,
    binding_object_hash: ObjectHash,
) -> RootCeremonyService<'a> {
    RootCeremonyService::new(
        head,
        provider,
        provider.handle(),
        ceremony.root_certificate_hash,
        audit.service(),
        binding_object_hash,
    )
}

/// Derselbe Dienst, aber unter einem ausdruecklich genannten
/// Wurzelzertifikatshash.
#[must_use]
pub fn ceremony_service_under_root<'a>(
    head: &'a SelectedRegistryHead,
    provider: &'a FixtureKeyProvider,
    audit: &'a AuditHarness,
    ceremony: &CeremonyLine,
    root_certificate_hash: CertificateHash,
) -> RootCeremonyService<'a> {
    RootCeremonyService::new(
        head,
        provider,
        provider.handle(),
        root_certificate_hash,
        audit.service(),
        ceremony.binding_object_hash,
    )
}

// ===========================================================================
// Die Kulisse des Zwoelfschrittablaufs (DRK-270)
// ===========================================================================

/// Das erste schreibgeschuetzte Recovery-Medium.
pub const FIRST_MEDIUM: AnchorMediumId = AnchorMediumId::new([0x01; 16]);
/// Das zweite — `:1780` verlangt „mindestens zwei".
pub const SECOND_MEDIUM: AnchorMediumId = AnchorMediumId::new([0x02; 16]);
/// Zwei getrennte Sicherungsmedien fuer Schritt 7.
pub const BACKUP_MEDIUM_A: AnchorMediumId = AnchorMediumId::new([0x0a; 16]);
/// Das zweite Sicherungsmedium.
pub const BACKUP_MEDIUM_B: AnchorMediumId = AnchorMediumId::new([0x0b; 16]);

/// Der Rechner, auf dem die Zeremonie lief.
const CEREMONY_MACHINE: u8 = 0xc0;
/// Ein ANDERER Rechner — der frische aus Schritt 12.
const FRESH_MACHINE: u8 = 0xf7;

/// Der Genesis-Eintragshash der Kulisse.
///
/// Er kommt vom Wirt: `ea_crypto::entry_hash` verlangt eine echte
/// Writer-Finalisierung, und die lebt in `ea-writer`.
const GENESIS_ENTRY_HASH: [u8; 32] = [0x44; 32];

/// Die Registrierungsfassung, die der Genesis der Kulisse bindet (`:1145`).
const GENESIS_REGISTRY_VERSION: u64 = 7;

fn hash32_of(byte: u8) -> Hash32 {
    Hash32::try_from(&[byte; 32][..]).expect("ein Hash32 ist 32 Byte")
}

fn thumbprint_of(byte: u8) -> KeyThumbprint {
    KeyThumbprint::from(hash32_of(byte))
}

fn object_hash_of(byte: u8) -> ObjectHash {
    ObjectHash::try_from(&[byte; 32][..]).expect("ein ObjectHash ist 32 Byte")
}

fn outer_handle(byte: u8) -> KeyHandle {
    KeyHandle::new(
        KeystoreProvider::InMemory,
        trust_support::hash32(byte),
        SecretPurpose::OperatorInstanceKey,
    )
}

/// Ein Stapel benannter Medien im Speicher.
///
/// Er liest zurueck, was er geschrieben hat — ausser fuer die Kennungen in
/// `corrupting`, die beim Lesen andere Bytes liefern.
#[derive(Default)]
pub struct MediaStack {
    written: BTreeMap<AnchorMediumId, Vec<u8>>,
    corrupting: Vec<AnchorMediumId>,
}

impl MediaStack {
    /// Ein Stapel, auf dem die genannten Medien beim Lesen luegen.
    #[must_use]
    pub fn corrupting(ids: &[AnchorMediumId]) -> Self {
        Self {
            written: BTreeMap::new(),
            corrupting: ids.to_vec(),
        }
    }
}

impl AnchorMedia for MediaStack {
    fn write_exact_bytes(
        &mut self,
        medium: AnchorMediumId,
        exact_bytes: &[u8],
    ) -> Result<(), AdminError> {
        self.written.insert(medium, exact_bytes.to_vec());
        Ok(())
    }

    fn read_exact_bytes(&self, medium: AnchorMediumId) -> Result<Vec<u8>, AdminError> {
        let stored = self
            .written
            .get(&medium)
            .cloned()
            .ok_or(AdminError::MediaUnavailable)?;
        if self.corrupting.contains(&medium) {
            let mut corrupted = stored;
            corrupted[0] ^= 0xff;
            return Ok(corrupted);
        }
        Ok(stored)
    }
}

/// Eine VORHERSAGBARE Zufallsquelle.
///
/// Jeder Aufruf fuellt mit einem anderen Byte. Damit unterscheiden sich
/// Organisations- und Ketten-ID voneinander UND von denen jeder spaeteren
/// Zeremonie — genau das, was `:1349` fuer den Neuanfang verlangt und was ein
/// Zeuge messen koennen muss.
pub struct SequentialRandom {
    counter: u8,
}

impl Default for SequentialRandom {
    fn default() -> Self {
        Self { counter: 0x20 }
    }
}

impl CeremonyRandomSource for SequentialRandom {
    fn fill_random(&mut self, destination: &mut [u8]) -> Result<(), AdminError> {
        self.counter = self.counter.wrapping_add(1);
        destination.fill(self.counter);
        Ok(())
    }
}

/// Die Ablage des Zeremoniezustands im Speicher.
///
/// Sie haelt BEIDES: den getippten Zustand fuer [`BootstrapStore::load`] und
/// das Byteabbild, das [`BootstrapStateV1::persisted_image`] herausgibt. Das
/// Abbild ist das, was ein Zeuge nach Schluesselmaterial durchsucht — der
/// Vertrag des Ports lautet, dass genau dieses Abbild persistiert wird.
#[derive(Default)]
pub struct MemoryBootstrapStore {
    state: Option<BootstrapStateV1>,
    image: Vec<u8>,
}

impl MemoryBootstrapStore {
    /// Das zuletzt geschriebene Byteabbild.
    #[must_use]
    pub fn image(&self) -> &[u8] {
        &self.image
    }
}

impl BootstrapStore for MemoryBootstrapStore {
    fn load(&self) -> Result<Option<BootstrapStateV1>, AdminError> {
        Ok(self.state.clone())
    }

    fn store(&mut self, state: &BootstrapStateV1) -> Result<(), AdminError> {
        self.image = state.persisted_image();
        self.state = Some(state.clone());
        Ok(())
    }
}

/// Der Anker der `ea-trust`-Fixture — eine ECHTE Linie, kein Bytehaufen.
fn fixture_anchor() -> ea_trust::TrustAnchorV1 {
    decode_trust_anchor(RegistryLineBuilder::new().exact_anchor_bytes())
        .expect("die Fixture traegt einen gueltigen Anker")
}

/// Das oeffentliche Wurzelmaterial, wie der Wirt es der Zeremonie gibt.
///
/// Der Griff ist der des [`FixtureKeyProvider`]; der oeffentliche Schluessel,
/// sein Abdruck und der Urkundenhash kommen aus der Linie, damit
/// `encode_pre_anchor_v1` seine RFC-9679-Pruefung besteht.
#[must_use]
pub fn fixture_root_material() -> RootKeyMaterialV1 {
    let anchor = fixture_anchor();
    RootKeyMaterialV1 {
        signing_handle: FixtureKeyProvider::root().handle(),
        exact_public_cose_key: anchor.root_public_cose_key_bytes().to_vec(),
        key_thumbprint: anchor.root_key_thumbprint(),
        certificate_object_hash: anchor.root_certificate_object_hash(),
    }
}

/// Die zwei ankergepinnten Admin-Paare der Fixture.
#[must_use]
pub fn bootstrap_admin_pairs() -> Vec<AdminBootstrapPairV1> {
    let anchor = fixture_anchor();
    anchor
        .initial_admin_certificate_object_hashes()
        .iter()
        .zip(anchor.initial_admin_operator_binding_object_hashes())
        .map(|(certificate, binding)| AdminBootstrapPairV1 {
            certificate_object_hash: *certificate,
            operator_binding_object_hash: *binding,
        })
        .collect()
}

/// Dieselben Paare mit EINER geaenderten Bindung.
///
/// Der GROESSTE Wert, damit die Liste sortiert bleibt: die Aenderung soll an
/// der Versiegelung scheitern und nicht schon an der Form.
#[must_use]
pub fn changed_admin_pairs() -> Vec<AdminBootstrapPairV1> {
    let mut pairs = bootstrap_admin_pairs();
    let last = pairs.len() - 1;
    pairs[last].operator_binding_object_hash = object_hash_of(0xfe);
    pairs
}

/// Der Recovery-KEM-Schluessel aus Schritt 5 — Griff und Abdruck, sonst
/// nichts.
#[must_use]
pub fn recovery_kem_record() -> OuterKeyRecordV1 {
    OuterKeyRecordV1 {
        handle: outer_handle(0x31),
        key_thumbprint: thumbprint_of(0x31),
    }
}

/// Der HGA-Signaturschluessel aus Schritt 5.
#[must_use]
pub fn hga_record() -> OuterKeyRecordV1 {
    OuterKeyRecordV1 {
        handle: outer_handle(0x32),
        key_thumbprint: thumbprint_of(0x32),
    }
}

/// Jedes ECHTE Geheimnis dieser Kulisse.
///
/// Es sind wirkliche private Ed25519-Schluessel und nicht ausgedachte Muster;
/// ein Zeuge, der nach Mustern suchte, die nirgends vorkommen, bewiese nichts.
#[must_use]
pub fn every_fixture_secret() -> Vec<Vec<u8>> {
    vec![
        trust_support::root_signing_secret().to_vec(),
        INSTANCE_SECRET.to_vec(),
        FOREIGN_ROOT_SECRET.to_vec(),
    ]
}

/// Baut die finalen Ankerbytes AUS einer Vorstufe (`:1346`, `:1750-1763`).
///
/// Finale Domaene, `bootstrap-anchor-hash` und `genesis-entry-hash` kommen
/// hinzu, alles andere wird bytegleich uebernommen.
#[must_use]
pub fn final_anchor_bytes(pre: &ea_trust::PreAnchorV1, genesis_entry_hash: &[u8; 32]) -> Vec<u8> {
    let certificates = pre.initial_admin_certificate_object_hashes();
    let bindings = pre.initial_admin_operator_binding_object_hashes();
    let mut bytes = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut bytes);
    encoder
        .array(12)
        .and_then(|encoder| encoder.str("EINSATZARCHIV-TRUST-ANCHOR-v1"))
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(pre.bootstrap_anchor_hash().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.organization_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.chain_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_public_cose_key_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_key_thumbprint().as_bytes()))
        .and_then(|encoder| encoder.bytes(pre.root_certificate_object_hash().as_bytes()))
        .and_then(|encoder| {
            encoder.array(u64::try_from(certificates.len()).expect("zwei Paare passen in u64"))
        })
        .expect("der Zeuge kodiert in einen Vec");
    for hash in certificates {
        encoder.bytes(hash.as_bytes()).expect("Hash kodiert");
    }
    encoder
        .array(u64::try_from(bindings.len()).expect("zwei Paare passen in u64"))
        .expect("Bindungsliste kodiert");
    for hash in bindings {
        encoder.bytes(hash.as_bytes()).expect("Hash kodiert");
    }
    encoder
        .bytes(genesis_entry_hash)
        .and_then(|encoder| encoder.array(0))
        .expect("Genesis und leere kritische Erweiterungen kodieren");
    bytes
}

/// Der Genesis-Datensatz der Kulisse — gebaut von `ea-schema`, nicht hier.
fn genesis_record(organization_id: OrganizationId, chain_id: ChainId) -> GenesisV1 {
    let mut record_id_bytes = [0x51_u8; 16];
    record_id_bytes[6] = 0x71;
    record_id_bytes[8] = 0x91;
    GenesisV1::new(
        CommonHeaderV1::new(
            RecordId::try_from(record_id_bytes.as_slice()).expect("eine UUIDv7 der Kulisse"),
            UnixMillis::new(1_700_000_000_000),
            "Europe/Berlin",
            OperatorSnapshotV1::new(
                organization_id,
                OperatorSubjectId::try_from(&[0x20; 16][..]).expect("16 Byte"),
                "Erika Beispiel",
                "Einsatzleitung",
                [0x30; 32],
                object_hash_of(0x40),
            )
            .expect("der Bedienerabzug der Kulisse ist gueltig"),
            NativeSourceV1::new("writer-native", 1).expect("die Quelle der Kulisse ist gueltig"),
            RegistryVersion::new(GENESIS_REGISTRY_VERSION),
        )
        .expect("der Kopf der Kulisse ist gueltig"),
        organization_id,
        chain_id,
        object_hash_of(0x12),
        1,
        object_hash_of(0x13),
    )
    .expect("der Genesis der Kulisse ist gueltig")
}

/// Die Kulisse des Zwoelfschrittablaufs.
///
/// Sie haelt Ablage, Zufallsquelle und Medien und baut je Bewegung einen
/// frischen [`BootstrapCoordinator`] aus der Ablage — genau so, wie ein Wirt
/// nach einem Neustart weitermacht.
pub struct BootstrapHarness {
    store: MemoryBootstrapStore,
    random: SequentialRandom,
    media: MediaStack,
}

impl Default for BootstrapHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapHarness {
    /// Eine leere Kulisse; die Zeremonie beginnt beim ersten Schritt.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: MemoryBootstrapStore::default(),
            random: SequentialRandom::default(),
            media: MediaStack::default(),
        }
    }

    fn state(&self) -> BootstrapStateV1 {
        self.store
            .load()
            .expect("die Ablage der Kulisse antwortet")
            .expect("die Kulisse hat begonnen")
    }

    /// Der zuletzt abgeschlossene Schritt.
    #[must_use]
    pub fn step(&self) -> BootstrapStep {
        self.state().step()
    }

    /// Der Freigabezustand.
    #[must_use]
    pub fn production_state(&self) -> ProductionState {
        self.state().production_state()
    }

    /// Organisations- und Ketten-ID der laufenden Zeremonie.
    #[must_use]
    pub fn current_ids(&self) -> (OrganizationId, ChainId) {
        let state = self.state();
        (state.organization_id(), state.chain_id())
    }

    /// Das persistierte Byteabbild.
    #[must_use]
    pub fn persisted_image(&self) -> Vec<u8> {
        self.store.image().to_vec()
    }

    /// Die versiegelten Vorstufenbytes.
    #[must_use]
    pub fn sealed_pre_anchor_bytes(&self) -> Vec<u8> {
        self.state()
            .exact_pre_anchor_bytes()
            .expect("Schritt 3 hat die Vorstufe gebaut")
            .to_vec()
    }

    /// Das Wurzel-signierte Transkript.
    #[must_use]
    pub fn transcript(&self) -> BootstrapTranscriptV1 {
        self.state()
            .transcript()
            .expect("Schritt 11 hat das Transkript gebildet")
            .clone()
    }

    /// Schritte 1 bis 4: bis zur VERSIEGELTEN Vorstufe.
    ///
    /// # Errors
    /// Jeder Befund der Schritte 1 bis 4.
    pub fn complete_through_pre_anchor_seal(&mut self) -> Result<(), AdminError> {
        let mut coordinator =
            BootstrapCoordinator::resume_or_begin(&mut self.store, &mut self.random)?;
        coordinator.generate_offline_root(fixture_root_material())?;
        let fingerprint = coordinator.create_admin_pairs(&bootstrap_admin_pairs())?;
        let confirmation = confirm_pre_anchor_fingerprint(
            coordinator
                .pre_anchor()
                .expect("Schritt 3 baut die Vorstufe"),
            fingerprint,
        )?;
        coordinator.pin_pre_anchor_on_media(
            &mut self.media,
            &[FIRST_MEDIUM, SECOND_MEDIUM],
            confirmation,
        )
    }

    /// Schritte 1 bis 10: bis zum ersten Wurzel-signierten Bootstrap-Ziel.
    ///
    /// Schritt 10 laeuft ueber den ECHTEN
    /// [`RootCeremonyService::publish_authorized_target`] gegen eine echte
    /// Registrierungslinie; der Koordinator signiert nichts selbst.
    ///
    /// # Errors
    /// Jeder Befund der Schritte 1 bis 10.
    pub fn complete_through_root_signed_targets(&mut self) -> Result<(), AdminError> {
        self.complete_through_pre_anchor_seal()?;

        let ceremony = ceremony_line();
        let head = selected_head(&ceremony.line);
        let intent = ceremony.intent(&head);
        let provider = FixtureKeyProvider::root();
        let audit = AuditHarness::new(&head, ceremony.writer_certificate_object_hash, 0);
        let service = ceremony_service(&head, &provider, &audit, &ceremony);
        let proof = ceremony_proof(&ceremony, &head, ReauthPurpose::AdminRootCeremony);
        let table = Arc::new(Mutex::new(ReplayTable::default()));
        let mut trust_store = PersistentStore::open(&table);
        let authorization = ceremony.authorization_bytes().to_vec();

        let mut coordinator =
            BootstrapCoordinator::resume(&mut self.store)?.expect("die Zeremonie laeuft bereits");
        coordinator.generate_recovery_and_hga_keys(recovery_kem_record(), hga_record())?;
        coordinator.enroll_key_approvers(&[
            OuterKeyRecordV1 {
                handle: outer_handle(0x41),
                key_thumbprint: thumbprint_of(0x41),
            },
            OuterKeyRecordV1 {
                handle: outer_handle(0x42),
                key_thumbprint: thumbprint_of(0x42),
            },
        ])?;
        coordinator.verify_key_backups(&[
            backup(BackedUpKeyClass::Root, 0x51),
            backup(BackedUpKeyClass::Admin, 0x52),
            backup(BackedUpKeyClass::RecoveryKem, 0x53),
            backup(BackedUpKeyClass::HistoricalGrantAuthority, 0x54),
        ])?;
        coordinator.provision_component_keys(&[
            ComponentBindingV1 {
                role: OperatorRoleV1::Writer,
                certificate_object_hash: object_hash_of(0x61),
                operator_binding_object_hash: object_hash_of(0x62),
            },
            ComponentBindingV1 {
                role: OperatorRoleV1::Reader,
                certificate_object_hash: object_hash_of(0x63),
                operator_binding_object_hash: object_hash_of(0x64),
            },
        ])?;
        let pre_bytes = coordinator
            .state()
            .exact_pre_anchor_bytes()
            .expect("die Vorstufe steht")
            .to_vec();
        let pre = ea_trust::decode_pre_anchor(&pre_bytes).expect("die Vorstufe ist gueltig");
        let confirmation = confirm_pre_anchor_fingerprint(&pre, pre.bootstrap_anchor_hash())?;
        coordinator.compare_fingerprints(confirmation)?;
        coordinator.root_sign_bootstrap_target(
            &service,
            &intent,
            ceremony.target_payload(),
            &authorization,
            &mut trust_store,
            &proof,
        )?;
        Ok(())
    }

    /// Schritte 1 bis 11: bis zu Genesis und finalem Anker.
    ///
    /// # Errors
    /// Jeder Befund der Schritte 1 bis 11.
    pub fn complete_through_genesis(&mut self) -> Result<(), AdminError> {
        self.complete_through_root_signed_targets()?;
        let pre_bytes = self.sealed_pre_anchor_bytes();
        let pre = ea_trust::decode_pre_anchor(&pre_bytes).expect("die Vorstufe ist gueltig");
        let anchor_bytes = final_anchor_bytes(&pre, &GENESIS_ENTRY_HASH);
        self.adopt_final_anchor(&anchor_bytes)
    }

    /// Schritt 11 mit AUSDRUECKLICH genannten finalen Ankerbytes.
    ///
    /// # Errors
    /// Jeder Befund des elften Schrittes — insbesondere
    /// `EA-ANCHOR-PRE-FIELD-CHANGED` fuer einen fremden Anker.
    pub fn adopt_final_anchor(&mut self, exact_bytes: &[u8]) -> Result<(), AdminError> {
        let provider = FixtureKeyProvider::root();
        let mut coordinator =
            BootstrapCoordinator::resume(&mut self.store)?.expect("die Zeremonie laeuft bereits");
        let organization_id = coordinator.organization_id();
        let chain_id = coordinator.chain_id();
        let genesis = genesis_record(organization_id, chain_id);
        let binding = bind_genesis(
            &genesis,
            organization_id,
            chain_id,
            object_hash_of(0x13),
            RegistryVersion::new(GENESIS_REGISTRY_VERSION),
            &GenesisEnvelopeV1 {
                chain_sequence: ChainSequence::new(0),
                previous_entry_hash: None,
                genesis_entry_hash: EntryHash::try_from(&GENESIS_ENTRY_HASH[..]).expect("32 Byte"),
            },
        )?;
        coordinator.create_genesis_and_final_anchor(&provider, &binding, exact_bytes)?;
        Ok(())
    }

    /// Schritt 3 mit ANDEREN Paaren — die Bewegung, die `:1349` verbietet.
    ///
    /// # Errors
    /// `EA-ANCHOR-PRE-FIELD-CHANGED`, sobald die Vorstufe versiegelt ist.
    pub fn rewrite_admin_pairs(
        &mut self,
        pairs: &[AdminBootstrapPairV1],
    ) -> Result<Hash32, AdminError> {
        let mut coordinator =
            BootstrapCoordinator::resume(&mut self.store)?.expect("die Zeremonie laeuft bereits");
        coordinator.create_admin_pairs(pairs)
    }

    /// Der Neuanfang mit NEUEN Kennungen (`:1349`).
    ///
    /// # Errors
    /// `EA-CEREMONY-BOOTSTRAP-STEP-REGRESSION`, wenn die Zeremonie gar nicht
    /// abgebrochen ist.
    pub fn restart_with_new_ids(&mut self) -> Result<(), AdminError> {
        BootstrapCoordinator::restart_with_new_ids(&mut self.store, &mut self.random)?;
        Ok(())
    }

    /// Schritt 12 auf einem FRISCHEN Rechner, vollstaendig.
    ///
    /// # Errors
    /// Jeder Befund des zwoelften Schrittes.
    pub fn run_fresh_machine_recovery(&mut self) -> Result<(), AdminError> {
        self.record_recovery(self.observation(FRESH_MACHINE, 2, true))
    }

    /// Derselbe Lauf, aber EIN Medium fehlt (`:1897`).
    ///
    /// # Errors
    /// `EA-CEREMONY-RECOVERY-TEST-FAILED`.
    pub fn run_fresh_machine_recovery_missing_one_medium(&mut self) -> Result<(), AdminError> {
        self.record_recovery(self.observation(FRESH_MACHINE, 1, true))
    }

    /// Derselbe Lauf, aber auf der ZEREMONIENMASCHINE (`:1347`).
    ///
    /// # Errors
    /// `EA-CEREMONY-RECOVERY-TEST-SAME-MACHINE`.
    pub fn run_recovery_on_the_ceremony_machine(&mut self) -> Result<(), AdminError> {
        self.record_recovery(self.observation(CEREMONY_MACHINE, 2, true))
    }

    fn observation(
        &self,
        machine: u8,
        media_present: usize,
        entry_readable: bool,
    ) -> RecoveryTestObservation {
        let state = self.state();
        let anchor = decode_trust_anchor(
            state
                .exact_final_anchor_bytes()
                .expect("Schritt 11 hat den Anker angenommen"),
        )
        .expect("der angenommene Anker ist gueltig");
        RecoveryTestObservation {
            machine_fingerprint: hash32_of(machine),
            media_expected: 2,
            media_present,
            expected_trust_anchor_hash: anchor.trust_anchor_hash(),
            observed_trust_anchor_hash: anchor.trust_anchor_hash(),
            expected_key_thumbprint: thumbprint_of(0x31),
            observed_key_thumbprint: thumbprint_of(0x31),
            test_entry_readable: entry_readable,
            sample_entries_expected: 1,
            sample_entries_decrypted: 1,
        }
    }

    fn record_recovery(&mut self, observation: RecoveryTestObservation) -> Result<(), AdminError> {
        let proof = verify_fresh_machine_recovery_test(hash32_of(CEREMONY_MACHINE), &observation)?;
        let mut coordinator =
            BootstrapCoordinator::resume(&mut self.store)?.expect("die Zeremonie laeuft bereits");
        coordinator.record_fresh_machine_recovery_test(proof)?;
        Ok(())
    }
}

fn backup(class: BackedUpKeyClass, byte: u8) -> KeyBackupRecordV1 {
    KeyBackupRecordV1 {
        class,
        key_thumbprint: thumbprint_of(byte),
        media: vec![BACKUP_MEDIUM_A, BACKUP_MEDIUM_B],
    }
}
