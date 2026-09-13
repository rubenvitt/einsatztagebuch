#![allow(dead_code)]
// Share the archive fixture's exact Trust types with preflight consumers.
#[path = "../../../ea-verify/tests/support/mod.rs"]
pub mod verify_support;
use ea_format::*;
use ea_trust::*;
use ea_types::*;
use trust::{ActionSpec, HeadOptions, RegistryLineBuilder};
pub use verify_support::archive_support::trust_support as trust;
pub const NOW: i64 = 1000;
pub struct Fixture {
    pub line: RegistryLineBuilder,
    pub approvers: [CertificateHash; 2],
    pub deletion: CertificateHash,
}
impl Fixture {
    pub fn new(enabled: bool, document: bool, same_subject: bool) -> Self {
        let mut line = RegistryLineBuilder::new();
        line.push(
            ActionSpec::Policy {
                policy_version: None,
                previous_policy_hash: None,
                effective_from: None,
            },
            HeadOptions {
                policy_destruction_enabled_override: Some(enabled),
                policy_eds_privacy_decision_document_hash_override: Some(
                    document.then(|| trust::hash32(0x91)),
                ),
                ..options()
            },
        );
        let mut approvers = Vec::new();
        for marker in [0x61, 0x62] {
            let h = line.push(
                ActionSpec::Device {
                    kind: CertificateKindV1::KeyApprover,
                    marker,
                    effective_from: None,
                },
                HeadOptions {
                    authority_subject_id_override: Some(
                        SubjectId::try_from(&[if same_subject { 0x61 } else { marker }; 16][..])
                            .unwrap(),
                    ),
                    certificate_capabilities_override: Some(vec!["destructionApprove".into()]),
                    ..options()
                },
            );
            approvers.push(CertificateHash::from(h.direct_object_hash.unwrap()));
        }
        let deletion = CertificateHash::from(
            line.push(
                ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0x70,
                    effective_from: None,
                },
                options(),
            )
            .direct_object_hash
            .unwrap(),
        );
        Self {
            line,
            approvers: approvers.try_into().ok().unwrap(),
            deletion,
        }
    }
    pub fn head(&self) -> SelectedRegistryHead {
        selected(&self.line, NOW)
    }
    pub fn fields(&self) -> DestructionAuthorizationFieldsV1 {
        let head = self.head();
        DestructionAuthorizationFieldsV1 {
            destruction_id: DestructionId::try_from(&[0x81; 16][..]).unwrap(),
            organization_id: trust::organization(),
            registry_version: head.registry_version(),
            registry_head_hash: Hash32::try_from(head.registry_head_hash().as_bytes().as_slice())
                .unwrap(),
            authorization_sequence: head.proposed_sequence().get(),
            targets: vec![
                DestructionTargetV1::new([1; 32], 1),
                DestructionTargetV1::new([2; 32], 1),
            ],
            scope_code: 0,
            legal_reason_code: 0,
        }
    }
    pub fn authorization(&self) -> Vec<u8> {
        self.sign(self.fields(), self.approvers.to_vec())
    }
    pub fn sign(
        &self,
        fields: DestructionAuthorizationFieldsV1,
        signers: Vec<CertificateHash>,
    ) -> Vec<u8> {
        let payload = TrustPayloadV1::destruction_authorization(fields).unwrap();
        let signatures = signers
            .into_iter()
            .map(|cert| {
                trust::authorized_device_signer()
                    .sign_destruction_approval_digest(cert, payload.exact_digest_input())
                    .unwrap()
            })
            .collect();
        exact(payload, signatures)
    }
}
pub fn exact(payload: TrustPayloadV1, signatures: Vec<Vec<u8>>) -> Vec<u8> {
    encode_trust(&TrustObjectV1::new(payload, signatures).unwrap())
        .unwrap()
        .as_bytes()
        .to_vec()
}
pub fn options() -> HeadOptions {
    HeadOptions {
        not_after: UnixMillis::new(10_000_000),
        ..HeadOptions::default()
    }
}
struct Store {
    time: ea_time::TrustedTimeState,
    pin: RegistryHeadPin,
}
impl TrustStateStore for Store {
    fn load(&mut self, _: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        Ok(PersistedTrustRecord::new(
            17,
            self.time.clone(),
            Some(self.pin),
        ))
    }
    fn commit_independent_time(
        &mut self,
        _: TrustStateKey,
        _: u64,
        _: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
    fn clock_release_consumed(
        &mut self,
        _: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Ok(false)
    }
    fn admin_authorization_consumed(
        &mut self,
        _: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        Ok(false)
    }
    fn commit_registry_selection(
        &mut self,
        _: TrustStateKey,
        _: u64,
        c: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Ok(PersistedTrustRecord::new(
            18,
            c.next_trusted_time().clone(),
            Some(*c.next_head()),
        ))
    }
}
pub fn selected(line: &RegistryLineBuilder, now: i64) -> SelectedRegistryHead {
    try_selected(line, now).unwrap()
}
pub fn try_selected(
    line: &RegistryLineBuilder,
    now: i64,
) -> Result<SelectedRegistryHead, RegistryError> {
    try_selected_at(line, line.heads().len() - 1, now)
}
pub fn try_selected_at(
    line: &RegistryLineBuilder,
    index: usize,
    now: i64,
) -> Result<SelectedRegistryHead, RegistryError> {
    let last = &line.heads()[index];
    let time = ea_time::TrustedTimeState::initial(UnixMillis::new(now));
    let trust = line.verified_with_record(
        trust::Pin::Exact(last.version, last.object_hash),
        17,
        time.clone(),
        trust::state_key(),
    );
    select_verified(
        &trust,
        last.version,
        last.object_hash,
        last.effective_from,
        now,
    )
}
pub fn select_verified(
    trust: &VerifiedTrust,
    version: RegistryVersion,
    hash: ObjectHash,
    sequence: ChainSequence,
    now: i64,
) -> Result<SelectedRegistryHead, RegistryError> {
    let time = ea_time::TrustedTimeState::initial(UnixMillis::new(now));
    let candidate = verify_registry_candidate(trust, sequence).unwrap();
    let mut store = Store {
        time,
        pin: RegistryHeadPin::new(version, hash),
    };
    let local = prepare_local_time(&mut store, &candidate, UnixMillis::new(now), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(head) = select_registry_head(candidate, local, None)?
    else {
        panic!()
    };
    Ok(head)
}

pub fn event_fields(
    f: &Fixture,
    auth: &[u8],
    id: u8,
    from: Option<u8>,
    to: u8,
    previous: Option<ObjectHash>,
) -> DestructionTransitionFieldsV1 {
    DestructionTransitionFieldsV1 {
        destruction_id: f.fields().destruction_id,
        destruction_authorization_object_hash: ea_crypto::object_hash(auth),
        event_id: EventId::try_from(&[id; 16][..]).unwrap(),
        previous_event_object_hash: previous,
        from_state: from,
        to_state: to,
        trigger_code: match (from, to) {
            (Some(4), 1) => 5,
            _ => u64::from(to),
        },
        executed_at: UnixMillis::new(NOW),
    }
}
pub fn event(f: &Fixture, auth: &[u8], fields: DestructionTransitionFieldsV1) -> Vec<u8> {
    let payload = TrustPayloadV1::destruction_transition(fields).unwrap();
    let signature = trust::authorized_device_signer()
        .sign_destruction_transition_digest(f.deletion, payload.exact_digest_input(), auth)
        .unwrap();
    exact(payload, vec![signature])
}
pub fn entry(f: &Fixture) -> EntryPackageV1 {
    let head = f.head();
    let cert = head
        .active_certificates()
        .find(|(_, fields)| fields.certificate_kind == CertificateKindV1::Writer)
        .unwrap()
        .0;
    let ciphertext = vec![0x11; 32];
    let manifest = ManifestCoreV1::new(
        ManifestCoreFieldsV1 {
            organization_id: trust::organization(),
            chain_id: head.chain_id(),
            chain_sequence: head.proposed_sequence(),
            previous_entry_hash: Some(EntryHash::try_from(&[0x12; 32][..]).unwrap()),
            writer_certificate_hash: cert,
            writer_transition_event_hash: None,
            registry_version: head.registry_version(),
            registry_head_hash: *head.registry_head_hash().as_bytes(),
            initial_grant_plan_hash: [0x13; 32],
            nonce: [0x14; 12],
        },
        &ciphertext,
    )
    .unwrap();
    let signed = SignedManifestV1::new(manifest, &ciphertext).unwrap();
    let signature = trust::authorized_device_signer()
        .sign_record(signed.exact_bytes())
        .unwrap();
    EntryPackageV1::new(signed, ciphertext, signature).unwrap()
}
pub fn with_writer(mut f: Fixture) -> Fixture {
    f.line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::Writer,
            marker: 0x78,
            effective_from: None,
        },
        options(),
    );
    f
}

use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_key_provider::{
    CoseSign1Bytes, InMemoryKeyProvider, KeyError, KeyHandle, KeyProvider, SecretPurpose,
};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OperatorSessionProof, OsAccountProvider,
    ReauthPurpose,
};
use ed25519_dalek::{Signer as _, SigningKey};
use std::sync::Arc;
pub struct Account {
    pub matching: bool,
}
impl OsAccountProvider for Account {
    fn os_account_binding_hash(
        &self,
        _: OrganizationId,
        _: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(trust::hash32(if self.matching { 0x75 } else { 0xff }))
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(Some(instance_key()))
    }
}
pub fn instance_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(
        SigningKey::from_bytes(&[0x44; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}
pub struct Authenticator {
    pub bound: BoundOperator,
}
impl OperatorAuthenticator for Authenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        Ok(SigningKey::from_bytes(&[0x44; 32])
            .sign(challenge)
            .to_bytes())
    }
}
struct Signer {
    invalid: bool,
    fail: bool,
}
impl KeyProvider for Signer {
    fn sign(
        &self,
        _: &KeyHandle,
        kind: ContentType,
        cert: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        if self.fail {
            return Err(KeyError::NotFound);
        }
        let key = SigningKey::from_bytes(&trust::device_signing_secret());
        let public = CanonicalPublicCoseKey::ed25519(key.verifying_key().to_bytes()).unwrap();
        let protected = ProtectedHeader::normal(kind, public.thumbprint(), cert);
        let mut sig = key.sign(&protected.sig_structure_bytes(payload)).to_bytes();
        if self.invalid {
            sig[0] ^= 1
        }
        CoseSign1Bytes::compose(&protected, payload, &sig)
    }
    fn generate(&self, _: SecretPurpose, _: KeyProtectionProfileV1) -> Result<KeyHandle, KeyError> {
        Err(KeyError::NotFound)
    }
    fn wrap_secret(&self, _: SecretPurpose, _: SecretBytes<32>) -> Result<KeyHandle, KeyError> {
        Err(KeyError::NotFound)
    }
    fn unwrap_secret(&self, _: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        Err(KeyError::NotFound)
    }
    fn unwrap_database_key(&self, _: &KeyHandle) -> Result<SecretVec, KeyError> {
        Err(KeyError::NotFound)
    }
    fn delete(&self, _: &KeyHandle) -> Result<(), KeyError> {
        Err(KeyError::NotFound)
    }
    fn contains(&self, _: &KeyHandle) -> Result<bool, KeyError> {
        Ok(true)
    }
    fn reached_protection_profile(
        &self,
        _: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        Ok(KeyProtectionProfileV1::OsWrapped)
    }
}
pub struct RequestFixture {
    pub f: Fixture,
    pub binding: ObjectHash,
    pub certificate: CertificateHash,
    pub database: Arc<ea_local_store::EncryptedDatabase>,
    pub directory: std::path::PathBuf,
    provider: InMemoryKeyProvider,
    db_key: KeyHandle,
    audit_key: KeyHandle,
}
impl Default for RequestFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestFixture {
    pub fn new() -> Self {
        let mut f = with_writer(Fixture::new(true, true, false));
        let certificate = f.head().current_writer_certificate_hash().unwrap();
        let binding = f
            .line
            .push(
                ActionSpec::OperatorBinding {
                    certificate_hash: ObjectHash::try_from(certificate.as_bytes().as_slice())
                        .unwrap(),
                    role: OperatorRoleV1::Writer,
                    marker: 0x73,
                    effective_from: None,
                },
                HeadOptions {
                    binding_instance_key_thumbprint_override: Some(instance_key().thumbprint()),
                    ..options()
                },
            )
            .direct_object_hash
            .unwrap();
        let provider = InMemoryKeyProvider::new_for_test([0x22; 32]);
        let db_key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let audit_key = provider
            .generate(
                SecretPurpose::WriterSigningKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "ea-destruction-{}-{unique}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let database = Arc::new(
            ea_local_store::EncryptedDatabase::open(
                &directory.join("local.db"),
                &provider,
                &db_key,
            )
            .unwrap(),
        );
        Self {
            f,
            binding,
            certificate,
            database,
            directory,
            provider,
            db_key,
            audit_key,
        }
    }
    pub fn proof(
        &self,
        head: &SelectedRegistryHead,
        purpose: ReauthPurpose,
    ) -> OperatorSessionProof {
        Authenticator {
            bound: BoundOperator::resolve(head, self.binding).unwrap(),
        }
        .reauthenticate(Box::new(Account { matching: true }), purpose)
        .unwrap()
    }
    pub fn audit(
        &self,
        head: &SelectedRegistryHead,
        invalid: bool,
        fail: bool,
    ) -> ea_audit::SignedLocalAuditService {
        ea_audit::SignedLocalAuditService::new(
            Arc::new(ea_audit::SqliteLocalAuditRepository::new(
                self.database.clone(),
            )),
            Arc::new(Signer { invalid, fail }),
            self.audit_key,
            ObjectHash::try_from(self.certificate.as_bytes().as_slice()).unwrap(),
            head.preexisting_effective_now().value(),
        )
    }
    pub fn reopen(&self) -> Arc<ea_local_store::EncryptedDatabase> {
        Arc::new(
            ea_local_store::EncryptedDatabase::open_existing(
                &self.directory.join("local.db"),
                &self.provider,
                &self.db_key,
            )
            .unwrap(),
        )
    }
    pub fn authorization(&self) -> (Vec<u8>, ea_destruction::VerifiedDestructionTarget) {
        let entry = entry(&self.f);
        let mut fields = self.f.fields();
        fields.targets = vec![DestructionTargetV1::new(
            *entry.entry_hash().as_bytes(),
            entry.manifest().fields().chain_sequence.get(),
        )];
        let bytes = self.f.sign(fields, self.f.approvers.to_vec());
        let verified = ea_destruction::verify_authorization(&bytes, &self.f.head()).unwrap();
        let target = verified.verify_target(&entry, &self.f.head()).unwrap();
        (bytes, target)
    }
}
impl Drop for RequestFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
