#![allow(dead_code)]
use super::support::{
    self,
    trust_support::{self, ActionSpec, HeadOptions, RegistryLineBuilder},
};
use ea_admin::*;
use ea_crypto::{CanonicalPublicCoseKey, object_hash, operator_profile_digest};
use ea_format::*;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::*;
use ea_trust::*;
use ea_types::*;
use ed25519_dalek::{Signer as _, SigningKey};
use std::{
    cell::{Cell, RefCell},
    sync::{Arc, Mutex},
};

const SECRET: [u8; 32] = [0x47; 32];
const SALT: [u8; 32] = [0x53; 32];
pub fn key(secret: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
        .unwrap()
}

pub struct Database {
    pub database: Arc<EncryptedDatabase>,
    pub directory: support::TempDir,
}
pub fn reopen_database(directory: &std::path::Path) -> Arc<EncryptedDatabase> {
    let provider = InMemoryKeyProvider::new_for_test([0x61; 32]);
    let handle = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    Arc::new(
        EncryptedDatabase::open(&directory.join("profile.sqlite"), &provider, &handle).unwrap(),
    )
}
pub fn database(tag: &str) -> Database {
    let directory = support::temp_dir(tag);
    let provider = InMemoryKeyProvider::new_for_test([0x61; 32]);
    let handle = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let database = Arc::new(
        EncryptedDatabase::open(&directory.path().join("profile.sqlite"), &provider, &handle)
            .unwrap(),
    );
    Database {
        database,
        directory,
    }
}

#[derive(Clone)]
pub struct Account {
    pub secret: Option<[u8; 32]>,
    pub hash: Hash32,
}
impl OsAccountProvider for Account {
    fn os_account_binding_hash(
        &self,
        _: OrganizationId,
        _: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        Ok(self.hash)
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        Ok(self.secret.map(key))
    }
}
pub struct Authenticator {
    bound: BoundOperator,
    secret: [u8; 32],
    pub fail: bool,
}
impl OperatorAuthenticator for Authenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        if self.fail {
            return Err(OperatorError::PresenceProofInvalid);
        }
        Ok(SigningKey::from_bytes(&self.secret)
            .sign(challenge)
            .to_bytes())
    }
}

pub struct Harness {
    pub line: RegistryLineBuilder,
    pub database: Arc<EncryptedDatabase>,
    pub directory: support::TempDir,
    pub binding: ObjectHash,
    pub certificate: CertificateHash,
    pub account: Account,
}
impl Harness {
    pub fn new() -> Self {
        let mut line = RegistryLineBuilder::new();
        let options = |start, end| HeadOptions {
            effective_from: Some(start),
            valid_through: Some(end),
            not_after: UnixMillis::new(10_000_000),
            ..HeadOptions::default()
        };
        line.push(
            ActionSpec::Policy {
                policy_version: None,
                previous_policy_hash: None,
                effective_from: None,
            },
            options(1, 10),
        );
        let cert = line
            .push(
                ActionSpec::Device {
                    kind: CertificateKindV1::Writer,
                    marker: 0x61,
                    effective_from: None,
                },
                options(11, 20),
            )
            .direct_object_hash
            .unwrap();
        let mut core = Vec::new();
        minicbor::Encoder::new(&mut core)
            .array(5)
            .unwrap()
            .bytes(trust_support::organization().as_bytes())
            .unwrap()
            .bytes(&[0x71; 16])
            .unwrap()
            .str("Ada Lovelace")
            .unwrap()
            .str("Einsatzleitung")
            .unwrap()
            .bytes(&SALT)
            .unwrap();
        let binding = line
            .push(
                ActionSpec::OperatorBinding {
                    certificate_hash: cert,
                    role: OperatorRoleV1::Writer,
                    marker: 0x71,
                    effective_from: None,
                },
                HeadOptions {
                    binding_operator_profile_commitment_override: Some(operator_profile_digest(
                        &core,
                    )),
                    binding_instance_key_thumbprint_override: Some(key(SECRET).thumbprint()),
                    ..options(21, 100)
                },
            )
            .direct_object_hash
            .unwrap();
        let db = database("actor");
        db.database
            .execute(
                "INSERT INTO operator_profile VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                    StoreValue::Blob(vec![0x71; 16]),
                    StoreValue::Text("Ada Lovelace".into()),
                    StoreValue::Text("Einsatzleitung".into()),
                    StoreValue::Blob(SALT.to_vec()),
                    StoreValue::Blob(binding.as_bytes().to_vec()),
                ],
            )
            .unwrap();
        Self {
            line,
            database: db.database,
            directory: db.directory,
            binding,
            certificate: CertificateHash::from(cert),
            account: Account {
                secret: Some(SECRET),
                hash: trust_support::hash32(0x73),
            },
        }
    }
    pub fn head(&self) -> SelectedRegistryHead {
        support::selected_head_at(&self.line, 2, 50)
    }
    pub fn audit(&self, head: &SelectedRegistryHead, failures: usize) -> support::AuditHarness {
        support::AuditHarness::with_provider(
            head,
            ObjectHash::try_from(self.certificate.as_bytes().as_slice()).unwrap(),
            failures,
            support::FixtureKeyProvider::device(),
        )
    }
    pub fn authenticator(&self, head: &SelectedRegistryHead) -> Authenticator {
        Authenticator {
            bound: BoundOperator::resolve(head, self.binding).unwrap(),
            secret: SECRET,
            fail: false,
        }
    }
    pub fn login<'a>(&'a self, authenticator: &'a Authenticator) -> VerifySessionRequest<'a> {
        VerifySessionRequest {
            database: &self.database,
            binding_object_hash: self.binding,
            device_certificate_hash: self.certificate,
            role: OperatorRoleV1::Writer,
            purpose: ReauthPurpose::AdminRootCeremony,
            account: Arc::new(self.account.clone()),
            authenticator,
        }
    }
}

pub struct Native {
    pub account: RefCell<Account>,
    pub reuse: Cell<bool>,
}
impl Native {
    pub fn new() -> Self {
        Self {
            account: RefCell::new(Account {
                secret: None,
                hash: trust_support::hash32(0x88),
            }),
            reuse: Cell::new(false),
        }
    }
    pub fn authenticator(&self, head: &SelectedRegistryHead, binding: ObjectHash) -> Authenticator {
        Authenticator {
            bound: BoundOperator::resolve(head, binding).unwrap(),
            secret: self.account.borrow().secret.unwrap(),
            fail: false,
        }
    }
    pub fn login<'a>(
        &self,
        database: &'a Arc<EncryptedDatabase>,
        authenticator: &'a Authenticator,
        binding: ObjectHash,
        certificate: CertificateHash,
    ) -> VerifySessionRequest<'a> {
        VerifySessionRequest {
            database,
            binding_object_hash: binding,
            device_certificate_hash: certificate,
            role: OperatorRoleV1::Writer,
            purpose: ReauthPurpose::AdminRootCeremony,
            account: Arc::new(self.account.borrow().clone()),
            authenticator,
        }
    }
}
impl OsAccountProvider for Native {
    fn os_account_binding_hash(
        &self,
        org: OrganizationId,
        device: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        self.account.borrow().os_account_binding_hash(org, device)
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        self.account.borrow().operator_instance_public_key()
    }
}
impl NativeOperatorProvisioning for Native {
    fn create_fresh_instance(
        &self,
        policy: InstanceKeyPolicy,
    ) -> Result<CanonicalPublicCoseKey, OperatorLifecycleError> {
        assert_eq!(
            policy,
            InstanceKeyPolicy::InstallationBoundNonRoamingBackupExcluded
        );
        let mut account = self.account.borrow_mut();
        if !self.reuse.get() || account.secret.is_none() {
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret).unwrap();
            account.secret = Some(secret);
        }
        Ok(key(account.secret.unwrap()))
    }
    fn prove_presence_and_sign(
        &self,
        challenge: &[u8],
    ) -> Result<[u8; 64], OperatorLifecycleError> {
        Ok(
            SigningKey::from_bytes(&self.account.borrow().secret.unwrap())
                .sign(challenge)
                .to_bytes(),
        )
    }
}

pub struct Identity {
    pub fail: bool,
    pub wrong_subject: bool,
    pub wrong_challenge: bool,
    pub previous_binding: Option<ObjectHash>,
    pub decomposed: bool,
    pub salt: Option<[u8; 32]>,
}
impl Identity {
    pub fn valid() -> Self {
        Self {
            fail: false,
            wrong_subject: false,
            wrong_challenge: false,
            previous_binding: None,
            decomposed: false,
            salt: None,
        }
    }
}
impl ExternalOperatorIdentityVerifier for Identity {
    fn verify_identity(
        &self,
        request: &ExternalIdentityRequest,
    ) -> Result<ExternalOperatorIdentity, OperatorLifecycleError> {
        if self.fail {
            return Err(OperatorLifecycleError::IdentityVerification);
        }
        let mut salt = [0; 32];
        getrandom::fill(&mut salt).unwrap();
        Ok(ExternalOperatorIdentity {
            profile_commitment_salt: self.salt.unwrap_or(salt),
            organization_id: request.organization_id,
            operator_subject_id: if self.wrong_subject {
                OperatorSubjectId::try_from(&[0x99; 16][..]).unwrap()
            } else {
                request
                    .previous_subject_id
                    .unwrap_or_else(|| OperatorSubjectId::try_from(&[0x81; 16][..]).unwrap())
            },
            display_name: if self.decomposed {
                "Ame\u{301}lie"
            } else {
                "Grace Hopper"
            }
            .into(),
            function_label: if self.decomposed {
                "Fu\u{308}hrung\r\nStab"
            } else {
                "Einsatzleitung"
            }
            .into(),
            previous_binding_object_hash: self
                .previous_binding
                .or(request.previous_binding_object_hash),
            challenge: if self.wrong_challenge {
                [0; 32]
            } else {
                request.challenge
            },
        })
    }
}

const ADMIN_SECRET: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
pub struct Authorization {
    pub line: RegistryLineBuilder,
    pub authorizations: Vec<Vec<u8>>,
    pub binding_authorization_timing: Option<(UnixMillis, UnixMillis)>,
    pub wrong_core: bool,
    pub root_only: bool,
    pub reused_nonce: bool,
    pub fail_stage: bool,
    pub staged: Vec<Vec<u8>>,
    pub included: Vec<Vec<u8>>,
    pub recovered: Option<Vec<u8>>,
    pub lose_activation_reply: bool,
    pub pending_authorization: Option<AuthorizedOperatorIntent>,
    pub replay_table: Arc<Mutex<support::ReplayTable>>,
    pub stage_directory: support::TempDir,
}
impl OperatorAuthorizationPort for Authorization {
    fn include_prepared_objects(
        &mut self,
        objects: &[&[u8]],
    ) -> Result<(), OperatorLifecycleError> {
        assert_eq!(objects.len(), 2);
        for bytes in objects {
            self.line.add_object(bytes.to_vec());
            self.included.push(bytes.to_vec());
        }
        Ok(())
    }
    fn recover_authorization(
        &mut self,
        _: &SelectedRegistryHead,
        _: &OperatorTrustTarget,
    ) -> Result<AuthorizedOperatorIntent, OperatorLifecycleError> {
        self.pending_authorization
            .take()
            .ok_or(OperatorLifecycleError::Unsupported)
    }
    fn recover_activation(
        &mut self,
        _: &SelectedRegistryHead,
        _: &OperatorTrustTarget,
        _: &[u8],
    ) -> Result<Vec<u8>, OperatorLifecycleError> {
        self.recovered
            .clone()
            .ok_or(OperatorLifecycleError::Unsupported)
    }

    fn stage_signed_objects(&mut self, objects: &[&[u8]]) -> Result<(), OperatorLifecycleError> {
        use std::io::Write;
        if self.fail_stage {
            return Err(OperatorLifecycleError::Store(
                ea_local_store::StoreError::Database,
            ));
        }
        for (index, bytes) in objects.iter().enumerate() {
            let mut file = std::fs::File::create(
                self.stage_directory
                    .path()
                    .join(format!("{}.etb", self.staged.len() + index)),
            )
            .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        self.staged.extend(objects.iter().map(|b| b.to_vec()));
        for object in objects {
            self.line.add_object(object.to_vec());
        }
        Ok(())
    }
    fn authorize(
        &mut self,
        head: &SelectedRegistryHead,
        target: &OperatorTrustTarget,
    ) -> Result<AuthorizedOperatorIntent, OperatorLifecycleError> {
        let (issued_at, use_time) = match target {
            OperatorTrustTarget::Binding(_) => self.binding_authorization_timing.unwrap_or((
                UnixMillis::new(100),
                head.preexisting_effective_now().value(),
            )),
            OperatorTrustTarget::Registry(event) => (UnixMillis::new(100), event.issued_at),
        };
        let provisional = target.payload(ObjectHash::from(Hash32::ZERO))?;
        let exact = provisional.exact_payload();
        let mut decoder = minicbor::Decoder::new(exact);
        decoder.array().unwrap();
        let start = decoder.position();
        decoder.skip().unwrap();
        let end = decoder.position();
        let mut core = Vec::new();
        minicbor::Encoder::new(&mut core)
            .array(2)
            .unwrap()
            .str(provisional.subtype().as_str())
            .unwrap();
        core.extend_from_slice(&exact[start..end]);
        let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(ADMIN_SECRET));
        let id = 0xb0 + u8::try_from(self.authorizations.len()).unwrap();
        let auth = TrustPayloadV1::organization_admin_authorization(
            OrganizationAdminAuthorizationFieldsV1 {
                authorization_id: AuthorizationId::try_from(&[id; 16][..]).unwrap(),
                organization_id: trust_support::organization(),
                registry_version: head.registry_version(),
                registry_head_hash: Hash32::try_from(
                    head.registry_head_hash().as_bytes().as_slice(),
                )
                .unwrap(),
                admin_key_thumbprint: key(ADMIN_SECRET).thumbprint(),
                admin_certificate_hash: CertificateHash::from(self.line.bootstrap_admin_hash()),
                admin_operator_binding_object_hash: self.line.bootstrap_admin_binding_hash(),
                action_code: match target {
                    OperatorTrustTarget::Binding(_) => 4,
                    OperatorTrustTarget::Registry(fields) => match fields.change {
                        RegistryChangeV1::OperatorBinding { .. } => 4,
                        RegistryChangeV1::AdminCertificate { .. } => 5,
                        _ => 1,
                    },
                },
                target_trust_subtype: provisional.subtype(),
                authorized_trust_core_hash: if self.wrong_core {
                    Hash32::ZERO
                } else {
                    ea_crypto::authorized_trust_digest(&core)
                },
                issued_at,
                expires_at: UnixMillis::new(1100),
                nonce: [if self.reused_nonce { 0xb0 } else { id }; 32],
            },
        )
        .unwrap();
        let cert = CertificateHash::from(self.line.bootstrap_admin_hash());
        let signed = if self.root_only {
            let provider = support::FixtureKeyProvider::root();
            provider
                .sign(
                    &provider.handle(),
                    ea_crypto::ContentType::TrustDigest,
                    cert,
                    ea_crypto::trust_digest(auth.exact_digest_input()).as_bytes(),
                )
                .unwrap()
                .as_bytes()
                .to_vec()
        } else {
            signer
                .sign_organization_admin_trust_digest(auth.exact_digest_input())
                .unwrap()
        };
        let bytes = encode_trust(&TrustObjectV1::new(auth, vec![signed]).unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
        let payload = target.payload(object_hash(&bytes))?;
        self.line.add_object(bytes.clone());
        let trust = self.line.verified(trust_support::Pin::None);
        let refreshed = selected_at(
            &self.line,
            self.line.exact_object_bytes(head.registry_head_hash()),
            head.proposed_sequence().get(),
            use_time,
        );
        let intent = verify_intended_trust_target(
            &trust,
            Some(&refreshed),
            &payload,
            use_time,
            head.proposed_sequence(),
        )
        .map_err(OperatorLifecycleError::Trust)?;
        self.authorizations.push(bytes.clone());
        let authorized = AuthorizedOperatorIntent {
            intent,
            exact_authorization: bytes,
        };
        if self.lose_activation_reply && matches!(target, OperatorTrustTarget::Registry(_)) {
            self.pending_authorization = Some(authorized);
            return Err(OperatorLifecycleError::Unsupported);
        }
        Ok(authorized)
    }
}
impl Authorization {
    pub fn activate(&mut self, prepared: &PublishedBinding) -> SelectedRegistryHead {
        self.line.add_object(prepared.binding_bytes().to_vec());
        self.line.add_object(prepared.activation_bytes().to_vec());
        let ParsedArchiveObject::Trust(parsed) =
            decode_exact_object(prepared.activation_bytes()).unwrap()
        else {
            panic!()
        };
        let DecodedTrustPayloadV1::RegistryEvent(event) = parsed.value().decoded_payload().unwrap()
        else {
            panic!()
        };
        selected_at(
            &self.line,
            prepared.activation_bytes(),
            event.fields().effective_from_sequence.get(),
            event.fields().issued_at.max(UnixMillis::new(1000)),
        )
    }
}

struct SelectionStore {
    time: ea_time::TrustedTimeState,
    pin: RegistryHeadPin,
}
impl TrustStateStore for SelectionStore {
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
pub fn selected(line: &RegistryLineBuilder, event: &[u8], sequence: u64) -> SelectedRegistryHead {
    selected_at(line, event, sequence, UnixMillis::new(1000))
}

pub fn selected_at(
    line: &RegistryLineBuilder,
    event: &[u8],
    sequence: u64,
    now: UnixMillis,
) -> SelectedRegistryHead {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(event).unwrap() else {
        panic!()
    };
    let DecodedTrustPayloadV1::RegistryEvent(fields) = parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let version = fields.fields().registry_version;
    let hash = object_hash(event);
    let time = ea_time::TrustedTimeState::initial(now);
    let trust = line.verified_with_record(
        trust_support::Pin::Exact(version, hash),
        17,
        time.clone(),
        trust_support::state_key(),
    );
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(sequence)).unwrap();
    let mut store = SelectionStore {
        time,
        pin: RegistryHeadPin::new(version, hash),
    };
    let local = prepare_local_time(&mut store, &candidate, now, &[]).unwrap();
    let RegistrySelectionOutcome::Selected(head) =
        select_registry_head(candidate, local, None).unwrap()
    else {
        panic!()
    };
    head
}

/// Same authenticated organizational Registry, pinned by a different chain anchor.
pub fn selected_on_chain(
    line: &RegistryLineBuilder,
    event: &[u8],
    sequence: u64,
    chain: ChainId,
) -> SelectedRegistryHead {
    let original = decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let pre = encode_pre_anchor_v1(
        original.organization_id(),
        chain,
        original.root_public_cose_key_bytes(),
        original.root_key_thumbprint(),
        original.root_certificate_object_hash(),
        original.initial_admin_certificate_object_hashes(),
        original.initial_admin_operator_binding_object_hashes(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut bytes);
    encoder
        .array(12)
        .unwrap()
        .str("EINSATZARCHIV-TRUST-ANCHOR-v1")
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(pre.bootstrap_anchor_hash().as_bytes())
        .unwrap()
        .bytes(original.organization_id().as_bytes())
        .unwrap()
        .bytes(chain.as_bytes())
        .unwrap()
        .bytes(original.root_public_cose_key_bytes())
        .unwrap()
        .bytes(original.root_key_thumbprint().as_bytes())
        .unwrap()
        .bytes(original.root_certificate_object_hash().as_bytes())
        .unwrap();
    for hashes in [
        original.initial_admin_certificate_object_hashes(),
        original.initial_admin_operator_binding_object_hashes(),
    ] {
        encoder.array(hashes.len().try_into().unwrap()).unwrap();
        for hash in hashes {
            encoder.bytes(hash.as_bytes()).unwrap();
        }
    }
    encoder
        .bytes(original.genesis_entry_hash().as_bytes())
        .unwrap()
        .array(0)
        .unwrap();
    let anchor = decode_trust_anchor(&bytes).unwrap();
    let mut store = SelectionStore {
        time: ea_time::TrustedTimeState::initial(UnixMillis::new(1000)),
        pin: RegistryHeadPin::new(registry_fields(event).registry_version, object_hash(event)),
    };
    let snapshot = load_trust_state(&mut store, trust_support::state_key()).unwrap();
    let trust = verify_trust(&anchor, &line.source(), snapshot).unwrap();
    let candidate = verify_registry_candidate(&trust, ChainSequence::new(sequence)).unwrap();
    let local = prepare_local_time(&mut store, &candidate, UnixMillis::new(1000), &[]).unwrap();
    let RegistrySelectionOutcome::Selected(head) =
        select_registry_head(candidate, local, None).unwrap()
    else {
        panic!()
    };
    head
}

impl Harness {
    pub fn service<'a>(
        &self,
        head: &'a SelectedRegistryHead,
        audit: &'a dyn ea_audit::LocalAuditService,
    ) -> OperatorBindingService<'a> {
        let local = VerifiedLocalDeviceIdentity::verify(
            head,
            self.certificate,
            head.active_certificate_fields(self.certificate)
                .unwrap()
                .device_id,
        )
        .unwrap();
        OperatorBindingService::new(head, audit, local)
    }
    pub fn authorization(&self) -> Authorization {
        Authorization {
            line: self.line.clone(),
            authorizations: Vec::new(),
            binding_authorization_timing: None,
            wrong_core: false,
            root_only: false,
            reused_nonce: false,
            fail_stage: false,
            staged: Vec::new(),
            included: Vec::new(),
            recovered: None,
            lose_activation_reply: false,
            pending_authorization: None,
            replay_table: Arc::new(Mutex::new(support::ReplayTable::default())),
            stage_directory: support::temp_dir("public-stage"),
        }
    }
    pub fn provision(
        &self,
        head: &SelectedRegistryHead,
        audit: &support::AuditHarness,
        database: &Arc<EncryptedDatabase>,
        native: &Native,
        identity: &Identity,
        authorization: &mut Authorization,
    ) -> Result<PublishedBinding, OperatorLifecycleError> {
        self.provision_at(
            head,
            audit.service(),
            database,
            native,
            identity,
            authorization,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_at(
        &self,
        head: &SelectedRegistryHead,
        audit: &dyn ea_audit::LocalAuditService,
        database: &Arc<EncryptedDatabase>,
        native: &Native,
        identity: &Identity,
        authorization: &mut Authorization,
        replacement: Option<&RevokedOperatorBinding>,
    ) -> Result<PreparedOperatorBinding, OperatorLifecycleError> {
        let authenticator = self.authenticator(head);
        let provider = support::FixtureKeyProvider::root();
        let ceremony = RootCeremonyService::new(
            head,
            &provider,
            provider.handle(),
            CertificateHash::from(head.root_certificate_object_hash()),
            audit,
            self.binding,
        );
        let mut store = SelectionStore {
            time: ea_time::TrustedTimeState::initial(UnixMillis::new(1000)),
            pin: RegistryHeadPin::new(head.registry_version(), head.registry_head_hash()),
        };
        let mut ports = OperatorMutationPorts {
            authorization,
            ceremony: &ceremony,
            store: &mut store,
        };
        self.service(head, audit).provision(
            ProvisionOperatorRequest {
                database,
                device_certificate_hash: self.certificate,
                role: OperatorRoleV1::Writer,
                window: window(
                    head.valid_through_sequence().get() + 1,
                    head.valid_through_sequence().get() + 100,
                ),
                replacement,
            },
            native,
            identity,
            &mut ports,
            self.login(&authenticator),
        )
    }
    pub fn revoke(
        &self,
        head: &SelectedRegistryHead,
        audit: &dyn ea_audit::LocalAuditService,
        binding: ObjectHash,
        authorization: &mut Authorization,
    ) -> Result<PreparedOperatorRevocation, OperatorLifecycleError> {
        let authenticator = self.authenticator(head);
        let provider = support::FixtureKeyProvider::root();
        let ceremony = RootCeremonyService::new(
            head,
            &provider,
            provider.handle(),
            CertificateHash::from(head.root_certificate_object_hash()),
            audit,
            self.binding,
        );
        let table = Arc::new(Mutex::new(support::ReplayTable::default()));
        let mut store = support::PersistentStore::open(&table);
        self.service(head, audit).revoke(
            RevokeOperatorRequest {
                database: &self.database,
                binding_object_hash: binding,
                window: window(
                    head.valid_through_sequence().get() + 1,
                    head.valid_through_sequence().get() + 100,
                ),
            },
            &mut OperatorMutationPorts {
                authorization,
                ceremony: &ceremony,
                store: &mut store,
            },
            self.login(&authenticator),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn provision_at(
        &self,
        head: &SelectedRegistryHead,
        audit: &dyn ea_audit::LocalAuditService,
        database: &Arc<EncryptedDatabase>,
        native: &Native,
        identity: &Identity,
        authorization: &mut Authorization,
        replacement: Option<&RevokedOperatorBinding>,
    ) -> Result<PublishedBinding, OperatorLifecycleError> {
        let prepared = self.prepare_at(
            head,
            audit,
            database,
            native,
            identity,
            authorization,
            replacement,
        )?;
        let authenticator = self.authenticator(head);
        let provider = support::FixtureKeyProvider::root();
        let ceremony = RootCeremonyService::new(
            head,
            &provider,
            provider.handle(),
            CertificateHash::from(head.root_certificate_object_hash()),
            audit,
            self.binding,
        );
        let table = Arc::new(Mutex::new(support::ReplayTable::default()));
        let mut store = support::PersistentStore::open(&table);
        self.service(head, audit).authorize_prepared(
            database,
            &prepared,
            native,
            &mut OperatorMutationPorts {
                authorization,
                ceremony: &ceremony,
                store: &mut store,
            },
            self.login(&authenticator),
        )?;
        publish(
            self.service(head, audit),
            database,
            &prepared,
            native,
            authorization,
        )
    }
}

pub struct PublishedBinding {
    objects: [Vec<u8>; 4],
}
impl PublishedBinding {
    pub fn binding_authorization_bytes(&self) -> &[u8] {
        &self.objects[0]
    }
    pub fn binding_bytes(&self) -> &[u8] {
        &self.objects[1]
    }
    pub fn activation_authorization_bytes(&self) -> &[u8] {
        &self.objects[2]
    }
    pub fn activation_bytes(&self) -> &[u8] {
        &self.objects[3]
    }
    pub fn binding_object_hash(&self) -> ObjectHash {
        object_hash(self.binding_bytes())
    }
}
struct Publishing<'a> {
    authorization: &'a mut Authorization,
    result: Option<PublishedBinding>,
}
impl OperatorBindingPublisher for Publishing<'_> {
    fn publish(&mut self, ready: &ReadyOperatorBinding) -> Result<(), OperatorLifecycleError> {
        let objects = [
            ready.binding_authorization_bytes(),
            ready.binding_bytes(),
            ready.activation_authorization_bytes(),
            ready.activation_bytes(),
        ];
        self.authorization.stage_signed_objects(&objects)?;
        self.result = Some(PublishedBinding {
            objects: objects.map(<[u8]>::to_vec),
        });
        Ok(())
    }
}
pub fn publish(
    service: OperatorBindingService<'_>,
    database: &Arc<EncryptedDatabase>,
    prepared: &PreparedOperatorBinding,
    native: &Native,
    authorization: &mut Authorization,
) -> Result<PublishedBinding, OperatorLifecycleError> {
    let mut publisher = Publishing {
        authorization,
        result: None,
    };
    service.publish_prepared(database, prepared, native, &mut publisher)?;
    Ok(publisher.result.unwrap())
}
pub fn window(effective: u64, through: u64) -> RegistryWindow {
    RegistryWindow {
        effective_from_sequence: ChainSequence::new(effective),
        valid_through_sequence: ChainSequence::new(through),
        not_after: UnixMillis::new(10_000_000),
    }
}

/// A separate, usable Admin account on the same real trust line as the lost Writer.
pub struct RecoveryAdmin {
    pub database: Database,
    pub binding: ObjectHash,
    pub certificate: CertificateHash,
    account: Account,
}
impl RecoveryAdmin {
    pub fn service<'a>(
        &self,
        head: &'a SelectedRegistryHead,
        audit: &'a dyn ea_audit::LocalAuditService,
    ) -> OperatorBindingService<'a> {
        OperatorBindingService::new(
            head,
            audit,
            VerifiedLocalDeviceIdentity::verify(
                head,
                self.certificate,
                head.active_certificate_fields(self.certificate)
                    .unwrap()
                    .device_id,
            )
            .unwrap(),
        )
    }
    pub fn enroll(line: &mut RegistryLineBuilder) -> Self {
        let database = database("recovery-admin");
        let secret = [0x68; 32];
        let certificate = line.second_bootstrap_admin_hash();
        let mut profile = Vec::new();
        minicbor::Encoder::new(&mut profile)
            .array(5)
            .unwrap()
            .bytes(trust_support::organization().as_bytes())
            .unwrap()
            .bytes(&[0x42; 16])
            .unwrap()
            .str("Admin")
            .unwrap()
            .str("Administration")
            .unwrap()
            .bytes(&SALT)
            .unwrap();
        let binding = line
            .push(
                ActionSpec::OperatorBinding {
                    certificate_hash: certificate,
                    role: OperatorRoleV1::OrganizationAdmin,
                    marker: 0x42,
                    effective_from: Some(21),
                },
                HeadOptions {
                    effective_from: Some(21),
                    valid_through: Some(100),
                    not_after: UnixMillis::new(10_000_000),
                    binding_operator_profile_commitment_override: Some(operator_profile_digest(
                        &profile,
                    )),
                    binding_instance_key_thumbprint_override: Some(key(secret).thumbprint()),
                    ..HeadOptions::default()
                },
            )
            .direct_object_hash
            .unwrap();
        database
            .database
            .execute(
                "INSERT INTO operator_profile VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                    StoreValue::Blob(vec![0x42; 16]),
                    StoreValue::Text("Admin".into()),
                    StoreValue::Text("Administration".into()),
                    StoreValue::Blob(SALT.to_vec()),
                    StoreValue::Blob(binding.as_bytes().to_vec()),
                ],
            )
            .unwrap();
        Self {
            database,
            binding,
            certificate: CertificateHash::from(certificate),
            account: Account {
                secret: Some(secret),
                hash: trust_support::hash32(0x44),
            },
        }
    }
    pub fn authenticator(&self, head: &SelectedRegistryHead) -> Authenticator {
        Authenticator {
            bound: BoundOperator::resolve(head, self.binding).unwrap(),
            secret: self.account.secret.unwrap(),
            fail: false,
        }
    }
    pub fn login<'a>(&'a self, authenticator: &'a Authenticator) -> VerifySessionRequest<'a> {
        VerifySessionRequest {
            database: &self.database.database,
            binding_object_hash: self.binding,
            device_certificate_hash: self.certificate,
            role: OperatorRoleV1::OrganizationAdmin,
            purpose: ReauthPurpose::AdminRootCeremony,
            account: Arc::new(self.account.clone()),
            authenticator,
        }
    }
    pub fn audit(&self, head: &SelectedRegistryHead) -> support::AuditHarness {
        support::AuditHarness::with_provider(
            head,
            ObjectHash::try_from(self.certificate.as_bytes().as_slice()).unwrap(),
            0,
            support::FixtureKeyProvider::second_admin(),
        )
    }
}

pub fn registry_fields(bytes: &[u8]) -> RegistryEventFieldsV1 {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(bytes).unwrap() else {
        panic!()
    };
    let DecodedTrustPayloadV1::RegistryEvent(event) = parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    event.fields().clone()
}

pub struct RevokedEnrollment {
    pub harness: Harness,
    pub target: Database,
    pub native: Native,
    pub authorization: Authorization,
    pub active: SelectedRegistryHead,
    pub revoked: SelectedRegistryHead,
    pub revocation: PreparedOperatorRevocation,
    pub evidence: RevokedOperatorBinding,
    pub binding: ObjectHash,
}
impl RevokedEnrollment {
    pub fn new() -> Self {
        let harness = Harness::new();
        let head = harness.head();
        let target = database("descendant-recovery");
        let native = Native::new();
        let mut authorization = harness.authorization();
        let prepared = harness
            .provision(
                &head,
                &harness.audit(&head, 0),
                &target.database,
                &native,
                &Identity::valid(),
                &mut authorization,
            )
            .unwrap();
        let binding = prepared.binding_object_hash();
        let active = authorization.activate(&prepared);
        let revocation = harness
            .revoke(
                &active,
                harness.audit(&active, 0).service(),
                binding,
                &mut authorization,
            )
            .unwrap();
        let revoked = selected(&authorization.line, revocation.registry_bytes(), 201);
        let evidence =
            RevokedOperatorBinding::verify(&active, &revoked, revocation.registry_bytes(), binding)
                .unwrap();
        Self {
            harness,
            target,
            native,
            authorization,
            active,
            revoked,
            revocation,
            evidence,
            binding,
        }
    }
    pub fn advance(&mut self) -> SelectedRegistryHead {
        let other = database("intervening-enrollment");
        let mut identity = Identity::valid();
        identity.wrong_subject = true;
        let prepared = self
            .harness
            .provision(
                &self.revoked,
                &self.harness.audit(&self.revoked, 0),
                &other.database,
                &Native::new(),
                &identity,
                &mut self.authorization,
            )
            .unwrap();
        self.authorization.activate(&prepared)
    }
}

pub fn sql_audit(
    head: &SelectedRegistryHead,
    database: &Arc<EncryptedDatabase>,
    certificate: CertificateHash,
) -> ea_audit::SignedLocalAuditService {
    let provider = Arc::new(support::FixtureKeyProvider::device());
    let handle = provider.handle();
    ea_audit::SignedLocalAuditService::new(
        Arc::new(ea_audit::SqliteLocalAuditRepository::new(database.clone())),
        provider,
        handle,
        ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap(),
        head.preexisting_effective_now().value(),
    )
}
