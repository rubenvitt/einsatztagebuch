//! Target-side adapters for an authenticated, separate offline authority.

use crate::{
    AuthorizedOperatorIntent, ExternalIdentityRequest, ExternalOperatorIdentity,
    ExternalOperatorIdentityVerifier, OperatorAuthorizationPort, OperatorLifecycleError,
    OperatorPresence, OperatorTrustTarget,
    native_provider::NativeOperatorProvider,
    operator_exchange::{
        ExchangeError, NativeExchangeSigner, PendingExchange, exchange_in_directory, wipe_value,
    },
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
    operator_trust_store::OperatorTrustStateStore,
};
use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec,
    VerificationContext, object_hash, parse_cose_sign1, trust_digest, verify_cose_sign1,
};
use ea_format::{
    KeyProtectionProfileV1, OperatorRoleV1, ParsedArchiveObject, TrustObjectV1, decode_exact_object,
};
use ea_key_provider::{
    CoseSign1Bytes, KeyError, KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose,
};
use ea_operator::{OperatorError, OsAccountProvider};
use ea_trust::{
    SelectedRegistryHead, TrustObjectSource, TrustSourceError, load_trust_state,
    prepare_local_time, select_registry_head, verify_intended_trust_target,
    verify_registry_candidate, verify_trust,
};
use ea_types::{CertificateHash, DeviceId, Hash32, ObjectHash, OperatorSubjectId, OrganizationId};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(crate) struct RemoteAuthority {
    native: Arc<NativeOperatorProvider>,
    database: Arc<ea_local_store::EncryptedDatabase>,
    target_public: CanonicalPublicCoseKey,
    directory: std::path::PathBuf,
    pub certificate: CertificateHash,
    pub binding: ObjectHash,
    pub organization: OrganizationId,
    pub device: DeviceId,
    pub signing_public: CanonicalPublicCoseKey,
    context: Value,
    request_as_admin: bool,
}
impl RemoteAuthority {
    pub fn new(runtime: &OperatorRuntime) -> Result<Self, OperatorRuntimeError> {
        let config = runtime.config();
        let certificate = config
            .admin_certificate_hash
            .ok_or(OperatorRuntimeError::Config)?;
        let binding = config
            .admin_binding_object_hash
            .ok_or(OperatorRuntimeError::Config)?;
        let fields = runtime
            .head()
            .active_certificate_fields(certificate)
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        let operator = runtime
            .head()
            .active_operator_binding_fields(binding)
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        if fields.certificate_kind != ea_format::CertificateKindV1::OrganizationAdmin
            || operator.operator_role != OperatorRoleV1::OrganizationAdmin
            || operator.device_certificate_hash != certificate
        {
            return Err(OperatorRuntimeError::SignerMismatch);
        }
        let signing_public = CanonicalPublicCoseKey::from_deterministic_cbor(
            fields
                .signing_public_cose_key
                .as_deref()
                .ok_or(OperatorRuntimeError::SignerMismatch)?,
        )
        .map_err(|_| OperatorRuntimeError::SignerMismatch)?;
        let context = json!({"organization_id":hex::encode(fields.organization_id.as_bytes()),"chain_id":hex::encode(runtime.head().chain_id().as_bytes()),"registry_head_hash":hex::encode(runtime.head().registry_head_hash().as_bytes()),"registry_version":runtime.head().registry_version().get(),"sequence":runtime.next_sequence().get(),"device_certificate_hash":hex::encode(config.device_certificate_hash.as_bytes()),"admin_certificate_hash":hex::encode(certificate.as_bytes()),"admin_binding_object_hash":hex::encode(binding.as_bytes())});
        let target = runtime
            .head()
            .active_certificate_fields(config.device_certificate_hash)
            .ok_or(OperatorRuntimeError::SignerMismatch)?;
        let target_public = CanonicalPublicCoseKey::from_deterministic_cbor(
            target
                .signing_public_cose_key
                .as_deref()
                .ok_or(OperatorRuntimeError::SignerMismatch)?,
        )
        .map_err(|_| OperatorRuntimeError::SignerMismatch)?;
        Ok(Self {
            native: runtime.native().clone(),
            database: runtime.database().clone(),
            target_public,
            directory: config
                .ceremony_exchange_directory
                .clone()
                .ok_or(OperatorRuntimeError::Config)?,
            certificate,
            binding,
            organization: fields.organization_id,
            device: fields.device_id,
            signing_public,
            context,
            request_as_admin: config.role == OperatorRoleV1::OrganizationAdmin,
        })
    }
    pub fn exchange(&self, op: &str, args: Value) -> Result<Value, ExchangeError> {
        let signer = if self.request_as_admin {
            NativeExchangeSigner::administrator(&self.native)
        } else {
            NativeExchangeSigner::device(&self.native)
        };
        let pending = PendingExchange::load_or_create(
            &self.database,
            json!({"context":self.context,"op":op,"args":args}),
            &signer,
            &self.target_public,
        )?;
        let bytes = exchange_in_directory(&pending, &self.directory, Duration::from_secs(300))?;
        let mut reply = pending.open_reply(&bytes, &self.signing_public)?;
        if reply.get("error").is_some() {
            wipe_value(&mut reply);
            return Err(ExchangeError::Invalid);
        }
        if op != "authorize-target" {
            pending.forget(&self.database)?;
        }
        Ok(reply)
    }
    pub fn describe(&self) -> Result<Value, ExchangeError> {
        self.exchange("describe-admin", json!({}))
    }
}
impl OsAccountProvider for RemoteAuthority {
    fn os_account_binding_hash(
        &self,
        org: OrganizationId,
        device: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        if org != self.organization || device != self.device {
            return Err(OperatorError::AccountMismatch);
        }
        let mut reply = self
            .describe()
            .map_err(|_| OperatorError::PresenceProofInvalid)?;
        let result = read_fixed::<32>(&reply, "os_account_binding_hash")
            .map_err(|_| OperatorError::AccountMismatch);
        wipe_value(&mut reply);
        result.map(|b| Hash32::try_from(b.as_slice()).expect("32 bytes"))
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        let mut reply = self
            .describe()
            .map_err(|_| OperatorError::PresenceProofInvalid)?;
        let result = read_hex(&reply, "instance_public_key")
            .map_err(|_| OperatorError::InstanceKeyMissing)
            .and_then(|bytes| {
                CanonicalPublicCoseKey::from_deterministic_cbor(&bytes)
                    .map_err(OperatorError::Crypto)
            });
        wipe_value(&mut reply);
        result.map(Some)
    }
}
impl OperatorPresence for RemoteAuthority {
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        let reply = self
            .exchange("presence", json!({"challenge":hex::encode(challenge)}))
            .map_err(|_| OperatorError::PresenceProofInvalid)?;
        read_fixed(&reply, "signature").map_err(|_| OperatorError::PresenceProofInvalid)
    }
}
impl ExternalOperatorIdentityVerifier for RemoteAuthority {
    fn verify_identity(
        &self,
        request: &ExternalIdentityRequest,
    ) -> Result<ExternalOperatorIdentity, OperatorLifecycleError> {
        let mut reply=self.exchange("identity",json!({"organization_id":hex::encode(request.organization_id.as_bytes()),"challenge":hex::encode(request.challenge),"device_id":hex::encode(request.device_id.as_bytes()),"role":role_name(request.role),"previous_subject_id":request.previous_subject_id.map(|id|hex::encode(id.as_bytes())),"previous_binding_object_hash":request.previous_binding_object_hash.map(|id|hex::encode(id.as_bytes()))})).map_err(|_|OperatorLifecycleError::IdentityVerification)?;
        let result = (|| {
            Ok(ExternalOperatorIdentity {
                organization_id: OrganizationId::try_from(
                    read_fixed::<16>(&reply, "organization_id")?.as_slice(),
                )
                .map_err(|_| ExchangeError::Invalid)?,
                operator_subject_id: OperatorSubjectId::try_from(
                    read_fixed::<16>(&reply, "operator_subject_id")?.as_slice(),
                )
                .map_err(|_| ExchangeError::Invalid)?,
                display_name: read_string(&reply, "display_name")?.to_owned(),
                function_label: read_string(&reply, "function_label")?.to_owned(),
                profile_commitment_salt: read_fixed(&reply, "profile_commitment_salt")?,
                previous_binding_object_hash: if reply.get("previous_binding_object_hash")
                    == Some(&Value::Null)
                {
                    None
                } else {
                    Some(
                        ObjectHash::try_from(
                            read_fixed::<32>(&reply, "previous_binding_object_hash")?.as_slice(),
                        )
                        .map_err(|_| ExchangeError::Invalid)?,
                    )
                },
                challenge: read_fixed(&reply, "challenge")?,
            })
        })();
        wipe_value(&mut reply);
        result.map_err(|_: ExchangeError| OperatorLifecycleError::IdentityVerification)
    }
}
fn role_name(role: OperatorRoleV1) -> &'static str {
    match role {
        OperatorRoleV1::Writer => "writer",
        OperatorRoleV1::Reader => "reader",
        OperatorRoleV1::OrganizationAdmin => "organization-admin",
    }
}

pub(crate) struct RemoteAuditProvider {
    pub authority: Arc<RemoteAuthority>,
}
pub(crate) struct CachedRootSignature {
    digest: [u8; 32],
    signature: [u8; 64],
}
pub(crate) struct PreparedRootProvider {
    public: CanonicalPublicCoseKey,
    certificate: CertificateHash,
    cache: Arc<Mutex<Vec<CachedRootSignature>>>,
}
impl PreparedRootProvider {
    pub fn new(head: &SelectedRegistryHead) -> Result<Self, OperatorRuntimeError> {
        let public = CanonicalPublicCoseKey::from_deterministic_cbor(
            &head.root_certificate_fields().root_public_cose_key,
        )
        .map_err(|_| OperatorRuntimeError::SignerMismatch)?;
        Ok(Self {
            public,
            certificate: CertificateHash::from(head.root_certificate_object_hash()),
            cache: Arc::new(Mutex::new(Vec::new())),
        })
    }
    pub fn handle(&self) -> KeyHandle {
        remote_handle(self.certificate)
    }
}
impl RemoteAuditProvider {
    pub fn handle(&self) -> KeyHandle {
        remote_handle(self.authority.certificate)
    }
}
fn remote_handle(cert: CertificateHash) -> KeyHandle {
    KeyHandle::new(
        KeystoreProvider::OperatingSystem,
        Hash32::try_from(cert.as_bytes().as_slice()).expect("32 bytes"),
        SecretPurpose::WriterSigningKey,
    )
}
macro_rules! closed_remote_secrets {
    () => {
        fn generate(
            &self,
            _: SecretPurpose,
            _: KeyProtectionProfileV1,
        ) -> Result<KeyHandle, KeyError> {
            Err(KeyError::ForbiddenPurpose)
        }
        fn wrap_secret(&self, _: SecretPurpose, _: SecretBytes<32>) -> Result<KeyHandle, KeyError> {
            Err(KeyError::ForbiddenPurpose)
        }
        fn unwrap_secret(&self, _: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
            Err(KeyError::ForbiddenPurpose)
        }
        fn unwrap_database_key(&self, _: &KeyHandle) -> Result<SecretVec, KeyError> {
            Err(KeyError::ForbiddenPurpose)
        }
        fn delete(&self, _: &KeyHandle) -> Result<(), KeyError> {
            Err(KeyError::ForbiddenPurpose)
        }
        fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError> {
            Ok(handle == &self.handle())
        }
        fn reached_protection_profile(
            &self,
            handle: &KeyHandle,
        ) -> Result<KeyProtectionProfileV1, KeyError> {
            if handle == &self.handle() {
                Ok(KeyProtectionProfileV1::OsWrapped)
            } else {
                Err(KeyError::NotFound)
            }
        }
    };
}
impl KeyProvider for RemoteAuditProvider {
    closed_remote_secrets!();
    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ContentType,
        certificate: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        if handle != &self.handle()
            || certificate != self.authority.certificate
            || content_type != ContentType::LocalAuditCbor
        {
            return Err(KeyError::PurposeMismatch);
        }
        let reply = self
            .authority
            .exchange("sign-audit", json!({"core":hex::encode(payload)}))
            .map_err(|_| KeyError::NotFound)?;
        let cose = read_hex(&reply, "cose").map_err(|_| KeyError::NotFound)?;
        recompose(
            &cose,
            &self.authority.signing_public,
            content_type,
            certificate,
            payload,
        )
    }
}
impl KeyProvider for PreparedRootProvider {
    closed_remote_secrets!();
    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ContentType,
        certificate: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        if handle != &self.handle()
            || content_type != ContentType::TrustDigest
            || certificate != self.certificate
        {
            return Err(KeyError::PurposeMismatch);
        }
        let cache = self.cache.lock().map_err(|_| KeyError::NotFound)?;
        let item = cache
            .iter()
            .find(|v| v.digest.as_slice() == payload)
            .ok_or(KeyError::NotFound)?;
        CoseSign1Bytes::compose(
            &ProtectedHeader::normal(content_type, self.public.thumbprint(), certificate),
            payload,
            &item.signature,
        )
    }
}
fn recompose(
    bytes: &[u8],
    public: &CanonicalPublicCoseKey,
    kind: ContentType,
    cert: CertificateHash,
    payload: &[u8],
) -> Result<CoseSign1Bytes, KeyError> {
    let parsed = parse_cose_sign1(bytes, &[]).map_err(KeyError::Crypto)?;
    if parsed.content_type() != kind
        || parsed.certificate_hash() != Some(cert)
        || parsed.payload() != payload
    {
        return Err(KeyError::PurposeMismatch);
    }
    let signature = *parsed.signature_bytes();
    let header = ProtectedHeader::normal(kind, public.thumbprint(), cert);
    public
        .verify_ed25519_strict(&header.sig_structure_bytes(payload), &signature)
        .map_err(KeyError::Crypto)?;
    let result = CoseSign1Bytes::compose(&header, payload, &signature)?;
    if result.as_bytes() != bytes {
        return Err(KeyError::PurposeMismatch);
    }
    Ok(result)
}

pub(crate) struct RemoteAuthorization<'a> {
    runtime: &'a OperatorRuntime,
    authority: Arc<RemoteAuthority>,
    root_cache: Arc<Mutex<Vec<CachedRootSignature>>>,
    objects: Vec<Vec<u8>>,
}
impl<'a> RemoteAuthorization<'a> {
    pub fn new(
        runtime: &'a OperatorRuntime,
        authority: Arc<RemoteAuthority>,
        root: &PreparedRootProvider,
    ) -> Self {
        Self {
            runtime,
            authority,
            root_cache: root.cache.clone(),
            objects: Vec::new(),
        }
    }
    fn target_response(
        &self,
        target: &OperatorTrustTarget,
    ) -> Result<Value, OperatorLifecycleError> {
        self.runtime
            .ensure_current()
            .map_err(|_| OperatorLifecycleError::Readiness)?;
        let proposed = target.payload(ObjectHash::from(Hash32::ZERO))?;
        // include_prepared_objects runs again after restart. Deduplicate and sort
        // the public catalog so it names the exact same durable transport request.
        let relevant: BTreeMap<_, _> = self
            .objects
            .iter()
            .map(|bytes| (object_hash(bytes), bytes))
            .collect();
        let result=self.authority.exchange("authorize-target",json!({"target_payload":hex::encode(proposed.exact_digest_input()),"relevant_objects":relevant.values().map(hex::encode).collect::<Vec<_>>()})).map_err(|_|OperatorLifecycleError::IdentityVerification)?;
        self.runtime
            .ensure_current()
            .map_err(|_| OperatorLifecycleError::Readiness)?;
        Ok(result)
    }
}
impl OperatorAuthorizationPort for RemoteAuthorization<'_> {
    fn include_prepared_objects(
        &mut self,
        objects: &[&[u8]],
    ) -> Result<(), OperatorLifecycleError> {
        self.objects.extend(objects.iter().map(|b| b.to_vec()));
        Ok(())
    }
    fn stage_signed_objects(&mut self, objects: &[&[u8]]) -> Result<(), OperatorLifecycleError> {
        self.runtime.database().transaction(|tx|{
            for bytes in objects {
                let hash=object_hash(bytes);
                tx.execute("INSERT INTO operator_remote_object(object_hash,exact_bytes) VALUES(?1,?2) ON CONFLICT(object_hash) DO NOTHING",&[ea_local_store::StoreValue::Blob(hash.as_bytes().to_vec()),ea_local_store::StoreValue::Blob(bytes.to_vec())])?;
                let row=tx.query_row("SELECT exact_bytes FROM operator_remote_object WHERE object_hash=?1",&[ea_local_store::StoreValue::Blob(hash.as_bytes().to_vec())])?.ok_or(OperatorLifecycleError::JournalConflict)?;
                if row.blob(0)?!=*bytes{return Err(OperatorLifecycleError::JournalConflict);}
            }
            Ok::<(),OperatorLifecycleError>(())
        })?;
        self.objects.extend(objects.iter().map(|b| b.to_vec()));
        Ok(())
    }
    fn authorize(
        &mut self,
        head: &SelectedRegistryHead,
        target: &OperatorTrustTarget,
    ) -> Result<AuthorizedOperatorIntent, OperatorLifecycleError> {
        self.runtime
            .ensure_current()
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        let reply = self.target_response(target)?;
        let authorization = read_hex(&reply, "authorization")
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        let signed =
            read_hex(&reply, "target").map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        let expected = target.payload(object_hash(&authorization))?;
        let parsed = trust_object(&signed)?;
        if parsed.exact_digest_input() != expected.exact_digest_input() {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        let context = VerificationContext::root_trust_digest(
            expected.exact_digest_input(),
            CertificateHash::from(head.root_certificate_object_hash()),
            Some(&authorization),
        )
        .map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        let signature = parsed
            .signatures()
            .first()
            .ok_or(OperatorLifecycleError::TargetMismatch)?;
        verify_cose_sign1(signature, head, &context)
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        let digest = *trust_digest(expected.exact_digest_input()).as_bytes();
        let raw = *parse_cose_sign1(signature, &[])
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?
            .signature_bytes();
        self.objects.push(authorization.clone());
        let mut store =
            fresh_store(self.runtime).map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        let source = ObjectOverlay::new(self.runtime.inventory(), &self.objects);
        let trust = verify_trust(
            self.runtime.anchor(),
            &source,
            load_trust_state(&mut store, self.runtime.trust().state_key())
                .map_err(OperatorLifecycleError::Trust)?,
        )
        .map_err(OperatorLifecycleError::Trust)?;
        let candidate = verify_registry_candidate(&trust, head.proposed_sequence())
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        // The offline administrator may issue this authorization after an
        // interactive prompt. Reselect the same head at actual current time;
        // the original runtime deadline and session watch still bound the call.
        let now = crate::operator_runtime::fresh_wall_clock()
            .map_err(|_| OperatorLifecycleError::Readiness)?;
        let time = prepare_local_time(&mut store, &candidate, now, &[])
            .map_err(OperatorLifecycleError::Trust)?;
        let selected = select_registry_head(candidate, time, None)
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        let selected = match selected {
            ea_trust::RegistrySelectionOutcome::Selected(h) => h,
            _ => return Err(OperatorLifecycleError::TargetMismatch),
        };
        if selected.registry_head_hash() != head.registry_head_hash()
            || selected.registry_version() != head.registry_version()
            || selected.chain_id() != head.chain_id()
            || selected.proposed_sequence() != head.proposed_sequence()
            || selected.preexisting_effective_now().value()
                < head.preexisting_effective_now().value()
        {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        let use_time = match target {
            OperatorTrustTarget::Registry(event) => event.issued_at,
            OperatorTrustTarget::Binding(_) => selected.preexisting_effective_now().value(),
        };
        let intent = verify_intended_trust_target(
            &trust,
            Some(&selected),
            &expected,
            use_time,
            head.proposed_sequence(),
        )
        .map_err(OperatorLifecycleError::Trust)?;
        self.runtime
            .ensure_current()
            .map_err(|_| OperatorLifecycleError::Readiness)?;
        // A signed activation/revocation must not enter the selected catalogue
        // while its own target-side audit/readiness transaction is unfinished.
        if matches!(target, OperatorTrustTarget::Binding(_)) {
            self.objects.push(signed);
        }
        self.root_cache
            .lock()
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?
            .push(CachedRootSignature {
                digest,
                signature: raw,
            });
        Ok(AuthorizedOperatorIntent {
            intent,
            exact_authorization: authorization,
        })
    }
    fn recover_authorization(
        &mut self,
        head: &SelectedRegistryHead,
        target: &OperatorTrustTarget,
    ) -> Result<AuthorizedOperatorIntent, OperatorLifecycleError> {
        // target_response's outbox is committed before file publication. It
        // reuses the original request/key, never a new nonce after exposure.
        // Absence proves this operation had not reached the exchange boundary.
        self.authorize(head, target)
    }
    fn recover_activation(
        &mut self,
        head: &SelectedRegistryHead,
        target: &OperatorTrustTarget,
        exact_authorization: &[u8],
    ) -> Result<Vec<u8>, OperatorLifecycleError> {
        let reply = self.target_response(target)?;
        let authorization = read_hex(&reply, "authorization")
            .map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        let signed =
            read_hex(&reply, "target").map_err(|_| OperatorLifecycleError::TargetMismatch)?;
        if authorization != exact_authorization
            || trust_object(&signed)?.exact_digest_input()
                != target
                    .payload(object_hash(exact_authorization))?
                    .exact_digest_input()
        {
            return Err(OperatorLifecycleError::TargetMismatch);
        }
        // Host reconciliation verifies the same Root/Admin pair, current native
        // key/account and encrypted profile, then journals Ready. No second
        // target-side replay consume or Root signature is attempted here.
        if head.registry_head_hash() != self.runtime.head().registry_head_hash() {
            return Err(OperatorLifecycleError::Readiness);
        }
        Ok(signed)
    }
}
pub(crate) fn fresh_store(
    runtime: &OperatorRuntime,
) -> Result<OperatorTrustStateStore, OperatorRuntimeError> {
    OperatorTrustStateStore::open(
        runtime.database().clone(),
        runtime.trust().state_key(),
        runtime.head().chain_id(),
        runtime.anchor().trust_anchor_hash(),
        runtime.head().preexisting_effective_now().value(),
    )
    .map_err(OperatorRuntimeError::State)
}
pub(crate) struct ObjectOverlay<'a> {
    base: &'a dyn TrustObjectSource,
    objects: BTreeMap<ObjectHash, Arc<[u8]>>,
}
impl<'a> ObjectOverlay<'a> {
    pub fn new(base: &'a dyn TrustObjectSource, objects: &[Vec<u8>]) -> Self {
        Self {
            base,
            objects: objects
                .iter()
                .map(|b| (object_hash(b), Arc::from(b.clone())))
                .collect(),
        }
    }
}
impl TrustObjectSource for ObjectOverlay<'_> {
    fn visit_trust_object_hashes(
        &self,
        visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
    ) -> Result<(), TrustSourceError> {
        self.base.visit_trust_object_hashes(visitor)?;
        for key in self.objects.keys() {
            if self.base.read_exact_trust_object(*key)?.is_none() {
                visitor(*key)?;
            }
        }
        Ok(())
    }
    fn read_exact_trust_object(
        &self,
        hash: ObjectHash,
    ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
        if let Some(bytes) = self.objects.get(&hash) {
            Ok(Some(bytes.clone()))
        } else {
            self.base.read_exact_trust_object(hash)
        }
    }
}
pub(crate) fn trust_object(bytes: &[u8]) -> Result<TrustObjectV1, OperatorLifecycleError> {
    match decode_exact_object(bytes)? {
        ParsedArchiveObject::Trust(parsed) => Ok(parsed.value().clone()),
        _ => Err(OperatorLifecycleError::TargetMismatch),
    }
}
pub(crate) fn read_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, ExchangeError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ExchangeError::Invalid)
}
pub(crate) fn read_hex(value: &Value, field: &str) -> Result<Vec<u8>, ExchangeError> {
    hex::decode(read_string(value, field)?).map_err(|_| ExchangeError::Invalid)
}
pub(crate) fn read_fixed<const N: usize>(
    value: &Value,
    field: &str,
) -> Result<[u8; N], ExchangeError> {
    read_hex(value, field)?
        .try_into()
        .map_err(|_| ExchangeError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn cached_root_signature_cannot_sign_another_digest_or_certificate() {
        let secret = SigningKey::from_bytes(&[7; 32]);
        let public = CanonicalPublicCoseKey::ed25519(secret.verifying_key().to_bytes()).unwrap();
        let cert = CertificateHash::try_from(&[9; 32][..]).unwrap();
        let digest = [3; 32];
        let protected =
            ProtectedHeader::normal(ContentType::TrustDigest, public.thumbprint(), cert);
        let signature = secret
            .sign(&protected.sig_structure_bytes(&digest))
            .to_bytes();
        let cache = Arc::new(Mutex::new(vec![CachedRootSignature { digest, signature }]));
        let provider = PreparedRootProvider {
            public,
            certificate: cert,
            cache,
        };
        let handle = provider.handle();
        assert!(
            provider
                .sign(&handle, ContentType::TrustDigest, cert, &digest)
                .is_ok()
        );
        assert!(
            provider
                .sign(&handle, ContentType::TrustDigest, cert, &[4; 32])
                .is_err()
        );
        assert!(
            provider
                .sign(&handle, ContentType::LocalAuditCbor, cert, &digest)
                .is_err()
        );
        assert!(
            provider
                .sign(
                    &handle,
                    ContentType::TrustDigest,
                    CertificateHash::from(ObjectHash::from(Hash32::ZERO)),
                    &digest
                )
                .is_err()
        );
        assert!(provider.unwrap_secret(&handle).is_err());
        assert!(provider.unwrap_database_key(&handle).is_err());
    }
}
