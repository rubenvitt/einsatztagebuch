//! Provision and revoke on the target host, using a separate offline authority.
//! The target can only replay an already verified Root signature, never access a
//! Root/Admin private key. Profiles and staged state remain in SQLCipher.
use crate::{
    AdminError, OperatorAuthorizationPort, OperatorBindingPublisher, OperatorBindingService,
    OperatorLifecycleError, OperatorMutationPorts, OperatorTrustTarget, PreparedBindingState,
    PreparedOperatorBinding, ProvisionOperatorRequest, ReadyOperatorBinding, RegistryWindow,
    RevokeOperatorRequest, RevokedOperatorBinding, RootCeremonyService,
    VerifiedLocalDeviceIdentity, VerifySessionRequest,
    operator_exchange::wipe_value,
    operator_remote::{
        PreparedRootProvider, RemoteAuditProvider, RemoteAuthority, RemoteAuthorization,
        fresh_store, read_fixed, read_hex, read_string, trust_object,
    },
    operator_runtime::{OperatorGoLiveReport, OperatorRuntime, OperatorRuntimeError},
};
use ea_audit::{
    AuditActorProof, SignedLocalAuditService, SqliteLocalAuditRepository, TypedLocalAuditEvent,
};
use ea_crypto::{CanonicalPublicCoseKey, object_hash};
use ea_format::{
    BindingLifecycleContextV1, DecodedTrustPayloadV1, ExactObjectBytes, LocalAuditActionV1,
    LocalAuditOutcomeV1, OperatorRoleV1, RegistryChangeV1,
};
use ea_key_provider::SecretPurpose;
use ea_local_store::{EncryptedDatabase, StoreValue};
use ea_operator::{OperatorSessionProof, OsAccountProvider, ReauthPurpose};
use ea_types::{CertificateHash, ObjectHash};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

pub fn provision(
    runtime: &mut OperatorRuntime,
) -> Result<OperatorGoLiveReport, OperatorRuntimeError> {
    runtime.ensure_current()?;
    if runtime.config().authority {
        return Err(OperatorRuntimeError::Config);
    }
    // A crash after publication may have advanced the archive already. Complete
    // that exact local enrollment against the current verified head; attempting
    // to publish it again against its old Previous Head would strand recovery.
    let resumed = {
        let audit = runtime.audit_service();
        OperatorBindingService::new(runtime.head(), &audit, runtime.local_device())
            .resume_prepared(runtime.database())?
    };
    if let Some(prepared) = resumed
        && matches!(
            prepared.state(),
            PreparedBindingState::PublicationUncertain
                | PreparedBindingState::Published
                | PreparedBindingState::Active
        )
        && runtime
            .head()
            .active_operator_binding_fields(prepared.binding_object_hash())
            .is_some()
    {
        runtime.refresh_with_binding(prepared.binding_object_hash())?;
        complete(runtime, &prepared)?;
        return runtime.go_live_report();
    }
    let prepared = prepare_and_publish(runtime)?;
    runtime.refresh_with_binding(prepared.binding_object_hash())?;
    if prepared.state() == PreparedBindingState::Active {
        return runtime.verify_session();
    }
    complete(runtime, &prepared)?;
    runtime.go_live_report()
}
fn prepare_and_publish(
    runtime: &OperatorRuntime,
) -> Result<PreparedOperatorBinding, OperatorRuntimeError> {
    let authority = Arc::new(RemoteAuthority::new(runtime)?);
    let actor_profile = RemoteProfile::load(runtime, &authority)?;
    let audit_provider = Arc::new(RemoteAuditProvider {
        authority: authority.clone(),
    });
    let audit = SignedLocalAuditService::new(
        Arc::new(SqliteLocalAuditRepository::new(runtime.database().clone())),
        audit_provider.clone(),
        audit_provider.handle(),
        certificate_object(authority.certificate),
        runtime.head().preexisting_effective_now().value(),
    );
    let local = VerifiedLocalDeviceIdentity::verify(
        runtime.head(),
        authority.certificate,
        authority.device,
    )?;
    let service = OperatorBindingService::new(runtime.head(), &audit, local);
    let root = PreparedRootProvider::new(runtime.head())?;
    let ceremony = RootCeremonyService::new(
        runtime.head(),
        &root,
        root.handle(),
        CertificateHash::from(runtime.head().root_certificate_object_hash()),
        &audit,
        authority.binding,
    );
    let mut authorization = RemoteAuthorization::new(runtime, authority.clone(), &root);
    let mut store = fresh_store(runtime)?;
    let mut ports = OperatorMutationPorts {
        authorization: &mut authorization,
        ceremony: &ceremony,
        store: &mut store,
    };
    let resume = service.resume_prepared(runtime.database())?;
    let revoked = resume
        .as_ref()
        .map(PreparedOperatorBinding::binding_object_hash)
        .filter(|h| runtime.head().revoked_operator_binding_fields(*h).is_some())
        .or_else(|| {
            runtime
                .head()
                .revoked_operator_binding_fields(runtime.config().binding_object_hash)
                .map(|_| runtime.config().binding_object_hash)
        });
    let replacement = revoked
        .map(|hash| RevokedOperatorBinding::resolve(runtime.head(), hash))
        .transpose()?;
    let resume = resume.filter(|p| {
        runtime
            .head()
            .revoked_operator_binding_fields(p.binding_object_hash())
            .is_none()
    });
    let prepared = if let Some(prepared) = resume {
        if prepared.state() == PreparedBindingState::Active {
            return Ok(prepared);
        }
        prepared
    } else {
        service.provision(
            ProvisionOperatorRequest {
                database: runtime.database(),
                device_certificate_hash: runtime.config().device_certificate_hash,
                role: runtime.config().role,
                window: window(runtime),
                replacement: replacement.as_ref(),
            },
            runtime.native().as_ref(),
            authority.as_ref(),
            &mut ports,
            actor_profile.request(&authority),
        )?
    };
    let prepared = match prepared.state() {
        PreparedBindingState::BindingPrepared | PreparedBindingState::ActivationRequested => {
            service.authorize_prepared(
                runtime.database(),
                &prepared,
                runtime.native().as_ref(),
                &mut ports,
                actor_profile.request(&authority),
            )?
        }
        _ => prepared,
    };
    let mut publisher = ArchivePublisher { runtime };
    service.publish_prepared(
        runtime.database(),
        &prepared,
        runtime.native().as_ref(),
        &mut publisher,
    )?;
    runtime.ensure_current()?;
    Ok(prepared)
}

pub fn revoke(runtime: &mut OperatorRuntime) -> Result<OperatorGoLiveReport, OperatorRuntimeError> {
    runtime.ensure_current()?;
    if runtime.config().authority {
        return Err(OperatorRuntimeError::Config);
    }
    let target = runtime.config().binding_object_hash;
    let existing = runtime.database().query_row(
        "SELECT authorization,registry FROM operator_revocation_journal WHERE binding_hash=?1",
        &[StoreValue::Blob(target.as_bytes().to_vec())],
    )?;
    let (authorization, registry) = if let Some(row) = existing {
        (row.blob(0)?.to_vec(), row.blob(1)?.to_vec())
    } else {
        prepare_revocation(runtime, target)?
    };
    verify_revocation_bytes(runtime, target, &authorization, &registry)?;
    publish_object(&runtime.config().archive_directory, &authorization)?;
    publish_object(&runtime.config().archive_directory, &registry)?;
    runtime.refresh_with_binding(target)?;
    if runtime
        .head()
        .revoked_operator_binding_fields(target)
        .is_none()
    {
        return Err(OperatorRuntimeError::Lifecycle(
            OperatorLifecycleError::Readiness,
        ));
    }
    runtime.revocation_report(target)
}
fn prepare_revocation(
    runtime: &OperatorRuntime,
    target: ObjectHash,
) -> Result<(Vec<u8>, Vec<u8>), OperatorRuntimeError> {
    let authority = Arc::new(RemoteAuthority::new(runtime)?);
    let actor_profile = RemoteProfile::load(runtime, &authority)?;
    let audit_provider = Arc::new(RemoteAuditProvider {
        authority: authority.clone(),
    });
    let audit = SignedLocalAuditService::new(
        Arc::new(SqliteLocalAuditRepository::new(runtime.database().clone())),
        audit_provider.clone(),
        audit_provider.handle(),
        certificate_object(authority.certificate),
        runtime.head().preexisting_effective_now().value(),
    );
    let local = VerifiedLocalDeviceIdentity::verify(
        runtime.head(),
        authority.certificate,
        authority.device,
    )?;
    let service = OperatorBindingService::new(runtime.head(), &audit, local);
    let root = PreparedRootProvider::new(runtime.head())?;
    let ceremony = RootCeremonyService::new(
        runtime.head(),
        &root,
        root.handle(),
        CertificateHash::from(runtime.head().root_certificate_object_hash()),
        &audit,
        authority.binding,
    );
    let mut authorization = RemoteAuthorization::new(runtime, authority.clone(), &root);
    let actor = service.verify_session(actor_profile.request(&authority))?;
    // Persist the exact intent BEFORE RemoteAuthorization opens an exchange.
    // A later process must reuse its original timestamps and operation hash.
    let event = service.revocation_target(
        &RevokeOperatorRequest {
            database: runtime.database(),
            binding_object_hash: target,
            window: window(runtime),
        },
        actor.proof(),
    )?;
    let intended = OperatorTrustTarget::Registry(event.clone());
    let authorized = authorization.authorize(runtime.head(), &intended)?;
    runtime.ensure_current()?;
    retain_revocation_authorization(runtime, target, &authorized.exact_authorization)?;
    let publication = RevocationPublication {
        runtime,
        binding: target,
        authorization: &authorized.exact_authorization,
        proof: actor.proof(),
        audit: &audit,
        effective: event.effective_from_sequence,
    };
    let registry = ceremony
        .publish_durably(
            &authorized.intent,
            intended.payload(object_hash(&authorized.exact_authorization))?,
            &authorized.exact_authorization,
            actor.proof(),
            &publication,
        )
        .map_err(OperatorLifecycleError::Ceremony)?;
    runtime.ensure_current()?;
    let decoded = trust_object(registry.as_bytes())?;
    let DecodedTrustPayloadV1::RegistryEvent(event) = decoded
        .decoded_payload()
        .map_err(|_| OperatorRuntimeError::Archive)?
    else {
        return Err(OperatorRuntimeError::Archive);
    };
    if event.fields().change
        != (RegistryChangeV1::Target {
            target_kind: 1,
            object_hash: target,
        })
    {
        return Err(OperatorRuntimeError::Archive);
    }
    Ok((authorized.exact_authorization, registry.as_bytes().to_vec()))
}

fn window(runtime: &OperatorRuntime) -> RegistryWindow {
    RegistryWindow {
        effective_from_sequence: runtime.next_sequence(),
        valid_through_sequence: runtime.head().valid_through_sequence(),
        not_after: runtime.head().not_after(),
    }
}
fn verify_revocation_bytes(
    runtime: &OperatorRuntime,
    target: ObjectHash,
    authorization: &[u8],
    registry: &[u8],
) -> Result<(), OperatorRuntimeError> {
    use ea_trust::TrustObjectSource;
    let decoded = trust_object(registry)?;
    let DecodedTrustPayloadV1::RegistryEvent(event) = decoded
        .decoded_payload()
        .map_err(|_| OperatorRuntimeError::Archive)?
    else {
        return Err(OperatorRuntimeError::Archive);
    };
    let fields = event.fields();
    if fields.organization_id != runtime.anchor().organization_id()
        || fields.change
            != (RegistryChangeV1::Target {
                target_kind: 1,
                object_hash: target,
            })
        || event.authorization_object_hash() != object_hash(authorization)
    {
        return Err(OperatorRuntimeError::Archive);
    }
    if runtime
        .head()
        .revoked_operator_binding_fields(target)
        .is_some()
    {
        // Already published and accepted by the ordinary full archive verifier.
        // A different valid revocation does not authorize exporting this journal.
        let stored = runtime
            .inventory()
            .read_exact_trust_object(object_hash(registry))
            .map_err(|_| OperatorRuntimeError::Archive)?
            .ok_or(OperatorRuntimeError::Archive)?;
        if stored.as_ref() != registry {
            return Err(OperatorRuntimeError::Archive);
        }
        return Ok(());
    }
    if fields
        .previous_registry_hash
        .is_none_or(|h| h.as_bytes() != runtime.head().registry_head_hash().as_bytes())
        || runtime.head().registry_version().get().checked_add(1)
            != Some(fields.registry_version.get())
    {
        return Err(OperatorRuntimeError::Lifecycle(
            OperatorLifecycleError::JournalConflict,
        ));
    }
    crate::operator::operator_host::verify_signed_pair(
        runtime.head(),
        registry,
        authorization,
        fields.effective_from_sequence,
        fields.issued_at,
    )?;
    runtime.ensure_current()
}
fn certificate_object(cert: CertificateHash) -> ObjectHash {
    ObjectHash::try_from(cert.as_bytes().as_slice()).expect("32-byte certificate hash")
}
fn complete(
    runtime: &OperatorRuntime,
    prepared: &PreparedOperatorBinding,
) -> Result<(), OperatorRuntimeError> {
    let audit = runtime.audit_service();
    let service = OperatorBindingService::new(runtime.head(), &audit, runtime.local_device());
    let account: Arc<dyn OsAccountProvider> = runtime.native().clone();
    let presence = runtime.presence();
    service.complete_prepared(
        prepared,
        VerifySessionRequest {
            database: runtime.database(),
            binding_object_hash: prepared.binding_object_hash(),
            device_certificate_hash: runtime.config().device_certificate_hash,
            role: runtime.config().role,
            purpose: runtime.config().purpose,
            account,
            authenticator: &presence,
        },
    )?;
    runtime.ensure_current()
}
struct ArchivePublisher<'a> {
    runtime: &'a OperatorRuntime,
}
impl OperatorBindingPublisher for ArchivePublisher<'_> {
    fn publish(&mut self, ready: &ReadyOperatorBinding) -> Result<(), OperatorLifecycleError> {
        self.runtime
            .ensure_current()
            .map_err(|_| OperatorLifecycleError::Readiness)?;
        for bytes in [
            ready.binding_authorization_bytes(),
            ready.binding_bytes(),
            ready.activation_authorization_bytes(),
            ready.activation_bytes(),
        ] {
            publish_object(&self.runtime.config().archive_directory, bytes)
                .map_err(|_| OperatorLifecycleError::Readiness)?;
        }
        Ok(())
    }
}
fn publish_object(directory: &Path, bytes: &[u8]) -> Result<(), OperatorRuntimeError> {
    // Flat content-addressed files are accepted by the existing archive source.
    // Activation comes last; every earlier published file is independently exact.
    let path = directory.join(format!(
        "{}.etb",
        hex::encode(object_hash(bytes).as_bytes())
    ));
    crate::operator_exchange::write_exchange_file(&path, bytes)
        .map_err(OperatorRuntimeError::Exchange)
}
fn retain_revocation_authorization(
    runtime: &OperatorRuntime,
    target: ObjectHash,
    authorization: &[u8],
) -> Result<(), OperatorRuntimeError> {
    runtime.database().execute("UPDATE operator_revocation_intent SET authorization=?1 WHERE binding_hash=?2 AND authorization IS NULL",&[StoreValue::Blob(authorization.to_vec()),StoreValue::Blob(target.as_bytes().to_vec())])?;
    let row = runtime
        .database()
        .query_row(
            "SELECT authorization FROM operator_revocation_intent WHERE binding_hash=?1",
            &[StoreValue::Blob(target.as_bytes().to_vec())],
        )?
        .ok_or(OperatorRuntimeError::Io)?;
    if row.blob(0)? != authorization {
        return Err(OperatorRuntimeError::Lifecycle(
            OperatorLifecycleError::JournalConflict,
        ));
    }
    Ok(())
}

/// Nothing is published until the local replay, both signed audit rows and the
/// exact final pair commit in one transaction. All remote signing precedes it.
struct RevocationPublication<'a> {
    runtime: &'a OperatorRuntime,
    binding: ObjectHash,
    authorization: &'a [u8],
    proof: &'a OperatorSessionProof,
    audit: &'a SignedLocalAuditService,
    effective: ea_types::ChainSequence,
}
impl crate::root_ceremony::DurableRootPublication for RevocationPublication<'_> {
    fn retained_signature(&self) -> Result<Option<Vec<u8>>, AdminError> {
        let row = self.runtime.database().query_row(
            "SELECT authorization,root_signature,root_signature IS NULL FROM operator_revocation_intent WHERE binding_hash=?1",
            &[StoreValue::Blob(self.binding.as_bytes().to_vec())],
        ).map_err(|_| AdminError::AuditFailed)?.ok_or(AdminError::AuthorizationMismatch)?;
        if row.blob(0).map_err(|_| AdminError::AuditFailed)? != self.authorization {
            return Err(AdminError::AuthorizationMismatch);
        }
        if row.integer(2).map_err(|_| AdminError::AuditFailed)? != 0 {
            Ok(None)
        } else {
            Ok(Some(
                row.blob(1).map_err(|_| AdminError::AuditFailed)?.to_vec(),
            ))
        }
    }
    fn stage_signature(&self, signature: &[u8]) -> Result<(), AdminError> {
        self.runtime
            .ensure_current()
            .map_err(|_| AdminError::ReauthMismatch)?;
        self.runtime.database().execute(
            "UPDATE operator_revocation_intent SET root_signature=?1 WHERE binding_hash=?2 AND authorization=?3 AND root_signature IS NULL",
            &[StoreValue::Blob(signature.to_vec()),StoreValue::Blob(self.binding.as_bytes().to_vec()),StoreValue::Blob(self.authorization.to_vec())],
        ).map_err(|_| AdminError::AuditFailed)?;
        if self.retained_signature()?.as_deref() != Some(signature) {
            return Err(AdminError::RootSignatureMismatch);
        }
        Ok(())
    }
    fn commit(
        &self,
        target: &ExactObjectBytes,
        replay: &[ea_trust::AdminAuthorizationReplayKey; 2],
        event: TypedLocalAuditEvent,
    ) -> Result<(), AdminError> {
        self.runtime
            .ensure_current()
            .map_err(|_| AdminError::ReauthMismatch)?;
        let root_audit = self
            .audit
            .prepare_signed(AuditActorProof::OperatorSession(self.proof), event)
            .map_err(|_| AdminError::AuditFailed)?;
        let revocation_audit = self
            .audit
            .prepare_signed(
                AuditActorProof::OperatorSession(self.proof),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::Revocation(BindingLifecycleContextV1::new(
                        Some(self.binding),
                        None,
                        self.effective,
                    )),
                    outcome: LocalAuditOutcomeV1::Completed,
                },
            )
            .map_err(|_| AdminError::AuditFailed)?;
        self.runtime
            .ensure_current()
            .map_err(|_| AdminError::ReauthMismatch)?;
        let now =
            crate::operator_runtime::fresh_wall_clock().map_err(|_| AdminError::ReauthMismatch)?;
        let device = self
            .runtime
            .head()
            .active_certificate_fields(self.runtime.config().device_certificate_hash)
            .ok_or(AdminError::BindingInactive)?
            .device_id;
        self.runtime.database().transaction(|tx| {
            let blob = |bytes: &[u8]| StoreValue::Blob(bytes.to_vec());
            let state = tx.query_row("SELECT chain_id,trust_anchor_hash,pin_hash,floor_ms FROM operator_trust_state WHERE organization_id=?1 AND device_id=?2",
                &[blob(self.runtime.anchor().organization_id().as_bytes()), blob(device.as_bytes())])?.ok_or(AdminError::HeadMismatch)?;
            if state.blob(0)? != self.runtime.anchor().chain_id().as_bytes()
                || state.blob(1)? != self.runtime.anchor().trust_anchor_hash().as_bytes()
                || state.blob(2)? != self.runtime.head().registry_head_hash().as_bytes()
                || state.integer(3)? > now.get()
            {
                return Err(RevocationCommitError::Admin(AdminError::HeadMismatch));
            }
            let staged = tx.query_row("SELECT authorization,root_signature IS NULL FROM operator_revocation_intent WHERE binding_hash=?1", &[blob(self.binding.as_bytes())])?.ok_or(AdminError::AuthorizationMismatch)?;
            if staged.blob(0)? != self.authorization || staged.integer(1)? != 0 {
                return Err(RevocationCommitError::Admin(AdminError::AuthorizationMismatch));
            }
            for key in replay {
                if key.organization_id() != self.runtime.anchor().organization_id() {
                    return Err(RevocationCommitError::Admin(AdminError::AuthorizationMismatch));
                }
                let (dimension, value) = match key.dimension() {
                    ea_trust::AdminAuthorizationReplayDimension::AuthorizationId(id) => (0, blob(id.as_bytes())),
                    ea_trust::AdminAuthorizationReplayDimension::Nonce(nonce) => (1, blob(&nonce)),
                };
                let inserted = tx.execute("INSERT INTO operator_admin_replay(organization_id,dimension,replay_value) VALUES(?1,?2,?3) ON CONFLICT(organization_id,dimension,replay_value) DO NOTHING",
                    &[blob(key.organization_id().as_bytes()), StoreValue::Integer(dimension), value])?;
                if inserted != 1 {
                    return Err(RevocationCommitError::Admin(AdminError::Trust(ea_trust::TrustError::AuthReplay)));
                }
            }
            for audit in [&root_audit, &revocation_audit] {
                SqliteLocalAuditRepository::append_prepared_in(tx, audit).map_err(|_| AdminError::AuditFailed)?;
            }
            tx.execute("INSERT INTO operator_revocation_journal(binding_hash,authorization,registry) VALUES(?1,?2,?3)",
                &[blob(self.binding.as_bytes()), blob(self.authorization), blob(target.as_bytes())])?;
            for bytes in [self.authorization, target.as_bytes()] {
                let hash = object_hash(bytes);
                tx.execute("INSERT INTO operator_remote_object(object_hash,exact_bytes) VALUES(?1,?2) ON CONFLICT(object_hash) DO NOTHING", &[blob(hash.as_bytes()), blob(bytes)])?;
                let stored = tx.query_row("SELECT exact_bytes FROM operator_remote_object WHERE object_hash=?1", &[blob(hash.as_bytes())])?.ok_or(AdminError::TargetMismatch)?;
                if stored.blob(0)? != bytes {
                    return Err(RevocationCommitError::Admin(AdminError::TargetMismatch));
                }
            }
            Ok(())
        }).map_err(|error| match error {
            RevocationCommitError::Admin(error) => error,
            RevocationCommitError::Store => AdminError::AuditFailed,
        })
    }
}
enum RevocationCommitError {
    Admin(AdminError),
    Store,
}
impl From<AdminError> for RevocationCommitError {
    fn from(error: AdminError) -> Self {
        Self::Admin(error)
    }
}
impl From<ea_local_store::StoreError> for RevocationCommitError {
    fn from(_: ea_local_store::StoreError) -> Self {
        Self::Store
    }
}

/// Temporary SQLCipher profile for the independently verified remote Admin.
/// The record is required by the same session/commitment checks as a local one.
/// Its random private directory is removed when this ceremony invocation ends.
struct RemoteProfile {
    database: Option<Arc<EncryptedDatabase>>,
    directory: PathBuf,
}
impl RemoteProfile {
    fn load(
        runtime: &OperatorRuntime,
        authority: &RemoteAuthority,
    ) -> Result<Self, OperatorRuntimeError> {
        let mut response = authority.describe()?;
        let result = (|| {
            let profile = response
                .get("profile")
                .ok_or(OperatorRuntimeError::Config)?;
            let org = read_fixed::<16>(profile, "organization_id")?;
            let subject = read_fixed::<16>(profile, "operator_subject_id")?;
            let salt = read_fixed::<32>(profile, "profile_commitment_salt")?;
            let binding = read_fixed::<32>(profile, "operator_binding_object_hash")?;
            let fields = runtime
                .head()
                .active_operator_binding_fields(authority.binding)
                .ok_or(OperatorRuntimeError::SignerMismatch)?;
            if org.as_slice() != authority.organization.as_bytes()
                || binding.as_slice() != authority.binding.as_bytes()
                || subject.as_slice() != fields.operator_subject_id.as_bytes()
            {
                return Err(OperatorRuntimeError::SignerMismatch);
            }
            let name = read_string(profile, "display_name")?;
            let function = read_string(profile, "function_label")?;
            if ea_crypto::operator_profile_commitment(
                authority.organization,
                fields.operator_subject_id,
                name,
                function,
                &salt,
            ) != fields.operator_profile_commitment
            {
                return Err(OperatorRuntimeError::Lifecycle(
                    OperatorLifecycleError::ProfileCommitment,
                ));
            }
            let public = CanonicalPublicCoseKey::from_deterministic_cbor(&read_hex(
                &response,
                "instance_public_key",
            )?)
            .map_err(|_| OperatorRuntimeError::SignerMismatch)?;
            if public.thumbprint() != fields.operator_instance_key_thumbprint
                || read_fixed::<32>(&response, "os_account_binding_hash")?.as_slice()
                    != fields.os_account_binding_hash.as_bytes()
            {
                return Err(OperatorRuntimeError::SignerMismatch);
            }
            let mut nonce = [0u8; 32];
            getrandom::fill(&mut nonce).map_err(|_| OperatorRuntimeError::Io)?;
            let directory = runtime
                .config()
                .database_path
                .parent()
                .ok_or(OperatorRuntimeError::Config)?
                .join(format!(".operator-ceremony-{}", hex::encode(nonce)));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(&directory)
                .map_err(|_| OperatorRuntimeError::Io)?;
            let mut temporary = Self {
                database: None,
                directory,
            };
            let provider = runtime.signing_provider();
            let database = Arc::new(EncryptedDatabase::open(
                &temporary.directory.join("admin.sqlite3"),
                provider.as_ref(),
                &provider.handle(SecretPurpose::LocalDatabaseKey),
            )?);
            temporary.database = Some(database.clone());
            database.execute(
                "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
                &[
                    StoreValue::Blob(org.to_vec()),
                    StoreValue::Blob(subject.to_vec()),
                    StoreValue::Text(name.to_owned()),
                    StoreValue::Text(function.to_owned()),
                    StoreValue::Blob(salt.to_vec()),
                    StoreValue::Blob(binding.to_vec()),
                ],
            )?;
            Ok(temporary)
        })();
        wipe_value(&mut response);
        result
    }
    fn request<'a>(&'a self, authority: &'a Arc<RemoteAuthority>) -> VerifySessionRequest<'a> {
        let account: Arc<dyn OsAccountProvider> = authority.clone();
        VerifySessionRequest {
            database: self.database.as_ref().expect("open temporary profile"),
            binding_object_hash: authority.binding,
            device_certificate_hash: authority.certificate,
            role: OperatorRoleV1::OrganizationAdmin,
            purpose: ReauthPurpose::AdminRootCeremony,
            account,
            authenticator: authority.as_ref(),
        }
    }
}
impl Drop for RemoteProfile {
    fn drop(&mut self) {
        self.database.take();
        let _ = fs::remove_dir_all(&self.directory);
    }
}
