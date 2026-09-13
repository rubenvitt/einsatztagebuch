//! Dedicated offline organizational authority. Transport is local, authenticated
//! and encrypted; Suite v1 trust objects still use the existing typed ceremony.
use crate::{
    AdminError, NativeOperatorProvisioning, OperatorTrustTarget,
    native_provider::NativeSigningSlot,
    operator_exchange::{
        ExchangeError, NativeExchangeSigner, VerifiedExchangeRequest, read_exchange_file,
        write_exchange_file,
    },
    operator_runtime::{OperatorRuntime, OperatorRuntimeError},
};
use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, ProtectedHeader, VerificationContext, object_hash,
    trust_digest,
};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, OperatorRoleV1, RegistryChangeV1, TrustPayloadV1,
};
use ea_key_provider::{CoseSign1Bytes, KeyProvider, SecretPurpose};
use ea_local_store::{EncryptedDatabase, StoreError, StoreValue};
use ea_operator::{MAX_INACTIVITY_MS, OsAccountProvider, REAUTH_CHALLENGE_DOMAIN, ReauthPurpose};
use ea_trust::SelectedRegistryHead;
use ea_types::{
    AuthorizationId, CertificateHash, Hash32, ObjectHash, OperatorSubjectId, UnixMillis,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fmt, fs,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub enum AuthorityError {
    Invalid,
    Context,
    Identity,
    Tty,
    Uncertain,
    Store(StoreError),
    Exchange(ExchangeError),
    Runtime(OperatorRuntimeError),
    Admin(AdminError),
}
impl AuthorityError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "EA-OPERATOR-AUTHORITY-REQUEST",
            Self::Context => "EA-OPERATOR-AUTHORITY-CONTEXT",
            Self::Identity => "EA-OPERATOR-EXTERNAL-IDENTITY",
            Self::Tty => "EA-OPERATOR-IDENTITY-PRIVATE-TTY-REQUIRED",
            Self::Uncertain => "EA-OPERATOR-AUTHORITY-RECOVERY-REQUIRED",
            Self::Store(e) => e.code(),
            Self::Exchange(e) => e.code(),
            Self::Runtime(e) => e.code(),
            Self::Admin(e) => e.code(),
        }
    }
    pub fn exit_code(&self) -> ea_recovery::ExitCode {
        match self {
            Self::Tty | Self::Invalid => ea_recovery::ExitCode::Usage,
            Self::Store(_) | Self::Exchange(ExchangeError::Io) => ea_recovery::ExitCode::Io,
            Self::Runtime(e) => e.exit_code(),
            _ => ea_recovery::ExitCode::Trust,
        }
    }
}
impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())?;
        match self {
        Self::Tty => f.write_str(": open the dedicated authority in a private interactive terminal and confirm the physical external identity check; OS display names cannot attest identity"),
        Self::Uncertain => f.write_str(": interrupted authority request; resume the original request on this authority with fresh Admin authentication; do not create a replacement authorization"),
        _ => Ok(()),
    }
    }
}
impl fmt::Debug for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for AuthorityError {}
impl From<StoreError> for AuthorityError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<ExchangeError> for AuthorityError {
    fn from(e: ExchangeError) -> Self {
        Self::Exchange(e)
    }
}
impl From<OperatorRuntimeError> for AuthorityError {
    fn from(e: OperatorRuntimeError) -> Self {
        Self::Runtime(e)
    }
}
impl From<AdminError> for AuthorityError {
    fn from(e: AdminError) -> Self {
        Self::Admin(e)
    }
}
impl From<ea_trust::TrustError> for AuthorityError {
    fn from(e: ea_trust::TrustError) -> Self {
        Self::Runtime(e.into())
    }
}
impl From<ea_trust::RegistryError> for AuthorityError {
    fn from(e: ea_trust::RegistryError) -> Self {
        Self::Runtime(e.into())
    }
}
impl From<crate::OperatorLifecycleError> for AuthorityError {
    fn from(e: crate::OperatorLifecycleError) -> Self {
        Self::Runtime(e.into())
    }
}
impl From<ea_operator::OperatorError> for AuthorityError {
    fn from(e: ea_operator::OperatorError) -> Self {
        Self::Runtime(e.into())
    }
}
impl From<ea_key_provider::KeyError> for AuthorityError {
    fn from(e: ea_key_provider::KeyError) -> Self {
        Self::Runtime(e.into())
    }
}
impl From<crate::native_provider::NativeProviderError> for AuthorityError {
    fn from(e: crate::native_provider::NativeProviderError) -> Self {
        Self::Runtime(e.into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestContext {
    organization_id: String,
    chain_id: String,
    registry_head_hash: String,
    registry_version: u64,
    sequence: u64,
    device_certificate_hash: String,
    admin_certificate_hash: String,
    admin_binding_object_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestPayload {
    context: RequestContext,
    op: String,
    args: Value,
}

fn verify_request(
    bytes: &[u8],
    head: &SelectedRegistryHead,
    target: CertificateHash,
    admin: CertificateHash,
    binding: ObjectHash,
) -> Result<(VerifiedExchangeRequest, RequestPayload), AuthorityError> {
    let (request, payload) = verify_request_source(bytes, head, target, admin, binding)?;
    let context = &payload.context;
    if fixed::<32>(&context.registry_head_hash)?.as_slice() != head.registry_head_hash().as_bytes()
        || context.registry_version != head.registry_version().get()
        || context.sequence != head.proposed_sequence().get()
    {
        return Err(AuthorityError::Context);
    }
    Ok((request, payload))
}

// A completed request may refer to an earlier head, but its signature and pinned
// organization/chain/target/Admin attribution must still match this authority.
fn verify_request_source(
    bytes: &[u8],
    head: &SelectedRegistryHead,
    target: CertificateHash,
    admin: CertificateHash,
    binding: ObjectHash,
) -> Result<(VerifiedExchangeRequest, RequestPayload), AuthorityError> {
    let source = head
        .active_certificate_fields(target)
        .ok_or(AuthorityError::Context)?;
    if !matches!(
        source.certificate_kind,
        CertificateKindV1::Writer
            | CertificateKindV1::Reader
            | CertificateKindV1::OrganizationAdmin
    ) || target == admin
    {
        return Err(AuthorityError::Context);
    }
    let key = CanonicalPublicCoseKey::from_deterministic_cbor(
        source
            .signing_public_cose_key
            .as_deref()
            .ok_or(AuthorityError::Context)?,
    )
    .map_err(|_| AuthorityError::Context)?;
    if source.signing_key_thumbprint != Some(key.thumbprint()) {
        return Err(AuthorityError::Context);
    }
    let request = VerifiedExchangeRequest::verify(bytes, &key)?;
    let payload: RequestPayload =
        serde_json::from_value(request.payload().clone()).map_err(|_| AuthorityError::Invalid)?;
    let c = &payload.context;
    fixed::<32>(&c.registry_head_hash)?;
    let authority = head
        .active_certificate_fields(admin)
        .ok_or(AuthorityError::Context)?;
    let operator = head
        .active_operator_binding_fields(binding)
        .ok_or(AuthorityError::Context)?;
    if authority.certificate_kind != CertificateKindV1::OrganizationAdmin
        || operator.operator_role != OperatorRoleV1::OrganizationAdmin
        || operator.device_certificate_hash != admin
        || operator.organization_id != source.organization_id
        || authority.organization_id != source.organization_id
        || source.organization_id != head.root_certificate_fields().organization_id
        || authority
            .authority_subject_id
            .is_none_or(|subject| subject.as_bytes() != operator.operator_subject_id.as_bytes())
        || fixed::<16>(&c.organization_id)?.as_slice() != source.organization_id.as_bytes()
        || fixed::<16>(&c.chain_id)?.as_slice() != head.chain_id().as_bytes()
        || fixed::<32>(&c.device_certificate_hash)?.as_slice() != target.as_bytes()
        || fixed::<32>(&c.admin_certificate_hash)?.as_slice() != admin.as_bytes()
        || fixed::<32>(&c.admin_binding_object_hash)?.as_slice() != binding.as_bytes()
    {
        return Err(AuthorityError::Context);
    }
    Ok((request, payload))
}

fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N], AuthorityError> {
    if s.len() != N * 2
        || s.bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(AuthorityError::Invalid);
    }
    hex::decode(s)
        .map_err(|_| AuthorityError::Invalid)?
        .try_into()
        .map_err(|_| AuthorityError::Invalid)
}
fn begin_request(
    database: &Arc<EncryptedDatabase>,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, AuthorityError> {
    let hash = object_hash(bytes);
    database.transaction(|tx| {
        if let Some(row) = tx.query_row("SELECT request_bytes,reply_bytes,state FROM operator_authority_request WHERE request_hash=?1", &[blob(hash.as_bytes())])? {
            if row.blob(0)? != bytes { return Err(AuthorityError::Invalid); }
            if row.integer(2)? != 1 { return Err(AuthorityError::Uncertain); }
            return Ok(Some(row.blob(1)?.to_vec()));
        }
        tx.execute("INSERT INTO operator_authority_request(request_hash,request_bytes,state) VALUES(?1,?2,0)", &[blob(hash.as_bytes()),blob(bytes)])?;
        Ok(None)
    })
}

fn completed_request(
    database: &EncryptedDatabase,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, AuthorityError> {
    let Some(row) = database.query_row("SELECT request_bytes,reply_bytes,state FROM operator_authority_request WHERE request_hash=?1", &[blob(object_hash(bytes).as_bytes())])? else {
        return Ok(None);
    };
    if row.blob(0)? != bytes {
        return Err(AuthorityError::Invalid);
    }
    if row.integer(2)? != 1 {
        return Ok(None);
    }
    Ok(Some(row.blob(1)?.to_vec()))
}
fn finish_request(
    database: &Arc<EncryptedDatabase>,
    bytes: &[u8],
    reply: &[u8],
) -> Result<(), AuthorityError> {
    let changed = database.execute("UPDATE operator_authority_request SET reply_bytes=?1,state=1 WHERE request_hash=?2 AND request_bytes=?3 AND state=0", &[blob(reply),blob(object_hash(bytes).as_bytes()),blob(bytes)])?;
    if changed != 1 {
        return Err(AuthorityError::Uncertain);
    }
    Ok(())
}

fn supported_target(bytes: &[u8]) -> Result<crate::OperatorTrustTarget, AuthorityError> {
    let payload =
        TrustPayloadV1::from_exact_digest_input(bytes).map_err(|_| AuthorityError::Invalid)?;
    match payload
        .decoded_payload()
        .map_err(|_| AuthorityError::Invalid)?
    {
        DecodedTrustPayloadV1::AuthorizedOperatorBinding(fields) => {
            Ok(crate::OperatorTrustTarget::Binding(fields.fields().clone()))
        }
        DecodedTrustPayloadV1::RegistryEvent(fields)
            if matches!(
                fields.fields().change,
                RegistryChangeV1::OperatorBinding { .. }
                    | RegistryChangeV1::Target { target_kind: 1, .. }
            ) =>
        {
            Ok(crate::OperatorTrustTarget::Registry(
                fields.fields().clone(),
            ))
        }
        _ => Err(AuthorityError::Invalid),
    }
}

/// Serves sequential requests for at most the runtime's five-minute lifetime.
/// Expiry terminates with an error before another request can be accepted.
/// A later invocation can publish the exact cached encrypted reply after media failure.
pub fn run_authority(runtime: &mut OperatorRuntime) -> Result<usize, AuthorityError> {
    runtime.ensure_current()?;
    let config = runtime.config();
    if !config.authority
        || config.role != OperatorRoleV1::OrganizationAdmin
        || config.purpose != ReauthPurpose::AdminRootCeremony
    {
        return Err(AuthorityError::Context);
    }
    let target = config
        .target_certificate_hash
        .ok_or(AuthorityError::Context)?;
    let directory = config
        .ceremony_exchange_directory
        .clone()
        .ok_or(AuthorityError::Invalid)?;
    let meta = fs::symlink_metadata(&directory).map_err(|_| ExchangeError::Io)?;
    if !meta.is_dir() || meta.is_symlink() {
        return Err(AuthorityError::Invalid);
    }
    let mut handled = std::collections::BTreeSet::new();
    loop {
        runtime.ensure_current()?;
        let paths = request_paths(&directory, &handled)?;
        for path in paths {
            process_file(runtime, target, &directory, &path)?;
            handled.insert(path);
            if handled.len() >= 1024 {
                return Ok(handled.len());
            }
        }
        runtime.ensure_current()?;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn request_paths(
    directory: &std::path::Path,
    handled: &std::collections::BTreeSet<std::path::PathBuf>,
) -> Result<Vec<std::path::PathBuf>, AuthorityError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| ExchangeError::Io)? {
        let entry = entry.map_err(|_| ExchangeError::Io)?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|s| s.starts_with("request-") && s.ends_with(".json"))
        {
            let path = entry.path();
            if !handled.contains(&path) {
                paths.push(path);
            }
        }
        if paths.len() > 1024 {
            return Err(AuthorityError::Invalid);
        }
    }
    paths.sort();
    Ok(paths)
}

struct PreparedRequestFile {
    bytes: Vec<u8>,
    request: VerifiedExchangeRequest,
    payload: RequestPayload,
    cached: Option<Vec<u8>>,
}

fn prepare_request_file(
    database: &Arc<EncryptedDatabase>,
    head: &SelectedRegistryHead,
    target: CertificateHash,
    admin: CertificateHash,
    binding: ObjectHash,
    path: &std::path::Path,
) -> Result<PreparedRequestFile, AuthorityError> {
    let bytes = read_exchange_file(path)?;
    // This read-only exact-byte lookup precedes new-operation head eligibility.
    // Unknown/pending requests still take the full live verification path; no
    // pending row is inserted or replayed merely because a file was discovered.
    let completed = completed_request(database, &bytes)?;
    let (request, payload) = if completed.is_some() {
        verify_request_source(&bytes, head, target, admin, binding)?
    } else {
        verify_request(&bytes, head, target, admin, binding)?
    };
    let id = request.request_id();
    if path.file_name().and_then(|n| n.to_str()) != Some(format!("request-{id}.json").as_str()) {
        return Err(AuthorityError::Invalid);
    }
    let cached = match completed {
        Some(reply) => Some(reply),
        None => match begin_request(database, &bytes) {
            Err(AuthorityError::Uncertain)
                if matches!(payload.op.as_str(), "authorize-target" | "admin-trust-target") => None,
            other => other?,
        },
    };
    Ok(PreparedRequestFile {
        bytes,
        request,
        payload,
        cached,
    })
}

fn process_file(
    runtime: &OperatorRuntime,
    target: CertificateHash,
    directory: &std::path::Path,
    path: &std::path::Path,
) -> Result<(), AuthorityError> {
    runtime.ensure_current()?;
    let PreparedRequestFile {
        bytes,
        request,
        payload,
        cached,
    } = prepare_request_file(
        runtime.database(),
        runtime.head(),
        target,
        runtime.config().device_certificate_hash,
        runtime.config().binding_object_hash,
        path,
    )?;
    let id = request.request_id();
    if payload.op == "admin-trust-target" {
        runtime.ensure_same_action_authority()?;
    }
    let reply = match cached {
        Some(reply) => reply,
        None if payload.op == "admin-trust-target" => {
            let session = runtime.reauthenticate()?;
            crate::administration_runtime::root_exchange::authorize(
                runtime, target, &request, &payload.args, &session,
            )?
        }
        None if payload.op == "authorize-target" => {
            let session = runtime.reauthenticate()?;
            authorize_target(
                runtime,
                target,
                &request,
                args(&payload.args)?,
                session.proof(),
            )?
        }
        None => {
            let result = dispatch(runtime, &payload, target);
            // Only authenticated requests receive errors, always encrypted.
            // Failed authentication is already durably audited by reauthenticate.
            let (response, error) = match result {
                Ok(response) => (response, None),
                Err(error) => (json!({"error":error.code()}), Some(error)),
            };
            runtime.ensure_current()?;
            let reply = request.reply(
                response,
                &NativeExchangeSigner::administrator(runtime.native()),
            )?;
            runtime.ensure_current()?;
            finish_request(runtime.database(), &bytes, &reply)?;
            if let Some(error) = error {
                write_exchange_file(&directory.join(format!("reply-{id}.json")), &reply)?;
                return Err(error);
            }
            reply
        }
    };
    publish_reply_file(directory, &id, &reply)
}

fn publish_reply_file(
    directory: &std::path::Path,
    id: &str,
    reply: &[u8],
) -> Result<(), AuthorityError> {
    let destination = directory.join(format!("reply-{id}.json"));
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            if read_exchange_file(&destination)? != reply {
                return Err(AuthorityError::Invalid);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_exchange_file(&destination, reply)?
        }
        Err(_) => return Err(ExchangeError::Io.into()),
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceArgs {
    challenge: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityArgs {
    organization_id: String,
    challenge: String,
    device_id: String,
    role: String,
    previous_subject_id: Option<String>,
    previous_binding_object_hash: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeArgs {
    target_payload: String,
    #[serde(default)]
    relevant_objects: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditArgs {
    core: String,
}
fn args<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, AuthorityError> {
    serde_json::from_value(value.clone()).map_err(|_| AuthorityError::Invalid)
}
fn bytes(s: &str) -> Result<Vec<u8>, AuthorityError> {
    if s.len() > 98_304 {
        return Err(AuthorityError::Invalid);
    }
    hex::decode(s).map_err(|_| AuthorityError::Invalid)
}
fn now() -> Result<UnixMillis, AuthorityError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthorityError::Context)?
        .as_millis();
    Ok(UnixMillis::new(
        i64::try_from(millis).map_err(|_| AuthorityError::Context)?,
    ))
}

fn dispatch(
    runtime: &OperatorRuntime,
    payload: &RequestPayload,
    target: CertificateHash,
) -> Result<Value, AuthorityError> {
    // Every accepted operation obtains an actual fresh, active Admin session.
    // The session includes the SQLCipher profile check and durable Login audit.
    let session = runtime.reauthenticate()?;
    let value = match payload.op.as_str() {
        "describe-admin" => {
            if payload.args.as_object().is_none_or(|m| !m.is_empty()) {
                return Err(AuthorityError::Invalid);
            }
            let profile = session.profile();
            let device = runtime
                .head()
                .active_certificate_fields(runtime.config().device_certificate_hash)
                .ok_or(AuthorityError::Context)?
                .device_id;
            let account = runtime
                .native()
                .os_account_binding_hash(profile.organization_id(), device)?;
            let instance = runtime
                .native()
                .operator_instance_public_key()?
                .ok_or(AuthorityError::Context)?;
            json!({"profile": {"organization_id":hex::encode(profile.organization_id().as_bytes()),
                "operator_subject_id":hex::encode(profile.operator_subject_id().as_bytes()),
                "display_name":profile.display_name(),"function_label":profile.function_label(),
                "profile_commitment_salt":hex::encode(profile.profile_commitment_salt()),
                "operator_binding_object_hash":hex::encode(profile.operator_binding_object_hash().as_bytes())},
                "os_account_binding_hash":hex::encode(account.as_bytes()),
                "instance_public_key":hex::encode(instance.to_deterministic_cbor())})
        }
        "presence" => {
            let input: PresenceArgs = args(&payload.args)?;
            let challenge = bytes(&input.challenge)?;
            check_presence_challenge(
                runtime.head(),
                runtime.config().device_certificate_hash,
                runtime.config().binding_object_hash,
                &challenge,
                now()?,
            )?;
            let signature = NativeOperatorProvisioning::prove_presence_and_sign(
                runtime.native().as_ref(),
                &challenge,
            )?;
            json!({"signature":hex::encode(signature)})
        }
        "identity" => collect_identity(runtime, target, args(&payload.args)?)?,
        "sign-audit" => sign_audit(runtime, target, args(&payload.args)?)?,
        _ => return Err(AuthorityError::Invalid),
    };
    runtime.ensure_current()?;
    Ok(value)
}

fn check_presence_challenge(
    head: &SelectedRegistryHead,
    admin: CertificateHash,
    binding: ObjectHash,
    input: &[u8],
    current: UnixMillis,
) -> Result<(), AuthorityError> {
    let label = ReauthPurpose::AdminRootCeremony.label().as_bytes();
    let prefix_len = REAUTH_CHALLENGE_DOMAIN.len() + 1 + label.len();
    let device = head
        .active_certificate_fields(admin)
        .ok_or(AuthorityError::Context)?;
    if input.len() != prefix_len + 16 + 16 + 32 + 32 + 8 + 8
        || !input.starts_with(REAUTH_CHALLENGE_DOMAIN)
        || input[REAUTH_CHALLENGE_DOMAIN.len()] as usize != label.len()
        || &input[REAUTH_CHALLENGE_DOMAIN.len() + 1..prefix_len] != label
        || &input[prefix_len..prefix_len + 16] != device.organization_id.as_bytes()
        || &input[prefix_len + 16..prefix_len + 32] != device.device_id.as_bytes()
        || &input[prefix_len + 32..prefix_len + 64] != binding.as_bytes()
    {
        return Err(AuthorityError::Context);
    }
    let issued = i64::from_be_bytes(
        input[input.len() - 16..input.len() - 8]
            .try_into()
            .map_err(|_| AuthorityError::Invalid)?,
    );
    let expires = i64::from_be_bytes(
        input[input.len() - 8..]
            .try_into()
            .map_err(|_| AuthorityError::Invalid)?,
    );
    if current.get() < issued
        || current.get() >= expires
        || expires
            .checked_sub(issued)
            .is_none_or(|ms| ms <= 0 || ms > MAX_INACTIVITY_MS)
    {
        return Err(AuthorityError::Context);
    }
    Ok(())
}

fn role_label(role: OperatorRoleV1) -> &'static str {
    match role {
        OperatorRoleV1::Writer => "writer",
        OperatorRoleV1::Reader => "reader",
        OperatorRoleV1::OrganizationAdmin => "organization-admin",
    }
}

/// The lookup reads activation and own revocation from the selected trust line.
/// An empty target profile database cannot hide an existing person binding.
fn previous_binding(
    head: &SelectedRegistryHead,
    hashes: impl IntoIterator<Item = ObjectHash>,
    subject: OperatorSubjectId,
    role: OperatorRoleV1,
    target: CertificateHash,
) -> Result<Option<ObjectHash>, AuthorityError> {
    let mut latest: Option<(u64, ObjectHash)> = None;
    for hash in hashes {
        if head.active_operator_binding_fields(hash).is_some_and(|f| {
            f.operator_subject_id == subject
                && f.operator_role == role
                && f.device_certificate_hash == target
        }) {
            return Err(AuthorityError::Identity);
        }
        if let Some(fields) = head.revoked_operator_binding_fields(hash).filter(|f| {
            f.operator_subject_id == subject
                && f.operator_role == role
                && f.device_certificate_hash == target
        }) {
            let revoked = fields
                .revoked_from_sequence
                .ok_or(AuthorityError::Identity)?
                .get();
            match latest {
                Some((sequence, old)) if sequence == revoked && old != hash => {
                    return Err(AuthorityError::Identity);
                }
                Some((sequence, _)) if sequence > revoked => {}
                _ => latest = Some((revoked, hash)),
            }
        }
    }
    Ok(latest.map(|(_, hash)| hash))
}

fn collect_identity(
    runtime: &OperatorRuntime,
    target: CertificateHash,
    input: IdentityArgs,
) -> Result<Value, AuthorityError> {
    let certificate = runtime
        .head()
        .active_certificate_fields(target)
        .ok_or(AuthorityError::Context)?;
    let role = match certificate.certificate_kind {
        CertificateKindV1::Writer => OperatorRoleV1::Writer,
        CertificateKindV1::Reader => OperatorRoleV1::Reader,
        CertificateKindV1::OrganizationAdmin => OperatorRoleV1::OrganizationAdmin,
        _ => return Err(AuthorityError::Context),
    };
    let challenge = fixed::<32>(&input.challenge)?;
    if fixed::<16>(&input.organization_id)?.as_slice() != certificate.organization_id.as_bytes()
        || fixed::<16>(&input.device_id)?.as_slice() != certificate.device_id.as_bytes()
        || input.role != role_label(role)
    {
        return Err(AuthorityError::Context);
    }
    // dispatch has just performed native Admin presence, active binding/profile
    // verification and the signed Login audit. No identity input precedes it.
    let remaining = runtime
        .head()
        .preexisting_effective_now()
        .value()
        .get()
        .checked_add(MAX_INACTIVITY_MS)
        .ok_or(AuthorityError::Context)?
        .min(runtime.head().not_after().get())
        .checked_sub(now()?.get())
        .filter(|ms| *ms > 0)
        .ok_or(AuthorityError::Context)?;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_millis(remaining.min(MAX_INACTIVITY_MS) as u64);
    let mut terminal = PrivateTerminal::open(runtime.native(), deadline)?;
    let confirmation = terminal.line("external-identity-confirmation", "Externe physische Identitaetspruefung anhand verlaesslicher Organisationsunterlagen abgeschlossen? Zur Bestaetigung extern-geprueft eingeben: ", 32)?;
    if confirmation.as_str() != "extern-geprueft" {
        return Err(AuthorityError::Identity);
    }
    runtime.ensure_current()?;
    let subject = terminal.line("authority-subject-id", "Bestehende stabile authoritySubjectId (16 Byte, 32 Hexzeichen) aus Organisationsunterlagen: ", 32)?;
    let subject = OperatorSubjectId::try_from(fixed::<16>(&subject)?.as_slice())
        .map_err(|_| AuthorityError::Identity)?;
    if input
        .previous_subject_id
        .as_deref()
        .map(fixed::<16>)
        .transpose()?
        .is_some_and(|id| id.as_slice() != subject.as_bytes())
        || certificate
            .authority_subject_id
            .is_some_and(|id| id.as_bytes() != subject.as_bytes())
    {
        return Err(AuthorityError::Identity);
    }
    let previous = previous_binding(
        runtime.head(),
        runtime.inventory().trust().iter().map(|p| p.object_hash()),
        subject,
        role,
        target,
    )?;
    if let Some(expected) = input.previous_binding_object_hash.as_deref()
        && previous.is_none_or(|hash| {
            fixed::<32>(expected)
                .ok()
                .as_ref()
                .is_none_or(|b| b.as_slice() != hash.as_bytes())
        })
    {
        return Err(AuthorityError::Identity);
    }
    let name = terminal.line(
        "display-name",
        "Extern gepruefter vollstaendiger Name (Eingabe verborgen): ",
        256,
    )?;
    let function = terminal.line(
        "function-label",
        "Extern gepruefte Funktion (Eingabe verborgen): ",
        256,
    )?;
    if name.trim().is_empty() || function.trim().is_empty() {
        return Err(AuthorityError::Identity);
    }
    let mut salt = Zeroizing::new([0; 32]);
    getrandom::fill(salt.as_mut()).map_err(|_| AuthorityError::Identity)?;
    let snapshot = ea_schema::OperatorSnapshotV1::new(
        certificate.organization_id,
        subject,
        name.as_str(),
        function.as_str(),
        *salt,
        ObjectHash::from(Hash32::ZERO),
    )
    .map_err(|_| AuthorityError::Identity)?;
    runtime.ensure_current()?;
    let current = now()?;
    runtime.database().execute(
        "DELETE FROM operator_authority_identity WHERE attested_at<?1",
        &[StoreValue::Integer(
            current.get().saturating_sub(MAX_INACTIVITY_MS),
        )],
    )?;
    runtime.database().execute("INSERT INTO operator_authority_identity(target_certificate_hash,registry_head_hash,organization_id,operator_subject_id,role,display_name,function_label,profile_commitment_salt,previous_binding_hash,attested_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(target_certificate_hash) DO UPDATE SET registry_head_hash=excluded.registry_head_hash,organization_id=excluded.organization_id,operator_subject_id=excluded.operator_subject_id,role=excluded.role,display_name=excluded.display_name,function_label=excluded.function_label,profile_commitment_salt=excluded.profile_commitment_salt,previous_binding_hash=excluded.previous_binding_hash,attested_at=excluded.attested_at", &[
        blob(target.as_bytes()),blob(runtime.head().registry_head_hash().as_bytes()),blob(certificate.organization_id.as_bytes()),blob(subject.as_bytes()),
        StoreValue::Text(role_label(role).into()),StoreValue::Text(snapshot.display_name().into()),StoreValue::Text(snapshot.function_label().into()),blob(salt.as_slice()),previous.map_or(StoreValue::Null,|h|blob(h.as_bytes())),StoreValue::Integer(current.get()),
    ])?;
    Ok(
        json!({"organization_id":hex::encode(certificate.organization_id.as_bytes()),"operator_subject_id":hex::encode(subject.as_bytes()),
        "display_name":snapshot.display_name(),"function_label":snapshot.function_label(),"profile_commitment_salt":hex::encode(salt.as_slice()),
        "previous_binding_object_hash":previous.map(|h|hex::encode(h.as_bytes())),"challenge":hex::encode(challenge)}),
    )
}

#[cfg(unix)]
struct PrivateTerminal {
    file: fs::File,
    mode: String,
    deadline: std::time::Instant,
}
#[cfg(unix)]
impl PrivateTerminal {
    fn open(
        _native: &Arc<crate::native_provider::NativeOperatorProvider>,
        deadline: std::time::Instant,
    ) -> Result<Self, AuthorityError> {
        use std::{
            io::IsTerminal,
            process::{Command, Stdio},
        };
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| AuthorityError::Tty)?;
        if !file.is_terminal() {
            return Err(AuthorityError::Tty);
        }
        let state = Command::new("/bin/stty")
            .arg("-g")
            .stdin(Stdio::from(
                file.try_clone().map_err(|_| AuthorityError::Tty)?,
            ))
            .output()
            .map_err(|_| AuthorityError::Tty)?;
        if !state.status.success() {
            return Err(AuthorityError::Tty);
        }
        let mode = String::from_utf8(state.stdout).map_err(|_| AuthorityError::Tty)?;
        let status = Command::new("/bin/stty")
            .args([
                "-echo", "-icanon", "-isig", "-iexten", "min", "0", "time", "1",
            ])
            .stdin(Stdio::from(
                file.try_clone().map_err(|_| AuthorityError::Tty)?,
            ))
            .status()
            .map_err(|_| AuthorityError::Tty)?;
        if !status.success() {
            return Err(AuthorityError::Tty);
        }
        Ok(Self {
            file,
            mode,
            deadline,
        })
    }
    fn line(
        &mut self,
        _label: &str,
        prompt: &str,
        limit: usize,
    ) -> Result<Zeroizing<String>, AuthorityError> {
        use std::io::Write;
        self.file
            .write_all(prompt.as_bytes())
            .and_then(|_| self.file.flush())
            .map_err(|_| AuthorityError::Tty)?;
        let result = read_private_line(&mut self.file, limit, self.deadline);
        self.file
            .write_all(b"\n")
            .map_err(|_| AuthorityError::Tty)?;
        result
    }
}
#[cfg(unix)]
fn read_private_line(
    reader: &mut impl std::io::Read,
    limit: usize,
    deadline: std::time::Instant,
) -> Result<Zeroizing<String>, AuthorityError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
    let mut invalid = false;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(AuthorityError::Tty);
        }
        let mut byte = [0];
        if reader.read(&mut byte).map_err(|_| AuthorityError::Tty)? == 0 {
            continue;
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        if byte[0] == 0x7f || byte[0] == 8 {
            while bytes.pop().is_some_and(|b| (b & 0xc0) == 0x80) {}
            continue;
        }
        if byte[0] < 0x20 || bytes.len() >= limit {
            invalid = true;
        }
        if !invalid {
            bytes.push(byte[0]);
        }
        // Consume the remainder of rejected private input with echo disabled,
        // so it cannot later become visible shell input after mode restoration.
    }
    if invalid {
        return Err(AuthorityError::Identity);
    }
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| AuthorityError::Identity)?
            .to_owned(),
    ))
}
#[cfg(unix)]
impl Drop for PrivateTerminal {
    fn drop(&mut self) {
        use std::process::{Command, Stdio};
        if let Ok(file) = self.file.try_clone() {
            let _ = Command::new("/bin/stty")
                .arg(self.mode.trim())
                .stdin(Stdio::from(file))
                .status();
        }
    }
}
#[cfg(windows)]
struct PrivateTerminal {
    native: Arc<crate::native_provider::NativeOperatorProvider>,
    deadline: std::time::Instant,
}
#[cfg(windows)]
impl PrivateTerminal {
    fn open(
        native: &Arc<crate::native_provider::NativeOperatorProvider>,
        deadline: std::time::Instant,
    ) -> Result<Self, AuthorityError> {
        Ok(Self {
            native: native.clone(),
            deadline,
        })
    }
    fn line(
        &mut self,
        label: &str,
        _prompt: &str,
        limit: usize,
    ) -> Result<Zeroizing<String>, AuthorityError> {
        let remaining = self
            .deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis();
        if remaining == 0 {
            return Err(AuthorityError::Tty);
        }
        self.native
            .private_console_line(label, limit, remaining as u64)
            .map_err(|_| AuthorityError::Tty)
    }
}
#[cfg(not(any(unix, windows)))]
struct PrivateTerminal;
#[cfg(not(any(unix, windows)))]
impl PrivateTerminal {
    fn open(
        _native: &Arc<crate::native_provider::NativeOperatorProvider>,
        deadline: std::time::Instant,
    ) -> Result<Self, AuthorityError> {
        Err(AuthorityError::Tty)
    }
    fn line(&mut self, _: &str, _: &str, _: usize) -> Result<Zeroizing<String>, AuthorityError> {
        Err(AuthorityError::Tty)
    }
}

fn verify_attested_profile(
    database: &EncryptedDatabase,
    head: &SelectedRegistryHead,
    target: CertificateHash,
    fields: &ea_format::OperatorBindingFieldsV1,
    previous: Option<ObjectHash>,
    current: UnixMillis,
) -> Result<(), AuthorityError> {
    let row = database.query_row("SELECT registry_head_hash,organization_id,operator_subject_id,role,display_name,function_label,profile_commitment_salt,COALESCE(previous_binding_hash,X''),attested_at FROM operator_authority_identity WHERE target_certificate_hash=?1", &[blob(target.as_bytes())])?.ok_or(AuthorityError::Identity)?;
    let elapsed = current
        .get()
        .checked_sub(row.integer(8)?)
        .ok_or(AuthorityError::Identity)?;
    let salt: &[u8; 32] = row
        .blob(6)?
        .try_into()
        .map_err(|_| AuthorityError::Identity)?;
    if !(0..MAX_INACTIVITY_MS).contains(&elapsed)
        || fields.device_certificate_hash != target
        || row.blob(0)? != head.registry_head_hash().as_bytes()
        || row.blob(1)? != fields.organization_id.as_bytes()
        || row.blob(2)? != fields.operator_subject_id.as_bytes()
        || row.text(3)? != role_label(fields.operator_role)
        || row.blob(7)?
            != previous
                .as_ref()
                .map_or(&[][..], |h| h.as_bytes().as_slice())
        || fields.operator_profile_commitment
            != ea_crypto::operator_profile_commitment(
                fields.organization_id,
                fields.operator_subject_id,
                row.text(4)?,
                row.text(5)?,
                salt,
            )
    {
        return Err(AuthorityError::Identity);
    }
    Ok(())
}

// Private ports make the complete typed ceremony testable. The public runtime
// constructs them only from the fixed installed native Admin and Root slots.
struct AuthorityCore<'a> {
    database: &'a Arc<EncryptedDatabase>,
    store: &'a crate::operator_trust_store::OperatorTrustStateStore,
    source: &'a dyn ea_trust::TrustObjectSource,
    anchor: &'a ea_trust::TrustAnchorV1,
    state_key: ea_trust::TrustStateKey,
    head: &'a SelectedRegistryHead,
    admin_certificate: CertificateHash,
    admin_binding: ObjectHash,
    admin_provider: Arc<dyn KeyProvider>,
    admin_handle: ea_key_provider::KeyHandle,
    root_provider: Arc<dyn KeyProvider>,
    root_handle: ea_key_provider::KeyHandle,
    current: &'a dyn Fn() -> Result<UnixMillis, AuthorityError>,
    reply_signer: &'a dyn crate::operator_exchange::ExchangeSigner,
}

fn authorize_target(
    runtime: &OperatorRuntime,
    certificate: CertificateHash,
    request: &VerifiedExchangeRequest,
    input: AuthorizeArgs,
    proof: &ea_operator::OperatorSessionProof,
) -> Result<Vec<u8>, AuthorityError> {
    let admin = Arc::new(runtime.native().signing_provider(NativeSigningSlot::Admin));
    let root = Arc::new(runtime.native().signing_provider(NativeSigningSlot::Root));
    let current = || {
        runtime.ensure_current()?;
        now()
    };
    let reply_signer = NativeExchangeSigner::administrator(runtime.native());
    let core = AuthorityCore {
        database: runtime.database(),
        store: runtime.trust_store(),
        source: runtime.inventory(),
        anchor: runtime.anchor(),
        state_key: runtime.trust().state_key(),
        head: runtime.head(),
        admin_certificate: runtime.config().device_certificate_hash,
        admin_binding: runtime.config().binding_object_hash,
        admin_handle: admin.handle(SecretPurpose::WriterSigningKey),
        admin_provider: admin,
        root_handle: root.handle(SecretPurpose::WriterSigningKey),
        root_provider: root,
        current: &current,
        reply_signer: &reply_signer,
    };
    core.authorize(certificate, request, input, proof)
}

impl AuthorityCore<'_> {
    fn overlay(
        &self,
        objects: &[Vec<u8>],
    ) -> Result<(ea_trust::VerifiedTrust, SelectedRegistryHead), AuthorityError> {
        use ea_trust::{
            RegistrySelectionOutcome, load_trust_state, prepare_local_time, select_registry_head,
            verify_registry_candidate, verify_trust,
        };
        let mut store = self.store.clone();
        let source = crate::operator_remote::ObjectOverlay::new(self.source, objects);
        let trust = verify_trust(
            self.anchor,
            &source,
            load_trust_state(&mut store, self.state_key)?,
        )?;
        let candidate = verify_registry_candidate(&trust, self.head.proposed_sequence())?;
        let time = prepare_local_time(&mut store, &candidate, (self.current)()?, &[])?;
        let RegistrySelectionOutcome::Selected(head) = select_registry_head(candidate, time, None)?
        else {
            return Err(AuthorityError::Context);
        };
        if head.registry_head_hash() != self.head.registry_head_hash()
            || head.registry_version() != self.head.registry_version()
            || head.chain_id() != self.head.chain_id()
            || head.proposed_sequence() != self.head.proposed_sequence()
            || head.preexisting_effective_now().value()
                < self.head.preexisting_effective_now().value()
        {
            return Err(AuthorityError::Context);
        }
        Ok((trust, head))
    }

    fn authorize(
        &self,
        certificate: CertificateHash,
        request: &VerifiedExchangeRequest,
        input: AuthorizeArgs,
        proof: &ea_operator::OperatorSessionProof,
    ) -> Result<Vec<u8>, AuthorityError> {
        let input_bytes = bytes(&input.target_payload)?;
        let target = supported_target(&input_bytes)?;
        let provisional = target.payload(ObjectHash::from(Hash32::ZERO))?;
        if provisional.exact_digest_input() != input_bytes {
            return Err(AuthorityError::Invalid);
        }
        let mut objects = Vec::new();
        if input.relevant_objects.len() > 32 {
            return Err(AuthorityError::Invalid);
        }
        for value in &input.relevant_objects {
            let bytes = bytes(value)?;
            let ea_format::ParsedArchiveObject::Trust(object) =
                ea_format::decode_exact_object(&bytes).map_err(|_| AuthorityError::Invalid)?
            else {
                return Err(AuthorityError::Invalid);
            };
            if !matches!(
                object
                    .value()
                    .decoded_payload()
                    .map_err(|_| AuthorityError::Invalid)?,
                DecodedTrustPayloadV1::OrganizationAdminAuthorization(_)
                    | DecodedTrustPayloadV1::AuthorizedOperatorBinding(_)
            ) {
                return Err(AuthorityError::Invalid);
            }
            objects.push(bytes);
        }
        let (trust, head) = self.overlay(&objects)?;
        for bytes in &objects {
            ea_trust::verify_catalogue_admission(
                &trust,
                Some(&head),
                bytes,
                head.preexisting_effective_now().value(),
                head.proposed_sequence(),
            )?;
        }
        match &target {
            OperatorTrustTarget::Binding(fields) => {
                let mut hashes = Vec::new();
                self.source
                    .visit_trust_object_hashes(&mut |hash| {
                        hashes.push(hash);
                        Ok(())
                    })
                    .map_err(|_| AuthorityError::Context)?;
                let previous = previous_binding(
                    &head,
                    hashes,
                    fields.operator_subject_id,
                    fields.operator_role,
                    certificate,
                )?;
                verify_attested_profile(
                    self.database,
                    &head,
                    certificate,
                    fields,
                    previous,
                    (self.current)()?,
                )?
            }
            OperatorTrustTarget::Registry(event) => {
                let hash = match event.change {
                    RegistryChangeV1::OperatorBinding { object_hash }
                    | RegistryChangeV1::Target {
                        target_kind: 1,
                        object_hash,
                    } => object_hash,
                    _ => return Err(AuthorityError::Invalid),
                };
                let fields = if let Some(fields) = head.active_operator_binding_fields(hash) {
                    fields.clone()
                } else {
                    let exact = objects
                        .iter()
                        .find(|bytes| object_hash(bytes) == hash)
                        .ok_or(AuthorityError::Context)?;
                    let ea_format::ParsedArchiveObject::Trust(object) =
                        ea_format::decode_exact_object(exact)
                            .map_err(|_| AuthorityError::Invalid)?
                    else {
                        return Err(AuthorityError::Invalid);
                    };
                    let DecodedTrustPayloadV1::AuthorizedOperatorBinding(binding) = object
                        .value()
                        .decoded_payload()
                        .map_err(|_| AuthorityError::Invalid)?
                    else {
                        return Err(AuthorityError::Invalid);
                    };
                    binding.fields().clone()
                };
                if fields.device_certificate_hash != certificate
                    || fields.organization_id != head.root_certificate_fields().organization_id
                {
                    return Err(AuthorityError::Context);
                }
            }
        }
        let description = ea_trust::describe_intended_trust_target(
            &trust,
            Some(&head),
            &provisional,
            head.proposed_sequence(),
        )?;
        let nonce = fixed::<32>(&request.request_id())?;
        let issued = match &target {
            OperatorTrustTarget::Registry(event) => event.issued_at,
            OperatorTrustTarget::Binding(_) => head.preexisting_effective_now().value(),
        };
        let expires = issued
            .get()
            .checked_add(MAX_INACTIVITY_MS)
            .ok_or(AuthorityError::Context)?
            .min(head.not_after().get());
        if (self.current)()?.get() >= expires {
            return Err(AuthorityError::Context);
        }
        let admin = self.admin_certificate;
        let admin_fields = head
            .active_certificate_fields(admin)
            .ok_or(AuthorityError::Context)?;
        let payload = TrustPayloadV1::organization_admin_authorization(
            ea_format::OrganizationAdminAuthorizationFieldsV1 {
                authorization_id: AuthorizationId::try_from(&nonce[..16])
                    .map_err(|_| AuthorityError::Invalid)?,
                organization_id: description.organization_id(),
                registry_version: head.registry_version(),
                registry_head_hash: Hash32::try_from(
                    head.registry_head_hash().as_bytes().as_slice(),
                )
                .map_err(|_| AuthorityError::Invalid)?,
                admin_key_thumbprint: admin_fields
                    .signing_key_thumbprint
                    .ok_or(AuthorityError::Context)?,
                admin_certificate_hash: admin,
                admin_operator_binding_object_hash: self.admin_binding,
                action_code: description.action_code(),
                target_trust_subtype: provisional.subtype(),
                authorized_trust_core_hash: description.authorized_core_hash(),
                issued_at: issued,
                expires_at: UnixMillis::new(expires),
                nonce,
            },
        )
        .map_err(|_| AuthorityError::Invalid)?;
        VerificationContext::organization_admin_trust_digest(payload.exact_digest_input())
            .map_err(|_| AuthorityError::Invalid)?;
        (self.current)()?;
        let retained = self.database.query_row("SELECT authorization,target_payload FROM operator_authority_staged WHERE request_hash=?1", &[blob(&nonce)])?;
        let authorization = if let Some(row) = retained {
            let authorization = row.blob(0)?.to_vec();
            if row.blob(1)?
                != target
                    .payload(object_hash(&authorization))?
                    .exact_digest_input()
            {
                return Err(AuthorityError::Context);
            }
            authorization
        } else {
            let admin_provider = &self.admin_provider;
            let signature = admin_provider.sign(
                &self.admin_handle,
                ContentType::TrustDigest,
                admin,
                trust_digest(payload.exact_digest_input()).as_bytes(),
            )?;
            (self.current)()?;
            let authorization = ea_format::encode_trust(
                &ea_format::TrustObjectV1::new(payload, vec![signature.as_bytes().to_vec()])
                    .map_err(|_| AuthorityError::Invalid)?,
            )
            .map_err(|_| AuthorityError::Invalid)?
            .into_vec();
            self.database.execute("INSERT INTO operator_authority_staged(request_hash,authorization,target_payload) VALUES(?1,?2,?3) ON CONFLICT(request_hash) DO NOTHING", &[blob(&nonce),blob(&authorization),blob(target.payload(object_hash(&authorization))?.exact_digest_input())])?;
            // A concurrent invocation may have staged first; use ONLY its exact bytes.
            self.database
                .query_row(
                    "SELECT authorization FROM operator_authority_staged WHERE request_hash=?1",
                    &[blob(&nonce)],
                )?
                .ok_or(AuthorityError::Uncertain)?
                .blob(0)?
                .to_vec()
        };
        let actual = target.payload(object_hash(&authorization))?;
        let ea_format::ParsedArchiveObject::Trust(parsed) =
            ea_format::decode_exact_object(&authorization).map_err(|_| AuthorityError::Invalid)?
        else {
            return Err(AuthorityError::Invalid);
        };
        let DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) = parsed
            .value()
            .decoded_payload()
            .map_err(|_| AuthorityError::Invalid)?
        else {
            return Err(AuthorityError::Invalid);
        };
        if fields.nonce != nonce
            || fields.authorization_id.as_bytes() != &nonce[..16]
            || (self.current)()? >= fields.expires_at
        {
            return Err(AuthorityError::Context);
        }
        objects.push(authorization.clone());
        let (trust, head) = self.overlay(&objects)?;
        let use_time = match &target {
            OperatorTrustTarget::Registry(event) => event.issued_at,
            _ => head.preexisting_effective_now().value(),
        };
        let intent = ea_trust::verify_intended_trust_target(
            &trust,
            Some(&head),
            &actual,
            use_time,
            head.proposed_sequence(),
        )?;
        let root = &self.root_provider;
        let audit_provider = self.admin_provider.clone();
        let audit = ea_audit::SignedLocalAuditService::new(
            Arc::new(ea_audit::SqliteLocalAuditRepository::new(
                self.database.clone(),
            )),
            audit_provider.clone(),
            self.admin_handle,
            ObjectHash::try_from(admin.as_bytes().as_slice())
                .map_err(|_| AuthorityError::Context)?,
            head.preexisting_effective_now().value(),
        );
        let ceremony = crate::RootCeremonyService::new(
            &head,
            root.as_ref(),
            self.root_handle,
            CertificateHash::from(head.root_certificate_object_hash()),
            &audit,
            self.admin_binding,
        );
        let publication = AuthorityPublication {
            core: self,
            head: &head,
            certificate,
            request,
            authorization: &authorization,
            target_payload: &actual,
            proof,
            audit: &audit,
        };
        ceremony.publish_durably(&intent, actual.clone(), &authorization, proof, &publication)?;
        (self.current)()?;
        self.database.query_row("SELECT reply_bytes FROM operator_authority_request WHERE request_hash=?1 AND state=1",&[blob(&nonce)])?.ok_or(AuthorityError::Uncertain)?.blob(0).map(<[u8]>::to_vec).map_err(Into::into)
    }
}

struct AuthorityPublication<'a, 'b> {
    core: &'a AuthorityCore<'b>,
    head: &'a SelectedRegistryHead,
    certificate: CertificateHash,
    request: &'a VerifiedExchangeRequest,
    authorization: &'a [u8],
    target_payload: &'a TrustPayloadV1,
    proof: &'a ea_operator::OperatorSessionProof,
    audit: &'a ea_audit::SignedLocalAuditService,
}
impl crate::root_ceremony::DurableRootPublication for AuthorityPublication<'_, '_> {
    fn retained_signature(&self) -> Result<Option<Vec<u8>>, AdminError> {
        let row = self.core.database.query_row("SELECT authorization,target_payload,root_signature,root_signature IS NULL FROM operator_authority_staged WHERE request_hash=?1",&[blob(&fixed::<32>(&self.request.request_id()).map_err(admin_publication_error)?)])
            .map_err(|_|AdminError::AuditFailed)?.ok_or(AdminError::AuthorizationMismatch)?;
        if row.blob(0).map_err(|_| AdminError::AuditFailed)? != self.authorization
            || row.blob(1).map_err(|_| AdminError::AuditFailed)?
                != self.target_payload.exact_digest_input()
        {
            return Err(AdminError::AuthorizationMismatch);
        }
        if row.integer(3).map_err(|_| AdminError::AuditFailed)? != 0 {
            Ok(None)
        } else {
            Ok(Some(
                row.blob(2).map_err(|_| AdminError::AuditFailed)?.to_vec(),
            ))
        }
    }
    fn stage_signature(&self, signature: &[u8]) -> Result<(), AdminError> {
        (self.core.current)().map_err(admin_publication_error)?;
        self.core.database.execute("UPDATE operator_authority_staged SET root_signature=?1 WHERE request_hash=?2 AND authorization=?3 AND target_payload=?4 AND root_signature IS NULL", &[
            blob(signature),blob(&fixed::<32>(&self.request.request_id()).map_err(admin_publication_error)?),blob(self.authorization),blob(self.target_payload.exact_digest_input())
        ]).map_err(|_|AdminError::AuditFailed)?;
        if self.retained_signature()?.as_deref() != Some(signature) {
            return Err(AdminError::RootSignatureMismatch);
        }
        Ok(())
    }
    fn commit(
        &self,
        target: &ea_format::ExactObjectBytes,
        replay: &[ea_trust::AdminAuthorizationReplayKey; 2],
        event: ea_audit::TypedLocalAuditEvent,
    ) -> Result<(), AdminError> {
        (self.core.current)().map_err(admin_publication_error)?;
        let audit = self
            .audit
            .prepare_signed(
                ea_audit::AuditActorProof::OperatorSession(self.proof),
                event,
            )
            .map_err(|_| AdminError::AuditFailed)?;
        verify_prepared_audit(&audit, self.head, ea_crypto::SignerRole::OrganizationAdmin)?;
        (self.core.current)().map_err(admin_publication_error)?;
        let reply = self.request.reply(json!({"authorization":hex::encode(self.authorization),"target":hex::encode(target.as_bytes())}),self.core.reply_signer).map_err(|_|AdminError::AuditFailed)?;
        (self.core.current)().map_err(admin_publication_error)?;
        self.commit_rows(target, replay, &audit, &reply)
            .map_err(admin_publication_error)
    }
}
fn admin_publication_error(error: AuthorityError) -> AdminError {
    match error {
        AuthorityError::Admin(error) => error,
        AuthorityError::Runtime(_) => AdminError::ReauthMismatch,
        _ => AdminError::AuditFailed,
    }
}
fn verify_prepared_audit(
    audit: &ea_audit::PreparedLocalAuditEvent,
    head: &SelectedRegistryHead,
    role: ea_crypto::SignerRole,
) -> Result<(), AdminError> {
    let parsed = ea_format::decode_local_audit_event(audit.exact_bytes())
        .map_err(|_| AdminError::AuditFailed)?;
    let context = VerificationContext::local_audit(
        parsed.exact_core(),
        head.proposed_sequence(),
        role,
        head.registry_version(),
    )
    .map_err(|_| AdminError::AuditFailed)?;
    let mut decoder = minicbor::Decoder::new(audit.exact_bytes());
    decoder.array().map_err(|_| AdminError::AuditFailed)?;
    decoder.skip().map_err(|_| AdminError::AuditFailed)?;
    let start = decoder.position();
    decoder.skip().map_err(|_| AdminError::AuditFailed)?;
    ea_crypto::verify_cose_sign1(
        &audit.exact_bytes()[start..decoder.position()],
        head,
        &context,
    )
    .map_err(|_| AdminError::AuditFailed)?;
    Ok(())
}
impl AuthorityPublication<'_, '_> {
    fn commit_rows(
        &self,
        target: &ea_format::ExactObjectBytes,
        replay: &[ea_trust::AdminAuthorizationReplayKey; 2],
        audit: &ea_audit::PreparedLocalAuditEvent,
        reply: &[u8],
    ) -> Result<(), AuthorityError> {
        let request_hash = fixed::<32>(&self.request.request_id())?;
        // BEGIN IMMEDIATE serializes all publication writers. A conflict or
        // failure at ANY later step rolls back both replay dimensions together
        // with the audit, target and encrypted reply. Native signing is complete.
        self.core.database.transaction(|tx| {
        let state = tx.query_row("SELECT chain_id,trust_anchor_hash,pin_hash,floor_ms FROM operator_trust_state WHERE organization_id=?1 AND device_id=?2",&[blob(self.core.state_key.organization_id.as_bytes()),blob(self.core.state_key.device_id.as_bytes())])?.ok_or(AuthorityError::Context)?;
        if state.blob(0)? != self.core.anchor.chain_id().as_bytes()
            || state.blob(1)? != self.core.anchor.trust_anchor_hash().as_bytes()
            || state.blob(2)? != self.head.registry_head_hash().as_bytes()
            || state.integer(3)? > self.head.preexisting_effective_now().value().get()
        {
            return Err(AuthorityError::Context);
        }
        let pending = tx
            .query_row(
                "SELECT state FROM operator_authority_request WHERE request_hash=?1",
                &[blob(&request_hash)],
            )?
            .ok_or(AuthorityError::Uncertain)?;
        if pending.integer(0)? != 0 {
            return Err(AuthorityError::Uncertain);
        }
        for key in replay {
            if key.organization_id() != self.core.anchor.organization_id() {
                return Err(AuthorityError::Context);
            }
            let (dimension, value) = match key.dimension() {
                ea_trust::AdminAuthorizationReplayDimension::AuthorizationId(id) => {
                    (0, blob(id.as_bytes()))
                }
                ea_trust::AdminAuthorizationReplayDimension::Nonce(nonce) => (1, blob(&nonce)),
            };
            let inserted = tx.execute("INSERT INTO operator_admin_replay(organization_id,dimension,replay_value) VALUES(?1,?2,?3) ON CONFLICT(organization_id,dimension,replay_value) DO NOTHING",&[blob(key.organization_id().as_bytes()),StoreValue::Integer(dimension),value])?;
            if inserted != 1 {
                return Err(AdminError::Trust(ea_trust::TrustError::AuthReplay).into());
            }
        }
        ea_audit::SqliteLocalAuditRepository::append_prepared_in(tx, audit)
        .map_err(|_| AuthorityError::Admin(AdminError::AuditFailed))?;
        let decoded = ea_format::decode_local_audit_event(audit.exact_bytes())
            .map_err(|_| AuthorityError::Invalid)?;
        let ea_format::LocalAuditActionV1::AdminRootCeremony(context) = decoded.action() else {
            return Err(AuthorityError::Invalid);
        };
        tx.execute("INSERT INTO operator_authority_target(target_hash,authorization_hash,request_hash,target_certificate_hash,authorization,target,action_code) VALUES(?1,?2,?3,?4,?5,?6,?7)",&[
            blob(object_hash(target.as_bytes()).as_bytes()),blob(object_hash(self.authorization).as_bytes()),blob(&request_hash),blob(self.certificate.as_bytes()),blob(self.authorization),blob(target.as_bytes()),StoreValue::Integer(context.action_code() as i64),
        ])?;
        if matches!(
            self.target_payload
                .decoded_payload()
                .map_err(|_| AuthorityError::Invalid)?,
            DecodedTrustPayloadV1::AuthorizedOperatorBinding(_)
        ) {
            tx.execute(
                "DELETE FROM operator_authority_identity WHERE target_certificate_hash=?1",
                &[blob(self.certificate.as_bytes())],
            )?;
        }
        if tx.execute("UPDATE operator_authority_request SET state=1,reply_bytes=?1 WHERE request_hash=?2 AND state=0",&[blob(reply),blob(&request_hash)])?!=1 {return Err(AuthorityError::Uncertain)}
        Ok(())
        })
    }
}

fn audit_event(
    core: &[u8],
    head: &SelectedRegistryHead,
    admin: CertificateHash,
    binding: ObjectHash,
    current: UnixMillis,
) -> Result<ea_format::LocalAuditEventV1, AuthorityError> {
    let fields = head
        .active_certificate_fields(admin)
        .ok_or(AuthorityError::Context)?;
    let public = CanonicalPublicCoseKey::from_deterministic_cbor(
        fields
            .signing_public_cose_key
            .as_deref()
            .ok_or(AuthorityError::Context)?,
    )
    .map_err(|_| AuthorityError::Context)?;
    // Only a schema carrier for the existing typed core decoder. This zero
    // signature is never verified, persisted or returned as an audit proof.
    let placeholder = CoseSign1Bytes::compose(
        &ProtectedHeader::normal(ContentType::LocalAuditCbor, public.thumbprint(), admin),
        core,
        &[0; 64],
    )?;
    let encoded = ea_format::encode_local_audit_event(core, placeholder.as_bytes())
        .map_err(|_| AuthorityError::Invalid)?;
    let event =
        ea_format::decode_local_audit_event(&encoded).map_err(|_| AuthorityError::Invalid)?;
    if event.organization_id() != fields.organization_id
        || event.device_id() != fields.device_id
        || event.signer_certificate_object_hash().as_bytes() != admin.as_bytes()
        || (event.operator_binding_object_hash() != Some(binding)
            && !(event.operator_binding_object_hash().is_none()
                && matches!(
                    event.action(),
                    ea_format::LocalAuditActionV1::BindingChange(_)
                )))
        || event.effective_now() < head.issued_at()
        || current
            .get()
            .checked_sub(event.effective_now().get())
            .is_none_or(|age| !(0..MAX_INACTIVITY_MS).contains(&age))
    {
        return Err(AuthorityError::Context);
    }
    if !matches!(
        event.action(),
        ea_format::LocalAuditActionV1::Login(_)
            | ea_format::LocalAuditActionV1::ReauthFailure(_)
            | ea_format::LocalAuditActionV1::BindingChange(_)
            | ea_format::LocalAuditActionV1::Revocation(_)
            | ea_format::LocalAuditActionV1::AdminRootCeremony(_)
    ) {
        return Err(AuthorityError::Context);
    }
    Ok(event)
}

fn verify_audit_scope(
    database: &EncryptedDatabase,
    head: &SelectedRegistryHead,
    target: CertificateHash,
    binding: ObjectHash,
    event: &ea_format::LocalAuditEventV1,
) -> Result<(), AuthorityError> {
    use ea_format::{LocalAuditActionV1, LocalAuditOutcomeV1};
    match event.action() {
        LocalAuditActionV1::Login(context) | LocalAuditActionV1::ReauthFailure(context)
            if context.subject_object_hash() == Some(binding) => {}
        LocalAuditActionV1::AdminRootCeremony(context) => {
            let issued = audit_publication(
                database,
                head,
                target,
                binding,
                event,
                context.target_object_hash(),
            )?;
            if issued.authorization_hash != context.authorization_object_hash()
                || u64::from(issued.action_code) != context.action_code()
            {
                return Err(AuthorityError::Context);
            }
        }
        LocalAuditActionV1::BindingChange(context) => {
            let Some(new_hash) = context.new_binding_object_hash() else {
                // A live Admin can audit a failed preparation before any target
                // exists. The device-only host form always needs a durable target.
                if event.outcome() != LocalAuditOutcomeV1::Failed
                    || event.operator_binding_object_hash() != Some(binding)
                    || context.old_binding_object_hash().is_some_and(|old| {
                        head.revoked_operator_binding_fields(old)
                            .is_none_or(|fields| fields.device_certificate_hash != target)
                    })
                {
                    return Err(AuthorityError::Context);
                }
                return Ok(());
            };
            let issued = audit_publication(database, head, target, binding, event, new_hash)?;
            let DecodedTrustPayloadV1::AuthorizedOperatorBinding(new) = issued
                .payload
                .decoded_payload()
                .map_err(|_| AuthorityError::Context)?
            else {
                return Err(AuthorityError::Context);
            };
            let fields = new.fields();
            if fields.device_certificate_hash != target
                || fields.effective_from_sequence != context.effective_from_sequence()
                || context.old_binding_object_hash().is_some_and(|old| {
                    head.revoked_operator_binding_fields(old).is_none_or(|old| {
                        old.device_certificate_hash != target
                            || old.organization_id != fields.organization_id
                            || old.operator_subject_id != fields.operator_subject_id
                            || old.operator_role != fields.operator_role
                    })
                })
            {
                return Err(AuthorityError::Context);
            }
        }
        LocalAuditActionV1::Revocation(context) => {
            let old_hash = context
                .old_binding_object_hash()
                .ok_or(AuthorityError::Context)?;
            if context.new_binding_object_hash().is_some()
                || head
                    .active_operator_binding_fields(old_hash)
                    .or_else(|| head.revoked_operator_binding_fields(old_hash))
                    .is_none_or(|fields| fields.device_certificate_hash != target)
            {
                return Err(AuthorityError::Context);
            }
            // Failed attempts may precede Root publication; successful claims
            // require this authority's exact signed revocation at this sequence.
            if event.outcome() != LocalAuditOutcomeV1::Failed {
                let mut matched = false;
                for offset in 0..1024 {
                    let Some(row) = database.query_row("SELECT target_hash,target FROM operator_authority_target WHERE target_certificate_hash=?1 AND action_code=1 ORDER BY rowid DESC LIMIT 1 OFFSET ?2", &[blob(target.as_bytes()), StoreValue::Integer(offset)])? else { break; };
                    let payload = exact_audit_trust(row.blob(1)?)?;
                    let DecodedTrustPayloadV1::RegistryEvent(registry) = payload
                        .decoded_payload()
                        .map_err(|_| AuthorityError::Context)?
                    else {
                        continue;
                    };
                    if registry.fields().change
                        == (RegistryChangeV1::Target {
                            target_kind: 1,
                            object_hash: old_hash,
                        })
                        && registry.fields().effective_from_sequence
                            == context.effective_from_sequence()
                    {
                        let hash = ObjectHash::try_from(row.blob(0)?)
                            .map_err(|_| AuthorityError::Context)?;
                        audit_publication(database, head, target, binding, event, hash)?;
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    return Err(AuthorityError::Context);
                }
            }
        }
        _ => return Err(AuthorityError::Context),
    }
    Ok(())
}

struct AuditPublication {
    payload: TrustPayloadV1,
    authorization_hash: ObjectHash,
    action_code: u8,
}

fn exact_audit_trust(bytes: &[u8]) -> Result<TrustPayloadV1, AuthorityError> {
    let ea_format::ParsedArchiveObject::Trust(object) =
        ea_format::decode_exact_object(bytes).map_err(|_| AuthorityError::Context)?
    else {
        return Err(AuthorityError::Context);
    };
    TrustPayloadV1::from_exact_digest_input(object.value().exact_digest_input())
        .map_err(|_| AuthorityError::Context)
}

fn audit_publication(
    database: &EncryptedDatabase,
    head: &SelectedRegistryHead,
    target: CertificateHash,
    binding: ObjectHash,
    event: &ea_format::LocalAuditEventV1,
    hash: ObjectHash,
) -> Result<AuditPublication, AuthorityError> {
    let row = database.query_row("SELECT t.authorization_hash,t.authorization,t.target,t.action_code FROM operator_authority_target t JOIN operator_authority_request r ON r.request_hash=t.request_hash WHERE t.target_hash=?1 AND t.target_certificate_hash=?2 AND r.state=1", &[blob(hash.as_bytes()),blob(target.as_bytes())])?.ok_or(AuthorityError::Context)?;
    let authorization = row.blob(1)?;
    let exact_target = row.blob(2)?;
    let authorization_hash = object_hash(authorization);
    if object_hash(exact_target) != hash || authorization_hash.as_bytes() != row.blob(0)? {
        return Err(AuthorityError::Context);
    }
    let payload = exact_audit_trust(exact_target)?;
    let expected_action = match payload
        .decoded_payload()
        .map_err(|_| AuthorityError::Context)?
    {
        DecodedTrustPayloadV1::AuthorizedOperatorBinding(fields)
            if fields.fields().device_certificate_hash == target =>
        {
            4
        }
        DecodedTrustPayloadV1::RegistryEvent(fields) => match fields.fields().change {
            RegistryChangeV1::OperatorBinding { .. } => 4,
            RegistryChangeV1::Target { target_kind: 1, .. } => 1,
            _ => return Err(AuthorityError::Context),
        },
        _ => return Err(AuthorityError::Context),
    };
    let auth_payload = exact_audit_trust(authorization)?;
    let DecodedTrustPayloadV1::OrganizationAdminAuthorization(auth) = auth_payload
        .decoded_payload()
        .map_err(|_| AuthorityError::Context)?
    else {
        return Err(AuthorityError::Context);
    };
    if auth.organization_id != event.organization_id()
        || auth.admin_certificate_hash.as_bytes()
            != event.signer_certificate_object_hash().as_bytes()
        || auth.admin_operator_binding_object_hash != binding
        || auth.registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        || auth.registry_version != head.registry_version()
        || auth.action_code != expected_action
        || row.integer(3)? != i64::from(expected_action)
    {
        return Err(AuthorityError::Context);
    }
    // Reuse the canonical contexts and verifier for BOTH exact signed objects;
    // no audit claim is justified by an unverified cache row or metadata alone.
    VerificationContext::root_trust_digest(
        payload.exact_digest_input(),
        CertificateHash::from(head.root_certificate_object_hash()),
        Some(authorization),
    )
    .map_err(|_| AuthorityError::Context)?;
    let admin_context =
        VerificationContext::organization_admin_trust_digest(auth_payload.exact_digest_input())
            .map_err(|_| AuthorityError::Context)?;
    for (exact, root) in [(exact_target, true), (authorization, false)] {
        let ea_format::ParsedArchiveObject::Trust(object) =
            ea_format::decode_exact_object(exact).map_err(|_| AuthorityError::Context)?
        else {
            return Err(AuthorityError::Context);
        };
        if object.value().signatures().len() != 1 {
            return Err(AuthorityError::Context);
        }
        if root {
            crate::root_ceremony::verify_root_attribution(
                head,
                CertificateHash::from(head.root_certificate_object_hash()),
                &object.value().signatures()[0],
                trust_digest(payload.exact_digest_input()).as_bytes(),
            )
            .map_err(|_| AuthorityError::Context)?;
        } else {
            ea_crypto::verify_cose_sign1(&object.value().signatures()[0], head, &admin_context)
                .map_err(|_| AuthorityError::Context)?;
        }
    }
    Ok(AuditPublication {
        payload,
        authorization_hash,
        action_code: expected_action,
    })
}

fn sign_audit(
    runtime: &OperatorRuntime,
    target: CertificateHash,
    input: AuditArgs,
) -> Result<Value, AuthorityError> {
    let core = bytes(&input.core)?;
    let admin = runtime.config().device_certificate_hash;
    let binding = runtime.config().binding_object_hash;
    let event = audit_event(&core, runtime.head(), admin, binding, now()?)?;
    verify_audit_scope(runtime.database(), runtime.head(), target, binding, &event)?;
    VerificationContext::local_audit(
        &core,
        runtime.head().proposed_sequence(),
        ea_crypto::SignerRole::OrganizationAdmin,
        runtime.head().registry_version(),
    )
    .map_err(|_| AuthorityError::Invalid)?;
    runtime.ensure_current()?;
    let provider = runtime.native().signing_provider(NativeSigningSlot::Admin);
    let signature = provider.sign(
        &provider.handle(SecretPurpose::WriterSigningKey),
        ContentType::LocalAuditCbor,
        admin,
        &core,
    )?;
    runtime.ensure_current()?;
    Ok(json!({"cose":hex::encode(signature.as_bytes())}))
}

#[cfg(test)]
#[path = "../tests/authority/mod.rs"]
mod tests;
