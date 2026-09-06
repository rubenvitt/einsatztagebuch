//! Native provider boundary. Private signing keys remain in the installed helper.

use crate::{InstanceKeyPolicy, NativeOperatorProvisioning, OperatorLifecycleError};
use crate::{native_identity::NativeExecutableIdentity, native_watch::SessionWatch};
use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{
    CoseSign1Bytes, KeyError, KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose,
};
use ea_operator::{
    BoundOperator, OperatorAuthenticator, OperatorError, OsAccountInputs, OsAccountProvider,
};
use ea_types::{CertificateHash, DeviceId, Hash32, OrganizationId};
use serde_json::{Value, json};
use std::{
    fmt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProviderError {
    Unavailable,
    Protocol,
    InstallationChanged,
    Locked,
    Denied,
    Timeout,
}
impl NativeProviderError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "EA-OPERATOR-NATIVE-UNAVAILABLE",
            Self::Protocol => "EA-OPERATOR-NATIVE-PROTOCOL",
            Self::InstallationChanged => "EA-OPERATOR-INSTALLATION-CHANGED",
            Self::Locked => "EA-OPERATOR-NATIVE-LOCKED",
            Self::Denied => "EA-OPERATOR-NATIVE-DENIED",
            Self::Timeout => "EA-OPERATOR-NATIVE-TIMEOUT",
        }
    }
}
impl fmt::Display for NativeProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for NativeProviderError {}

#[cfg(any(windows, test))]
fn console_process_timeout(input_timeout_ms: u64) -> Result<Duration, NativeProviderError> {
    if !(1..=300_000).contains(&input_timeout_ms) {
        return Err(NativeProviderError::Protocol);
    }
    // Separate the cooperative input deadline from the last-resort kill. This
    // includes validator/startup overhead and time to restore the console and
    // close private pipes; it is not additional authenticated session time.
    Ok(Duration::from_millis(input_timeout_ms + 30_000))
}

/// Fixed installed sibling executable; neither configuration nor environment
/// can substitute an identity or signing executable. The installer owns the
/// executable and its platform dependencies together with the CLI.
pub struct NativeOperatorProvider {
    helper: PathBuf,
    installation: [u8; 32],
    identity: NativeExecutableIdentity,
    watch: SessionWatch,
}

impl NativeOperatorProvider {
    /// Initialization is explicit and only used by provisioning. A login never
    /// creates a replacement installation or falls back to an old key namespace.
    pub fn open_installed(initialize: bool) -> Result<Arc<Self>, NativeProviderError> {
        let executable = std::env::current_exe().map_err(|_| NativeProviderError::Unavailable)?;
        let helper = executable
            .parent()
            .ok_or(NativeProviderError::Unavailable)?
            .join(if cfg!(windows) {
                "ea-native-operator.exe"
            } else {
                "ea-native-operator"
            });
        let identity = NativeExecutableIdentity::for_installed(&executable, &helper)?;
        Self::open_with_identity(helper, initialize, identity)
    }

    /// Explicit fixture constructor for a separate test executable. The shipped
    /// CLI always calls open_installed, even when Cargo unifies test features.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_test_fixture(
        helper_path: PathBuf,
        initialize: bool,
    ) -> Result<Arc<Self>, NativeProviderError> {
        Self::open_with_identity(helper_path, initialize, NativeExecutableIdentity::fixture())
    }
    fn open_with_identity(
        helper: PathBuf,
        initialize: bool,
        identity: NativeExecutableIdentity,
    ) -> Result<Arc<Self>, NativeProviderError> {
        let mut response = invoke_checked_helper(
            &helper,
            json!({"op": if initialize {"initialize"} else {"account"}}),
            Duration::from_secs(300),
            |pid| identity.verify_child(&helper, pid),
        )?;
        let installation = checked_response(std::mem::take(&mut response), None)?.1;
        let watch = SessionWatch::start(&helper, &installation, &identity)?;
        let provider = Arc::new(Self {
            helper,
            installation,
            identity,
            watch,
        });
        provider.account()?;
        Ok(provider)
    }

    fn call(&self, request: Value) -> Result<Value, NativeProviderError> {
        self.call_with_timeout(request, Duration::from_secs(300))
    }

    fn call_with_timeout(
        &self,
        mut request: Value,
        timeout: Duration,
    ) -> Result<Value, NativeProviderError> {
        self.watch.ensure_valid()?;
        request["installation_id"] = Value::String(hex::encode(self.installation));
        let mut response = invoke_checked_helper(&self.helper, request, timeout, |pid| {
            self.identity.verify_child(&self.helper, pid)
        })?;
        if let Err(error) = self.watch.ensure_valid() {
            wipe_json(&mut response);
            return Err(error);
        }
        checked_response(response, Some(&self.installation)).map(|r| r.0)
    }

    pub fn installation_id(&self) -> Hash32 {
        Hash32::try_from(self.installation.as_slice()).expect("32 bytes")
    }

    /// Fixed private-console prompts for the separate Windows authority. The
    /// helper opens the real console; stdin remains the private JSON protocol.
    #[cfg(windows)]
    pub fn private_console_line(
        &self,
        label: &str,
        max_bytes: usize,
        timeout_ms: u64,
    ) -> Result<Zeroizing<String>, NativeProviderError> {
        if !matches!(
            label,
            "external-identity-confirmation"
                | "authority-subject-id"
                | "display-name"
                | "function-label"
        ) || max_bytes == 0
            || max_bytes > 4096
            || timeout_ms == 0
            || timeout_ms > 300_000
        {
            return Err(NativeProviderError::Protocol);
        }
        self.account()?;
        // The helper owns the earlier cooperative input timeout and restores
        // console mode before replying. The parent reserves bounded launch and
        // cleanup time before forced termination. This never extends the
        // provider/session lifetime: the watch still rejects every stale reply.
        let parent_timeout = console_process_timeout(timeout_ms)?;
        let mut response=self.call_with_timeout(json!({"op":"private-console-line","prompt":label,"max_bytes":max_bytes,"timeout_ms":timeout_ms}),parent_timeout)?;
        let line = response
            .get("line")
            .and_then(Value::as_str)
            .map(|s| Zeroizing::new(s.to_owned()))
            .ok_or(NativeProviderError::Protocol);
        wipe_json(&mut response);
        let line = line?;
        if line.len() > max_bytes || line.contains(['\r', '\n', '\0']) {
            return Err(NativeProviderError::Protocol);
        }
        self.account()?;
        Ok(line)
    }

    fn account(&self) -> Result<OsAccountInputs, NativeProviderError> {
        let value = self.call(json!({"op":"account"}))?;
        if value.get("locked").and_then(Value::as_bool) != Some(false) {
            return Err(NativeProviderError::Locked);
        }
        let uid = || {
            value
                .get("uid")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(NativeProviderError::Protocol)
        };
        let strings = |name| -> Result<Vec<String>, NativeProviderError> {
            value
                .get(name)
                .and_then(Value::as_array)
                .ok_or(NativeProviderError::Protocol)?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(NativeProviderError::Protocol)
                })
                .collect()
        };
        match value.get("platform").and_then(Value::as_str) {
            Some("macos") if cfg!(target_os = "macos") => Ok(ea_operator::macos::account_inputs(
                strings("guid_values")?,
                strings("unique_id_values")?,
                uid()?,
            )),
            Some("linux") if cfg!(target_os = "linux") => Ok(ea_operator::linux::account_inputs(
                decode_hex(&value, "machine_id_bytes")?,
                uid()?,
            )),
            Some("windows") if cfg!(target_os = "windows") => {
                let sid = decode_hex(&value, "sid")?;
                let authority: [u8; 6] = decode_hex(&value, "identifier_authority")?
                    .try_into()
                    .map_err(|_| NativeProviderError::Protocol)?;
                let subs = value
                    .get("subauthorities")
                    .and_then(Value::as_array)
                    .ok_or(NativeProviderError::Protocol)?
                    .iter()
                    .map(|v| {
                        v.as_u64()
                            .and_then(|v| u32::try_from(v).ok())
                            .ok_or(NativeProviderError::Protocol)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ea_operator::windows::account_inputs(sid, authority, subs))
            }
            _ => Err(NativeProviderError::Protocol),
        }
    }

    pub fn public_key(
        &self,
        slot: NativeSigningSlot,
    ) -> Result<Option<CanonicalPublicCoseKey>, NativeProviderError> {
        self.account()?;
        let value = self.call(json!({"op":"public-key","slot":slot.name()}))?;
        if value.get("public_key") == Some(&Value::Null) {
            return Ok(None);
        }
        let bytes: [u8; 32] = decode_hex(&value, "public_key")?
            .try_into()
            .map_err(|_| NativeProviderError::Protocol)?;
        CanonicalPublicCoseKey::ed25519(bytes)
            .map(Some)
            .map_err(|_| NativeProviderError::Protocol)
    }

    /// Raw signing remains internal to typed adapters, except for the narrowly
    /// domain-separated external identity protocol in the operator host.
    pub(crate) fn sign_raw(
        &self,
        slot: NativeSigningSlot,
        bytes: &[u8],
        presence: bool,
    ) -> Result<[u8; 64], NativeProviderError> {
        self.account()?;
        let public = self.public_key(slot)?.ok_or(NativeProviderError::Denied)?;
        let value = self.call(
            json!({"op":"sign","slot":slot.name(),"data":hex::encode(bytes),"presence":presence}),
        )?;
        let signature = decode_hex(&value, "signature")?
            .try_into()
            .map_err(|_| NativeProviderError::Protocol)?;
        public
            .verify_ed25519_strict(bytes, &signature)
            .map_err(|_| NativeProviderError::Denied)?;
        self.account()?;
        if self
            .public_key(slot)?
            .as_ref()
            .map(CanonicalPublicCoseKey::thumbprint)
            != Some(public.thumbprint())
        {
            return Err(NativeProviderError::InstallationChanged);
        }
        Ok(signature)
    }

    pub fn signing_provider(self: &Arc<Self>, slot: NativeSigningSlot) -> NativeKeyProvider {
        NativeKeyProvider {
            native: Arc::clone(self),
            signing_slot: slot,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum NativeSigningSlot {
    Operator,
    Writer,
    Admin,
    Root,
}
impl NativeSigningSlot {
    const fn name(self) -> &'static str {
        match self {
            Self::Operator => "operator-instance",
            Self::Writer => "writer-signing",
            Self::Admin => "admin-signing",
            Self::Root => "root-signing",
        }
    }
}

impl OsAccountProvider for NativeOperatorProvider {
    fn os_account_binding_hash(
        &self,
        org: OrganizationId,
        device: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        self.account()
            .map_err(operator_error)?
            .binding_hash(org, device)
    }
    fn operator_instance_public_key(
        &self,
    ) -> Result<Option<CanonicalPublicCoseKey>, OperatorError> {
        self.public_key(NativeSigningSlot::Operator)
            .map_err(operator_error)
    }
}
impl NativeOperatorProvisioning for NativeOperatorProvider {
    fn create_fresh_instance(
        &self,
        _: InstanceKeyPolicy,
    ) -> Result<CanonicalPublicCoseKey, OperatorLifecycleError> {
        self.account().map_err(lifecycle_error)?;
        self.call(json!({"op":"generate","slot":"operator-instance","kind":"ed25519","replace":true,"presence":true})).map_err(lifecycle_error)?;
        self.public_key(NativeSigningSlot::Operator)
            .map_err(lifecycle_error)?
            .ok_or(OperatorLifecycleError::FreshInstanceRequired)
    }
    fn prove_presence_and_sign(
        &self,
        challenge: &[u8],
    ) -> Result<[u8; 64], OperatorLifecycleError> {
        self.sign_raw(NativeSigningSlot::Operator, challenge, true)
            .map_err(lifecycle_error)
    }
}

impl crate::OperatorPresence for NativeOperatorProvider {
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        self.sign_raw(NativeSigningSlot::Operator, challenge, true)
            .map_err(operator_error)
    }
}

pub struct NativeAuthenticator {
    native: Arc<NativeOperatorProvider>,
    bound: BoundOperator,
}
impl NativeAuthenticator {
    pub fn new(native: Arc<NativeOperatorProvider>, bound: BoundOperator) -> Self {
        Self { native, bound }
    }
}
impl OperatorAuthenticator for NativeAuthenticator {
    fn bound_operator(&self) -> &BoundOperator {
        &self.bound
    }
    fn prove_presence_and_sign(&self, challenge: &[u8]) -> Result<[u8; 64], OperatorError> {
        self.native
            .sign_raw(NativeSigningSlot::Operator, challenge, true)
            .map_err(operator_error)
    }
}

/// Local secrets use the native installation namespace. Root and Admin signing
/// are explicit offline-host selections, never a fallback of a Writer provider.
pub struct NativeKeyProvider {
    native: Arc<NativeOperatorProvider>,
    signing_slot: NativeSigningSlot,
}
impl NativeKeyProvider {
    pub fn handle(&self, purpose: SecretPurpose) -> KeyHandle {
        KeyHandle::new(
            KeystoreProvider::OperatingSystem,
            self.native.installation_id(),
            purpose,
        )
    }
    fn slot(&self, handle: &KeyHandle) -> Result<&'static str, KeyError> {
        if handle.keystore_provider() != KeystoreProvider::OperatingSystem
            || handle.account_instance() != self.native.installation_id()
        {
            return Err(KeyError::NotFound);
        }
        Ok(match handle.purpose() {
            SecretPurpose::WriterSigningKey => self.signing_slot.name(),
            SecretPurpose::OperatorInstanceKey => "operator-instance",
            SecretPurpose::LocalDatabaseKey => "database-key",
            SecretPurpose::DraftDek => "draft-key",
        })
    }
}
impl KeyProvider for NativeKeyProvider {
    fn generate(
        &self,
        purpose: SecretPurpose,
        protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, KeyError> {
        if protection != KeyProtectionProfileV1::OsWrapped {
            return Err(KeyError::UnreachableProtectionProfile);
        }
        let handle = self.handle(purpose);
        let slot = self.slot(&handle)?;
        self.native.call(json!({"op":"generate","slot":slot,"kind":if matches!(purpose,SecretPurpose::DraftDek|SecretPurpose::LocalDatabaseKey){"secret32"}else{"ed25519"},"replace":false,"presence":true})).map_err(key_error)?;
        Ok(handle)
    }
    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ContentType,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        handle.require_purpose(&[
            SecretPurpose::WriterSigningKey,
            SecretPurpose::OperatorInstanceKey,
        ])?;
        self.slot(handle)?;
        let slot = if handle.purpose() == SecretPurpose::OperatorInstanceKey {
            NativeSigningSlot::Operator
        } else {
            self.signing_slot
        };
        let public = self
            .native
            .public_key(slot)
            .map_err(key_error)?
            .ok_or(KeyError::NotFound)?;
        let protected =
            ProtectedHeader::normal(content_type, public.thumbprint(), certificate_hash);
        let bytes = protected.sig_structure_bytes(payload);
        let signature = self
            .native
            .sign_raw(slot, &bytes, slot != NativeSigningSlot::Writer)
            .map_err(key_error)?;
        // The exact key named by the header must verify the returned signature,
        // including a slot replacement between our lookup and sign_raw's lookup.
        checked_cose_signature(&public, &protected, payload, &signature)
    }
    fn wrap_secret(
        &self,
        purpose: SecretPurpose,
        secret: SecretBytes<32>,
    ) -> Result<KeyHandle, KeyError> {
        if !matches!(
            purpose,
            SecretPurpose::DraftDek | SecretPurpose::LocalDatabaseKey
        ) {
            return Err(KeyError::ForbiddenPurpose);
        }
        let handle = self.handle(purpose);
        let request=secret.with_exposed(|bytes|json!({"op":"wrap-secret","slot":self.slot(&handle).unwrap_or(""),"data":hex::encode(bytes)}));
        self.native.call(request).map_err(key_error)?;
        Ok(handle)
    }
    fn unwrap_secret(&self, handle: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        handle.require_purpose(&[SecretPurpose::DraftDek, SecretPurpose::LocalDatabaseKey])?;
        let mut value = self
            .native
            .call(json!({"op":"unwrap-secret","slot":self.slot(handle)?}))
            .map_err(key_error)?;
        let decoded = decode_hex(&value, "secret");
        wipe_json(&mut value);
        let mut bytes = Zeroizing::new(decoded.map_err(key_error)?);
        if bytes.len() != 32 {
            return Err(KeyError::NotFound);
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(SecretBytes::new(secret))
    }
    fn unwrap_database_key(&self, handle: &KeyHandle) -> Result<SecretVec, KeyError> {
        handle.require_purpose(&[SecretPurpose::LocalDatabaseKey])?;
        self.unwrap_secret(handle)
            .map(|secret| secret.with_exposed(|b| SecretVec::new(b.to_vec())))
    }
    fn delete(&self, handle: &KeyHandle) -> Result<(), KeyError> {
        self.native
            .call(json!({"op":"delete","slot":self.slot(handle)?}))
            .map_err(key_error)?;
        Ok(())
    }
    fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError> {
        self.native
            .call(json!({"op":"contains","slot":self.slot(handle)?}))
            .map_err(key_error)?
            .get("contains")
            .and_then(Value::as_bool)
            .ok_or(KeyError::NotFound)
    }
    fn reached_protection_profile(
        &self,
        handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        if self.contains(handle)? {
            Ok(KeyProtectionProfileV1::OsWrapped)
        } else {
            Err(KeyError::NotFound)
        }
    }
}

fn operator_error(error: NativeProviderError) -> OperatorError {
    match error {
        NativeProviderError::InstallationChanged => OperatorError::InstanceKeyMismatch,
        _ => OperatorError::PresenceProofInvalid,
    }
}
fn lifecycle_error(error: NativeProviderError) -> OperatorLifecycleError {
    OperatorLifecycleError::Operator(operator_error(error))
}
fn key_error(_: NativeProviderError) -> KeyError {
    KeyError::NotFound
}
fn checked_cose_signature(
    public: &CanonicalPublicCoseKey,
    protected: &ProtectedHeader,
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<CoseSign1Bytes, KeyError> {
    public
        .verify_ed25519_strict(&protected.sig_structure_bytes(payload), signature)
        .map_err(KeyError::Crypto)?;
    CoseSign1Bytes::compose(protected, payload, signature)
}
fn decode_hex(value: &Value, field: &str) -> Result<Vec<u8>, NativeProviderError> {
    hex::decode(
        value
            .get(field)
            .and_then(Value::as_str)
            .ok_or(NativeProviderError::Protocol)?,
    )
    .map_err(|_| NativeProviderError::Protocol)
}
fn checked_response(
    mut value: Value,
    expected: Option<&[u8; 32]>,
) -> Result<(Value, [u8; 32]), NativeProviderError> {
    let checked = (|| {
        match value.get("ok").and_then(Value::as_bool) {
            Some(true) => {}
            Some(false) => return Err(NativeProviderError::Denied),
            None => return Err(NativeProviderError::Protocol),
        }
        let installation = decode_hex(&value, "installation_id")?
            .try_into()
            .map_err(|_| NativeProviderError::Protocol)?;
        if expected.is_some_and(|id| id != &installation) {
            return Err(NativeProviderError::InstallationChanged);
        }
        Ok(installation)
    })();
    match checked {
        Ok(installation) => Ok((value, installation)),
        Err(error) => {
            wipe_json(&mut value);
            Err(error)
        }
    }
}
fn wipe_json(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_json),
        Value::Object(fields) => fields.values_mut().for_each(wipe_json),
        _ => {}
    }
}
pub(crate) fn helper_command(
    path: &std::path::Path,
    environment: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Command {
    let mut command = Command::new(path);
    command.env_clear();
    for (name, value) in environment {
        // Session routing is needed by the real desktop APIs. Runtime/library
        // injection switches and a substitute system bus are never inherited.
        if name.to_str().is_some_and(|name| {
            matches!(
                name.to_ascii_uppercase().as_str(),
                "HOME"
                    | "USERPROFILE"
                    | "LOCALAPPDATA"
                    | "APPDATA"
                    | "SYSTEMROOT"
                    | "WINDIR"
                    | "TEMP"
                    | "TMP"
                    | "DBUS_SESSION_BUS_ADDRESS"
                    | "XDG_RUNTIME_DIR"
                    | "DISPLAY"
                    | "WAYLAND_DISPLAY"
                    | "XAUTHORITY"
                    | "LANG"
                    | "LC_ALL"
            )
        }) {
            command.env(name, value);
        }
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}
#[cfg(test)]
fn invoke_helper_with_timeout(
    path: &std::path::Path,
    request: Value,
    timeout: Duration,
) -> Result<Value, NativeProviderError> {
    invoke_checked_helper(path, request, timeout, |_| Ok(()))
}
fn invoke_checked_helper(
    path: &std::path::Path,
    mut request: Value,
    timeout: Duration,
    check: impl FnOnce(u32) -> Result<(), NativeProviderError>,
) -> Result<Value, NativeProviderError> {
    let encoded = serde_json::to_vec(&request)
        .map(Zeroizing::new)
        .map_err(|_| NativeProviderError::Protocol);
    wipe_json(&mut request);
    let encoded = encoded?;
    let output = crate::native_process::run(
        helper_command(path, std::env::vars_os()),
        encoded,
        timeout,
        check,
    )?;
    if !output.success {
        return Err(NativeProviderError::Denied);
    }
    serde_json::from_slice(&output.stdout).map_err(|_| NativeProviderError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_console_deadline_reserves_cleanup_without_extending_input() {
        for input in [1, 800, 300_000] {
            let bound = console_process_timeout(input).unwrap();
            assert!(bound > Duration::from_millis(input));
            assert_eq!(
                bound - Duration::from_millis(input),
                Duration::from_secs(30)
            );
            assert!(bound <= Duration::from_secs(330));
        }
        assert!(console_process_timeout(0).is_err());
        assert!(console_process_timeout(300_001).is_err());
    }

    #[test]
    fn a_response_from_a_recreated_installation_is_rejected() {
        let value = serde_json::json!({"ok": true, "installation_id": hex::encode([2;32])});
        assert!(matches!(
            checked_response(value, Some(&[1; 32])),
            Err(NativeProviderError::InstallationChanged)
        ));
    }

    #[test]
    fn absent_or_malformed_native_evidence_never_defaults_to_success() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"ok":true}),
            serde_json::json!({"ok":true,"installation_id":"00"}),
            serde_json::json!({"ok":"true"}),
        ] {
            assert!(checked_response(value, None).is_err());
        }
    }

    #[test]
    fn helper_error_text_is_never_exposed() {
        let error = checked_response(
            serde_json::json!({"ok": false, "code": "secret account details"}),
            None,
        )
        .err()
        .unwrap();
        assert_eq!(error.code(), "EA-OPERATOR-NATIVE-DENIED");
    }

    #[test]
    fn a_slot_replaced_during_signing_cannot_return_a_cose_success_under_the_old_header() {
        use ed25519_dalek::{Signer, SigningKey};
        let old = SigningKey::from_bytes(&[10; 32]);
        let replacement = SigningKey::from_bytes(&[11; 32]);
        let public = CanonicalPublicCoseKey::ed25519(old.verifying_key().to_bytes()).unwrap();
        let cert = CertificateHash::try_from(&[9; 32][..]).unwrap();
        let header = ProtectedHeader::normal(ContentType::TrustDigest, public.thumbprint(), cert);
        let payload = &[5; 32];
        let input = header.sig_structure_bytes(payload);
        assert!(
            checked_cose_signature(&public, &header, payload, &old.sign(&input).to_bytes()).is_ok()
        );
        assert!(
            checked_cose_signature(
                &public,
                &header,
                payload,
                &replacement.sign(&input).to_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn helper_launch_does_not_inherit_runtime_code_loading_overrides() {
        let values = [
            ("DOTNET_STARTUP_HOOKS", "foreign.dll"),
            ("CORECLR_ENABLE_PROFILING", "1"),
            ("DOTNET_ROOT", "foreign-runtime"),
            ("LD_PRELOAD", "foreign.so"),
            ("DYLD_INSERT_LIBRARIES", "foreign.dylib"),
            ("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=foreign"),
            ("HOME", "test-home"),
        ];
        let command = helper_command(
            std::path::Path::new("fixed-helper"),
            values
                .into_iter()
                .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v))),
        );
        let passed = command
            .get_envs()
            .filter_map(|(k, v)| {
                v.map(|v| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(passed, vec![("HOME".to_owned(), "test-home".to_owned())]);
    }

    #[cfg(unix)]
    #[test]
    fn stalled_native_process_has_a_parent_owned_deadline() {
        use std::{
            os::unix::fs::PermissionsExt,
            time::{Duration, Instant},
        };
        let directory =
            std::env::temp_dir().join(format!("ea-native-stall-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("helper");
        std::fs::write(&path, b"#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let started = Instant::now();
        let result =
            invoke_helper_with_timeout(&path, json!({"op":"account"}), Duration::from_millis(100));
        assert!(matches!(result, Err(NativeProviderError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(2));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
