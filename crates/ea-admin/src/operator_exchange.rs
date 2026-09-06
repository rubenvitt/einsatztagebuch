//! Authenticated offline ceremony exchange. These are local transport envelopes,
//! never archive objects or new Suite v1 trust types.

use ea_crypto::{
    CanonicalPublicCoseKey, HpkeRecipientPrivateKey, HpkeRecipientPublicKey, HpkeSealed,
    SecretBytes, SecretVec, aead_open, aead_seal, hpke_open, hpke_seal, object_hash,
};
use ea_local_store::{EncryptedDatabase, StoreError, StoreValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const REQUEST_DOMAIN: &[u8] = b"EINSATZARCHIV-OPERATOR-EXCHANGE-REQUEST-v1\0";
const REPLY_DOMAIN: &[u8] = b"EINSATZARCHIV-OPERATOR-EXCHANGE-REPLY-v1\0";
const WRAP_DOMAIN: &[u8] = b"EINSATZARCHIV-OPERATOR-EXCHANGE-KEY-v1\0";
pub const MAX_EXCHANGE_BYTES: usize = 262_144;
// Native IPC hex-encodes the domain+body in a 64 KiB JSON request. Reserve
// framing space there, and for HPKE/ciphertext expansion in encrypted replies.
const MAX_BODY_BYTES: usize = 30_000;
const MAX_REPLY_CLEAR_BYTES: usize = 14_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeError {
    Invalid,
    Signature,
    Encryption,
    TooLarge,
    Io,
    Timeout,
    State,
}
impl ExchangeError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "EA-OPERATOR-EXCHANGE-INVALID",
            Self::Signature => "EA-OPERATOR-EXCHANGE-SIGNATURE",
            Self::Encryption => "EA-OPERATOR-EXCHANGE-ENCRYPTION",
            Self::TooLarge => "EA-OPERATOR-EXCHANGE-SIZE",
            Self::Io => "EA-OPERATOR-EXCHANGE-IO",
            Self::Timeout => "EA-OPERATOR-EXCHANGE-TIMEOUT",
            Self::State => "EA-OPERATOR-EXCHANGE-STATE",
        }
    }
}
impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ExchangeError {}
impl From<StoreError> for ExchangeError {
    fn from(_: StoreError) -> Self {
        Self::State
    }
}

pub trait ExchangeSigner {
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], ExchangeError>;
}

pub struct NativeExchangeSigner<'a> {
    native: &'a crate::native_provider::NativeOperatorProvider,
    slot: crate::native_provider::NativeSigningSlot,
}
impl<'a> NativeExchangeSigner<'a> {
    pub fn device(native: &'a crate::native_provider::NativeOperatorProvider) -> Self {
        Self {
            native,
            slot: crate::native_provider::NativeSigningSlot::Writer,
        }
    }
    pub fn administrator(native: &'a crate::native_provider::NativeOperatorProvider) -> Self {
        Self {
            native,
            slot: crate::native_provider::NativeSigningSlot::Admin,
        }
    }
}
impl ExchangeSigner for NativeExchangeSigner<'_> {
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], ExchangeError> {
        if !bytes.starts_with(REQUEST_DOMAIN) && !bytes.starts_with(REPLY_DOMAIN) {
            return Err(ExchangeError::Invalid);
        }
        self.native
            .sign_raw(
                self.slot,
                bytes,
                self.slot == crate::native_provider::NativeSigningSlot::Admin,
            )
            .map_err(|_| ExchangeError::Signature)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEnvelope {
    body: String,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestBody {
    version: u8,
    nonce: String,
    reply_public_key: String,
    payload: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyBody {
    version: u8,
    request_hash: String,
    encapsulated_key: String,
    wrapped_key: String,
    nonce: String,
    ciphertext: String,
}

pub struct PendingExchange {
    request: Vec<u8>,
    request_hash: [u8; 32],
    private: HpkeRecipientPrivateKey,
    journal_key: Option<[u8; 32]>,
}
impl PendingExchange {
    pub fn new(payload: Value, signer: &dyn ExchangeSigner) -> Result<Self, ExchangeError> {
        Self::with_seed(payload, signer, &Zeroizing::new(random()?))
    }
    fn with_seed(
        payload: Value,
        signer: &dyn ExchangeSigner,
        seed: &[u8; 32],
    ) -> Result<Self, ExchangeError> {
        let private = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(*seed))
            .map_err(|_| ExchangeError::Encryption)?;
        let body = serialize(&RequestBody {
            version: 1,
            nonce: hex::encode(random::<32>()?),
            reply_public_key: hex::encode(private.public_key().as_bytes()),
            payload,
        })?;
        let request = sign_envelope(&body, REQUEST_DOMAIN, signer)?;
        let request_hash = *object_hash(&request).as_bytes();
        Ok(Self {
            request,
            request_hash,
            private,
            journal_key: None,
        })
    }
    /// Persist the ephemeral transport secret BEFORE exposing the request. It is
    /// not an archive/Reader key and exists only in this native-key-bound
    /// SQLCipher database. Reopening the store recovers the exact signed request,
    /// not a newly minted authorization with a new replay identity.
    pub fn load_or_create(
        database: &EncryptedDatabase,
        payload: Value,
        signer: &dyn ExchangeSigner,
        device: &CanonicalPublicCoseKey,
    ) -> Result<Self, ExchangeError> {
        let key = *object_hash(&serialize(&payload)?).as_bytes();
        let query = "SELECT request_bytes,reply_private_key FROM operator_pending_exchange WHERE operation_hash=?1";
        let params = [StoreValue::Blob(key.to_vec())];
        if let Some(row) = database.query_row(query, &params)? {
            return Self::resume(row.blob(0)?, row.blob(1)?, key, &payload, device);
        }
        // Native signing may display a presence dialog, so it cannot happen
        // while a SQLCipher write transaction is held.
        let seed = Zeroizing::new(random::<32>()?);
        let pending = Self::with_seed(payload.clone(), signer, &seed)?;
        let verified = VerifiedExchangeRequest::verify(pending.request_bytes(), device)?;
        if verified.payload() != &payload {
            return Err(ExchangeError::Invalid);
        }
        let mut fields = [
            StoreValue::Blob(key.to_vec()),
            StoreValue::Blob(pending.request.clone()),
            StoreValue::Blob(seed.to_vec()),
        ];
        let written=database.execute("INSERT INTO operator_pending_exchange(operation_hash,request_bytes,reply_private_key) VALUES(?1,?2,?3) ON CONFLICT(operation_hash) DO NOTHING",&fields);
        if let StoreValue::Blob(bytes) = &mut fields[2] {
            use zeroize::Zeroize;
            bytes.zeroize();
        }
        written?;
        let row = database
            .query_row(query, &params)?
            .ok_or(ExchangeError::State)?;
        Self::resume(row.blob(0)?, row.blob(1)?, key, &payload, device)
    }
    fn resume(
        request: &[u8],
        seed: &[u8],
        key: [u8; 32],
        payload: &Value,
        device: &CanonicalPublicCoseKey,
    ) -> Result<Self, ExchangeError> {
        let verified = VerifiedExchangeRequest::verify(request, device)?;
        let private = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(
            seed.try_into().map_err(|_| ExchangeError::State)?,
        ))
        .map_err(|_| ExchangeError::Encryption)?;
        if verified.payload() != payload
            || verified.recipient.as_bytes() != private.public_key().as_bytes()
        {
            return Err(ExchangeError::State);
        }
        Ok(Self {
            request: request.to_vec(),
            request_hash: *object_hash(request).as_bytes(),
            private,
            journal_key: Some(key),
        })
    }
    /// Use only after a disposable response was authenticated and consumed.
    /// Typed authorization replies stay journalled through lifecycle completion.
    pub fn forget(&self, database: &EncryptedDatabase) -> Result<(), ExchangeError> {
        if let Some(key) = self.journal_key {
            database.execute("DELETE FROM operator_pending_exchange WHERE operation_hash=?1 AND request_bytes=?2",&[StoreValue::Blob(key.to_vec()),StoreValue::Blob(self.request.clone())])?;
        }
        Ok(())
    }
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }
    pub fn request_id(&self) -> String {
        hex::encode(self.request_hash)
    }
    pub fn open_reply(
        &self,
        bytes: &[u8],
        authority: &CanonicalPublicCoseKey,
    ) -> Result<Value, ExchangeError> {
        let body = verify_envelope(bytes, REPLY_DOMAIN, authority)?;
        let reply: ReplyBody = parse(&body)?;
        if reply.version != 1 || decode::<32>(&reply.request_hash)? != self.request_hash {
            return Err(ExchangeError::Invalid);
        }
        let sealed = HpkeSealed::from_parts(
            decode(&reply.encapsulated_key)?,
            decode(&reply.wrapped_key)?,
        )
        .map_err(|_| ExchangeError::Encryption)?;
        let key = hpke_open(&self.private, &sealed, WRAP_DOMAIN, &self.request_hash)
            .map_err(|_| ExchangeError::Encryption)?;
        let ciphertext = hex::decode(&reply.ciphertext).map_err(|_| ExchangeError::Invalid)?;
        let clear = aead_open(
            &key,
            &SecretBytes::new(decode(&reply.nonce)?),
            &ciphertext,
            &self.request_hash,
        )
        .map_err(|_| ExchangeError::Encryption)?;
        clear.with_exposed(parse)
    }
}

/// Constructible only after verifying the exact signed request bytes with the
/// active device key selected from the independently pinned Registry.
pub struct VerifiedExchangeRequest {
    request_hash: [u8; 32],
    recipient: HpkeRecipientPublicKey,
    payload: Value,
}
impl VerifiedExchangeRequest {
    pub fn verify(bytes: &[u8], device: &CanonicalPublicCoseKey) -> Result<Self, ExchangeError> {
        let body = verify_envelope(bytes, REQUEST_DOMAIN, device)?;
        let request: RequestBody = parse(&body)?;
        if request.version != 1 {
            return Err(ExchangeError::Invalid);
        }
        decode::<32>(&request.nonce)?;
        let recipient = HpkeRecipientPublicKey::from_bytes(decode(&request.reply_public_key)?)
            .map_err(|_| ExchangeError::Encryption)?;
        Ok(Self {
            request_hash: *object_hash(bytes).as_bytes(),
            recipient,
            payload: request.payload,
        })
    }
    pub fn payload(&self) -> &Value {
        &self.payload
    }
    pub fn request_id(&self) -> String {
        hex::encode(self.request_hash)
    }
    pub fn reply(
        &self,
        mut payload: Value,
        signer: &dyn ExchangeSigner,
    ) -> Result<Vec<u8>, ExchangeError> {
        let bytes = serialize(&payload).map(Zeroizing::new);
        wipe_value(&mut payload);
        let bytes = bytes?;
        if bytes.len() > MAX_REPLY_CLEAR_BYTES {
            return Err(ExchangeError::TooLarge);
        }
        let key = SecretBytes::new(random()?);
        let nonce = random::<12>()?;
        let sealed = hpke_seal(&self.recipient, &key, WRAP_DOMAIN, &self.request_hash)
            .map_err(|_| ExchangeError::Encryption)?;
        let ciphertext = aead_seal(
            &key,
            &SecretBytes::new(nonce),
            SecretVec::new(bytes.to_vec()),
            &self.request_hash,
        )
        .map_err(|_| ExchangeError::Encryption)?;
        let body = serialize(&ReplyBody {
            version: 1,
            request_hash: hex::encode(self.request_hash),
            encapsulated_key: hex::encode(sealed.encapsulated_key()),
            wrapped_key: hex::encode(sealed.wrapped_cek()),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        })?;
        sign_envelope(&body, REPLY_DOMAIN, signer)
    }
}

/// USB/removable-media exchange. Only public signed requests and encrypted
/// replies are written. Each request is create-if-absent and named by its hash.
/// A journalled request survives restart with its exact ephemeral reply key.
pub fn exchange_in_directory(
    pending: &PendingExchange,
    directory: &Path,
    timeout: Duration,
) -> Result<Vec<u8>, ExchangeError> {
    require_directory(directory)?;
    let id = pending.request_id();
    write_exchange_file(
        &directory.join(format!("request-{id}.json")),
        pending.request_bytes(),
    )?;
    let response = directory.join(format!("reply-{id}.json"));
    let start = Instant::now();
    loop {
        match fs::symlink_metadata(&response) {
            Ok(_) => return read_exchange_file(&response),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ExchangeError::Io),
        }
        if start.elapsed() >= timeout {
            return Err(ExchangeError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
pub fn read_exchange_file(path: &Path) -> Result<Vec<u8>, ExchangeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ExchangeError::Io)?;
    if !metadata.is_file() || metadata.is_symlink() || metadata.len() > MAX_EXCHANGE_BYTES as u64 {
        return Err(ExchangeError::Invalid);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| ExchangeError::Io)?
        .take((MAX_EXCHANGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ExchangeError::Io)?;
    if bytes.len() > MAX_EXCHANGE_BYTES {
        return Err(ExchangeError::TooLarge);
    }
    Ok(bytes)
}
pub fn write_exchange_file(path: &Path, bytes: &[u8]) -> Result<(), ExchangeError> {
    if bytes.len() > MAX_EXCHANGE_BYTES {
        return Err(ExchangeError::TooLarge);
    }
    let directory = path.parent().ok_or(ExchangeError::Io)?;
    require_directory(directory)?;
    let lock_path = directory.join(".ea-exchange-write.lock");
    if fs::symlink_metadata(&lock_path).is_ok_and(|m| !m.is_file() || m.is_symlink()) {
        return Err(ExchangeError::Io);
    }
    let mut lock_options = OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    // The OS releases this lock even when the process is killed. A leftover
    // lock file does not strand recovery, unlike a create-directory lock.
    let lock = lock_options
        .open(&lock_path)
        .map_err(|_| ExchangeError::Io)?;
    lock.try_lock().map_err(|_| ExchangeError::Io)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return if read_exchange_file(path)? == bytes {
                Ok(())
            } else {
                Err(ExchangeError::Invalid)
            };
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ExchangeError::Io),
    }
    let temporary = directory.join(format!(
        ".ea-exchange-{}.partial",
        hex::encode(random::<32>()?)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary).map_err(|_| ExchangeError::Io)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ExchangeError::Io)?;
        drop(file);
        // Same-volume rename publishes only complete bytes. Every protocol
        // writer holds the exclusive OS lock above; existing bytes are never
        // replaced. This also works on removable volumes without hard links.
        fs::rename(&temporary, path).map_err(|_| ExchangeError::Io)?;
        #[cfg(unix)]
        fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| ExchangeError::Io)?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}
fn require_directory(path: &Path) -> Result<(), ExchangeError> {
    let meta = fs::symlink_metadata(path).map_err(|_| ExchangeError::Io)?;
    if meta.is_dir() && !meta.is_symlink() {
        Ok(())
    } else {
        Err(ExchangeError::Io)
    }
}
fn random<const N: usize>() -> Result<[u8; N], ExchangeError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| ExchangeError::Encryption)?;
    Ok(bytes)
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N], ExchangeError> {
    hex::decode(value)
        .map_err(|_| ExchangeError::Invalid)?
        .try_into()
        .map_err(|_| ExchangeError::Invalid)
}
fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, ExchangeError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ExchangeError::Invalid)?;
    if bytes.len() > MAX_BODY_BYTES {
        Err(ExchangeError::TooLarge)
    } else {
        Ok(bytes)
    }
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ExchangeError> {
    if bytes.len() > MAX_EXCHANGE_BYTES {
        return Err(ExchangeError::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| ExchangeError::Invalid)
}
fn signed_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(body);
    bytes
}
fn sign_envelope(
    body: &[u8],
    domain: &[u8],
    signer: &dyn ExchangeSigner,
) -> Result<Vec<u8>, ExchangeError> {
    let signature = signer.sign(&signed_input(domain, body))?;
    let result = serde_json::to_vec(&SignedEnvelope {
        body: hex::encode(body),
        signature: hex::encode(signature),
    })
    .map_err(|_| ExchangeError::Invalid)?;
    if result.len() > MAX_EXCHANGE_BYTES {
        Err(ExchangeError::TooLarge)
    } else {
        Ok(result)
    }
}
fn verify_envelope(
    bytes: &[u8],
    domain: &[u8],
    public: &CanonicalPublicCoseKey,
) -> Result<Vec<u8>, ExchangeError> {
    let envelope: SignedEnvelope = parse(bytes)?;
    // Replay IDs cover exact outer bytes. Permit exactly one representation of
    // those bytes for any signed inner body, including field order and hex case.
    if serde_json::to_vec(&envelope).map_err(|_| ExchangeError::Invalid)? != bytes
        || envelope
            .body
            .bytes()
            .chain(envelope.signature.bytes())
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(ExchangeError::Invalid);
    }
    let body = hex::decode(&envelope.body).map_err(|_| ExchangeError::Invalid)?;
    if body.len() > MAX_BODY_BYTES {
        return Err(ExchangeError::TooLarge);
    }
    public
        .verify_ed25519_strict(&signed_input(domain, &body), &decode(&envelope.signature)?)
        .map_err(|_| ExchangeError::Signature)?;
    Ok(body)
}
pub(crate) fn wipe_value(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_value),
        Value::Object(o) => o.values_mut().for_each(wipe_value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    struct Signing(SigningKey);
    impl ExchangeSigner for Signing {
        fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], ExchangeError> {
            Ok(self.0.sign(bytes).to_bytes())
        }
    }
    impl Signing {
        fn public(&self) -> CanonicalPublicCoseKey {
            CanonicalPublicCoseKey::ed25519(self.0.verifying_key().to_bytes()).unwrap()
        }
    }
    fn signer(n: u8) -> Signing {
        Signing(SigningKey::from_bytes(&[n; 32]))
    }

    #[test]
    fn only_the_requesting_device_can_read_the_authority_profile() {
        let device = signer(1);
        let authority = signer(2);
        let pending = PendingExchange::new(
            serde_json::json!({"op":"identity","challenge":"fresh"}),
            &device,
        )
        .unwrap();
        let request =
            VerifiedExchangeRequest::verify(pending.request_bytes(), &device.public()).unwrap();
        let response = request
            .reply(
                serde_json::json!({"display_name":"Private Operator","function_label":"Stab"}),
                &authority,
            )
            .unwrap();
        assert!(
            !response
                .windows(b"Private Operator".len())
                .any(|w| w == b"Private Operator")
        );
        assert_eq!(
            pending.open_reply(&response, &authority.public()).unwrap()["display_name"],
            "Private Operator"
        );
        let other = PendingExchange::new(serde_json::json!({"op":"identity"}), &device).unwrap();
        assert!(other.open_reply(&response, &authority.public()).is_err());
    }

    #[test]
    fn tampering_wrong_signers_and_replayed_responses_fail_closed() {
        let device = signer(1);
        let authority = signer(2);
        let foreign = signer(3);
        let pending = PendingExchange::new(
            serde_json::json!({"op":"authorize","target":"one"}),
            &device,
        )
        .unwrap();
        assert!(
            VerifiedExchangeRequest::verify(pending.request_bytes(), &foreign.public()).is_err()
        );
        let request =
            VerifiedExchangeRequest::verify(pending.request_bytes(), &device.public()).unwrap();
        let response = request
            .reply(serde_json::json!({"accepted":true}), &authority)
            .unwrap();
        assert!(pending.open_reply(&response, &foreign.public()).is_err());
        let mut corrupt = response.clone();
        let pos = corrupt.iter().position(|b| *b == b'0').unwrap();
        corrupt[pos] = b'1';
        assert!(pending.open_reply(&corrupt, &authority.public()).is_err());
        let mut request: serde_json::Value =
            serde_json::from_slice(pending.request_bytes()).unwrap();
        request["signature"] = serde_json::Value::String(hex::encode([0; 64]));
        assert!(
            VerifiedExchangeRequest::verify(
                &serde_json::to_vec(&request).unwrap(),
                &device.public()
            )
            .is_err()
        );
    }

    #[test]
    fn outer_envelope_reformatting_cannot_create_a_new_authorization_identity() {
        let device = signer(8);
        let pending =
            PendingExchange::new(serde_json::json!({"op":"authorize-target"}), &device).unwrap();
        let mut envelope: Value = serde_json::from_slice(pending.request_bytes()).unwrap();
        let pretty = serde_json::to_vec_pretty(&envelope).unwrap();
        assert!(VerifiedExchangeRequest::verify(&pretty, &device.public()).is_err());
        envelope["body"] = Value::String(envelope["body"].as_str().unwrap().to_ascii_uppercase());
        assert!(
            VerifiedExchangeRequest::verify(
                &serde_json::to_vec(&envelope).unwrap(),
                &device.public()
            )
            .is_err()
        );
    }

    #[test]
    fn accepted_envelopes_fit_the_complete_native_signing_request() {
        struct Bounded(Signing);
        impl ExchangeSigner for Bounded {
            fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], ExchangeError> {
                let ipc=serde_json::to_vec(&serde_json::json!({"op":"sign","installation_id":hex::encode([0;32]),"slot":"admin-signing","presence":true,"data":hex::encode(bytes)})).unwrap();
                assert!(ipc.len() <= 65_536, "accepted body exceeded native IPC");
                self.0.sign(bytes)
            }
        }
        let device = signer(7);
        let authority = Bounded(signer(8));
        let pending = PendingExchange::new(
            serde_json::json!({"data":"x".repeat(MAX_BODY_BYTES-500)}),
            &Bounded(signer(7)),
        )
        .unwrap();
        let request =
            VerifiedExchangeRequest::verify(pending.request_bytes(), &device.public()).unwrap();
        request
            .reply(
                serde_json::json!({"data":"x".repeat(MAX_REPLY_CLEAR_BYTES-100)}),
                &authority,
            )
            .unwrap();
        assert_eq!(
            request
                .reply(
                    serde_json::json!({"data":"x".repeat(MAX_REPLY_CLEAR_BYTES)}),
                    &authority
                )
                .unwrap_err(),
            ExchangeError::TooLarge
        );
        assert!(matches!(
            PendingExchange::new(
                serde_json::json!({"data":"x".repeat(MAX_BODY_BYTES)}),
                &device
            ),
            Err(ExchangeError::TooLarge)
        ));
    }

    #[test]
    fn exchange_files_resume_exactly_and_never_replace_a_conflicting_reply() {
        let directory = std::env::temp_dir().join(format!(
            "ea-exchange-{}",
            hex::encode(random::<16>().unwrap())
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("reply.json");
        write_exchange_file(&path, b"exact reply").unwrap();
        write_exchange_file(&path, b"exact reply").unwrap();
        assert!(write_exchange_file(&path, b"other reply").is_err());
        assert_eq!(read_exchange_file(&path).unwrap(), b"exact reply");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn encrypted_exchange_journal_recovers_the_exact_request_and_reply_key() {
        use ea_format::KeyProtectionProfileV1;
        use ea_key_provider::{InMemoryKeyProvider, KeyProvider, SecretPurpose};
        let directory = std::env::temp_dir().join(format!(
            "ea-exchange-db-{}",
            hex::encode(random::<16>().unwrap())
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("exchange.sqlite");
        let provider = InMemoryKeyProvider::new_for_test([21; 32]);
        let key = provider
            .generate(
                SecretPurpose::LocalDatabaseKey,
                KeyProtectionProfileV1::OsWrapped,
            )
            .unwrap();
        let database = ea_local_store::EncryptedDatabase::open(&path, &provider, &key).unwrap();
        let device = signer(1);
        let authority = signer(2);
        let payload = serde_json::json!({"context":"pinned-head","op":"authorize-target","args":{"target":"exact"}});
        let pending =
            PendingExchange::load_or_create(&database, payload.clone(), &device, &device.public())
                .unwrap();
        let request_bytes = pending.request_bytes().to_vec();
        let request = VerifiedExchangeRequest::verify(&request_bytes, &device.public()).unwrap();
        let response = request
            .reply(
                serde_json::json!({"display_name":"Private Operator","accepted":true}),
                &authority,
            )
            .unwrap();
        drop(pending);
        drop(database);
        let database =
            ea_local_store::EncryptedDatabase::open_existing(&path, &provider, &key).unwrap();
        let resumed =
            PendingExchange::load_or_create(&database, payload.clone(), &device, &device.public())
                .unwrap();
        assert_eq!(resumed.request_bytes(), request_bytes);
        assert_eq!(
            resumed.open_reply(&response, &authority.public()).unwrap()["accepted"],
            true
        );
        let other = PendingExchange::load_or_create(
            &database,
            serde_json::json!({"context":"another-head"}),
            &device,
            &device.public(),
        )
        .unwrap();
        assert!(other.open_reply(&response, &authority.public()).is_err());
        assert!(
            PendingExchange::load_or_create(
                &database,
                payload.clone(),
                &authority,
                &authority.public()
            )
            .is_err()
        );
        resumed.forget(&database).unwrap();
        let fresh =
            PendingExchange::load_or_create(&database, payload, &device, &device.public()).unwrap();
        assert_ne!(fresh.request_bytes(), request_bytes);
        assert!(fresh.open_reply(&response, &authority.public()).is_err());
        drop(database);
        assert!(
            !fs::read(&path)
                .unwrap()
                .windows(b"pinned-head".len())
                .any(|w| w == b"pinned-head")
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
