//! Explicit offline token operations. No long-term private attribute is read.
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        Mechanism,
        eddsa::{EddsaParams, EddsaSignatureScheme},
        elliptic_curve::{EcKdf, Ecdh1DeriveParams},
    },
    object::{Attribute as A, AttributeType as T, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::RawAuthPin,
};
use ea_crypto::{
    CanonicalPublicCoseKey, ExternalCoseSigningRequest, HpkeRecipientPublicKey, HpkeSealed,
    SecretBytes, hpke_open_with_token_dh,
};
use ea_types::CertificateHash;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{Pkcs11KeyReference, RecoveryError, read_secret_file};

// PKCS#11 login and initialization are module-wide. Own the entire lifecycle
// under this lock, including failure cleanup; never borrow an existing login.
static MODULE_LIFECYCLE: Mutex<()> = Mutex::new(());
const X25519_OID: &[u8] = &[6, 3, 0x2b, 0x65, 0x6e];
const ED25519_OID: &[u8] = &[6, 3, 0x2b, 0x65, 0x70];

/// Closed, path-free failure categories; native module messages never escape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pkcs11ProviderError {
    Unavailable,
    Authentication,
    KeySelection,
    KeyProtection,
    Operation,
    Cleanup,
}

impl Pkcs11ProviderError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "EA-RECOVERY-PKCS11-UNAVAILABLE",
            Self::Authentication => "EA-RECOVERY-PKCS11-AUTHENTICATION",
            Self::KeySelection => "EA-RECOVERY-PKCS11-KEY-SELECTION",
            Self::KeyProtection => "EA-RECOVERY-PKCS11-KEY-PROTECTION",
            Self::Operation => "EA-RECOVERY-PKCS11-OPERATION",
            Self::Cleanup => "EA-RECOVERY-PKCS11-CLEANUP",
        }
    }
}
impl From<Pkcs11ProviderError> for RecoveryError {
    fn from(value: Pkcs11ProviderError) -> Self {
        Self::Pkcs11Provider(value)
    }
}
type TokenResult<T> = Result<T, Pkcs11ProviderError>;

#[derive(Clone, Copy)]
enum Curve {
    X25519,
    Ed25519,
}

/// A token reference pinned to its validated public key, without a session,
/// PIN, private key bytes, or reusable authentication state.
pub struct Pkcs11RecipientKey {
    reference: Pkcs11KeyReference,
    pin_file: PathBuf,
    public: HpkeRecipientPublicKey,
}
impl Pkcs11RecipientKey {
    pub fn open(reference: Pkcs11KeyReference, pin_file: &Path) -> Result<Self, RecoveryError> {
        let public = with_key(
            &reference,
            pin_file,
            Curve::X25519,
            |_, _, public| match public {
                CanonicalPublicCoseKey::X25519(bytes) => HpkeRecipientPublicKey::from_bytes(bytes)
                    .map_err(|_| Pkcs11ProviderError::KeySelection),
                _ => Err(Pkcs11ProviderError::KeySelection),
            },
        )?;
        Ok(Self {
            reference,
            pin_file: pin_file.to_path_buf(),
            public,
        })
    }
    #[must_use]
    pub const fn public_key(&self) -> HpkeRecipientPublicKey {
        self.public
    }

    pub fn open_envelope(
        &self,
        sealed: &HpkeSealed,
        info: &[u8],
        aad: &[u8],
    ) -> Result<SecretBytes<32>, RecoveryError> {
        with_key(
            &self.reference,
            &self.pin_file,
            Curve::X25519,
            |session, key, public| {
                if public != CanonicalPublicCoseKey::X25519(*self.public.as_bytes()) {
                    return Err(Pkcs11ProviderError::KeySelection);
                }
                let dh = derive_shared_secret(session, key, sealed.encapsulated_key())?;
                hpke_open_with_token_dh(&self.public, dh, sealed, info, aad)
                    .map_err(|_| Pkcs11ProviderError::Operation)
            },
        )
    }
}

/// A non-exporting Ed25519 key with only the existing HGA and recovery-test
/// signing contexts. There is deliberately no arbitrary-digest signing API.
pub struct Pkcs11SigningKey {
    reference: Pkcs11KeyReference,
    pin_file: PathBuf,
    public: CanonicalPublicCoseKey,
}
impl Pkcs11SigningKey {
    pub fn open(reference: Pkcs11KeyReference, pin_file: &Path) -> Result<Self, RecoveryError> {
        let public = with_key(&reference, pin_file, Curve::Ed25519, |_, _, public| {
            Ok(public)
        })?;
        Ok(Self {
            reference,
            pin_file: pin_file.to_path_buf(),
            public,
        })
    }
    #[must_use]
    pub const fn public_key(&self) -> &CanonicalPublicCoseKey {
        &self.public
    }

    pub fn sign_historical_grant(&self, exact_body: &[u8]) -> Result<Vec<u8>, RecoveryError> {
        let request = ExternalCoseSigningRequest::historical_grant(self.public.clone(), exact_body)
            .map_err(|_| Pkcs11ProviderError::Operation)?;
        self.sign(request)
    }
    pub fn sign_recovery_test(
        &self,
        certificate: CertificateHash,
        challenge: SecretBytes<32>,
    ) -> Result<Vec<u8>, RecoveryError> {
        let request =
            ExternalCoseSigningRequest::recovery_test(self.public.clone(), certificate, challenge)
                .map_err(|_| Pkcs11ProviderError::Operation)?;
        self.sign(request)
    }
    fn sign(&self, request: ExternalCoseSigningRequest) -> Result<Vec<u8>, RecoveryError> {
        with_key(
            &self.reference,
            &self.pin_file,
            Curve::Ed25519,
            |session, key, public| {
                if public != self.public {
                    return Err(Pkcs11ProviderError::KeySelection);
                }
                let signature = session
                    .sign(
                        &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
                        key,
                        &request.sig_structure_bytes(),
                    )
                    .map_err(|_| Pkcs11ProviderError::Operation)?;
                let signature = signature
                    .try_into()
                    .map_err(|_| Pkcs11ProviderError::Operation)?;
                request
                    .complete(signature)
                    .map_err(|_| Pkcs11ProviderError::Operation)
            },
        )
    }
}

fn with_key<R>(
    reference: &Pkcs11KeyReference,
    pin_file: &Path,
    curve: Curve,
    operation: impl FnOnce(&Session, ObjectHandle, CanonicalPublicCoseKey) -> TokenResult<R>,
) -> Result<R, RecoveryError> {
    let pin = read_secret_file(pin_file)?;
    // Resolve the explicitly supplied path, never a loader search path.
    let module_path = std::fs::canonicalize(reference.module())?;
    if !std::fs::metadata(&module_path)?.is_file() {
        return Err(Pkcs11ProviderError::Unavailable.into());
    }
    let _guard = MODULE_LIFECYCLE
        .lock()
        .map_err(|_| Pkcs11ProviderError::Unavailable)?;
    let module = Pkcs11::new(module_path).map_err(|_| Pkcs11ProviderError::Unavailable)?;
    // AlreadyInitialized is an error: we must not finalize someone else's
    // context, or use a token-wide login established by another consumer.
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|_| Pkcs11ProviderError::Unavailable)?;
    let result = (|| {
        let info = module
            .get_library_info()
            .map_err(|_| Pkcs11ProviderError::Unavailable)?;
        let legacy_x25519 = info.manufacturer_id() == "SoftHSM"
            && info.library_description() == "Implementation of PKCS11"
            && info.library_version().major() == 2
            && info.library_version().minor() == 7;
        let mut matching_slot = None;
        for slot in module
            .get_slots_with_token()
            .map_err(|_| Pkcs11ProviderError::Unavailable)?
        {
            let token = module
                .get_token_info(slot)
                .map_err(|_| Pkcs11ProviderError::Unavailable)?;
            if token.label() == reference.token_label() && matching_slot.replace(slot).is_some() {
                return Err(Pkcs11ProviderError::KeySelection);
            }
        }
        let slot = matching_slot.ok_or(Pkcs11ProviderError::KeySelection)?;
        let session = module
            .open_ro_session(slot)
            .map_err(|_| Pkcs11ProviderError::Unavailable)?;
        let raw_pin = pin.with_exposed(|bytes| RawAuthPin::new(Box::new(bytes.to_vec())));
        let login = session.login_with_raw(UserType::User, &raw_pin);
        drop(raw_pin);
        if login.is_err() {
            return Err(Pkcs11ProviderError::Authentication);
        }
        let result = (|| {
            let private = exact_object(&session, reference, ObjectClass::PRIVATE_KEY)?;
            let public = exact_object(&session, reference, ObjectClass::PUBLIC_KEY)?;
            let public_key = validate_key(&session, private, public, curve, legacy_x25519)?;
            operation(&session, private, public_key)
        })();
        let logout = session.logout();
        // Session's Drop closes the session; finalization below also closes
        // all owned sessions and makes cleanup failures observable.
        drop(session);
        logout.map_err(|_| Pkcs11ProviderError::Cleanup)?;
        result
    })();
    module
        .finalize()
        .map_err(|_| Pkcs11ProviderError::Cleanup)?;
    result.map_err(Into::into)
}

fn exact_object(
    session: &Session,
    reference: &Pkcs11KeyReference,
    class: ObjectClass,
) -> TokenResult<ObjectHandle> {
    let objects = session
        .find_objects(&[A::Class(class), A::Id(reference.key_id().to_vec())])
        .map_err(|_| Pkcs11ProviderError::KeySelection)?;
    match objects.as_slice() {
        [object] => Ok(*object),
        _ => Err(Pkcs11ProviderError::KeySelection),
    }
}

fn validate_key(
    session: &Session,
    private: ObjectHandle,
    public: ObjectHandle,
    curve: Curve,
    legacy_x25519: bool,
) -> TokenResult<CanonicalPublicCoseKey> {
    let attributes = session
        .get_attributes(
            private,
            &[
                T::Token,
                T::Private,
                T::Sensitive,
                T::Extractable,
                T::AlwaysAuthenticate,
                T::KeyType,
                T::EcParams,
                T::Derive,
                T::Sign,
            ],
        )
        .map_err(|_| Pkcs11ProviderError::KeyProtection)?;
    for expected in [
        A::Token(true),
        A::Private(true),
        A::Sensitive(true),
        A::Extractable(false),
        A::AlwaysAuthenticate(false),
    ] {
        if !attributes.contains(&expected) {
            return Err(Pkcs11ProviderError::KeyProtection);
        }
    }
    let (oid, key_type, usage) = match curve {
        Curve::X25519 => (X25519_OID, KeyType::EC_MONTGOMERY, A::Derive(true)),
        Curve::Ed25519 => (ED25519_OID, KeyType::EC_EDWARDS, A::Sign(true)),
    };
    let valid_type = |attrs: &[A]| {
        attrs.contains(&A::KeyType(key_type))
            || matches!(curve, Curve::X25519)
                && legacy_x25519
                && attrs.contains(&A::KeyType(KeyType::EC_EDWARDS))
    };
    if !valid_type(&attributes)
        || !attributes.contains(&A::EcParams(oid.to_vec()))
        || !attributes.contains(&usage)
    {
        return Err(Pkcs11ProviderError::KeySelection);
    }
    let public_attrs = session
        .get_attributes(public, &[T::Token, T::KeyType, T::EcParams, T::EcPoint])
        .map_err(|_| Pkcs11ProviderError::KeySelection)?;
    if !public_attrs.contains(&A::Token(true))
        || !valid_type(&public_attrs)
        || !public_attrs.contains(&A::EcParams(oid.to_vec()))
    {
        return Err(Pkcs11ProviderError::KeySelection);
    }
    let point = public_attrs
        .iter()
        .find_map(|attr| {
            if let A::EcPoint(bytes) = attr {
                Some(bytes.as_slice())
            } else {
                None
            }
        })
        .ok_or(Pkcs11ProviderError::KeySelection)?;
    let raw = match point {
        [4, 32, bytes @ ..] if bytes.len() == 32 => bytes,
        bytes if bytes.len() == 32 => bytes,
        _ => return Err(Pkcs11ProviderError::KeySelection),
    };
    let bytes = raw
        .try_into()
        .map_err(|_| Pkcs11ProviderError::KeySelection)?;
    match curve {
        Curve::X25519 => CanonicalPublicCoseKey::x25519(bytes),
        Curve::Ed25519 => CanonicalPublicCoseKey::ed25519(bytes),
    }
    .map_err(|_| Pkcs11ProviderError::KeySelection)
}

fn derive_shared_secret(
    session: &Session,
    key: ObjectHandle,
    enc: &[u8; 32],
) -> TokenResult<SecretBytes<32>> {
    let derived = session
        .derive_key(
            &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), enc)),
            key,
            &[
                A::Class(ObjectClass::SECRET_KEY),
                A::KeyType(KeyType::GENERIC_SECRET),
                A::Token(false),
                A::Sensitive(false),
                A::Extractable(true),
                A::ValueLen(32.into()),
            ],
        )
        .map_err(|_| Pkcs11ProviderError::Operation)?;
    // The only CKA_VALUE query in production is this fresh ephemeral DH
    // object, never the long-term private key. Wipe even malformed replies.
    let result = session
        .get_attributes(derived, &[T::Value])
        .map_err(|_| Pkcs11ProviderError::Operation)
        .and_then(|mut attrs| {
            let mut bytes = Zeroizing::new([0; 32]);
            let valid = matches!(attrs.as_slice(), [A::Value(value)] if value.len() == 32);
            for attr in &mut attrs {
                if let A::Value(value) = attr {
                    if valid {
                        bytes.copy_from_slice(value);
                    }
                    value.zeroize();
                }
            }
            if valid {
                Ok(SecretBytes::new(*bytes))
            } else {
                Err(Pkcs11ProviderError::Operation)
            }
        });
    session
        .destroy_object(derived)
        .map_err(|_| Pkcs11ProviderError::Cleanup)?;
    result
}
