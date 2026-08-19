//! Ein deterministischer In-Prozess-Provider fuer Tests.
//!
//! Nur unter dem Feature `test-support` uebersetzt, das NIE ein Default-Feature
//! ist: dieser Provider haelt Schluesselmaterial im Prozessspeicher und gibt es
//! heraus, und genau das darf ein Produktionsbau nicht enthalten.
//!
//! Er erreicht ausschliesslich [`KeyProtectionProfileV1::OsWrapped`] und
//! behauptet nie mehr. Ein Provider, der Hardware verspricht und Software
//! liefert, waere der stille Rueckfall, den `design.md`:1489 verbietet.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_format::KeyProtectionProfileV1;
use ea_types::{CertificateHash, Hash32};
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    contract::{CoseSign1Bytes, KeyError, KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose},
    profile::{WriterKeyProfile, require_stage_two_protection_profile},
};

/// Das einzige Schutzprofil, das ein In-Prozess-Provider erreichen kann.
const REACHED_PROTECTION_PROFILE: KeyProtectionProfileV1 = KeyProtectionProfileV1::OsWrapped;

/// Die Zwecke, die durch [`KeyProvider::sign`] signieren.
const SIGNING_PURPOSES: &[SecretPurpose] = &[
    SecretPurpose::WriterSigningKey,
    SecretPurpose::OperatorInstanceKey,
];

pub struct InMemoryKeyProvider {
    account_instance: Hash32,
    seed: [u8; 32],
    entries: Mutex<HashMap<KeyHandle, [u8; 32]>>,
}

impl InMemoryKeyProvider {
    /// Ein Provider, der aus `seed` reproduzierbar dieselben Schluessel bildet.
    ///
    /// Der Startwert ist zugleich die Kontoinstanz: zwei Provider mit
    /// demselben Startwert sind dasselbe Geraet mit demselben Konto, und ein
    /// Griff des einen adressiert denselben Eintrag beim anderen.
    #[must_use]
    pub fn new_for_test(seed: [u8; 32]) -> Self {
        Self {
            account_instance: Hash32::try_from(seed.as_slice())
                .expect("a 32-byte seed is a 32-byte hash"),
            seed,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<KeyHandle, [u8; 32]>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn handle(&self, purpose: SecretPurpose) -> KeyHandle {
        KeyHandle::new(KeystoreProvider::InMemory, self.account_instance, purpose)
    }

    /// Deterministisches Testmaterial, AUSDRUECKLICH OHNE Sicherheitsanspruch.
    ///
    /// Der Startwert wird mit einer Zweckmarke ueberlagert, damit die vier
    /// Zwecke verschiedenes Material tragen. Das genuegt fuer einen
    /// reproduzierbaren Testlauf und fuer nichts sonst; `test-support` ist nie
    /// ein Default-Feature, also verlaesst dieses Material keinen Testlauf.
    fn derive(&self, purpose: SecretPurpose) -> [u8; 32] {
        let tag = match purpose {
            SecretPurpose::WriterSigningKey => 1u8,
            SecretPurpose::OperatorInstanceKey => 2,
            SecretPurpose::DraftDek => 3,
            SecretPurpose::LocalDatabaseKey => 4,
        };
        let mut material = self.seed;
        for (index, byte) in material.iter_mut().enumerate() {
            // Der Index bleibt unter 32, die Umwandlung kann nicht scheitern.
            let mixer = u8::try_from(index).unwrap_or(u8::MAX) | 1;
            *byte ^= tag.wrapping_mul(mixer);
        }
        material
    }

    fn material(&self, handle: &KeyHandle) -> Result<[u8; 32], KeyError> {
        self.entries()
            .get(handle)
            .copied()
            .ok_or(KeyError::NotFound)
    }
}

impl KeyProvider for InMemoryKeyProvider {
    fn generate(
        &self,
        purpose: SecretPurpose,
        protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, KeyError> {
        WriterKeyProfile::validate_local(&[purpose])?;
        require_stage_two_protection_profile(protection)?;
        if protection != REACHED_PROTECTION_PROFILE {
            return Err(KeyError::UnreachableProtectionProfile);
        }
        let handle = self.handle(purpose);
        self.entries().insert(handle, self.derive(purpose));
        Ok(handle)
    }

    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ContentType,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        handle.require_purpose(SIGNING_PURPOSES)?;
        let signing_key = SigningKey::from_bytes(&self.material(handle)?);
        let public = CanonicalPublicCoseKey::ed25519(signing_key.verifying_key().to_bytes())
            .map_err(KeyError::Crypto)?;
        let protected =
            ProtectedHeader::normal(content_type, public.thumbprint(), certificate_hash);
        let signature = signing_key.sign(&protected.sig_structure_bytes(payload));
        CoseSign1Bytes::compose(&protected, payload, &signature.to_bytes())
    }

    fn wrap_secret(
        &self,
        purpose: SecretPurpose,
        secret: SecretBytes<32>,
    ) -> Result<KeyHandle, KeyError> {
        let handle = self.handle(purpose);
        handle.require_purpose(&[SecretPurpose::DraftDek])?;
        self.entries()
            .insert(handle, secret.with_exposed(|bytes| *bytes));
        Ok(handle)
    }

    fn unwrap_secret(&self, handle: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        handle.require_purpose(&[SecretPurpose::DraftDek])?;
        self.material(handle).map(SecretBytes::new)
    }

    fn unwrap_database_key(&self, handle: &KeyHandle) -> Result<SecretVec, KeyError> {
        handle.require_purpose(&[SecretPurpose::LocalDatabaseKey])?;
        self.material(handle)
            .map(|material| SecretVec::new(material.to_vec()))
    }

    fn delete(&self, handle: &KeyHandle) -> Result<(), KeyError> {
        self.entries().remove(handle);
        Ok(())
    }

    fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError> {
        Ok(self.entries().contains_key(handle))
    }

    fn reached_protection_profile(
        &self,
        handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        self.material(handle).map(|_| REACHED_PROTECTION_PROFILE)
    }
}
