//! Der Registrierungsantrag des Browser-Readers (`web-reader-design.md` §6.6
//! Schritte 3–4, Ruling U3 des Escrow-Profils und Q2 der Scheibe e).
//!
//! Der Browser übergibt ihn als DATEI an die native Admin-Inbox — dieselbe
//! Form, die `crates/ea-admin/src/administration_runtime/inbox.rs`
//! (`verify_registration`) prüft: ein selbstsignierter
//! `DeviceRegistrationRequestV1` mit Rolle 1, dem X25519-KEM und dem
//! Ed25519-Schlüssel des entsperrten Tresors, dazu der Besitznachweis über den
//! EXAKTEN Core. Der Dateiname ist `hex(object_hash(bytes))` plus
//! `.registration.cbor`, wie `inbox_directory.rs` ihn nachrechnet.
//!
//! Der Antrag ist Nachweis des Schlüsselbesitzes, KEIN Zertifikat; er trägt
//! nur öffentliche Schlüssel. Serverregistrierung, Bundle-Fingerprint-
//! Vergleich in der Desktop-Anwendung und Upload bleiben benannte Grenzen.

use ea_crypto::{
    CanonicalPublicCoseKey, CryptoError, DeviceRegistrationRequestCoreV1, SUITE_ID,
    encode_device_registration_request_core, object_hash,
};
use ea_sync_protocol::DeviceRegistrationRequestV1;
use ea_types::{DeviceId, KeyThumbprint};

use crate::reader_key_escrow::ReaderKeyEscrowError;
use crate::vault::UnlockedVault;

/// Die Rolle „Reader" des Registrierungsantrags.
const READER_REQUESTED_ROLE_V1: u8 = 1;

/// Die Archivformatversion, die dieser Reader liest.
const SUPPORTED_FORMAT_VERSIONS_V1: [u64; 1] = [1];

/// Das Dateisuffix der Admin-Inbox.
pub const READER_REGISTRATION_FILE_SUFFIX_V1: &str = ".registration.cbor";

/// Die fertige Antragsdatei: exakte Bytes, ihr Name und die zwei Abdrücke zur
/// Anzeige. Alles öffentlich.
pub struct ReaderRegistrationFileV1 {
    file_name: String,
    exact_bytes: Vec<u8>,
    kem_key_thumbprint: KeyThumbprint,
    signing_key_thumbprint: KeyThumbprint,
}

impl ReaderRegistrationFileV1 {
    /// `hex(object_hash(bytes))` plus [`READER_REGISTRATION_FILE_SUFFIX_V1`].
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    #[must_use]
    pub const fn kem_key_thumbprint(&self) -> KeyThumbprint {
        self.kem_key_thumbprint
    }

    #[must_use]
    pub const fn signing_key_thumbprint(&self) -> KeyThumbprint {
        self.signing_key_thumbprint
    }
}

/// Baut den Registrierungsantrag aus dem entsperrten Tresor.
///
/// Die Organisation kommt aus dem gepinnten Anker, die `device_id` frisch vom
/// Wirt (`getrandom`), beide Schlüssel aus dem Tresor. Signiert wird mit dem
/// Ed25519-Schlüssel des Tresors über den exakten Core
/// (`CoseSigner::sign_enrollment`).
///
/// # Errors
///
/// `EA-LOCAL-CRYPTO-RNG` ohne Entropie, sonst die durchgereichten Codes von
/// `ea-crypto` und des Protokollrahmens.
pub fn reader_registration_request(
    vault: &UnlockedVault,
) -> Result<ReaderRegistrationFileV1, ReaderKeyEscrowError> {
    let mut device = [0_u8; 16];
    getrandom::fill(&mut device).map_err(|_| CryptoError::LocalRng)?;
    let device_id = DeviceId::try_from(device.as_slice()).map_err(|_| CryptoError::SizeLimit)?;
    let signer = vault.audit_signer();
    let signing_public_cose_key = signer.public_key()?;
    let kem_public_cose_key =
        CanonicalPublicCoseKey::x25519(*vault.kem_private_key().public_key().as_bytes())?;
    let core = DeviceRegistrationRequestCoreV1 {
        organization_id: vault.pinned_anchor().organization_id(),
        device_id,
        requested_role: READER_REQUESTED_ROLE_V1,
        signing_public_cose_key: signing_public_cose_key.clone(),
        kem_public_cose_key: Some(kem_public_cose_key.clone()),
        supported_format_versions: SUPPORTED_FORMAT_VERSIONS_V1.to_vec(),
        supported_suite_ids: vec![SUITE_ID.to_owned()],
    };
    let exact_core = encode_device_registration_request_core(&core)?;
    let signature = signer.sign_enrollment(&exact_core)?;
    let request = DeviceRegistrationRequestV1::new(core, &signature)?;
    let exact_bytes = request.exact_bytes().to_vec();
    let file_name = format!(
        "{}{READER_REGISTRATION_FILE_SUFFIX_V1}",
        hex::encode(object_hash(&exact_bytes).as_bytes())
    );
    Ok(ReaderRegistrationFileV1 {
        file_name,
        exact_bytes,
        kem_key_thumbprint: kem_public_cose_key.thumbprint(),
        signing_key_thumbprint: signing_public_cose_key.thumbprint(),
    })
}
