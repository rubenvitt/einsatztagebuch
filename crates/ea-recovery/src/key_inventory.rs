//! The existing public inventory describes expectations; it is not authority
//! that a medium exists, a key was tested or the required inventory is complete.
use ea_format::KeyProtectionProfileV1;
use ea_types::{CertificateHash, KeyThumbprint, ObjectHash};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryKeyRole {
    Root,
    OrganizationAdmin,
    Writer,
    Reader,
    RecoveryRecipient,
    ServerReceipt,
    KeyApprover,
    HistoricalGrantAuthority,
    DeletionAttest,
}
impl RecoveryKeyRole {
    pub const ALL: [Self; 9] = [
        Self::Root,
        Self::OrganizationAdmin,
        Self::Writer,
        Self::Reader,
        Self::RecoveryRecipient,
        Self::ServerReceipt,
        Self::KeyApprover,
        Self::HistoricalGrantAuthority,
        Self::DeletionAttest,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::OrganizationAdmin => "organizationAdmin",
            Self::Writer => "writer",
            Self::Reader => "reader",
            Self::RecoveryRecipient => "recoveryRecipient",
            Self::ServerReceipt => "serverReceipt",
            Self::KeyApprover => "keyApprover",
            Self::HistoricalGrantAuthority => "historicalGrantAuthority",
            Self::DeletionAttest => "deletionAttest",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryTestKind {
    SignatureChallenge,
    RecoveryDecrypt,
    ProviderPresence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyInventoryError;
impl KeyInventoryError {
    pub const fn code(self) -> &'static str {
        "EA-RECOVERY-INVENTORY-INVALID"
    }
}
impl std::fmt::Display for KeyInventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for KeyInventoryError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Wire {
    schema_id: String,
    inventory_id: String,
    media: Vec<MediumWire>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MediumWire {
    medium_id: String,
    key_role: RecoveryKeyRole,
    expected_key_thumbprint: String,
    certificate_object_hash: String,
    protection_profile: String,
    test_kind: RecoveryTestKind,
}
pub struct KeyInventory {
    id: [u8; 16],
    media: Vec<RecoveryMedium>,
    exact_hash: ObjectHash,
}
pub struct RecoveryMedium {
    id: String,
    role: RecoveryKeyRole,
    thumbprint: KeyThumbprint,
    certificate: CertificateHash,
    protection: KeyProtectionProfileV1,
    test_kind: RecoveryTestKind,
}
fn hash<const N: usize>(value: &str) -> Result<[u8; N], KeyInventoryError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(KeyInventoryError);
    }
    hex::decode(value)
        .map_err(|_| KeyInventoryError)?
        .try_into()
        .map_err(|_| KeyInventoryError)
}
impl KeyInventory {
    pub fn parse(exact: &[u8]) -> Result<Self, KeyInventoryError> {
        if exact.len() > 1024 * 1024 {
            return Err(KeyInventoryError);
        }
        let wire: Wire = serde_json::from_slice(exact).map_err(|_| KeyInventoryError)?;
        if wire.schema_id != "ea.key-inventory/v1" || wire.media.len() > 1024 {
            return Err(KeyInventoryError);
        }
        let id = hash(&wire.inventory_id)?;
        let mut media: Vec<RecoveryMedium> = Vec::with_capacity(wire.media.len());
        for value in wire.media {
            if value.medium_id.is_empty()
                || value.medium_id.len() > 256
                || media
                    .last()
                    .is_some_and(|old| old.id.as_bytes() >= value.medium_id.as_bytes())
            {
                return Err(KeyInventoryError);
            }
            let protection = match value.protection_profile.as_str() {
                "osWrapped" => KeyProtectionProfileV1::OsWrapped,
                "hardwareNonExportable" => KeyProtectionProfileV1::HardwareNonExportable,
                "offlineEncryptedContainer" => KeyProtectionProfileV1::OfflineEncryptedContainer,
                "pkcs11" => KeyProtectionProfileV1::Pkcs11,
                "serverSecretStoreOrHsm" => KeyProtectionProfileV1::ServerSecretStoreOrHsm,
                _ => return Err(KeyInventoryError),
            };
            media.push(RecoveryMedium {
                id: value.medium_id,
                role: value.key_role,
                thumbprint: KeyThumbprint::try_from(
                    hash::<32>(&value.expected_key_thumbprint)?.as_slice(),
                )
                .map_err(|_| KeyInventoryError)?,
                certificate: CertificateHash::try_from(
                    hash::<32>(&value.certificate_object_hash)?.as_slice(),
                )
                .map_err(|_| KeyInventoryError)?,
                protection,
                test_kind: value.test_kind,
            });
        }
        Ok(Self {
            id,
            media,
            exact_hash: ea_crypto::object_hash(exact),
        })
    }
    pub fn inventory_id(&self) -> &[u8; 16] {
        &self.id
    }
    pub fn media(&self) -> &[RecoveryMedium] {
        &self.media
    }
    pub fn exact_hash(&self) -> ObjectHash {
        self.exact_hash
    }
}
impl RecoveryMedium {
    /// Local matching only. Public reports use pseudonymous_id_hash instead.
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn pseudonymous_id_hash(&self) -> ObjectHash {
        ea_crypto::object_hash(self.id.as_bytes())
    }
    pub fn role(&self) -> RecoveryKeyRole {
        self.role
    }
    pub fn expected_thumbprint(&self) -> KeyThumbprint {
        self.thumbprint
    }
    pub fn certificate(&self) -> CertificateHash {
        self.certificate
    }
    pub fn protection(&self) -> KeyProtectionProfileV1 {
        self.protection
    }
    pub fn test_kind(&self) -> RecoveryTestKind {
        self.test_kind
    }
}
