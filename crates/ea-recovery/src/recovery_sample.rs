//! Recovery reads exact archived bytes only after the public verification gates.
//! These sample proofs contain public routing metadata, never payloads or CEKs.
use crate::{
    FsArchiveSource, RecoveryKeyRole, RecoveryMedium, RecoveryTestError, RecoveryTestKind,
};
use ea_archive::ArchiveInventory;
use ea_crypto::{
    HpkeRecipient, HpkeSealed, SecretBytes, aead_open, hpke_aad, hpke_info, hpke_open, payload_aad,
};
use ea_format::{CertificateKindV1, GrantPurposeV1, OperatorRoleV1};
use ea_schema::{CommonHeaderV1, PayloadV1, SchemaRegistry};
use ea_trust::TrustAnchorV1;
use ea_types::{CertificateHash, ChainSequence, EntryHash, ObjectHash, UnixMillis};

pub struct RecoveryArchiveProbe<'a> {
    source: FsArchiveSource,
    anchor: &'a TrustAnchorV1,
    inventory: ArchiveInventory,
    now: UnixMillis,
    chain_head: ea_verify::ChainHeadV1,
}
pub struct VerifiedRecoverySample {
    entry: EntryHash,
    object: ObjectHash,
    grant: ObjectHash,
    sequence: ChainSequence,
    writer: CertificateHash,
    schema: &'static str,
}
impl VerifiedRecoverySample {
    pub fn entry_hash(&self) -> EntryHash {
        self.entry
    }
    pub fn object_hash(&self) -> ObjectHash {
        self.object
    }
    pub fn grant_hash(&self) -> ObjectHash {
        self.grant
    }
    pub fn sequence(&self) -> ChainSequence {
        self.sequence
    }
    pub fn writer_certificate(&self) -> CertificateHash {
        self.writer
    }
    pub fn schema_id(&self) -> &'static str {
        self.schema
    }
    pub fn schema_version(&self) -> u64 {
        ea_schema::SCHEMA_VERSION_V1
    }
    pub fn suite_id(&self) -> &'static str {
        ea_schema::SUITE_ID_V1
    }
}
/// A cryptographically tested medium. Full-archive verification is tracked
/// independently: an old KEM epoch may not read later destruction Evidence.
/// The complete service requires a fully verified archive before success.
pub struct VerifiedRecoveryMedium {
    samples: Vec<VerifiedRecoverySample>,
    full_archive_verified: bool,
}
impl VerifiedRecoveryMedium {
    pub fn samples(&self) -> &[VerifiedRecoverySample] {
        &self.samples
    }
    pub fn full_archive_verified(&self) -> bool {
        self.full_archive_verified
    }
}
impl<'a> RecoveryArchiveProbe<'a> {
    pub fn verify(
        source: &'a FsArchiveSource,
        anchor: &'a TrustAnchorV1,
        now: UnixMillis,
    ) -> Result<Self, RecoveryTestError> {
        let source = source.committed_view();
        let report = crate::verify::verify_source(&source, anchor, now, None)
            .map_err(|_| RecoveryTestError::Archive)?;
        // This opaque getter requires all public gates, including a continuous
        // signed chain. It does not promote an unreadable destruction Stub.
        let chain_head = report
            .verified_public_chain_head()
            .ok_or(RecoveryTestError::Archive)?;
        let inventory = ArchiveInventory::build(&source).map_err(|_| RecoveryTestError::Archive)?;
        Ok(Self {
            source,
            anchor,
            inventory,
            now,
            chain_head,
        })
    }
    pub fn inventory(&self) -> &ArchiveInventory {
        &self.inventory
    }
    pub fn verified_public_chain_head(&self) -> ea_verify::ChainHeadV1 {
        self.chain_head
    }
    pub fn test_recovery_medium(
        &self,
        medium: &RecoveryMedium,
        setup_entry: EntryHash,
        setup_grant: ObjectHash,
        key: &dyn HpkeRecipient,
    ) -> Result<VerifiedRecoveryMedium, RecoveryTestError> {
        if medium.role() != RecoveryKeyRole::RecoveryRecipient
            || medium.test_kind() != RecoveryTestKind::RecoveryDecrypt
        {
            return Err(RecoveryTestError::Role);
        }
        let thumb = crate::recipient_key_thumbprint(key).map_err(|_| RecoveryTestError::Key)?;
        if thumb != medium.expected_thumbprint() {
            return Err(RecoveryTestError::Key);
        }
        let mut samples = Vec::new();
        let mut setup_seen = false;
        for entry in self.inventory.entries() {
            let manifest = entry.value().manifest();
            let fields = manifest.fields();
            let own = self.inventory.grants().iter().find(|grant| {
                let fields = grant.value().grant_body().fields();
                fields.entry_hash == entry.value().entry_hash()
                    && fields.purpose == GrantPurposeV1::Recovery
                    && fields.recipient_key_thumbprint == thumb
                    && fields.recipient_certificate_hash == medium.certificate()
            });
            let Some(grant) = own else {
                continue;
            };
            ea_verify::verify_original_recovery_grant(
                &self.inventory,
                self.anchor,
                entry,
                grant,
                self.now,
            )
            .map_err(|_| RecoveryTestError::Archive)?;
            let head = ea_verify::historical_registry_head(
                &self.inventory,
                self.anchor,
                fields.registry_version,
                ObjectHash::try_from(fields.registry_head_hash.as_slice())
                    .map_err(|_| RecoveryTestError::Archive)?,
                fields.chain_sequence,
                self.now,
            )
            .ok_or(RecoveryTestError::Archive)?;
            let certificate = head
                .active_certificate_fields(medium.certificate())
                .ok_or(RecoveryTestError::Role)?;
            if certificate.certificate_kind != CertificateKindV1::RecoveryRecipient
                || certificate.kem_key_thumbprint != Some(thumb)
            {
                return Err(RecoveryTestError::Role);
            }
            let body = grant.value().grant_body();
            let grant_fields = body.fields();
            let context = body
                .exact_grant_context()
                .ok_or(RecoveryTestError::Archive)?;
            let sealed =
                HpkeSealed::from_parts(grant_fields.encapsulated_key, grant_fields.wrapped_cek)
                    .map_err(|_| RecoveryTestError::Key)?;
            let cek = hpke_open(key, &sealed, &hpke_info(context), &hpke_aad(context))
                .map_err(|_| RecoveryTestError::Key)?;
            let plaintext = aead_open(
                &cek,
                &SecretBytes::new(fields.nonce),
                entry.value().ciphertext(),
                &payload_aad(manifest.exact_bytes()),
            )
            .map_err(|_| RecoveryTestError::Key)?;
            drop(cek);
            let schema = plaintext.with_exposed(|bytes| {
                let schemas = SchemaRegistry::v1();
                for schema in schemas.schemas() {
                    let Ok(validated) =
                        schemas.validate(schema.schema_id(), schema.schema_version(), bytes)
                    else {
                        continue;
                    };
                    let header = header(validated.payload());
                    let operator = header.operator();
                    let binding = head
                        .active_operator_binding_fields(operator.operator_binding_object_hash())
                        .ok_or(RecoveryTestError::Payload)?;
                    if header.registry_version() != fields.registry_version
                        || operator.organization_id() != fields.organization_id
                        || binding.organization_id != operator.organization_id()
                        || binding.operator_subject_id != operator.operator_subject_id()
                        || binding.device_certificate_hash != fields.writer_certificate_hash
                        || binding.operator_role != OperatorRoleV1::Writer
                        || ea_crypto::operator_profile_commitment(
                            operator.organization_id(),
                            operator.operator_subject_id(),
                            operator.display_name(),
                            operator.function_label(),
                            operator.salt(),
                        ) != binding.operator_profile_commitment
                    {
                        return Err(RecoveryTestError::Payload);
                    }
                    return Ok(schema.schema_id());
                }
                Err(RecoveryTestError::Payload)
            })?;
            drop(plaintext);
            setup_seen |=
                entry.value().entry_hash() == setup_entry && grant.object_hash() == setup_grant;
            samples.push(VerifiedRecoverySample {
                entry: entry.value().entry_hash(),
                object: entry.object_hash(),
                grant: grant.object_hash(),
                sequence: fields.chain_sequence,
                writer: fields.writer_certificate_hash,
                schema,
            });
        }
        if !setup_seen {
            return Err(RecoveryTestError::Incomplete);
        }
        samples.sort_by_key(|sample| sample.sequence);
        let report =
            crate::verify::verify_source(&self.source, self.anchor, self.now, Some((thumb, key)))
                .map_err(|_| RecoveryTestError::Archive)?;
        Ok(VerifiedRecoveryMedium {
            samples,
            full_archive_verified: report.is_fully_verified(),
        })
    }
}
fn header(payload: &PayloadV1) -> &CommonHeaderV1 {
    match payload {
        PayloadV1::Genesis(value) => value.header(),
        PayloadV1::Incident(value) => value.header(),
        PayloadV1::Amendment(value) => value.header(),
        PayloadV1::KeyTransition(value) => value.header(),
        PayloadV1::DestructionEvidence(value) => value.header(),
    }
}
