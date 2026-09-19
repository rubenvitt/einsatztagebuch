//! Verified managed-cache instructions. The encrypted local receipt is a
//! measurement for the registered component, never a v1 deletion attestation.
use ea_archive::ArchiveInventory;
use ea_crypto::{VerificationContext, object_hash, verify_cose_sign1};
use ea_format::{CertificateKindV1, DecodedTrustPayloadV1, ParsedArchiveObject};
use ea_trust::{SelectedRegistryHead, TrustAnchorV1};
use ea_types::{
    CertificateHash, ChainSequence, DestructionId, DeviceId, EntryHash, KeyThumbprint, ObjectHash,
    RegistryVersion,
};
use minicbor::Decoder;
const INVALID: &str = "EA-READER-DESTRUCTION-UNVERIFIED";
pub struct ReaderDestructionInstructionBytes<'a> {
    pub authorization: &'a [u8],
    pub initiating_event: &'a [u8],
    pub preflight_core: &'a [u8],
    pub preflight_signature: &'a [u8],
    pub inventory: &'a [u8],
    pub preflight_certificate: CertificateHash,
}
/// Minted only after original approval, current component authority and the
/// signed job inventory agree. It confers local removal scope, no attestation.
pub struct VerifiedReaderDestructionInstruction {
    pub(crate) job: ObjectHash,
    pub(crate) reader: KeyThumbprint,
    certificate: CertificateHash,
    destruction_id: DestructionId,
    pub(crate) replica: DeviceId,
    pub(crate) targets: Vec<(EntryHash, ObjectHash)>,
    pub(crate) exact_instruction: Vec<u8>,
    pub(crate) current_pin: ea_trust::RegistryHeadPin,
    pub(crate) current_time: ea_types::UnixMillis,
}
impl VerifiedReaderDestructionInstruction {
    pub(crate) fn input(&self) -> Result<ReaderDestructionInstructionBytes<'_>, &'static str> {
        ReaderDestructionInstructionBytes::from_exact(&self.exact_instruction)
    }
    pub fn preflight_certificate_hash(&self) -> CertificateHash {
        self.certificate
    }
    pub fn exact_instruction_bytes(&self) -> &[u8] {
        &self.exact_instruction
    }
    pub fn job_hash(&self) -> ObjectHash {
        self.job
    }
    pub fn replica_id(&self) -> DeviceId {
        self.replica
    }
    pub fn destruction_id(&self) -> DestructionId {
        self.destruction_id
    }
    pub fn targets(&self) -> &[(EntryHash, ObjectHash)] {
        &self.targets
    }
    pub fn verify(
        inventory: &ArchiveInventory,
        anchor: &TrustAnchorV1,
        current: &SelectedRegistryHead,
        reader: KeyThumbprint,
        input: ReaderDestructionInstructionBytes<'_>,
    ) -> Result<Self, &'static str> {
        let ParsedArchiveObject::Trust(auth) =
            ea_format::decode_exact_object(input.authorization).map_err(|_| INVALID)?
        else {
            return Err(INVALID);
        };
        let DecodedTrustPayloadV1::DestructionAuthorization(fields) =
            auth.value().decoded_payload().map_err(|_| INVALID)?
        else {
            return Err(INVALID);
        };
        let core = ea_crypto::decode_destruction_preflight_core(input.preflight_core)
            .map_err(|_| INVALID)?;
        let now = current.preexisting_effective_now().value();
        if fields.organization_id != anchor.organization_id()
            || current.policy_fields().organization_id != anchor.organization_id()
            || current.chain_id() != anchor.chain_id()
            || &core.organization_id != fields.organization_id.as_bytes()
            || &core.chain_id != anchor.chain_id().as_bytes()
            || &core.destruction_id != fields.destruction_id.as_bytes()
            || &core.authorization_hash != auth.object_hash().as_bytes()
            || &core.inventory_hash != object_hash(input.inventory).as_bytes()
            || core.authorization_registry != fields.registry_version.get()
            || &core.authorization_head != fields.registry_head_hash.as_bytes()
            || core.authorization_sequence != fields.authorization_sequence
            || core.observed_effective_now > now.get()
            || current.registry_version().get() < core.execution_registry
            || !current.policy_fields().retention_policy.destruction_enabled
            || current
                .policy_fields()
                .retention_policy
                .eds_privacy_decision_document_hash
                .is_none()
        {
            return Err(INVALID);
        }
        let original = ea_verify::historical_registry_head(
            inventory,
            anchor,
            fields.registry_version,
            ObjectHash::from(fields.registry_head_hash),
            ChainSequence::new(fields.authorization_sequence),
            now,
        )
        .ok_or(INVALID)?;
        let policy = &original.policy_fields().retention_policy;
        if !policy.destruction_enabled
            || policy.eds_privacy_decision_document_hash.is_none()
            || ea_trust::distinct_authority_subjects(
                auth.value().signatures(),
                auth.value().exact_digest_input(),
                &original,
                VerificationContext::destruction_approval_trust_digest,
            )
            .map_err(|_| INVALID)?
                < 2
        {
            return Err(INVALID);
        }
        let execution = ea_verify::historical_registry_head(
            inventory,
            anchor,
            RegistryVersion::new(core.execution_registry),
            ObjectHash::try_from(core.execution_head.as_slice()).map_err(|_| INVALID)?,
            ChainSequence::new(core.execution_sequence),
            now,
        )
        .ok_or(INVALID)?;
        let eligible = |certificate: Option<&ea_format::DeviceCertificateFieldsV1>| {
            certificate.is_some_and(|cert| {
                cert.certificate_kind == CertificateKindV1::DeletionAttest
                    && cert.capabilities.iter().any(|cap| cap == "deletionAttest")
            })
        };
        if !eligible(original.active_certificate_fields(input.preflight_certificate)) {
            return Err(INVALID);
        }
        let context = VerificationContext::destruction_preflight_report(
            input.preflight_core,
            input.preflight_certificate,
        )
        .map_err(|_| INVALID)?;
        verify_cose_sign1(input.preflight_signature, &execution, &context).map_err(|_| INVALID)?;
        let ParsedArchiveObject::Trust(event) =
            ea_format::decode_exact_object(input.initiating_event).map_err(|_| INVALID)?
        else {
            return Err(INVALID);
        };
        let DecodedTrustPayloadV1::DestructionTransition(transition) =
            event.value().decoded_payload().map_err(|_| INVALID)?
        else {
            return Err(INVALID);
        };
        if transition.destruction_id != fields.destruction_id
            || transition.destruction_authorization_object_hash != auth.object_hash()
            || transition.from_state != Some(0)
            || transition.to_state != 1
            || transition.previous_event_object_hash.is_none()
            || transition.executed_at > now
            || event.value().signatures().len() != 1
        {
            return Err(INVALID);
        }
        let signature = &event.value().signatures()[0];
        let certificate = ea_crypto::parse_cose_sign1(signature, &[])
            .map_err(|_| INVALID)?
            .certificate_hash()
            .ok_or(INVALID)?;
        if !eligible(current.active_certificate_fields(certificate)) {
            return Err(INVALID);
        }
        let context = VerificationContext::destruction_transition_trust_digest(
            event.value().exact_digest_input(),
            input.authorization,
            certificate,
        )
        .map_err(|_| INVALID)?;
        verify_cose_sign1(signature, &original, &context).map_err(|_| INVALID)?;
        // Web-Reader-Design §3, same rule as `ea_destruction::verify_event_at`:
        // a signer on a device that holds a Reader certificate at the
        // authorization head (revoked included) never signs a transition.
        let signer = original
            .active_certificate_fields(certificate)
            .ok_or(INVALID)?;
        if ea_verify::device_holds_reader_certificate(
            signer.device_id,
            original.known_certificate_fields(),
        ) {
            return Err(INVALID);
        }
        let (replica, targets) = parse_inventory(
            input.inventory,
            inventory,
            anchor,
            current,
            reader,
            &fields,
            auth.object_hash(),
            now,
        )?;
        let report_targets: Vec<_> = targets
            .iter()
            .zip(&fields.targets)
            .map(|((entry, original), target)| {
                (
                    *entry,
                    ChainSequence::new(target.chain_sequence()),
                    *original,
                )
            })
            .collect();
        ea_verify::verify_destruction_preflight_report(
            core.report_json,
            anchor.chain_id(),
            &report_targets,
        )
        .map_err(|_| INVALID)?;
        let mut exact = Vec::new();
        let mut e = minicbor::Encoder::new(&mut exact);
        e.array(6).map_err(|_| INVALID)?;
        for bytes in [
            input.authorization,
            input.initiating_event,
            input.preflight_core,
            input.preflight_signature,
            input.inventory,
            input.preflight_certificate.as_bytes(),
        ] {
            e.bytes(bytes).map_err(|_| INVALID)?;
        }
        Ok(Self {
            current_pin: ea_trust::RegistryHeadPin::new(
                current.registry_version(),
                current.registry_head_hash(),
            ),
            current_time: now,
            job: object_hash(input.preflight_core),
            reader,
            certificate: input.preflight_certificate,
            destruction_id: fields.destruction_id,
            replica,
            targets,
            exact_instruction: exact,
        })
    }
}
type LocalTargets = Vec<(EntryHash, ObjectHash)>;
#[allow(clippy::too_many_arguments)]
fn parse_inventory(
    bytes: &[u8],
    archive: &ArchiveInventory,
    anchor: &TrustAnchorV1,
    current: &SelectedRegistryHead,
    reader: KeyThumbprint,
    auth: &ea_format::DestructionAuthorizationFieldsV1,
    auth_hash: ObjectHash,
    now: ea_types::UnixMillis,
) -> Result<(DeviceId, LocalTargets), &'static str> {
    ea_cbor::validate(bytes, ea_cbor::ParserLimits::V1).map_err(|_| INVALID)?;
    let parsed = (|| -> Result<_, minicbor::decode::Error> {
        let mut d = Decoder::new(bytes);
        if d.array()? != Some(4) || d.str()? != "EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1" {
            return Err(bad());
        }
        let custody = d.bytes()?;
        ea_cbor::validate(custody, ea_cbor::ParserLimits::V1).map_err(|_| bad())?;
        let mut c = Decoder::new(custody);
        if c.array()? != Some(6)
            || c.str()? != "EINSATZARCHIV-MANAGED-CUSTODY-v1"
            || c.bytes()? != auth.organization_id.as_bytes()
            || c.bytes()? != auth.destruction_id.as_bytes()
            || c.bytes()? != auth_hash.as_bytes()
            || c.bytes()? != anchor.chain_id().as_bytes()
        {
            return Err(bad());
        }
        let mut replica = None;
        let mut previous_record_hash = None;
        for _ in 0..c.array()?.ok_or_else(bad)? {
            let record = c.bytes()?;
            let hash = object_hash(record);
            if previous_record_hash.is_some_and(|previous| previous >= hash) {
                return Err(bad());
            }
            previous_record_hash = Some(hash);
            ea_cbor::validate(record, ea_cbor::ParserLimits::V1).map_err(|_| bad())?;
            let mut r = Decoder::new(record);
            let length = r.array()?.ok_or_else(bad)?;
            let record_kind = r.u8()?;
            if length
                != match record_kind {
                    0 => 4,
                    1 => 6,
                    2 => 9,
                    _ => return Err(bad()),
                }
            {
                return Err(bad());
            }
            let cert = CertificateHash::try_from(r.bytes()?).map_err(|_| bad())?;
            let device = DeviceId::try_from(r.bytes()?).map_err(|_| bad())?;
            let kind = r.u8()?;
            if !matches!(kind, 0 | 1 | 6) {
                return Err(bad());
            }
            if matches!(record_kind, 1 | 2) && (r.bytes()?.len() != 32 || r.bytes()?.len() != 32) {
                return Err(bad());
            }
            if record_kind == 2
                && (r.bytes()?.len() != 32 || r.bytes()?.len() != 32 || !matches!(r.u8()?, 1 | 2))
            {
                return Err(bad());
            }
            if r.position() != record.len() {
                return Err(bad());
            }
            if record_kind == 0
                && kind == CertificateKindV1::Reader as u8
                && current.known_certificate_fields().any(|(hash, fields)| {
                    hash == cert
                        && fields.certificate_kind == CertificateKindV1::Reader
                        && fields.device_id == device
                        && fields.kem_key_thumbprint == Some(reader)
                })
            {
                if replica.is_some_and(|previous| previous != device) {
                    return Err(bad());
                }
                replica = Some(device);
            }
        }
        if c.position() != custody.len() {
            return Err(bad());
        }
        let replica = replica.ok_or_else(bad)?;
        let count = d.array()?.ok_or_else(bad)?;
        if count != auth.targets.len() as u64 {
            return Err(bad());
        }
        let mut targets = Vec::new();
        for target in &auth.targets {
            if d.array()? != Some(3) {
                return Err(bad());
            }
            let entry_hash = EntryHash::try_from(d.bytes()?).map_err(|_| bad())?;
            let original = ObjectHash::try_from(d.bytes()?).map_err(|_| bad())?;
            let ParsedArchiveObject::Destroyed(stub) =
                ea_format::decode_exact_object(d.bytes()?).map_err(|_| bad())?
            else {
                return Err(bad());
            };
            let value = stub.value();
            let fields = value.signed_manifest().manifest().fields();
            if entry_hash.as_bytes() != target.entry_hash()
                || value.entry_hash() != entry_hash
                || value.original_eip_object_hash() != original
                || fields.chain_sequence.get() != target.chain_sequence()
                || fields.organization_id != anchor.organization_id()
                || fields.chain_id != anchor.chain_id()
                || value.destruction_id() != auth.destruction_id
                || value.destruction_authorization_object_hash() != auth_hash
            {
                return Err(bad());
            }
            let head = ea_verify::historical_registry_head(
                archive,
                anchor,
                fields.registry_version,
                ObjectHash::try_from(fields.registry_head_hash.as_slice()).map_err(|_| bad())?,
                fields.chain_sequence,
                now,
            )
            .ok_or_else(bad)?;
            let context = VerificationContext::record(value.signed_manifest().exact_bytes())
                .map_err(|_| bad())?;
            verify_cose_sign1(value.writer_signature(), &head, &context).map_err(|_| bad())?;
            targets.push((entry_hash, original));
        }
        for _ in 0..d.array()?.ok_or_else(bad)? {
            if d.array()? != Some(2) || d.bytes()?.len() != 32 {
                return Err(bad());
            }
            for _ in 0..d.array()?.ok_or_else(bad)? {
                d.str()?;
            }
        }
        if d.position() != bytes.len() {
            return Err(bad());
        }
        Ok((replica, targets))
    })();
    parsed.map_err(|_| INVALID)
}
fn bad() -> minicbor::decode::Error {
    minicbor::decode::Error::message("invalid bound job inventory")
}

impl<'a> ReaderDestructionInstructionBytes<'a> {
    pub(crate) fn from_exact(exact: &'a [u8]) -> Result<Self, &'static str> {
        let mut d = Decoder::new(exact);
        if d.array().map_err(|_| INVALID)? != Some(6) {
            return Err(INVALID);
        }
        let input = ReaderDestructionInstructionBytes {
            authorization: d.bytes().map_err(|_| INVALID)?,
            initiating_event: d.bytes().map_err(|_| INVALID)?,
            preflight_core: d.bytes().map_err(|_| INVALID)?,
            preflight_signature: d.bytes().map_err(|_| INVALID)?,
            inventory: d.bytes().map_err(|_| INVALID)?,
            preflight_certificate: CertificateHash::try_from(d.bytes().map_err(|_| INVALID)?)
                .map_err(|_| INVALID)?,
        };
        if d.position() != exact.len() {
            return Err(INVALID);
        }
        Ok(input)
    }
}
