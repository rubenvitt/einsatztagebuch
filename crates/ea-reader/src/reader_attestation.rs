//! Private, measured Reader component evidence. No global destruction authority.
use crate::cache_destruction::{Job, holdings, secondary_keys};
use crate::{
    ReaderBlobKey, ReaderBlobStore, ReaderCacheDestruction, ReaderDestructionInstructionBytes,
    ReaderVaultError as Error, UnlockedVault, VerifiedReaderDestructionInstruction,
};
use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_crypto::{
    AEAD_NONCE_SIZE, CoseSigner, SecretBytes, SecretVec, VerificationContext, aead_open, aead_seal,
    object_hash, verify_cose_sign1,
};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, DeletionAttestationFieldsV1, ParsedArchiveObject,
    TrustObjectV1, TrustPayloadV1, encode_trust,
};
use ea_trust::{HistoricalRegistryAuthority, SelectedRegistryHead};
use ea_types::{CertificateHash, ChainSequence, ObjectHash, UnixMillis};
const INVALID: &str = "EA-READER-DESTRUCTION-UNVERIFIED";
const PREFIX: &str = "destruction-attestation/v1/";
pub(crate) fn is_attestation_key(key: &ReaderBlobKey) -> bool {
    key.as_str().strip_prefix(PREFIX).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
impl ReaderCacheDestruction {
    pub fn attestation_key(job: ObjectHash) -> Result<ReaderBlobKey, Error> {
        Ok(ReaderBlobKey::new(&format!(
            "{PREFIX}{}",
            hex::encode(job.as_bytes())
        ))?)
    }
    /// Sign only the internally stored complete job after fresh authority and
    /// actual full-namespace measurement. No caller can supply claim fields.
    pub fn attest(
        vault: &UnlockedVault,
        store: &mut dyn ReaderBlobStore,
        source: &dyn ArchiveSource,
        job_hash: ObjectHash,
        certificate: CertificateHash,
        now: UnixMillis,
    ) -> Result<Vec<u8>, Error> {
        let job = complete_job(vault, store, job_hash)?.ok_or(Error::Contents)?;
        let input = ReaderDestructionInstructionBytes::from_exact(&job.instruction)
            .map_err(|_| Error::Contents)?;
        let (proof, historical) = crate::destruction_authority::prepare_with(
            vault,
            store,
            source,
            input,
            now,
            |inventory, current, proof| admit(vault, inventory, current, proof, certificate),
        )
        .map_err(|_| Error::Contents)?;
        bind_job(&job, &proof)?;
        // Current-action entry always requires current admission, even on repeat.
        // Historical reading after revocation has its own explicit entry point.
        if let Some(exact) = Self::historical_attestation(vault, store, source, job_hash)? {
            let ParsedArchiveObject::Trust(saved) =
                ea_format::decode_exact_object(&exact).map_err(|_| Error::Contents)?
            else {
                return Err(Error::Contents);
            };
            let [signature] = saved.value().signatures() else {
                return Err(Error::Contents);
            };
            if ea_crypto::parse_cose_sign1(signature, &[])?.certificate_hash() != Some(certificate)
            {
                return Err(Error::Contents);
            }
            return Ok(exact);
        }
        // Last measurement immediately before creating the signature capability.
        let measured = complete_job(vault, store, job_hash)?.ok_or(Error::Contents)?;
        if measured != job {
            return Err(Error::Contents);
        }
        let input = proof.input().map_err(|_| Error::Contents)?;
        let payload = TrustPayloadV1::deletion_attestation(DeletionAttestationFieldsV1 {
            destruction_id: proof.destruction_id(),
            destruction_authorization_object_hash: object_hash(input.authorization),
            replica_id: *job.replica.as_bytes(),
            replica_kind: 1,
            removed_object_hashes: job.removed.clone(),
            result: 0,
            backup_expiry_at: None,
            executed_at: proof.current_time,
        })
        .map_err(|_| Error::Contents)?;
        let signer = vault
            .audit_signing_key()
            .with_exposed(|key| CoseSigner::from_secret(SecretBytes::new(*key)));
        let signature = signer.sign_deletion_attestation_digest(
            certificate,
            payload.exact_digest_input(),
            input.authorization,
        )?;
        let exact = encode_trust(
            &TrustObjectV1::new(payload, vec![signature]).map_err(|_| Error::Contents)?,
        )
        .map_err(|_| Error::Contents)?
        .into_vec();
        verify_exact(vault, &job, &exact, &historical)?;
        // Signing is not a lease: fresh source/pin/time/certificate admission again.
        let (after, _) = crate::destruction_authority::prepare_with(
            vault,
            store,
            source,
            input,
            proof.current_time,
            |inventory, current, proof| admit(vault, inventory, current, proof, certificate),
        )
        .map_err(|_| Error::Contents)?;
        bind_job(&job, &after)?;
        if complete_job(vault, store, job_hash)?.as_ref() != Some(&job) {
            return Err(Error::Contents);
        }
        save(vault, store, &job, &exact)?;
        let saved =
            Self::historical_attestation(vault, store, source, job_hash)?.ok_or(Error::Contents)?;
        if saved != exact {
            return Err(Error::Contents);
        }
        Ok(saved)
    }
    /// Historical verification with byte-identical durability confirmation,
    /// never permission to sign. New target holdings veto
    /// reuse even if an old, correctly signed attestation is still present.
    pub fn historical_attestation(
        vault: &UnlockedVault,
        store: &mut dyn ReaderBlobStore,
        source: &dyn ArchiveSource,
        job_hash: ObjectHash,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(job) = complete_job(vault, store, job_hash)? else {
            return Ok(None);
        };
        let Some(exact) = load(vault, store, &job)? else {
            return Ok(None);
        };
        let ParsedArchiveObject::Trust(parsed) =
            ea_format::decode_exact_object(&exact).map_err(|_| Error::Contents)?
        else {
            return Err(Error::Contents);
        };
        let DecodedTrustPayloadV1::DeletionAttestation(fields) = parsed
            .value()
            .decoded_payload()
            .map_err(|_| Error::Contents)?
        else {
            return Err(Error::Contents);
        };
        let inventory = ArchiveInventory::build(source).map_err(|_| Error::Contents)?;
        if !inventory.quarantined().is_empty() || !inventory.format_errors().is_empty() {
            return Err(Error::Contents);
        }
        let historical = history(vault, &inventory, &job.instruction, fields.executed_at)
            .map_err(|_| Error::Contents)?;
        verify_exact(vault, &job, &exact, &historical)?;
        // A prior put can have written every byte and still failed its flush.
        // Confirm durability even on historical retry, without changing a single
        // ciphertext byte, nonce, signature, timestamp or authority decision.
        let address = Self::attestation_key(job_hash)?;
        let ciphertext = store.get(&address)?.ok_or(Error::Contents)?;
        store.put(&address, &ciphertext)?;
        if store.get(&address)?.as_deref() != Some(ciphertext.as_slice())
            || load(vault, store, &job)?.as_deref() != Some(exact.as_slice())
            || complete_job(vault, store, job_hash)?.as_ref() != Some(&job)
        {
            return Err(Error::Contents);
        }
        Ok(Some(exact))
    }
}
fn complete_job(
    vault: &UnlockedVault,
    store: &dyn ReaderBlobStore,
    hash: ObjectHash,
) -> Result<Option<Job>, Error> {
    if !store.inventory_is_complete() {
        return Err(Error::Contents);
    }
    let job = crate::cache_destruction::read(store, &vault.cache_key()?)?
        .into_iter()
        .find(|j| j.hash == hash && j.complete);
    if let Some(job) = &job
        && (!holdings(vault, store, &job.targets)?.is_empty()
            || !secondary_keys(store, &job.targets)?.is_empty())
    {
        return Err(Error::Contents);
    }
    Ok(job)
}
fn bind_job(job: &Job, proof: &VerifiedReaderDestructionInstruction) -> Result<(), Error> {
    if job.hash != proof.job_hash()
        || job.replica != proof.replica_id()
        || job.instruction != proof.exact_instruction_bytes()
        || job.targets
            != proof
                .targets()
                .iter()
                .map(|(hash, _)| *hash)
                .collect::<Vec<_>>()
    {
        return Err(Error::Contents);
    }
    Ok(())
}
fn eligible(
    vault: &UnlockedVault,
    certificate: Option<&ea_format::DeviceCertificateFieldsV1>,
    replica: ea_types::DeviceId,
) -> Result<(), &'static str> {
    let public = vault
        .audit_signing_key()
        .with_exposed(|key| CoseSigner::from_secret(SecretBytes::new(*key)))
        .public_key()
        .map_err(|_| INVALID)?;
    let cert = certificate.ok_or(INVALID)?;
    if cert.certificate_kind != CertificateKindV1::DeletionAttest
        || cert.device_id != replica
        || !cert.capabilities.iter().any(|cap| cap == "deletionAttest")
        || cert.signing_public_cose_key.as_deref()
            != Some(public.to_deterministic_cbor().as_slice())
        || cert.signing_key_thumbprint != Some(public.thumbprint())
        || cert.kem_public_cose_key.is_some()
        || cert.kem_key_thumbprint.is_some()
    {
        return Err(INVALID);
    }
    Ok(())
}
fn history(
    vault: &UnlockedVault,
    inventory: &ArchiveInventory,
    instruction: &[u8],
    now: UnixMillis,
) -> Result<HistoricalRegistryAuthority, &'static str> {
    let input = ReaderDestructionInstructionBytes::from_exact(instruction)?;
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
    let head = ea_verify::historical_registry_head(
        inventory,
        vault.pinned_anchor(),
        fields.registry_version,
        ObjectHash::from(fields.registry_head_hash),
        ChainSequence::new(fields.authorization_sequence),
        now,
    )
    .ok_or(INVALID)?;
    if !head.policy_fields().retention_policy.destruction_enabled
        || head
            .policy_fields()
            .retention_policy
            .eds_privacy_decision_document_hash
            .is_none()
        || fields.organization_id != vault.pinned_anchor().organization_id()
        || ea_trust::distinct_authority_subjects(
            auth.value().signatures(),
            auth.value().exact_digest_input(),
            &head,
            VerificationContext::destruction_approval_trust_digest,
        )
        .map_err(|_| INVALID)?
            < 2
    {
        return Err(INVALID);
    }
    Ok(head)
}
fn admit(
    vault: &UnlockedVault,
    inventory: &ArchiveInventory,
    current: &SelectedRegistryHead,
    proof: &VerifiedReaderDestructionInstruction,
    certificate: CertificateHash,
) -> Result<HistoricalRegistryAuthority, &'static str> {
    eligible(
        vault,
        current.active_certificate_fields(certificate),
        proof.replica_id(),
    )?;
    let historical = history(
        vault,
        inventory,
        proof.exact_instruction_bytes(),
        proof.current_time,
    )?;
    eligible(
        vault,
        historical.active_certificate_fields(certificate),
        proof.replica_id(),
    )?;
    Ok(historical)
}
fn verify_exact(
    vault: &UnlockedVault,
    job: &Job,
    exact: &[u8],
    historical: &HistoricalRegistryAuthority,
) -> Result<(), Error> {
    let input = ReaderDestructionInstructionBytes::from_exact(&job.instruction)
        .map_err(|_| Error::Contents)?;
    if object_hash(input.preflight_core) != job.hash {
        return Err(Error::Contents);
    }
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact).map_err(|_| Error::Contents)?
    else {
        return Err(Error::Contents);
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::DeletionAttestation(fields) =
        object.decoded_payload().map_err(|_| Error::Contents)?
    else {
        return Err(Error::Contents);
    };
    let ParsedArchiveObject::Trust(event) =
        ea_format::decode_exact_object(input.initiating_event).map_err(|_| Error::Contents)?
    else {
        return Err(Error::Contents);
    };
    let DecodedTrustPayloadV1::DestructionTransition(event) = event
        .value()
        .decoded_payload()
        .map_err(|_| Error::Contents)?
    else {
        return Err(Error::Contents);
    };
    if fields.replica_id != *job.replica.as_bytes()
        || fields.replica_kind != 1
        || fields.removed_object_hashes != job.removed
        || fields.result != 0
        || fields.backup_expiry_at.is_some()
        || fields.executed_at < event.executed_at
        || fields.executed_at.get() < 0
    {
        return Err(Error::Contents);
    }
    let [signature] = object.signatures() else {
        return Err(Error::Contents);
    };
    let certificate = ea_crypto::parse_cose_sign1(signature, &[])?
        .certificate_hash()
        .ok_or(Error::Contents)?;
    eligible(
        vault,
        historical.active_certificate_fields(certificate),
        job.replica,
    )
    .map_err(|_| Error::Contents)?;
    let context = VerificationContext::deletion_attestation_trust_digest(
        object.exact_digest_input(),
        input.authorization,
        certificate,
    )?;
    verify_cose_sign1(signature, historical, &context)?;
    Ok(())
}
fn save(
    vault: &UnlockedVault,
    store: &mut dyn ReaderBlobStore,
    job: &Job,
    exact: &[u8],
) -> Result<(), Error> {
    let address = ReaderCacheDestruction::attestation_key(job.hash)?;
    let mut plaintext = Vec::new();
    minicbor::Encoder::new(&mut plaintext)
        .array(5)
        .unwrap()
        .str("EINSATZARCHIV-READER-ATTESTATION-v1")
        .unwrap()
        .bytes(job.hash.as_bytes())
        .unwrap()
        .bytes(object_hash(&job.instruction).as_bytes())
        .unwrap()
        .bytes(job.replica.as_bytes())
        .unwrap()
        .bytes(exact)
        .unwrap();
    let mut nonce = [0; AEAD_NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|_| Error::Crypto(ea_crypto::CryptoError::LocalRng))?;
    let ciphertext = aead_seal(
        &vault.cache_key()?,
        &SecretBytes::new(nonce),
        SecretVec::new(plaintext),
        &crate::envelope::blob_aad(address.as_str().as_bytes()),
    )?;
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&ciphertext);
    store.put(&address, &bytes)?;
    if load(vault, store, job)?.as_deref() != Some(exact) {
        return Err(Error::Contents);
    }
    Ok(())
}
fn load(
    vault: &UnlockedVault,
    store: &dyn ReaderBlobStore,
    job: &Job,
) -> Result<Option<Vec<u8>>, Error> {
    let address = ReaderCacheDestruction::attestation_key(job.hash)?;
    let Some(bytes) = store.get(&address)? else {
        return Ok(None);
    };
    if bytes.len() < AEAD_NONCE_SIZE {
        return Err(Error::Contents);
    }
    let (nonce, ciphertext) = bytes.split_at(AEAD_NONCE_SIZE);
    let plaintext = aead_open(
        &vault.cache_key()?,
        &SecretBytes::new(nonce.try_into().map_err(|_| Error::Contents)?),
        ciphertext,
        &crate::envelope::blob_aad(address.as_str().as_bytes()),
    )?;
    plaintext.with_exposed(|bytes| {
        ea_cbor::validate(bytes, ea_cbor::ParserLimits::V1).map_err(|_| Error::Contents)?;
        let mut d = minicbor::Decoder::new(bytes);
        let value = (|| -> Result<_, minicbor::decode::Error> {
            if d.array()? != Some(5)
                || d.str()? != "EINSATZARCHIV-READER-ATTESTATION-v1"
                || d.bytes()? != job.hash.as_bytes()
                || d.bytes()? != object_hash(&job.instruction).as_bytes()
                || d.bytes()? != job.replica.as_bytes()
            {
                return Err(minicbor::decode::Error::message(
                    "invalid attestation binding",
                ));
            }
            let exact = d.bytes()?.to_vec();
            if d.position() != bytes.len() {
                return Err(minicbor::decode::Error::message("trailing bytes"));
            }
            Ok(exact)
        })()
        .map_err(|_| Error::Contents)?;
        Ok(Some(value))
    })
}
