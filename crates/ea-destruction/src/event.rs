use crate::{DestructionError as Error, VerifiedDestructionAuthorization, transition_allowed};
use ea_crypto::{VerificationContext, parse_cose_sign1, verify_cose_sign1};
use ea_format::{
    DecodedTrustPayloadV1, DestructionTransitionFieldsV1, ParsedArchiveObject, decode_exact_object,
};
use ea_trust::SelectedRegistryHead;
use ea_types::ObjectHash;

/// Signature-verified history, not proof that physical deletion was complete.
/// Executor admission additionally requires its verified preflight and inventory.
#[derive(Clone)]
pub struct VerifiedDestructionEvent {
    pub(crate) fields: DestructionTransitionFieldsV1,
    pub(crate) exact: Vec<u8>,
    pub(crate) hash: ObjectHash,
}
impl VerifiedDestructionEvent {
    pub const fn object_hash(&self) -> ObjectHash {
        self.hash
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    pub const fn fields(&self) -> &DestructionTransitionFieldsV1 {
        &self.fields
    }
}
/// Application trigger mapping (wire uint remains unchanged):
/// 0 operatorRequested, 1 executionStarted, 2 backupDeferred,
/// 3 managedRemovalConfirmed, 4 replicaUnreachable, 5 replicaReachable.
/// The reducer verifies the claim's signature; the executor proves its condition.
/// This entry point verifies historical v1 authority at the original
/// authorization head. Current continuation uses `DestructionRequestService::resume`
/// and its separate current native/time/certificate checks.
pub fn verify_event(
    exact: &[u8],
    auth: &VerifiedDestructionAuthorization,
    head: &SelectedRegistryHead,
) -> Result<VerifiedDestructionEvent, Error> {
    verify_event_at(exact, auth, head, head.preexisting_effective_now().value())
}

/// Verify immutable v1 signer authority at the authorization head, with a
/// separate trusted observation time. The caller performs current admission.
pub(crate) fn verify_event_at(
    exact: &[u8],
    auth: &VerifiedDestructionAuthorization,
    head: &SelectedRegistryHead,
    observed_at: ea_types::UnixMillis,
) -> Result<VerifiedDestructionEvent, Error> {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(exact)? else {
        return Err(Error::Format);
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::DestructionTransition(fields) = object.decoded_payload()? else {
        return Err(Error::Format);
    };
    if fields.destruction_id != auth.fields().destruction_id
        || fields.destruction_authorization_object_hash != auth.object_hash()
        || auth.fields().registry_version != head.registry_version()
        || auth.fields().registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        || auth.fields().authorization_sequence != head.proposed_sequence().get()
        || fields.executed_at > observed_at
        || fields.executed_at.get() < 0
        || !transition_allowed(fields.from_state, fields.to_state)
        || fields.trigger_code
            != match (fields.from_state, fields.to_state) {
                (Some(4), 1) => 5,
                _ => u64::from(fields.to_state),
            }
    {
        return Err(Error::Event);
    }
    let [signature] = object.signatures() else {
        return Err(Error::Signature);
    };
    let cert = parse_cose_sign1(signature, &[])?
        .certificate_hash()
        .ok_or(Error::Signature)?;
    let context = VerificationContext::destruction_transition_trust_digest(
        object.exact_digest_input(),
        auth.exact_bytes(),
        cert,
    )?;
    verify_cose_sign1(signature, head, &context)?;
    Ok(VerifiedDestructionEvent {
        fields,
        hash: parsed.object_hash(),
        exact: exact.to_vec(),
    })
}

/// Historical v1 signature attribution with an independent observation time.
/// Current physical/action admission remains a separate caller obligation.
pub fn verify_event_historical(
    exact: &[u8],
    auth: &VerifiedDestructionAuthorization,
    head: &ea_trust::HistoricalRegistryAuthority,
    observed_at: ea_types::UnixMillis,
) -> Result<VerifiedDestructionEvent, Error> {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(exact)? else {
        return Err(Error::Format);
    };
    let object = parsed.value();
    let DecodedTrustPayloadV1::DestructionTransition(fields) = object.decoded_payload()? else {
        return Err(Error::Format);
    };
    if fields.destruction_id != auth.fields().destruction_id
        || fields.destruction_authorization_object_hash != auth.object_hash()
        || auth.fields().registry_version != head.registry_version()
        || auth.fields().registry_head_hash.as_bytes() != head.registry_head_hash().as_bytes()
        || auth.fields().authorization_sequence != head.proposed_sequence().get()
        || fields.executed_at > observed_at
        || fields.executed_at.get() < 0
        || !transition_allowed(fields.from_state, fields.to_state)
        || fields.trigger_code
            != match (fields.from_state, fields.to_state) {
                (Some(4), 1) => 5,
                _ => u64::from(fields.to_state),
            }
    {
        return Err(Error::Event);
    }
    let [signature] = object.signatures() else {
        return Err(Error::Signature);
    };
    let cert = parse_cose_sign1(signature, &[])?
        .certificate_hash()
        .ok_or(Error::Signature)?;
    let context = VerificationContext::destruction_transition_trust_digest(
        object.exact_digest_input(),
        auth.exact_bytes(),
        cert,
    )?;
    verify_cose_sign1(signature, head, &context)?;
    Ok(VerifiedDestructionEvent {
        fields,
        hash: parsed.object_hash(),
        exact: exact.to_vec(),
    })
}
