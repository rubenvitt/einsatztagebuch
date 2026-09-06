//! Durable target intent. A restart keeps the original Registry timestamps and
//! exact authorization operation; it cannot turn a lost reply into a new intent.
use super::*;
use ea_format::DecodedTrustPayloadV1;
use ea_local_store::StoreValue;

impl OperatorBindingService<'_> {
    pub(crate) fn revocation_target(
        &self,
        request: &RevokeOperatorRequest<'_>,
        proof: &OperatorSessionProof,
    ) -> Result<RegistryEventFieldsV1, OperatorLifecycleError> {
        self.head
            .active_operator_binding_fields(request.binding_object_hash)
            .ok_or(OperatorError::BindingNotActive)?;
        let candidate = self.registry_event(
            request.window,
            RegistryChangeV1::Target {
                target_kind: 1,
                object_hash: request.binding_object_hash,
            },
        )?;
        let payload = OperatorTrustTarget::Registry(candidate.clone())
            .payload(ObjectHash::from(Hash32::ZERO))?;
        request.database.transaction(|tx| {
            tx.execute(
                "INSERT INTO operator_revocation_intent(binding_hash,chain_id,admin_binding_hash,admin_certificate_hash,target_payload) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(binding_hash) DO NOTHING",
                &[
                    blob(request.binding_object_hash.as_bytes()),
                    blob(self.head.chain_id().as_bytes()),
                    blob(proof.binding_object_hash().as_bytes()),
                    blob(self.local_device.certificate.as_bytes()),
                    blob(payload.exact_digest_input()),
                ],
            )?;
            let row = tx.query_row(
                "SELECT chain_id,admin_binding_hash,admin_certificate_hash,target_payload FROM operator_revocation_intent WHERE binding_hash=?1",
                &[blob(request.binding_object_hash.as_bytes())],
            )?.ok_or(OperatorLifecycleError::JournalConflict)?;
            if row.blob(0)? != self.head.chain_id().as_bytes()
                || row.blob(1)? != proof.binding_object_hash().as_bytes()
                || row.blob(2)? != self.local_device.certificate.as_bytes()
            {
                return Err(OperatorLifecycleError::JournalConflict);
            }
            let saved = TrustPayloadV1::from_exact_digest_input(row.blob(3)?)?;
            let DecodedTrustPayloadV1::RegistryEvent(event) = saved.decoded_payload()? else {
                return Err(OperatorLifecycleError::JournalConflict);
            };
            let fields = event.fields();
            let mut expected = candidate.clone();
            expected.issued_at = fields.issued_at;
            expected.not_before = fields.not_before;
            if *fields != expected
                || fields.issued_at != fields.not_before
                || fields.issued_at > candidate.issued_at
                || event.authorization_object_hash() != ObjectHash::from(Hash32::ZERO)
            {
                return Err(OperatorLifecycleError::JournalConflict);
            }
            Ok(fields.clone())
        })
    }
}

fn blob(bytes: &[u8]) -> StoreValue {
    StoreValue::Blob(bytes.to_vec())
}
