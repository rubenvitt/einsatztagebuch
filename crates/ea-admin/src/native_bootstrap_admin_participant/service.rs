use super::store::{Journal, NativeBootstrapParticipantStore};
use super::*;
use crate::OperatorPresence as _;
use crate::native_provider::NativeSigningSlot;
use ea_key_provider::{KeyProvider, SecretPurpose};
use ea_operator::{OperatorError, OsAccountProvider as _};

pub(super) fn prepare(
    ceremony: &mut FileBootstrapStore,
    path: &Path,
    native: &Arc<NativeOperatorProvider>,
    identity: BootstrapAdminParticipantIdentity,
) -> Result<PreparedNativeBootstrapAdminParticipant, OperatorLifecycleError> {
    let state = crate::native_bootstrap_root::read_participant_context(ceremony)
        .map_err(OperatorLifecycleError::Ceremony)?;
    let organization = state.organization_id();
    let commitment = ea_crypto::operator_profile_commitment(
        organization,
        identity.subject,
        identity.name.as_str(),
        identity.function.as_str(),
        &identity.salt,
    );
    let account = native.os_account_binding_hash(organization, identity.device)?;
    current(native, organization, identity.device, account)?;
    let expected = Journal {
        state: state.persisted_image(),
        installation: native.installation_id(),
        account,
        identity,
        commitment,
        admin: None,
        operator: None,
    };
    // Bound input encoding is checked before SQLCipher's key unwrap or migrations.
    let _ = expected.encode()?;
    let store = NativeBootstrapParticipantStore::open(path, native)?;
    store.transaction(|tx| {
        match store::read(tx)? {
            Some(journal) => validate_inputs(&journal, &expected)?,
            None => {
                current(native, organization, expected.identity.device, account)?;
                if read_key(
                    native,
                    NativeSigningSlot::Admin,
                    SecretPurpose::WriterSigningKey,
                )?
                .is_some()
                    || read_key(
                        native,
                        NativeSigningSlot::Operator,
                        SecretPurpose::OperatorInstanceKey,
                    )?
                    .is_some()
                {
                    return Err(OperatorLifecycleError::FreshInstanceRequired);
                }
                store::insert(tx, &expected)?;
            }
        }
        Ok(())
    })?;
    // Each intent is durable before a helper can generate. BEGIN IMMEDIATE
    // serializes the freshly reread phase through native effect and result commit.
    // Any failure rolls back only that DB result; a possibly generated key is
    // deliberately left pending and cannot be adopted by a subsequent call.
    for admin in [true, false] {
        ceremony
            .ensure_lease()
            .map_err(OperatorLifecycleError::Ceremony)?;
        if crate::native_bootstrap_root::read_participant_context(ceremony)
            .map_err(OperatorLifecycleError::Ceremony)?
            .persisted_image()
            != expected.state
        {
            return Err(OperatorLifecycleError::JournalConflict);
        }
        store.transaction(|tx| {
            let mut journal = store::read(tx)?.ok_or(OperatorLifecycleError::JournalConflict)?;
            validate_inputs(&journal, &expected)?;
            current(native, organization, expected.identity.device, account)?;
            validate_recorded_keys(native, &journal)?;
            let (slot, purpose, recorded) = if admin {
                (
                    NativeSigningSlot::Admin,
                    SecretPurpose::WriterSigningKey,
                    journal.admin.as_ref(),
                )
            } else {
                if journal.admin.is_none() {
                    return Err(OperatorLifecycleError::JournalConflict);
                }
                (
                    NativeSigningSlot::Operator,
                    SecretPurpose::OperatorInstanceKey,
                    journal.operator.as_ref(),
                )
            };
            if recorded.is_some() {
                return Ok(());
            }
            if read_key(native, slot, purpose)?.is_some() {
                return Err(OperatorLifecycleError::FreshInstanceRequired);
            }
            let before = journal.encode()?;
            ceremony
                .ensure_lease()
                .map_err(OperatorLifecycleError::Ceremony)?;
            let provider = native.signing_provider(NativeSigningSlot::Admin);
            let generated = provider
                .generate(purpose, KeyProtectionProfileV1::OsWrapped)
                .map_err(key_error)?;
            if generated != provider.handle(purpose) {
                return Err(OperatorLifecycleError::TargetMismatch);
            }
            let public = read_key(native, slot, purpose)?
                .ok_or(OperatorLifecycleError::FreshInstanceRequired)?;
            if admin {
                journal.admin = Some(public);
            } else {
                journal.operator = Some(public);
            }
            validate_recorded_keys(native, &journal)?;
            current(native, organization, expected.identity.device, account)?;
            ceremony
                .ensure_lease()
                .map_err(OperatorLifecycleError::Ceremony)?;
            store::update(tx, &journal, &before)
        })?;
    }
    let journal =
        store.transaction(|tx| store::read(tx)?.ok_or(OperatorLifecycleError::JournalConflict))?;
    validate_inputs(&journal, &expected)?;
    validate_recorded_keys(native, &journal)?;
    let admin = journal
        .admin
        .as_ref()
        .ok_or(OperatorLifecycleError::JournalConflict)?;
    let operator = journal
        .operator
        .as_ref()
        .ok_or(OperatorLifecycleError::JournalConflict)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| OperatorLifecycleError::IdentityVerification)?;
    let mut challenge = b"EINSATZARCHIV-OPERATOR-PROVISION-v1".to_vec();
    challenge.extend_from_slice(organization.as_bytes());
    challenge.extend_from_slice(expected.identity.device.as_bytes());
    challenge.extend_from_slice(&nonce);
    current(native, organization, expected.identity.device, account)?;
    operator
        .verify_ed25519_strict(&challenge, &native.prove_presence_and_sign(&challenge)?)
        .map_err(|_| OperatorLifecycleError::Operator(OperatorError::PresenceProofInvalid))?;
    // An old SQLCipher connection does not prove that the currently held native
    // DB key still opens this file. Reopen through the same exact native handle.
    store.confirm(&journal.encode()?)?;
    if crate::native_bootstrap_root::read_participant_context(ceremony)
        .map_err(OperatorLifecycleError::Ceremony)?
        .persisted_image()
        != expected.state
    {
        return Err(OperatorLifecycleError::JournalConflict);
    }
    validate_recorded_keys(native, &journal)?;
    current(native, organization, expected.identity.device, account)?;
    store.ensure_path()?;
    ceremony
        .ensure_lease()
        .map_err(OperatorLifecycleError::Ceremony)?;
    Ok(PreparedNativeBootstrapAdminParticipant {
        organization,
        chain: state.chain_id(),
        device: expected.identity.device,
        subject: expected.identity.subject,
        admin: admin.clone(),
        operator: operator.clone(),
        account,
        commitment,
    })
}
fn validate_inputs(journal: &Journal, expected: &Journal) -> Result<(), OperatorLifecycleError> {
    if !journal.same_inputs(expected) {
        return Err(OperatorLifecycleError::JournalConflict);
    }
    Ok(())
}
fn key_error(error: ea_key_provider::KeyError) -> OperatorLifecycleError {
    OperatorLifecycleError::Store(ea_local_store::StoreError::Key(error))
}
fn current(
    native: &NativeOperatorProvider,
    organization: OrganizationId,
    device: DeviceId,
    account: Hash32,
) -> Result<(), OperatorLifecycleError> {
    native
        .ensure_session_active()
        .map_err(|_| OperatorLifecycleError::Readiness)?;
    if native.os_account_binding_hash(organization, device)? != account {
        return Err(OperatorLifecycleError::TargetMismatch);
    }
    native
        .ensure_session_active()
        .map_err(|_| OperatorLifecycleError::Readiness)
}
fn read_key(
    native: &Arc<NativeOperatorProvider>,
    slot: NativeSigningSlot,
    purpose: SecretPurpose,
) -> Result<Option<CanonicalPublicCoseKey>, OperatorLifecycleError> {
    let provider = native.signing_provider(NativeSigningSlot::Admin);
    let handle = provider.handle(purpose);
    let contains = provider.contains(&handle).map_err(key_error)?;
    let public = native
        .public_key(slot)
        .map_err(|_| OperatorLifecycleError::Readiness)?;
    if contains != public.is_some() {
        return Err(OperatorLifecycleError::TargetMismatch);
    }
    if let Some(public) = &public
        && (!matches!(public, CanonicalPublicCoseKey::Ed25519(_))
            || provider
                .reached_protection_profile(&handle)
                .map_err(key_error)?
                != KeyProtectionProfileV1::OsWrapped)
    {
        return Err(OperatorLifecycleError::TargetMismatch);
    }
    Ok(public)
}
fn validate_recorded_keys(
    native: &Arc<NativeOperatorProvider>,
    journal: &Journal,
) -> Result<(), OperatorLifecycleError> {
    for (expected, slot, purpose) in [
        (
            &journal.admin,
            NativeSigningSlot::Admin,
            SecretPurpose::WriterSigningKey,
        ),
        (
            &journal.operator,
            NativeSigningSlot::Operator,
            SecretPurpose::OperatorInstanceKey,
        ),
    ] {
        if let Some(expected) = expected
            && read_key(native, slot, purpose)?.as_ref() != Some(expected)
        {
            return Err(OperatorLifecycleError::FreshInstanceRequired);
        }
    }
    if journal
        .admin
        .as_ref()
        .zip(journal.operator.as_ref())
        .is_some_and(|(a, b)| a.thumbprint() == b.thumbprint())
    {
        return Err(OperatorLifecycleError::FreshInstanceRequired);
    }
    Ok(())
}
