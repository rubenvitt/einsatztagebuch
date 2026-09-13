//! Initial Root PoP using an already provisioned native Root slot.

mod step_two;
#[cfg(feature = "test-support")]
pub use step_two::complete_native_root_step_with_test_opener;
pub(crate) use step_two::read_participant_context;
pub use step_two::{complete_installed_native_root_step, complete_native_root_step};

use crate::{
    AdminError, BootstrapCoordinator, BootstrapStep, ProductionState, RootKeyMaterialV1,
    native_provider::{NativeOperatorProvider, NativeProviderError, NativeSigningSlot},
};
use ea_crypto::{
    CanonicalPublicCoseKey, ProtectedHeader, object_hash, trust_digest, verify_initial_root_pop,
};
use ea_format::{
    DecodedTrustPayloadV1, ExactObjectBytes, ParsedArchiveObject, RootCertificateFieldsV1,
    TrustObjectV1, TrustPayloadV1, decode_exact_object, encode_trust,
};
use ea_key_provider::{CoseSign1Bytes, KeyError, SecretPurpose};
use ea_types::RegistryVersion;
use std::sync::Arc;

/// Exact public certificate and matching bootstrap material. This is a PoP,
/// not an independently pinned anchor, completed setup or production release.
pub struct NativeInitialRootV1 {
    certificate: ExactObjectBytes,
    material: RootKeyMaterialV1,
}

impl NativeInitialRootV1 {
    #[must_use]
    pub fn exact_certificate(&self) -> &ExactObjectBytes {
        &self.certificate
    }

    #[must_use]
    pub fn material(&self) -> &RootKeyMaterialV1 {
        &self.material
    }
}

/// Prepares public Root material for this Coordinator's existing organization.
/// The explicit Registry version is preserved, without selecting an initial
/// host convention. No state or certificate is persisted and step 1 remains
/// unchanged; a later committing host must revalidate its persisted predecessor.
///
/// # Errors
/// Aborted, later-step or inconsistent predecessors reject before native I/O.
/// Otherwise returns the existing native initial-Root adapter's errors.
pub fn prepare_native_root_for_ceremony(
    coordinator: &BootstrapCoordinator<'_>,
    native: &Arc<NativeOperatorProvider>,
    initial_effective_version: RegistryVersion,
) -> Result<NativeInitialRootV1, AdminError> {
    let state = coordinator.state();
    if state.is_aborted() {
        return Err(AdminError::AnchorPreFieldChanged);
    }
    coordinator.re_enter(BootstrapStep::GenerateIds)?;
    if !state.has_only_early_root_fields()
        || state.has_root_material()
        || state.exact_pre_anchor_bytes().is_some()
        || state.sealed_pre_anchor_fingerprint().is_some()
        || state.exact_final_anchor_bytes().is_some()
        || state.production_state() != ProductionState::BlockedRecoveryTest
    {
        return Err(AdminError::BootstrapContextMismatch);
    }
    let public = native
        .public_key(NativeSigningSlot::Root)
        .map_err(native_error)?
        .ok_or(AdminError::Key(KeyError::NotFound))?;
    sign_native_initial_root(
        native,
        RootCertificateFieldsV1 {
            organization_id: coordinator.organization_id(),
            root_public_cose_key: public.to_deterministic_cbor(),
            root_key_thumbprint: public.thumbprint(),
            previous_root_certificate_object_hash: None,
            effective_from_registry_version: initial_effective_version,
        },
    )
}

/// Signs only the existing initial-Root certificate form with native presence.
/// No key is generated, replaced, exported or selected from another slot.
/// Account, installation and lock checks are the native provider's existing
/// checks on each public-key/sign call, including the final readback.
///
/// # Errors
/// Rejects malformed/rotated cores, mismatched embedded key or thumbprint,
/// unavailable native authority, invalid signature or changed Root slot.
pub fn sign_native_initial_root(
    native: &Arc<NativeOperatorProvider>,
    fields: RootCertificateFieldsV1,
) -> Result<NativeInitialRootV1, AdminError> {
    let payload = TrustPayloadV1::initial_root_certificate(fields.clone())?;
    let public = CanonicalPublicCoseKey::from_deterministic_cbor(&fields.root_public_cose_key)?;
    if !matches!(public, CanonicalPublicCoseKey::Ed25519(_))
        || public.thumbprint() != fields.root_key_thumbprint
    {
        return Err(AdminError::RootCertificateMismatch);
    }
    native.ensure_session_active().map_err(native_error)?;
    require_root_key(native, &public)?;
    let digest = trust_digest(payload.exact_digest_input());
    let protected = ProtectedHeader::initial_root(public.thumbprint());
    let signature = native
        .sign_raw(
            NativeSigningSlot::Root,
            &protected.sig_structure_bytes(digest.as_bytes()),
            true,
        )
        .map_err(native_error)?;
    let cose = CoseSign1Bytes::compose(&protected, digest.as_bytes(), &signature)?;
    // Verify against the exact embedded key, also catching replacement between
    // this adapter's lookup and sign_raw's own before/after lookups.
    verify_initial_root_pop(cose.as_bytes(), &public, digest.as_bytes())
        .map_err(|_| AdminError::RootSignatureMismatch)?;
    let certificate = encode_trust(&TrustObjectV1::new(
        payload,
        vec![cose.as_bytes().to_vec()],
    )?)?;
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(certificate.as_bytes())? else {
        return Err(AdminError::RootCertificateMismatch);
    };
    if !matches!(parsed.value().decoded_payload()?, DecodedTrustPayloadV1::InitialRoot(actual) if actual == fields)
    {
        return Err(AdminError::RootCertificateMismatch);
    }
    let material = RootKeyMaterialV1 {
        signing_handle: native
            .signing_provider(NativeSigningSlot::Root)
            .handle(SecretPurpose::WriterSigningKey),
        exact_public_cose_key: fields.root_public_cose_key,
        key_thumbprint: public.thumbprint(),
        certificate_object_hash: object_hash(certificate.as_bytes()),
    };
    require_root_key(native, &public)?;
    native.ensure_session_active().map_err(native_error)?;
    Ok(NativeInitialRootV1 {
        certificate,
        material,
    })
}

fn require_root_key(
    native: &NativeOperatorProvider,
    expected: &CanonicalPublicCoseKey,
) -> Result<(), AdminError> {
    let actual = native
        .public_key(NativeSigningSlot::Root)
        .map_err(native_error)?
        .ok_or(AdminError::Key(KeyError::NotFound))?;
    if &actual != expected {
        return Err(AdminError::RootCertificateMismatch);
    }
    Ok(())
}

fn native_error(_: NativeProviderError) -> AdminError {
    AdminError::Key(KeyError::ProviderUnavailable)
}
