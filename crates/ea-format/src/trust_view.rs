use ea_types::ObjectHash;

use crate::{
    DeletionAttestationFieldsV1, DestructionAuthorizationFieldsV1, DestructionTransitionFieldsV1,
    DeviceCertificateFieldsV1, FormatError, GrantAuthorizationFieldsV1, OperatorBindingFieldsV1,
    OrganizationAdminAuthorizationFieldsV1, PolicyFieldsV1, RegistryEventFieldsV1,
    RootCertificateFieldsV1, TrustObjectV1, TrustPayloadV1, TrustSubtypeV1, WebBundleReleaseCoreV1,
    WebBundleRevocationCoreV1, WriterTransitionFieldsV1,
    etb::{
        decode_admin_authorization, decode_authorized_parts, decode_deletion_attestation,
        decode_destruction_authorization, decode_destruction_transition, decode_device_core,
        decode_grant_authorization, decode_operator_core, decode_policy, decode_registry_event,
        decode_root_core, decode_web_bundle_release, decode_web_bundle_revocation,
        decode_writer_transition, payload_wraps_core,
    },
};

pub struct AuthorizedTrustCoreV1<T> {
    fields: T,
    authorization_object_hash: ObjectHash,
    exact_core: Vec<u8>,
    exact_digest_input: Vec<u8>,
}

impl<T> AuthorizedTrustCoreV1<T> {
    #[must_use]
    pub const fn fields(&self) -> &T {
        &self.fields
    }

    #[must_use]
    pub const fn authorization_object_hash(&self) -> ObjectHash {
        self.authorization_object_hash
    }

    #[must_use]
    pub fn exact_core(&self) -> &[u8] {
        &self.exact_core
    }

    #[must_use]
    pub fn exact_digest_input(&self) -> &[u8] {
        &self.exact_digest_input
    }
}

pub enum DecodedTrustPayloadV1 {
    InitialRoot(RootCertificateFieldsV1),
    InitialAdminDevice(DeviceCertificateFieldsV1),
    InitialAdminOperatorBinding(OperatorBindingFieldsV1),
    AuthorizedRoot(AuthorizedTrustCoreV1<RootCertificateFieldsV1>),
    AuthorizedDevice(AuthorizedTrustCoreV1<DeviceCertificateFieldsV1>),
    AuthorizedOperatorBinding(AuthorizedTrustCoreV1<OperatorBindingFieldsV1>),
    OrganizationAdminAuthorization(OrganizationAdminAuthorizationFieldsV1),
    RegistryEvent(AuthorizedTrustCoreV1<RegistryEventFieldsV1>),
    Policy(AuthorizedTrustCoreV1<PolicyFieldsV1>),
    WriterTransition(AuthorizedTrustCoreV1<WriterTransitionFieldsV1>),
    GrantAuthorization(GrantAuthorizationFieldsV1),
    DestructionAuthorization(DestructionAuthorizationFieldsV1),
    DestructionTransition(DestructionTransitionFieldsV1),
    DeletionAttestation(DeletionAttestationFieldsV1),
    WebBundleRelease(WebBundleReleaseCoreV1),
    WebBundleRevocation(WebBundleRevocationCoreV1),
}

impl TrustPayloadV1 {
    /// Dieselbe Deutung wie [`TrustObjectV1::decoded_payload`], aber VOR der
    /// Signatur.
    ///
    /// Die Bedeutung einer Nutzlast haengt nicht an ihren Signaturen: beide
    /// Wege rufen dieselbe Dekodierung ueber dieselben drei Eingaben. Ein
    /// Verbraucher, der ein Zielobjekt erst noch unterschreiben laesst, hat
    /// genau diesen Stand in der Hand — [`TrustObjectV1::new`] weist eine
    /// leere Signaturliste fuer JEDEN Subtyp ab, ein unsigniertes
    /// [`TrustObjectV1`] gibt es also nicht.
    ///
    /// # Errors
    ///
    /// [`FormatError`] fuer eine Nutzlast, die ihre eigene Grammatik nicht
    /// erfuellt.
    pub fn decoded_payload(&self) -> Result<DecodedTrustPayloadV1, FormatError> {
        decode_payload(
            self.subtype(),
            self.exact_payload(),
            self.exact_digest_input(),
        )
    }
}

impl TrustObjectV1 {
    pub fn decoded_payload(&self) -> Result<DecodedTrustPayloadV1, FormatError> {
        decode_payload(
            self.subtype(),
            self.exact_payload(),
            self.exact_digest_input(),
        )
    }
}

fn decode_payload(
    subtype: TrustSubtypeV1,
    exact_payload: &[u8],
    exact_digest_input: &[u8],
) -> Result<DecodedTrustPayloadV1, FormatError> {
    match subtype {
        TrustSubtypeV1::RootCertificate if payload_wraps_core(exact_payload)? => {
            Ok(DecodedTrustPayloadV1::AuthorizedRoot(decode_authorized(
                exact_payload,
                exact_digest_input,
                |core| decode_root_core(core, false),
            )?))
        }
        TrustSubtypeV1::RootCertificate => Ok(DecodedTrustPayloadV1::InitialRoot(
            decode_root_core(exact_payload, true)?,
        )),
        TrustSubtypeV1::DeviceCertificate if payload_wraps_core(exact_payload)? => {
            Ok(DecodedTrustPayloadV1::AuthorizedDevice(decode_authorized(
                exact_payload,
                exact_digest_input,
                |core| decode_device_core(core, None),
            )?))
        }
        TrustSubtypeV1::DeviceCertificate => Ok(DecodedTrustPayloadV1::InitialAdminDevice(
            decode_device_core(exact_payload, Some(2))?,
        )),
        TrustSubtypeV1::OperatorBinding if payload_wraps_core(exact_payload)? => {
            Ok(DecodedTrustPayloadV1::AuthorizedOperatorBinding(
                decode_authorized(exact_payload, exact_digest_input, |core| {
                    decode_operator_core(core, None)
                })?,
            ))
        }
        TrustSubtypeV1::OperatorBinding => Ok(DecodedTrustPayloadV1::InitialAdminOperatorBinding(
            decode_operator_core(exact_payload, Some(2))?,
        )),
        TrustSubtypeV1::OrganizationAdminAuthorization => {
            Ok(DecodedTrustPayloadV1::OrganizationAdminAuthorization(
                decode_admin_authorization(exact_payload)?,
            ))
        }
        TrustSubtypeV1::RegistryEvent => Ok(DecodedTrustPayloadV1::RegistryEvent(
            decode_authorized(exact_payload, exact_digest_input, decode_registry_event)?,
        )),
        TrustSubtypeV1::Policy => Ok(DecodedTrustPayloadV1::Policy(decode_authorized(
            exact_payload,
            exact_digest_input,
            decode_policy,
        )?)),
        TrustSubtypeV1::WriterTransition => Ok(DecodedTrustPayloadV1::WriterTransition(
            decode_authorized(exact_payload, exact_digest_input, decode_writer_transition)?,
        )),
        TrustSubtypeV1::GrantAuthorization => Ok(DecodedTrustPayloadV1::GrantAuthorization(
            decode_grant_authorization(exact_payload)?,
        )),
        TrustSubtypeV1::DestructionAuthorization => {
            Ok(DecodedTrustPayloadV1::DestructionAuthorization(
                decode_destruction_authorization(exact_payload)?,
            ))
        }
        TrustSubtypeV1::DestructionTransition => Ok(DecodedTrustPayloadV1::DestructionTransition(
            decode_destruction_transition(exact_payload)?,
        )),
        TrustSubtypeV1::DeletionAttestation => Ok(DecodedTrustPayloadV1::DeletionAttestation(
            decode_deletion_attestation(exact_payload)?,
        )),
        TrustSubtypeV1::WebBundleRelease => Ok(DecodedTrustPayloadV1::WebBundleRelease(
            decode_web_bundle_release(exact_payload)?,
        )),
        TrustSubtypeV1::WebBundleRevocation => Ok(DecodedTrustPayloadV1::WebBundleRevocation(
            decode_web_bundle_revocation(exact_payload)?,
        )),
    }
}

fn decode_authorized<T>(
    input: &[u8],
    exact_digest_input: &[u8],
    decode_core: impl FnOnce(&[u8]) -> Result<T, FormatError>,
) -> Result<AuthorizedTrustCoreV1<T>, FormatError> {
    let parts = decode_authorized_parts(input)?;
    let fields = decode_core(parts.exact_core)?;
    Ok(AuthorizedTrustCoreV1 {
        fields,
        authorization_object_hash: parts.authorization_object_hash,
        exact_core: parts.exact_core.to_vec(),
        exact_digest_input: exact_digest_input.to_vec(),
    })
}
