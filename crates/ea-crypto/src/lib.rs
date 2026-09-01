#![forbid(unsafe_code)]

mod aead;
mod cose;
mod digest;
mod error;
mod hpke;
mod os_account;
mod secret;
mod thumbprint;

pub use aead::{
    AEAD_NONCE_SIZE, AEAD_OVERHEAD, CEK_SIZE, aead_open, aead_seal, checked_ciphertext_length,
};
pub use cose::{
    CertificateCapability, ChallengeResponseCoreV1, ContentType, CoseSigner, CoseVerifier,
    DeviceRegistrationRequestCoreV1, ParsedCoseSign1, ProtectedHeader, ReaderAckCoreV1,
    RecoveryVerificationContext, ResolvedSigner, SignerCertificateResolver, SignerRole,
    UnverifiedRfc3161TimeStampToken, VerificationContext, VerifiedRecoveryTest, VerifiedSigner,
    attach_rfc3161_ctt, cose_sign1_ctt_imprint, decode_challenge_response_core,
    decode_device_registration_request_core, decode_reader_ack_core,
    encode_challenge_response_core, encode_device_registration_request_core,
    encode_reader_ack_core, encode_signed_protocol_wrapper, parse_cose_sign1,
    validate_signer_certificate, validate_unsigned_protocol_core, verify_cose_sign1,
    verify_enrollment_pop, verify_initial_root_pop, verify_recovery_test, verify_technical_cursor,
    verify_web_bundle_trust_signature,
};
pub use digest::{
    GRANT_SUITE_ID, SUITE_ID, StreamingObjectHasher, SuiteV1, active_profile_pointer_digest,
    archive_inventory_digest, archive_profile_digest, authorized_trust_digest,
    bootstrap_anchor_hash, ciphertext_digest, entry_hash, finalization_preview_digest,
    grant_digest, grant_plan_digest, hpke_aad, hpke_info, object_hash, operator_profile_digest,
    payload_aad, receipt_digest, record_digest, recovery_test_digest, renewal_input_digest,
    trust_anchor_hash, trust_digest, verification_report_hash, web_bundle_hash,
};
pub use error::CryptoError;
pub use hpke::{
    HPKE_AEAD_ID, HPKE_ENCAPSULATED_KEY_SIZE, HPKE_KDF_ID, HPKE_KEM_ID, HPKE_MODE,
    HPKE_WRAPPED_CEK_SIZE, HpkeRecipientPrivateKey, HpkeRecipientPublicKey, HpkeSealed, hpke_open,
    hpke_seal,
};
pub use os_account::{
    linux_os_account_binding_hash, macos_os_account_binding_hash, windows_os_account_binding_hash,
};
pub use secret::{SecretBytes, SecretVec};
pub use thumbprint::CanonicalPublicCoseKey;
