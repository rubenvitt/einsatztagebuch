use ea_types::{EntryHash, Hash32, KeyThumbprint, ObjectHash};
use minicbor::Encoder;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::SecretBytes;

pub const SUITE_ID: &str = "EINSATZARCHIV-SUITE-1";
pub const GRANT_SUITE_ID: &str = "EINSATZARCHIV-HPKE-1";

pub struct SuiteV1;

impl SuiteV1 {
    pub const SUITE_ID: &'static str = SUITE_ID;
    pub const GRANT_SUITE_ID: &'static str = GRANT_SUITE_ID;
}

const CIPHERTEXT_DOMAIN: &[u8] = b"EINSATZARCHIV-CIPHERTEXT-v1";
const RECORD_DOMAIN: &[u8] = b"EINSATZARCHIV-RECORD-v1";
const PACKAGE_DOMAIN: &[u8] = b"EINSATZARCHIV-PACKAGE-v1";
const OBJECT_DOMAIN: &[u8] = b"EINSATZARCHIV-OBJECT-v1";
const GRANT_PLAN_DOMAIN: &[u8] = b"EINSATZARCHIV-GRANT-PLAN-v1";
const GRANT_DOMAIN: &[u8] = b"EINSATZARCHIV-GRANT-v1";
const RECEIPT_DOMAIN: &[u8] = b"EINSATZARCHIV-RECEIPT-v1";
const TRUST_DOMAIN: &[u8] = b"EINSATZARCHIV-TRUST-OBJECT-v1";
const AUTHORIZED_TRUST_DOMAIN: &[u8] = b"EINSATZARCHIV-ADMIN-AUTHORIZED-TRUST-v1";
const RENEWAL_INPUT_DOMAIN: &[u8] = b"EINSATZARCHIV-EVIDENCE-RENEWAL-INPUT-v1";
const ANCHOR_PRE_DOMAIN: &[u8] = b"EINSATZARCHIV-TRUST-ANCHOR-PRE-v1";
const ANCHOR_DOMAIN: &[u8] = b"EINSATZARCHIV-TRUST-ANCHOR-v1";
const OPERATOR_PROFILE_DOMAIN: &[u8] = b"EINSATZARCHIV-OPERATOR-PROFILE-v1";
const RECOVERY_TEST_DOMAIN: &[u8] = b"EINSATZARCHIV-RECOVERY-TEST-v1";

pub(crate) fn sha256_parts(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Hash32::try_from(bytes.as_slice()).expect("SHA-256 always emits exactly 32 bytes")
}

macro_rules! digest_fn {
    ($name:ident, $domain:ident) => {
        #[must_use]
        pub fn $name(bytes: &[u8]) -> Hash32 {
            sha256_parts(&[$domain, bytes])
        }
    };
}

digest_fn!(ciphertext_digest, CIPHERTEXT_DOMAIN);
digest_fn!(record_digest, RECORD_DOMAIN);
digest_fn!(grant_plan_digest, GRANT_PLAN_DOMAIN);
digest_fn!(grant_digest, GRANT_DOMAIN);
digest_fn!(receipt_digest, RECEIPT_DOMAIN);
digest_fn!(trust_digest, TRUST_DOMAIN);
digest_fn!(authorized_trust_digest, AUTHORIZED_TRUST_DOMAIN);
digest_fn!(renewal_input_digest, RENEWAL_INPUT_DOMAIN);
digest_fn!(bootstrap_anchor_hash, ANCHOR_PRE_DOMAIN);
digest_fn!(trust_anchor_hash, ANCHOR_DOMAIN);
digest_fn!(operator_profile_digest, OPERATOR_PROFILE_DOMAIN);

#[must_use]
pub fn object_hash(exact_object_bytes: &[u8]) -> ObjectHash {
    ObjectHash::from(sha256_parts(&[OBJECT_DOMAIN, exact_object_bytes]))
}

#[must_use]
pub fn entry_hash(record_digest: Hash32, exact_writer_cose: &[u8]) -> EntryHash {
    EntryHash::from(sha256_parts(&[
        PACKAGE_DOMAIN,
        record_digest.as_bytes(),
        exact_writer_cose,
    ]))
}

#[must_use]
pub fn recovery_test_digest(challenge: SecretBytes<32>, key_thumbprint: KeyThumbprint) -> Hash32 {
    let mut context = Vec::with_capacity(70);
    Encoder::new(&mut context)
        .array(3)
        .and_then(|encoder| encoder.u64(1))
        .and_then(|encoder| encoder.bytes(challenge.expose()))
        .and_then(|encoder| encoder.bytes(key_thumbprint.as_bytes()))
        .expect("encoding the fixed recovery-test context into Vec cannot fail");
    let context = Zeroizing::new(context);
    sha256_parts(&[RECOVERY_TEST_DOMAIN, context.as_slice()])
}

fn domain_context(domain: &[u8], deterministic_cbor: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len().saturating_add(deterministic_cbor.len()));
    output.extend_from_slice(domain);
    output.extend_from_slice(deterministic_cbor);
    output
}

#[must_use]
pub fn payload_aad(manifest_core_cbor: &[u8]) -> Vec<u8> {
    domain_context(b"EINSATZARCHIV-AAD-v1", manifest_core_cbor)
}

#[must_use]
pub fn hpke_info(grant_context_cbor: &[u8]) -> Vec<u8> {
    domain_context(b"EINSATZARCHIV-HPKE-INFO-v1", grant_context_cbor)
}

#[must_use]
pub fn hpke_aad(grant_context_cbor: &[u8]) -> Vec<u8> {
    domain_context(b"EINSATZARCHIV-HPKE-AAD-v1", grant_context_cbor)
}
