use ea_types::{EntryHash, Hash32, KeyThumbprint, ObjectHash};
use minicbor::Encoder;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::SecretBytes;

pub const SUITE_ID: &str = ea_types::SUITE_ID_V1;
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
const ARCHIVE_PROFILE_DOMAIN: &[u8] = b"EINSATZARCHIV-ARCHIVE-PROFILE-v1";
const ARCHIVE_INVENTORY_DOMAIN: &[u8] = b"EINSATZARCHIV-ARCHIVE-INVENTORY-v1";
const ACTIVE_PROFILE_POINTER_DOMAIN: &[u8] = b"EINSATZARCHIV-ACTIVE-PROFILE-POINTER-v1";
const FINALIZATION_PREVIEW_DOMAIN: &[u8] = b"EINSATZARCHIV-FINALIZATION-PREVIEW-v1";

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

// `archiveProfileHash` ueber die deterministischen
// `archive-backend-profile-core-v1`-Bytes. Das Urbild traegt WEDER einen
// Ausgabepfad NOCH einen Hostnamen NOCH einen Kontonamen
// (`schemas/archive/v1/archive-profile.cddl`), damit der Wert ueber
// Organisationsgrenzen hinweg reproduzierbar bleibt. Genau diese Werte stehen
// in `allowed-archive-profile-hashes` des Root-signierten `policy-core-v1`.
digest_fn!(archive_profile_digest, ARCHIVE_PROFILE_DOMAIN);
// `inventoryHash` ueber die deterministischen `archive-inventory-list-v1`-Bytes.
digest_fn!(archive_inventory_digest, ARCHIVE_INVENTORY_DOMAIN);
// `activePointerHash` ueber die deterministischen
// `active-profile-pointer-core-v1`-Bytes.
digest_fn!(active_profile_pointer_digest, ACTIVE_PROFILE_POINTER_DOMAIN);
// `previewHash` ueber die deterministischen
// `finalization-preview-core-v1`-Bytes. Das Urbild deckt alles, worauf
// `finalize` handelt, und NICHTS, was ein CSPRNG erzeugt: es wird am Ende von
// Spec-Schritt 5 gerechnet, also VOR der einmaligen Ziehung von Sequenz,
// UUIDv7, CEK und AEAD-Nonce, damit `finalize` es unter dem Writer-Lock Byte
// fuer Byte nachrechnen kann. Der Wert wandert nie in Archivbytes.
digest_fn!(finalization_preview_digest, FINALIZATION_PREVIEW_DOMAIN);

#[must_use]
pub fn object_hash(exact_object_bytes: &[u8]) -> ObjectHash {
    ObjectHash::from(sha256_parts(&[OBJECT_DOMAIN, exact_object_bytes]))
}

/// Derselbe Objekthash, aber STUECKWEISE.
///
/// Der Sync-Server nimmt Objektbytes als Strom entgegen und muss sie
/// groessenbegrenzt hashen, ohne den vollen Koerper zu halten
/// (`design.md` §13.3, Schritt 1). Ohne diesen Typ muesste er dafuer entweder
/// puffern oder `OBJECT_DOMAIN` abschreiben — und eine zweite Kopie einer
/// Domaenenkonstante ist genau die Art Duplikat, die spaeter auseinanderlaeuft.
/// Deshalb steht der Streamer HIER, neben der Konstante, die er verwendet.
///
/// [`Self::finish`] liefert bitgleich das, was [`object_hash`] ueber die
/// aneinandergehaengten Stuecke liefert; `crates/ea-crypto/tests/suite_v1.rs`
/// pinnt genau diese Gleichheit.
pub struct StreamingObjectHasher(Sha256);

impl StreamingObjectHasher {
    #[must_use]
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(OBJECT_DOMAIN);
        Self(hasher)
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    #[must_use]
    pub fn finish(self) -> ObjectHash {
        let digest: [u8; 32] = self.0.finalize().into();
        ObjectHash::from(
            Hash32::try_from(digest.as_slice()).expect("SHA-256 always emits exactly 32 bytes"),
        )
    }
}

impl Default for StreamingObjectHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 ueber die kanonischen Bytes eines Verifikationsberichts.
///
/// BEWUSST OHNE Domain-Trennung — als einzige Hashfunktion dieses Moduls. Die
/// Formel ist als `reportHash = SHA-256(canonical report bytes without
/// reportHash/signature)` in
/// `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-1-trust-core-format.md`
/// (Task 10) gepinnt und wird von Werkzeugen ausserhalb dieses Workspaces
/// nachgerechnet; ein Domainpraefix waere dort nicht reproduzierbar.
///
/// Die Trennung entsteht stattdessen aus dem Urbild selbst: es ist ein
/// vollstaendiges JSON-Dokument, das mit `{"schemaId":"ea.verification-report/v1"`
/// beginnt. Kein anderes Urbild dieses Workspaces hat diese Gestalt, denn alle
/// uebrigen sind CBOR mit vorangestellter Domain. Diese Funktion darf deshalb
/// AUSSCHLIESSLICH auf Berichtsbytes angewandt werden.
///
/// Sie lebt hier und nicht in `ea-verify`, damit `ea-verify` kein rohes `sha2`
/// einbindet.
#[must_use]
pub fn verification_report_hash(canonical_bytes: &[u8]) -> Hash32 {
    sha256_parts(&[canonical_bytes])
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
    recovery_test_digest_ref(&challenge, key_thumbprint)
}

pub(crate) fn recovery_test_digest_ref(
    challenge: &SecretBytes<32>,
    key_thumbprint: KeyThumbprint,
) -> Hash32 {
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
