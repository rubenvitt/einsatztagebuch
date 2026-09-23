//! Die Kryptobausteine des Reader-Key-Escrows (v1.1-Profil §3.1, §4).
//!
//! Drei Aussagen:
//!
//! 1. `reader_key_escrow_core_hash` ist SHA-256 über die Profil-Domäne gefolgt
//!    vom exakten Core — gegen einen Wert, der AUSSERHALB dieses Codes
//!    gerechnet wurde (`printf … | shasum -a 256`), sonst wäre der KAT
//!    selbstreferenziell.
//! 2. `verify_reader_key_escrow_trust_signature` prüft die EINE Wurzelsignatur
//!    direkt gegen den gepinnten Anker, ohne `VerificationContext` und ohne
//!    Katalog, und nimmt nur einen Escrow-Digest-Eingang an.
//! 3. `root_trust_bindings` bleibt unberührt: der Wurzelpfad der
//!    registrywirksamen Objekte weist einen Escrow-Eingang ab.
//!
//! Die Signaturen entstehen hier von Hand: für diese Familien gibt es bewusst
//! keine `CoseSigner`-Methode (keine Emission vor Scheibe f).

use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, CryptoError, ProtectedHeader, SecretBytes,
    VerificationContext, reader_key_escrow_core_hash, trust_digest,
    verify_reader_key_escrow_trust_signature,
};
use ea_types::CertificateHash;
use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::Encoder;

/// Ein Escrow-Core mit festen Füllbytes, von Hand kodiert (302 Byte).
///
/// Dieselben Werte wie `hand::escrow_core_items` in
/// `crates/ea-format/tests/reader_key_escrow.rs`.
const ESCROW_CORE_HEX: &str = concat!(
    "8e015031313131313131313131313131313131582032323232323232323232323232",
    "32323232323232323232323232323232323232503333333333333333333333333333",
    "33330458203535353535353535353535353535353535353535353535353535353535",
    "35353506582037373737373737373737373737373737373737373737373737373737",
    "37373737582038383838383838383838383838383838383838383838383838383838",
    "38383838582039393939393939393939393939393939393939393939393939393939",
    "3939393958303a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a",
    "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a1b0000018bcfe5680058203b3b3b",
    "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b80",
);

/// SHA-256 über die ASCII-Domäne des Profils gefolgt von [`ESCROW_CORE_HEX`],
/// gerechnet mit `shasum -a 256` und unabhängig mit Python `hashlib`.
const ESCROW_CORE_HASH_HEX: &str =
    "049541241e95688596632f3f0e8ccefa356cc89d9f3e8b85bbe7fdff9f5197ff";

/// Der Seed der Testwurzel.
const ROOT_SEED: [u8; 32] = [0xa0; 32];

/// Der Zertifikatshash, unter dem die Wurzel signiert.
const ROOT_CERTIFICATE_HASH: [u8; 32] = [0x92; 32];

fn escrow_core() -> Vec<u8> {
    hex::decode(ESCROW_CORE_HEX).unwrap()
}

fn root_public_key(seed: [u8; 32]) -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
        .unwrap()
}

fn certificate_hash(bytes: [u8; 32]) -> CertificateHash {
    CertificateHash::try_from(bytes.as_slice()).unwrap()
}

/// `[subtype, nutzlast]`, von Hand.
fn digest_input(literal: &str, exact_payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    Encoder::new(&mut input)
        .array(2)
        .unwrap()
        .str(literal)
        .unwrap();
    input.extend_from_slice(exact_payload);
    input
}

/// Die Escrow-Nutzlast `[core, approval-object-hash]`.
fn escrow_payload(exact_core: &[u8]) -> Vec<u8> {
    let mut payload = vec![0x82];
    payload.extend_from_slice(exact_core);
    Encoder::new(&mut payload).bytes(&[0x3c; 32]).unwrap();
    payload
}

/// Der Escrow-Core mit dem Wurzelabdruck des gegebenen Seeds an Position 13.
fn escrow_core_for_root(seed: [u8; 32]) -> Vec<u8> {
    let mut core = escrow_core();
    let thumbprint = root_public_key(seed).thumbprint();
    let at = core.len() - 33;
    core[at..at + 32].copy_from_slice(thumbprint.as_bytes());
    core
}

fn escrow_digest_input(seed: [u8; 32]) -> Vec<u8> {
    digest_input(
        "readerKeyEscrow",
        &escrow_payload(&escrow_core_for_root(seed)),
    )
}

/// Eine Normalprofil-Signatur über `trust_digest(input)`.
fn signed_normal(seed: [u8; 32], certificate: [u8; 32], exact_digest_input: &[u8]) -> Vec<u8> {
    let digest = trust_digest(exact_digest_input);
    let protected = ProtectedHeader::normal(
        ContentType::TrustDigest,
        root_public_key(seed).thumbprint(),
        certificate_hash(certificate),
    );
    let signature = SigningKey::from_bytes(&seed)
        .sign(&protected.sig_structure_bytes(digest.as_bytes()))
        .to_bytes();
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .tag(minicbor::data::Tag::new(18))
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&protected.to_deterministic_cbor())
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(digest.as_bytes())
        .unwrap()
        .bytes(&signature)
        .unwrap();
    encoded
}

#[test]
fn the_escrow_core_hash_matches_an_externally_computed_answer() {
    assert_eq!(escrow_core().len(), 302);
    assert_eq!(
        hex::encode(reader_key_escrow_core_hash(&escrow_core()).as_bytes()),
        ESCROW_CORE_HASH_HEX
    );
    // Die Domäne trennt: derselbe Core unter dem Trust-Digest ergibt etwas
    // anderes.
    assert!(
        reader_key_escrow_core_hash(&escrow_core()).as_bytes()
            != trust_digest(&escrow_core()).as_bytes()
    );
}

#[test]
fn a_root_signature_over_the_escrow_digest_input_verifies_directly() {
    let input = escrow_digest_input(ROOT_SEED);
    let signature = signed_normal(ROOT_SEED, ROOT_CERTIFICATE_HASH, &input);
    verify_reader_key_escrow_trust_signature(
        &signature,
        &root_public_key(ROOT_SEED),
        certificate_hash(ROOT_CERTIFICATE_HASH),
        &input,
    )
    .unwrap();
}

#[test]
fn a_foreign_key_certificate_or_digest_is_a_signer_mismatch() {
    let input = escrow_digest_input(ROOT_SEED);
    let signature = signed_normal(ROOT_SEED, ROOT_CERTIFICATE_HASH, &input);

    // Ein fremder Anker.
    assert_eq!(
        verify_reader_key_escrow_trust_signature(
            &signature,
            &root_public_key([0xa1; 32]),
            certificate_hash(ROOT_CERTIFICATE_HASH),
            &input,
        )
        .unwrap_err(),
        CryptoError::SignerMismatch
    );
    // Ein fremder Zertifikatshash.
    assert_eq!(
        verify_reader_key_escrow_trust_signature(
            &signature,
            &root_public_key(ROOT_SEED),
            certificate_hash([0x93; 32]),
            &input,
        )
        .unwrap_err(),
        CryptoError::SignerMismatch
    );
    // Die Signatur eines anderen Escrows.
    let mut other_core = escrow_core_for_root(ROOT_SEED);
    other_core[3] ^= 0x01;
    let other_input = digest_input("readerKeyEscrow", &escrow_payload(&other_core));
    assert_eq!(
        verify_reader_key_escrow_trust_signature(
            &signature,
            &root_public_key(ROOT_SEED),
            certificate_hash(ROOT_CERTIFICATE_HASH),
            &other_input,
        )
        .unwrap_err(),
        CryptoError::SignerMismatch
    );
    // Der Core nennt eine andere Wurzel als die, die signiert hat.
    let foreign_core_input = escrow_digest_input([0xa1; 32]);
    let signature = signed_normal(ROOT_SEED, ROOT_CERTIFICATE_HASH, &foreign_core_input);
    assert_eq!(
        verify_reader_key_escrow_trust_signature(
            &signature,
            &root_public_key(ROOT_SEED),
            certificate_hash(ROOT_CERTIFICATE_HASH),
            &foreign_core_input,
        )
        .unwrap_err(),
        CryptoError::SignerMismatch
    );
}

#[test]
fn only_an_escrow_digest_input_is_admissible() {
    let core = escrow_core_for_root(ROOT_SEED);
    let three = {
        let mut payload = vec![0x83];
        payload.extend_from_slice(&core);
        Encoder::new(&mut payload)
            .bytes(&[0x3c; 32])
            .unwrap()
            .bytes(&[0x3d; 32])
            .unwrap();
        payload
    };
    let short_core = {
        let mut shortened = vec![0x8d];
        shortened.extend_from_slice(&core[1..core.len() - 1]);
        shortened
    };
    for (label, input) in [
        (
            "neighbour subtype",
            digest_input("readerKeyEscrowApproval", &escrow_payload(&core)),
        ),
        (
            "web bundle subtype",
            digest_input("webBundleRelease", &escrow_payload(&core)),
        ),
        (
            "three element payload",
            digest_input("readerKeyEscrow", &three),
        ),
        ("bare core", digest_input("readerKeyEscrow", &core)),
        (
            "core without extension slot",
            digest_input("readerKeyEscrow", &escrow_payload(&short_core)),
        ),
    ] {
        let signature = signed_normal(ROOT_SEED, ROOT_CERTIFICATE_HASH, &input);
        assert_eq!(
            verify_reader_key_escrow_trust_signature(
                &signature,
                &root_public_key(ROOT_SEED),
                certificate_hash(ROOT_CERTIFICATE_HASH),
                &input,
            )
            .unwrap_err(),
            CryptoError::InvalidProtocolCore,
            "{label}"
        );
    }
}

/// `root_trust_bindings` wird NICHT angefasst (Profil §1.2): weder der
/// Prüf- noch der Signierweg der registrywirksamen Wurzelobjekte nimmt einen
/// Escrow-Eingang an. Das ist zugleich der Beleg der Emissionsgrenze.
#[test]
fn the_registry_root_path_refuses_an_escrow_digest_input() {
    let input = escrow_digest_input(ROOT_SEED);
    assert_eq!(
        VerificationContext::root_trust_digest(
            &input,
            certificate_hash(ROOT_CERTIFICATE_HASH),
            None
        )
        .err()
        .unwrap(),
        CryptoError::InvalidProtocolCore
    );
    let signer = CoseSigner::from_secret(SecretBytes::new(ROOT_SEED));
    assert_eq!(
        signer
            .sign_root_trust_digest(certificate_hash(ROOT_CERTIFICATE_HASH), &input, None)
            .unwrap_err(),
        CryptoError::InvalidProtocolCore
    );
}
