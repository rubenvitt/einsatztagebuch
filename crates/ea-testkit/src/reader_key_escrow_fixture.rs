//! Fixture-Bauer für die drei Reader-Key-Escrow-Familien (v1.1-Profil §3).
//!
//! Anders als [`super::reader_key_escrow`] erzeugt dieses Modul KEINE
//! eingefrorenen Vektoren, sondern Objekte zu beliebigen, vom Zeugen gewählten
//! Feldern und Signierern: der Trust-Kern (`ea-trust`), die native Zeremonie
//! (`ea-admin`) und der Server (`apps/server`) brauchen Escrows, deren
//! Zertifikatshashes auf eine ECHTE Registry-Linie zeigen.
//!
//! # Grenzen
//!
//! - Reine Byte-Bauer über Felder, Seeds und Zertifikatshashes. `ea-testkit`
//!   bekommt dafür keine Kante zu `ea-trust`; die Linie liefert der Zeuge.
//! - Signiert wird über [`super::trust_signed_normal`], nicht über einen
//!   `CoseSigner`: für diese Familien gibt es bewusst keine Signiermethode, und
//!   diese Bauer öffnen keinen Emissionsweg.
//! - Die Kodierung ist die des Codecs (`TrustPayloadV1`), keine zweite.
//! - [`seal_reader_kem_key_for_escrow`] zieht frische Entropie und taugt
//!   deshalb nie für eingefrorene Vektoren.

use ea_crypto::{
    CryptoError, HpkeRecipientPublicKey, SecretBytes, hpke_aad, hpke_info, hpke_seal,
    reader_key_escrow_core_hash, trust_digest,
};
use ea_format::{
    ReaderKeyEscrowApprovalCoreV1, ReaderKeyEscrowCoreV1, ReaderKeyEscrowHpkeContextV1,
    ReaderKeyEscrowRecoveryAuthorizationCoreV1, TrustPayloadV1,
};
use ea_types::{CertificateHash, Hash32, ObjectHash};

use super::{trust_exact_object, trust_signed_normal};

/// Ein Signierer einer Fixture: sein Ed25519-Seed und der Hash des
/// Zertifikats, das ihn im Katalog trägt.
#[derive(Clone, Copy)]
pub struct FixtureTrustSigner {
    pub seed: [u8; 32],
    pub certificate_hash: CertificateHash,
}

/// Die exakten Bytes des Escrow-Cores, wie der Codec sie in die Nutzlast
/// schreibt — das Urbild von `escrow-core-hash`.
///
/// # Panics
///
/// Wenn der Core die Grammatik verletzt; Fixtures bauen nur gültige Cores.
#[must_use]
pub fn escrow_core_bytes(core: &ReaderKeyEscrowCoreV1) -> Vec<u8> {
    let payload = TrustPayloadV1::reader_key_escrow(core.clone(), ObjectHash::from(Hash32::ZERO))
        .expect("a fixture escrow core is well formed");
    let exact = payload.exact_payload();
    // `[core, bstr .size 32]`: ein Kopfbyte vorn, 34 Byte Hash hinten.
    assert_eq!(exact[0], 0x82, "the escrow payload has two elements");
    let tail = exact.len() - 34;
    assert_eq!(&exact[tail..tail + 2], &[0x58, 0x20]);
    exact[1..tail].to_vec()
}

/// `escrow-core-hash` über die exakten Core-Bytes (Profil §4).
#[must_use]
pub fn escrow_core_hash(core: &ReaderKeyEscrowCoreV1) -> Hash32 {
    reader_key_escrow_core_hash(&escrow_core_bytes(core))
}

/// Eine Publikationsfreigabe mit genau einer Signatur des Administrators.
///
/// # Panics
///
/// Wenn der Kern die Grammatik verletzt (etwa eine Lebensdauer über
/// 300 000 ms).
#[must_use]
pub fn signed_reader_key_escrow_approval(
    core: &ReaderKeyEscrowApprovalCoreV1,
    admin: &FixtureTrustSigner,
) -> Vec<u8> {
    let payload = TrustPayloadV1::reader_key_escrow_approval(core.clone())
        .expect("a fixture approval core is well formed");
    let signature = trust_signed_normal(
        admin.seed,
        admin.certificate_hash,
        trust_digest(payload.exact_digest_input()).as_bytes(),
    );
    trust_exact_object(payload, vec![signature])
}

/// Ein Escrow mit genau einer Wurzelsignatur, das die Freigabe
/// `approval_object_hash` nennt.
///
/// # Panics
///
/// Wenn der Core die Grammatik verletzt.
#[must_use]
pub fn signed_reader_key_escrow(
    core: &ReaderKeyEscrowCoreV1,
    approval_object_hash: ObjectHash,
    root: &FixtureTrustSigner,
) -> Vec<u8> {
    let payload = TrustPayloadV1::reader_key_escrow(core.clone(), approval_object_hash)
        .expect("a fixture escrow payload is well formed");
    let signature = trust_signed_normal(
        root.seed,
        root.certificate_hash,
        trust_digest(payload.exact_digest_input()).as_bytes(),
    );
    trust_exact_object(payload, vec![signature])
}

/// Eine Öffnungsautorisierung mit einer Signatur je Approver, aufsteigend
/// nach Zertifikatshash sortiert (die Totalordnung, die der Trust-Kern
/// verlangt).
///
/// # Panics
///
/// Wenn der Kern die Grammatik verletzt oder weniger als zwei Approver
/// genannt sind.
#[must_use]
pub fn signed_reader_key_escrow_recovery_authorization(
    core: &ReaderKeyEscrowRecoveryAuthorizationCoreV1,
    approvers: &[FixtureTrustSigner],
) -> Vec<u8> {
    let payload = TrustPayloadV1::reader_key_escrow_recovery_authorization(core.clone())
        .expect("a fixture recovery authorization core is well formed");
    let mut approvers = approvers.to_vec();
    approvers.sort_by_key(|approver| approver.certificate_hash);
    let digest = trust_digest(payload.exact_digest_input());
    let signatures = approvers
        .iter()
        .map(|approver| {
            trust_signed_normal(approver.seed, approver.certificate_hash, digest.as_bytes())
        })
        .collect();
    trust_exact_object(payload, signatures)
}

/// Versiegelt den privaten Reader-KEM an den Recovery-Empfänger im
/// Escrow-Kontext des Cores (Profil §4) und gibt `(encapsulated-key,
/// encrypted-reader-kem-key)` zurück.
///
/// Die Kontextfelder kommen aus `core`; dessen beide Chiffratfelder werden
/// nicht gelesen. Frische Entropie: NUR für Fixtures, nie für Vektoren.
///
/// # Errors
///
/// Jeder Befund von `hpke_seal`, etwa ein ungültiger Empfängerschlüssel.
pub fn seal_reader_kem_key_for_escrow(
    reader_kem_secret: &SecretBytes<32>,
    recovery_public: [u8; 32],
    core: &ReaderKeyEscrowCoreV1,
) -> Result<([u8; 32], [u8; 48]), CryptoError> {
    let context = ReaderKeyEscrowHpkeContextV1::from_escrow_core(core).encode();
    let sealed = hpke_seal(
        &HpkeRecipientPublicKey::from_bytes(recovery_public)?,
        reader_kem_secret,
        &hpke_info(&context),
        &hpke_aad(&context),
    )?;
    Ok((*sealed.encapsulated_key(), *sealed.wrapped_cek()))
}

/// Freigabe und Escrow zu EINEM Core, konsistent gebunden: die Freigabe trägt
/// den `escrow-core-hash` genau dieses Cores und dessen Reader-Zertifikat und
/// Subjekt, das Escrow den Objekthash genau dieser Freigabe.
///
/// `approval` liefert alle übrigen Freigabefelder; `escrow_core_hash`,
/// `reader_certificate_object_hash` und `reader_subject_id` werden aus `core`
/// überschrieben. Zurück kommen `(freigabe, escrow)`.
#[must_use]
pub fn escrow_with_approval(
    core: &ReaderKeyEscrowCoreV1,
    approval: &ReaderKeyEscrowApprovalCoreV1,
    admin: &FixtureTrustSigner,
    root: &FixtureTrustSigner,
) -> (Vec<u8>, Vec<u8>) {
    let mut approval = approval.clone();
    approval.escrow_core_hash = escrow_core_hash(core);
    approval.reader_certificate_object_hash = core.reader_certificate_object_hash;
    approval.reader_subject_id = core.reader_subject_id;
    let approval_bytes = signed_reader_key_escrow_approval(&approval, admin);
    let escrow_bytes =
        signed_reader_key_escrow(core, ea_crypto::object_hash(&approval_bytes), root);
    (approval_bytes, escrow_bytes)
}

#[cfg(test)]
mod tests {
    use ea_crypto::{
        CanonicalPublicCoseKey, HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, hpke_aad,
        hpke_info, hpke_open, object_hash, parse_cose_sign1, trust_digest,
        verify_reader_key_escrow_trust_signature,
    };
    use ea_format::{
        DecodedTrustPayloadV1, ParsedArchiveObject, ReaderKeyEscrowApprovalCoreV1,
        ReaderKeyEscrowCoreV1, ReaderKeyEscrowHpkeContextV1,
        ReaderKeyEscrowRecoveryAuthorizationCoreV1, TrustSubtypeV1, decode_exact_object,
    };
    use ea_types::{
        AuthorizationId, CertificateHash, ChainSequence, Hash32, KeyThumbprint, ObjectHash,
        OrganizationId, RegistryVersion, SubjectId, UnixMillis,
    };
    use ed25519_dalek::{Signature, Verifier as _};

    use super::{
        FixtureTrustSigner, escrow_core_hash, escrow_with_approval, seal_reader_kem_key_for_escrow,
        signed_reader_key_escrow_recovery_authorization,
    };
    use crate::trust_public_key;

    const ROOT_SEED: [u8; 32] = [0x11; 32];
    const ADMIN_SEED: [u8; 32] = [0x12; 32];
    const FIRST_APPROVER_SEED: [u8; 32] = [0x13; 32];
    const SECOND_APPROVER_SEED: [u8; 32] = [0x14; 32];
    const READER_KEM_SEED: [u8; 32] = [0x15; 32];
    const RECOVERY_KEM_SEED: [u8; 32] = [0x16; 32];

    fn certificate(fill: u8) -> CertificateHash {
        CertificateHash::try_from([fill; 32].as_slice()).unwrap()
    }

    fn hash32(fill: u8) -> Hash32 {
        Hash32::try_from([fill; 32].as_slice()).unwrap()
    }

    fn x25519_public(seed: [u8; 32]) -> [u8; 32] {
        *HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(seed))
            .unwrap()
            .public_key()
            .as_bytes()
    }

    fn core() -> ReaderKeyEscrowCoreV1 {
        ReaderKeyEscrowCoreV1 {
            organization_id: OrganizationId::try_from([0x21; 16].as_slice()).unwrap(),
            reader_certificate_object_hash: certificate(0x22),
            reader_subject_id: SubjectId::try_from([0x23; 16].as_slice()).unwrap(),
            enrollment_registry_version: RegistryVersion::new(3),
            enrollment_registry_head_hash: hash32(0x24),
            enrollment_sequence: ChainSequence::new(201),
            recovery_certificate_object_hash: certificate(0x25),
            recovery_kem_key_thumbprint: CanonicalPublicCoseKey::x25519(x25519_public(
                RECOVERY_KEM_SEED,
            ))
            .unwrap()
            .thumbprint(),
            encapsulated_key: [0; 32],
            encrypted_reader_kem_key: [0; 48],
            issued_at: UnixMillis::new(1_000),
            root_key_thumbprint: trust_public_key(ROOT_SEED).thumbprint(),
        }
    }

    fn approval() -> ReaderKeyEscrowApprovalCoreV1 {
        ReaderKeyEscrowApprovalCoreV1 {
            authorization_id: AuthorizationId::try_from([0x31; 16].as_slice()).unwrap(),
            organization_id: OrganizationId::try_from([0x21; 16].as_slice()).unwrap(),
            registry_version: RegistryVersion::new(4),
            registry_head_hash: hash32(0x32),
            authorization_sequence: 301,
            admin_key_thumbprint: trust_public_key(ADMIN_SEED).thumbprint(),
            admin_certificate_object_hash: certificate(0x33),
            admin_operator_binding_object_hash: ObjectHash::from(hash32(0x34)),
            escrow_core_hash: Hash32::ZERO,
            reader_certificate_object_hash: certificate(0x00),
            reader_subject_id: SubjectId::try_from([0; 16].as_slice()).unwrap(),
            issued_at: UnixMillis::new(900),
            expires_at: UnixMillis::new(1_100),
            nonce: [0x35; 32],
        }
    }

    fn recovery(escrow_object_hash: ObjectHash) -> ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
        ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
            authorization_id: AuthorizationId::try_from([0x41; 16].as_slice()).unwrap(),
            organization_id: OrganizationId::try_from([0x21; 16].as_slice()).unwrap(),
            registry_version: RegistryVersion::new(5),
            registry_head_hash: hash32(0x42),
            authorization_sequence: 401,
            escrow_object_hash,
            reader_certificate_object_hash: certificate(0x22),
            reader_subject_id: SubjectId::try_from([0x23; 16].as_slice()).unwrap(),
            enrollment_registry_version: RegistryVersion::new(3),
            enrollment_registry_head_hash: hash32(0x24),
            target_transport_key_thumbprint: KeyThumbprint::try_from([0x43; 32].as_slice())
                .unwrap(),
            issued_at: UnixMillis::new(2_000),
            expires_at: UnixMillis::new(2_900),
            nonce: [0x44; 32],
        }
    }

    fn trust_object(bytes: &[u8], subtype: TrustSubtypeV1) -> ea_format::TrustObjectV1 {
        let ParsedArchiveObject::Trust(parsed) = decode_exact_object(bytes).unwrap() else {
            panic!("a trust object")
        };
        assert_eq!(parsed.value().subtype(), subtype);
        parsed.value().clone()
    }

    /// Der rohe Ed25519-Beleg einer Normalprofil-Signatur über den
    /// Trust-Digest — ohne Resolver, denn Rolle und Capability belegt erst der
    /// Trust-Kern.
    fn verify_raw(signature: &[u8], seed: [u8; 32], certificate_hash: CertificateHash) {
        let parsed = parse_cose_sign1(signature, &[]).unwrap();
        assert!(parsed.certificate_hash() == Some(certificate_hash));
        let key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let protected = ea_crypto::ProtectedHeader::normal(
            ea_crypto::ContentType::TrustDigest,
            trust_public_key(seed).thumbprint(),
            certificate_hash,
        );
        let signature = Signature::from_bytes(parsed.signature_bytes());
        key.verify(&protected.sig_structure_bytes(parsed.payload()), &signature)
            .unwrap();
    }

    #[test]
    fn fixture_objects_decode_bind_each_other_and_carry_their_signers() {
        let admin = FixtureTrustSigner {
            seed: ADMIN_SEED,
            certificate_hash: certificate(0x33),
        };
        let root = FixtureTrustSigner {
            seed: ROOT_SEED,
            certificate_hash: certificate(0x51),
        };
        let mut core = core();
        let (encapsulated_key, encrypted) = seal_reader_kem_key_for_escrow(
            &SecretBytes::new(READER_KEM_SEED),
            x25519_public(RECOVERY_KEM_SEED),
            &core,
        )
        .unwrap();
        core.encapsulated_key = encapsulated_key;
        core.encrypted_reader_kem_key = encrypted;
        let (approval_bytes, escrow_bytes) =
            escrow_with_approval(&core, &approval(), &admin, &root);

        let approval_object =
            trust_object(&approval_bytes, TrustSubtypeV1::ReaderKeyEscrowApproval);
        let DecodedTrustPayloadV1::ReaderKeyEscrowApproval(approval_fields) =
            approval_object.decoded_payload().unwrap()
        else {
            panic!("an approval")
        };
        assert!(approval_fields.escrow_core_hash == escrow_core_hash(&core));
        assert!(
            approval_fields.reader_certificate_object_hash == core.reader_certificate_object_hash
        );
        assert!(approval_fields.reader_subject_id == core.reader_subject_id);
        assert_eq!(approval_object.signatures().len(), 1);
        verify_raw(
            &approval_object.signatures()[0],
            ADMIN_SEED,
            admin.certificate_hash,
        );

        let escrow_object = trust_object(&escrow_bytes, TrustSubtypeV1::ReaderKeyEscrow);
        let DecodedTrustPayloadV1::ReaderKeyEscrow(payload) =
            escrow_object.decoded_payload().unwrap()
        else {
            panic!("an escrow")
        };
        assert!(payload.approval_object_hash() == object_hash(&approval_bytes));
        assert!(
            ea_crypto::reader_key_escrow_core_hash(payload.exact_core()) == escrow_core_hash(&core)
        );
        verify_reader_key_escrow_trust_signature(
            &escrow_object.signatures()[0],
            &trust_public_key(ROOT_SEED),
            root.certificate_hash,
            escrow_object.exact_digest_input(),
        )
        .unwrap();

        // Der Recovery-Empfänger öffnet das Chiffrat im Kontext des Cores und
        // erhält den privaten Reader-KEM zurück.
        let context = ReaderKeyEscrowHpkeContextV1::from_escrow_core(&core).encode();
        let opened = hpke_open(
            &HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECOVERY_KEM_SEED)).unwrap(),
            &HpkeSealed::from_parts(core.encapsulated_key, core.encrypted_reader_kem_key).unwrap(),
            &hpke_info(&context),
            &hpke_aad(&context),
        )
        .unwrap();
        assert!(opened.matches(&READER_KEM_SEED));

        let first = FixtureTrustSigner {
            seed: FIRST_APPROVER_SEED,
            certificate_hash: certificate(0x62),
        };
        let second = FixtureTrustSigner {
            seed: SECOND_APPROVER_SEED,
            certificate_hash: certificate(0x61),
        };
        let recovery_bytes = signed_reader_key_escrow_recovery_authorization(
            &recovery(object_hash(&escrow_bytes)),
            &[first, second],
        );
        let recovery_object = trust_object(
            &recovery_bytes,
            TrustSubtypeV1::ReaderKeyEscrowRecoveryAuthorization,
        );
        let signatures = recovery_object.signatures();
        assert_eq!(signatures.len(), 2);
        // Aufsteigend nach Zertifikatshash, unabhängig von der Übergabe.
        verify_raw(
            &signatures[0],
            SECOND_APPROVER_SEED,
            second.certificate_hash,
        );
        verify_raw(&signatures[1], FIRST_APPROVER_SEED, first.certificate_hash);
        assert_eq!(
            parse_cose_sign1(&signatures[0], &[]).unwrap().payload(),
            trust_digest(recovery_object.exact_digest_input()).as_bytes()
        );
    }
}
