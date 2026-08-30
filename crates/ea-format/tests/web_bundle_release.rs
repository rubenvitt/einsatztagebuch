//! Die Trust-Objektfamilie `webBundleRelease`/`webBundleRevocation`.
//!
//! Der Test treibt AUSSCHLIESSLICH den oeffentlichen Weg: `encode_trust` und
//! `decode_exact_object`. `TrustSubtypeV1::from_str` bleibt privat, und genau
//! dieselbe Strecke faehrt der Trust-Endpunkt des Servers.
//!
//! Die eingefrorenen Bytes stammen aus `vectors/web-bundle/v1/`; der Erzeuger
//! ist `ea_testkit::web_bundle_v1_manifest`. Die Feldwerte stehen HIER noch
//! einmal als Konstanten, obwohl der Erzeuger sie ebenfalls fuehrt: zoege der
//! Test sie aus `ea-testkit`, wanderte der Vektor bei einer Umbenennung still
//! mit, statt rot zu werden. Dieselbe Begruendung traegt `TRUST_CASES_V1` in
//! `crates/ea-testkit/src/lib.rs`.

use std::{fs, path::PathBuf};

use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, object_hash, trust_digest};
use ea_format::{
    FormatError, OrganizationAdminAuthorizationFieldsV1, ParsedArchiveObject, TrustObjectV1,
    TrustPayloadV1, TrustSubtypeV1, WebBundleReleaseCoreV1, WebBundleRevocationCoreV1,
    decode_exact_object, encode_trust,
};
use ea_testkit::{TEST_ENTROPY_ROOT_ED25519_SEED, ed25519_public_key, ed25519_sign_raw};
use ea_types::{
    AuthorizationId, CertificateHash, Hash32, KeyThumbprint, ObjectHash, OrganizationId,
    RegistryVersion, UnixMillis,
};
use minicbor::Encoder;

#[test]
fn the_release_object_round_trips_through_the_public_path() {
    let payload = TrustPayloadV1::web_bundle_release(fixtures::release_fields()).unwrap();
    let object =
        TrustObjectV1::new(payload.clone(), vec![fixtures::root_signature(&payload)]).unwrap();
    let bytes = encode_trust(&object).unwrap();
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(bytes.as_bytes()).unwrap() else {
        panic!("a release object parses as a trust object")
    };
    assert_eq!(parsed.value().subtype(), TrustSubtypeV1::WebBundleRelease);
    assert_eq!(
        TrustSubtypeV1::WebBundleRelease.as_str(),
        "webBundleRelease"
    );
    assert_eq!(bytes.as_bytes(), fixtures::frozen_release_vector_bytes());
}

#[test]
fn the_revocation_object_round_trips_through_the_public_path() {
    let payload = TrustPayloadV1::web_bundle_revocation(fixtures::revocation_fields()).unwrap();
    let object =
        TrustObjectV1::new(payload.clone(), vec![fixtures::root_signature(&payload)]).unwrap();
    let bytes = encode_trust(&object).unwrap();
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(bytes.as_bytes()).unwrap() else {
        panic!("a revocation object parses as a trust object")
    };
    assert_eq!(
        parsed.value().subtype(),
        TrustSubtypeV1::WebBundleRevocation
    );
    assert_eq!(
        TrustSubtypeV1::WebBundleRevocation.as_str(),
        "webBundleRevocation"
    );
    assert_eq!(bytes.as_bytes(), fixtures::frozen_revocation_vector_bytes());
}

#[test]
fn both_wire_literals_decode_into_their_variant_instead_of_a_tag_mismatch() {
    for literal in ["webBundleRelease", "webBundleRevocation"] {
        assert!(decode_exact_object(&fixtures::hand_built_trust_object(literal)).is_ok());
    }
    assert_eq!(
        decode_exact_object(&fixtures::hand_built_trust_object("webBundleReleases")).unwrap_err(),
        FormatError::TagMismatch
    );
}

#[test]
fn exactly_one_root_signature_is_admissible_for_both_subtypes() {
    for payload in [fixtures::release_payload(), fixtures::revocation_payload()] {
        assert!(
            TrustObjectV1::new(payload.clone(), vec![fixtures::root_signature(&payload)]).is_ok()
        );
        assert_eq!(
            TrustObjectV1::new(payload.clone(), Vec::new())
                .err()
                .unwrap(),
            FormatError::Shape
        );
        assert_eq!(
            TrustObjectV1::new(
                payload.clone(),
                vec![
                    fixtures::root_signature(&payload),
                    fixtures::second_root_signature(&payload),
                ],
            )
            .err()
            .unwrap(),
            FormatError::Shape
        );
    }
}

#[test]
fn the_revocation_binds_the_release_it_withdraws() {
    let revocation = fixtures::decode_revocation(fixtures::frozen_revocation_vector_bytes());
    assert!(revocation.release_object_hash == fixtures::frozen_release_object_hash());
    assert_eq!(revocation.effective_from_registry_version.get(), 7);
}

/// Die beiden Subtypen sind KEIN zulaessiges Ziel einer Admin-Autorisierung.
///
/// Beide Richtungen, weil `ea-format` die Liste zweimal fuehrt: beim Kodieren
/// in `encode_organization_admin_authorization` und beim Dekodieren in
/// `decode_admin_authorization`. Faellt eine der beiden Zeilen aus, waere ein
/// Bundle-Release ueber `registryEvent` autorisierbar — und damit an der
/// Wurzelsignatur vorbei.
#[test]
fn neither_subtype_is_admissible_as_an_administrative_target() {
    for subtype in [
        TrustSubtypeV1::WebBundleRelease,
        TrustSubtypeV1::WebBundleRevocation,
    ] {
        assert_eq!(
            TrustPayloadV1::organization_admin_authorization(fixtures::admin_fields(subtype))
                .err()
                .unwrap(),
            FormatError::Shape
        );
        assert_eq!(
            decode_exact_object(&fixtures::hand_built_admin_authorization(subtype.as_str()))
                .unwrap_err(),
            FormatError::TagMismatch
        );
    }
}

mod fixtures {
    use super::{
        AuthorizationId, CanonicalPublicCoseKey, CertificateHash, ContentType, Encoder, Hash32,
        KeyThumbprint, ObjectHash, OrganizationAdminAuthorizationFieldsV1, OrganizationId,
        ParsedArchiveObject, PathBuf, ProtectedHeader, RegistryVersion,
        TEST_ENTROPY_ROOT_ED25519_SEED, TrustPayloadV1, TrustSubtypeV1, UnixMillis,
        WebBundleReleaseCoreV1, WebBundleRevocationCoreV1, decode_exact_object, ed25519_public_key,
        ed25519_sign_raw, fs, object_hash, trust_digest,
    };

    /// Die Organisationskennung der Familie.
    const ORGANIZATION_ID: [u8; 16] = [0x90; 16];

    /// Der Bundle-Hash des Releases.
    const BUNDLE_HASH: [u8; 32] = [0x91; 32];

    /// Der Zertifikatshash, unter dem die Wurzel signiert.
    ///
    /// Eine erklaerte Testkonstante, kein Objekthash: ein Objektvektor wird
    /// gegen keinen Katalog aufgeloest.
    const ROOT_CERTIFICATE_HASH: [u8; 32] = [0x92; 32];

    /// Der Zertifikatshash der ZWEITEN Wurzelsignatur des
    /// Kardinalitaetsnegativs.
    const SECOND_ROOT_CERTIFICATE_HASH: [u8; 32] = [0x93; 32];

    /// Die Bundle-Version des Releases.
    const BUNDLE_VERSION: &str = "2026.3.1";

    /// Die Registry-Version, ab der das Release wirksam ist.
    const RELEASE_EFFECTIVE_FROM_REGISTRY_VERSION: u64 = 6;

    /// Die Registry-Version, ab der der Widerruf wirksam ist.
    const REVOCATION_EFFECTIVE_FROM_REGISTRY_VERSION: u64 = 7;

    /// Der Ausstellungszeitpunkt des Releases.
    const RELEASE_ISSUED_AT_MS: i64 = 1_700_000_005_000;

    /// Der Ausstellungszeitpunkt des Widerrufs.
    const REVOCATION_ISSUED_AT_MS: i64 = 1_700_000_006_000;

    /// Der Dateiname des eingefrorenen Releasevektors.
    const RELEASE_VECTOR_FILE: &str = "vectors/web-bundle/v1/object/accepted-release.bin";

    /// Der Dateiname des eingefrorenen Widerrufsvektors.
    const REVOCATION_VECTOR_FILE: &str = "vectors/web-bundle/v1/object/accepted-revocation.bin";

    /// Das neun Byte lange Objektpraefix eines Vertrauensbausteins.
    const ETB_PREFIX: [u8; 9] = [0x85, 0x44, b'E', b'A', b'1', 0, 5, 1, 0x80];

    pub fn organization_id() -> OrganizationId {
        OrganizationId::try_from(ORGANIZATION_ID.as_slice()).expect("16 bytes")
    }

    pub fn root_key_thumbprint() -> KeyThumbprint {
        root_public_key().thumbprint()
    }

    fn root_public_key() -> CanonicalPublicCoseKey {
        CanonicalPublicCoseKey::ed25519(ed25519_public_key(&TEST_ENTROPY_ROOT_ED25519_SEED))
            .expect("a declared Ed25519 seed yields a canonical public key")
    }

    pub fn release_fields() -> WebBundleReleaseCoreV1 {
        WebBundleReleaseCoreV1 {
            organization_id: organization_id(),
            bundle_hash: Hash32::try_from(BUNDLE_HASH.as_slice()).expect("32 bytes"),
            bundle_version: BUNDLE_VERSION.to_owned(),
            effective_from_registry_version: RegistryVersion::new(
                RELEASE_EFFECTIVE_FROM_REGISTRY_VERSION,
            ),
            issued_at: UnixMillis::new(RELEASE_ISSUED_AT_MS),
            root_key_thumbprint: root_key_thumbprint(),
        }
    }

    pub fn revocation_fields() -> WebBundleRevocationCoreV1 {
        WebBundleRevocationCoreV1 {
            organization_id: organization_id(),
            release_object_hash: frozen_release_object_hash(),
            effective_from_registry_version: RegistryVersion::new(
                REVOCATION_EFFECTIVE_FROM_REGISTRY_VERSION,
            ),
            issued_at: UnixMillis::new(REVOCATION_ISSUED_AT_MS),
            root_key_thumbprint: root_key_thumbprint(),
        }
    }

    pub fn release_payload() -> TrustPayloadV1 {
        TrustPayloadV1::web_bundle_release(release_fields())
            .expect("the frozen release payload is well formed")
    }

    pub fn revocation_payload() -> TrustPayloadV1 {
        TrustPayloadV1::web_bundle_revocation(revocation_fields())
            .expect("the frozen revocation payload is well formed")
    }

    /// Die Wurzelsignatur ueber den Digest-Eingang genau dieses Nutzinhalts.
    ///
    /// Sie haengt am Subtype-Literal, weil `trust_digest_input` es vor den
    /// Nutzinhalt setzt; eine Signatur des Releases traegt den Widerruf
    /// deshalb NICHT.
    pub fn root_signature(payload: &TrustPayloadV1) -> Vec<u8> {
        signed_normal(ROOT_CERTIFICATE_HASH, payload.exact_digest_input())
    }

    /// Eine zweite, fuer sich wohlgeformte Wurzelsignatur desselben Digests.
    pub fn second_root_signature(payload: &TrustPayloadV1) -> Vec<u8> {
        signed_normal(SECOND_ROOT_CERTIFICATE_HASH, payload.exact_digest_input())
    }

    /// Eine COSE_Sign1 im Normalprofil, von Hand kodiert.
    ///
    /// Von Hand, weil `CoseSigner` fuer diese Familie keine Signiermethode
    /// fuehrt: jede vorhandene bindet ihren eigenen Kern nach.
    fn signed_normal(certificate_hash: [u8; 32], exact_digest_input: &[u8]) -> Vec<u8> {
        let digest = trust_digest(exact_digest_input);
        let protected = ProtectedHeader::normal(
            ContentType::TrustDigest,
            root_key_thumbprint(),
            CertificateHash::try_from(certificate_hash.as_slice()).expect("32 bytes"),
        );
        let signature = ed25519_sign_raw(
            &TEST_ENTROPY_ROOT_ED25519_SEED,
            &protected.sig_structure_bytes(digest.as_bytes()),
        );
        let mut encoded = vec![0xd2, 0x84];
        encoded.extend_from_slice(&cbor_bytes(&protected.to_deterministic_cbor()));
        encoded.push(0xa0);
        encoded.extend_from_slice(&cbor_bytes(digest.as_bytes()));
        encoded.extend_from_slice(&cbor_bytes(&signature));
        encoded
    }

    /// Ein Vertrauensbaustein mit FREI gewaehltem Subtype-Literal.
    ///
    /// Der Nutzinhalt richtet sich nach dem Literal: das unbekannte
    /// `webBundleReleases` traegt den Releasekern, denn `from_str` weist es
    /// ab, bevor der Nutzinhalt geprueft wird.
    pub fn hand_built_trust_object(literal: &str) -> Vec<u8> {
        let payload = if literal == "webBundleRevocation" {
            revocation_payload()
        } else {
            release_payload()
        };
        let digest_input = digest_input_for(literal, payload.exact_payload());
        let signature = signed_normal(ROOT_CERTIFICATE_HASH, &digest_input);
        trust_object(literal, payload.exact_payload(), &[signature])
    }

    /// Eine Admin-Autorisierung mit FREI gewaehltem Ziel-Subtype-Literal.
    pub fn hand_built_admin_authorization(target_literal: &str) -> Vec<u8> {
        let mut payload = vec![0x8f];
        payload.extend_from_slice(&cbor_unsigned(1));
        payload.extend_from_slice(&cbor_bytes(&[0x94_u8; 16]));
        payload.extend_from_slice(&cbor_bytes(&ORGANIZATION_ID));
        payload.extend_from_slice(&cbor_unsigned(1));
        payload.extend_from_slice(&cbor_bytes(&[0x95_u8; 32]));
        payload.extend_from_slice(&cbor_bytes(root_key_thumbprint().as_bytes()));
        payload.extend_from_slice(&cbor_bytes(&[0x96_u8; 32]));
        payload.extend_from_slice(&cbor_bytes(&[0x97_u8; 32]));
        payload.extend_from_slice(&cbor_unsigned(2));
        payload.extend_from_slice(&cbor_text(target_literal));
        payload.extend_from_slice(&cbor_bytes(&[0x98_u8; 32]));
        payload.extend_from_slice(&cbor_unsigned(100));
        payload.extend_from_slice(&cbor_unsigned(1_100));
        payload.extend_from_slice(&cbor_bytes(&[0x99_u8; 32]));
        payload.push(0x80);

        let digest_input = digest_input_for("organizationAdminAuthorization", &payload);
        let signature = signed_normal(ROOT_CERTIFICATE_HASH, &digest_input);
        trust_object("organizationAdminAuthorization", &payload, &[signature])
    }

    /// Die Felder einer Admin-Autorisierung auf ein gegebenes Ziel.
    pub fn admin_fields(target: TrustSubtypeV1) -> OrganizationAdminAuthorizationFieldsV1 {
        OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from([0x94_u8; 16].as_slice())
                .expect("16 bytes"),
            organization_id: organization_id(),
            registry_version: RegistryVersion::new(1),
            registry_head_hash: Hash32::try_from([0x95_u8; 32].as_slice()).expect("32 bytes"),
            admin_key_thumbprint: root_key_thumbprint(),
            admin_certificate_hash: CertificateHash::try_from([0x96_u8; 32].as_slice())
                .expect("32 bytes"),
            admin_operator_binding_object_hash: ObjectHash::try_from([0x97_u8; 32].as_slice())
                .expect("32 bytes"),
            action_code: 2,
            target_trust_subtype: target,
            authorized_trust_core_hash: Hash32::try_from([0x98_u8; 32].as_slice())
                .expect("32 bytes"),
            issued_at: UnixMillis::new(100),
            expires_at: UnixMillis::new(1_100),
            nonce: [0x99_u8; 32],
        }
    }

    /// Der Digest-Eingang `[subtype, nutzinhalt]`, von Hand.
    fn digest_input_for(literal: &str, exact_payload: &[u8]) -> Vec<u8> {
        let mut input = vec![0x82];
        input.extend_from_slice(&cbor_text(literal));
        input.extend_from_slice(exact_payload);
        input
    }

    /// Das fertige Objekt `praefix || [subtype, nutzinhalt, [signaturen]]`.
    fn trust_object(literal: &str, exact_payload: &[u8], signatures: &[Vec<u8>]) -> Vec<u8> {
        let mut object = ETB_PREFIX.to_vec();
        object.push(0x83);
        object.extend_from_slice(&cbor_text(literal));
        object.extend_from_slice(exact_payload);
        object
            .push(0x80 | u8::try_from(signatures.len()).expect("no vector carries 24 signatures"));
        for signature in signatures {
            object.extend_from_slice(signature);
        }
        object
    }

    fn cbor_bytes(value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .bytes(value)
            .expect("encoding into a vector cannot fail");
        bytes
    }

    fn cbor_unsigned(value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .u64(value)
            .expect("encoding into a vector cannot fail");
        bytes
    }

    fn cbor_text(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .str(value)
            .expect("encoding into a vector cannot fail");
        bytes
    }

    /// Die eingefrorenen Bytes des Releasevektors.
    pub fn frozen_release_vector_bytes() -> Vec<u8> {
        frozen(RELEASE_VECTOR_FILE)
    }

    /// Die eingefrorenen Bytes des Widerrufsvektors.
    pub fn frozen_revocation_vector_bytes() -> Vec<u8> {
        frozen(REVOCATION_VECTOR_FILE)
    }

    /// Der Objekthash des eingefrorenen Releases.
    pub fn frozen_release_object_hash() -> ObjectHash {
        object_hash(&frozen_release_vector_bytes())
    }

    fn frozen(relative: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read the frozen vector {}: {error}",
                path.display()
            )
        })
    }

    /// Der dekodierte Widerruf aus eingefrorenen Bytes.
    pub fn decode_revocation(bytes: Vec<u8>) -> WebBundleRevocationCoreV1 {
        let ParsedArchiveObject::Trust(parsed) =
            decode_exact_object(&bytes).expect("the frozen revocation vector parses")
        else {
            panic!("a revocation object parses as a trust object")
        };
        assert_eq!(
            parsed.value().subtype(),
            TrustSubtypeV1::WebBundleRevocation
        );
        match parsed
            .value()
            .decoded_payload()
            .expect("the frozen revocation payload decodes")
        {
            ea_format::DecodedTrustPayloadV1::WebBundleRevocation(fields) => fields,
            _ => panic!("a webBundleRevocation decodes into its own variant"),
        }
    }
}
