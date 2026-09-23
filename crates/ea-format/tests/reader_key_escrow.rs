//! Die drei Trust-Familien des Reader-Key-Escrows (v1.1-Profil §3, §4).
//!
//! Der Test treibt AUSSCHLIESSLICH den öffentlichen Weg: `encode_trust` und
//! `decode_exact_object`, dazu die Konstruktoren von `TrustPayloadV1`.
//! `TrustSubtypeV1::from_str` bleibt privat.
//!
//! Die Negativobjekte werden von Hand gebaut: Arität, Kardinalität und
//! Feldformen sollen gerade NICHT durch den Kodierer gehen, der sie abweisen
//! würde.

use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, ProtectedHeader,
    READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS,
    READER_KEY_ESCROW_RECOVERY_AUTHORIZATION_MAX_LIFETIME_MS, trust_digest,
};
use ea_format::{
    DecodedTrustPayloadV1, FormatError, OrganizationAdminAuthorizationFieldsV1,
    ParsedArchiveObject, READER_KEY_ESCROW_RESTORE_SUITE_ID, READER_KEY_ESCROW_SUITE_ID,
    ReaderKeyEscrowApprovalCoreV1, ReaderKeyEscrowCoreV1, ReaderKeyEscrowHpkeContextV1,
    ReaderKeyEscrowRecoveryAuthorizationCoreV1, ReaderKeyEscrowRestoreContextV1, TrustObjectV1,
    TrustPayloadV1, TrustSubtypeV1, decode_exact_object, encode_trust,
};
use ea_testkit::{TEST_ENTROPY_ROOT_ED25519_SEED, ed25519_public_key, ed25519_sign_raw};
use ea_types::{
    AuthorizationId, CertificateHash, ChainSequence, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId, RegistryVersion, SubjectId, UnixMillis,
};
use minicbor::Encoder;

use hand::Item;

/// Heute (HEAD `670f6d4`) weist der Codec alle drei Literale mit
/// `EA-FORMAT-TAG-MISMATCH` ab. Nach dem Codec dekodiert jedes Literal in
/// seine eigene Variante.
#[test]
fn all_three_escrow_literals_decode_instead_of_a_tag_mismatch() {
    for (literal, payload, signatures) in [
        (
            "readerKeyEscrow",
            hand::escrow_payload(&hand::escrow_core()),
            1,
        ),
        ("readerKeyEscrowApproval", hand::approval_core(), 1),
        (
            "readerKeyEscrowRecoveryAuthorization",
            hand::recovery_core(),
            2,
        ),
    ] {
        let object = hand::object(literal, &payload, signatures);
        let parsed = decode_exact_object(&object)
            .unwrap_or_else(|error| panic!("{literal} must decode, got {}", error.code()));
        let ParsedArchiveObject::Trust(parsed) = parsed else {
            panic!("{literal} is a trust object")
        };
        assert_eq!(parsed.value().subtype().as_str(), literal);
    }
    assert_eq!(
        decode_exact_object(&hand::object(
            "readerKeyEscrows",
            &hand::escrow_payload(&hand::escrow_core()),
            1
        ))
        .unwrap_err(),
        FormatError::TagMismatch
    );
}

/// Die drei Konstruktoren kodieren, und der öffentliche Weg liest genau die
/// Felder zurück — je Subtyp in seine EIGENE Variante.
#[test]
fn all_three_subtypes_round_trip_through_the_public_path() {
    let escrow = TrustPayloadV1::reader_key_escrow(typed::escrow_core(), typed::hash(0x3c))
        .expect("the escrow payload is well formed");
    let object = TrustObjectV1::new(escrow.clone(), vec![typed::signature(&escrow, 0)]).unwrap();
    let bytes = encode_trust(&object).unwrap();
    let decoded = typed::decode(bytes.as_bytes(), TrustSubtypeV1::ReaderKeyEscrow);
    let DecodedTrustPayloadV1::ReaderKeyEscrow(payload) = decoded else {
        panic!("a readerKeyEscrow decodes into its own variant")
    };
    assert!(payload.core() == &typed::escrow_core());
    assert!(payload.approval_object_hash() == typed::hash(0x3c));
    // Nie reserialisiert: der exakte Core ist der Slice der Nutzlast.
    let exact_payload = escrow.exact_payload();
    assert_eq!(exact_payload[0], 0x82);
    assert_eq!(
        payload.exact_core(),
        &exact_payload[1..exact_payload.len() - 34]
    );
    assert_eq!(payload.exact_core(), hand::escrow_core().as_slice());
    assert_eq!(TrustSubtypeV1::ReaderKeyEscrow.as_str(), "readerKeyEscrow");

    let approval = TrustPayloadV1::reader_key_escrow_approval(typed::approval_core())
        .expect("the approval core is well formed");
    assert_eq!(approval.exact_payload(), hand::approval_core().as_slice());
    let object =
        TrustObjectV1::new(approval.clone(), vec![typed::signature(&approval, 0)]).unwrap();
    let decoded = typed::decode(
        encode_trust(&object).unwrap().as_bytes(),
        TrustSubtypeV1::ReaderKeyEscrowApproval,
    );
    let DecodedTrustPayloadV1::ReaderKeyEscrowApproval(core) = decoded else {
        panic!("a readerKeyEscrowApproval decodes into its own variant")
    };
    assert!(core == typed::approval_core());
    assert_eq!(
        TrustSubtypeV1::ReaderKeyEscrowApproval.as_str(),
        "readerKeyEscrowApproval"
    );

    let recovery = TrustPayloadV1::reader_key_escrow_recovery_authorization(typed::recovery_core())
        .expect("the recovery authorization core is well formed");
    assert_eq!(recovery.exact_payload(), hand::recovery_core().as_slice());
    let object = TrustObjectV1::new(
        recovery.clone(),
        vec![
            typed::signature(&recovery, 0),
            typed::signature(&recovery, 1),
        ],
    )
    .unwrap();
    let decoded = typed::decode(
        encode_trust(&object).unwrap().as_bytes(),
        TrustSubtypeV1::ReaderKeyEscrowRecoveryAuthorization,
    );
    let DecodedTrustPayloadV1::ReaderKeyEscrowRecoveryAuthorization(core) = decoded else {
        panic!("a readerKeyEscrowRecoveryAuthorization decodes into its own variant")
    };
    assert!(core == typed::recovery_core());
    assert_eq!(
        TrustSubtypeV1::ReaderKeyEscrowRecoveryAuthorization.as_str(),
        "readerKeyEscrowRecoveryAuthorization"
    );
}

/// Kardinalität 1 / 1 / 2* — auf BEIDEN Wegen: beim Bauen über
/// `TrustObjectV1::new` und beim Dekodieren handgebauter Körper.
///
/// Die Freigabe mit zwei Signaturen ist der Zeuge gegen den Auffangzweig
/// `count >= 1` in `validate_signature_count`.
#[test]
fn signature_cardinality_is_one_one_and_at_least_two() {
    let escrow =
        TrustPayloadV1::reader_key_escrow(typed::escrow_core(), typed::hash(0x3c)).unwrap();
    let approval = TrustPayloadV1::reader_key_escrow_approval(typed::approval_core()).unwrap();
    let recovery =
        TrustPayloadV1::reader_key_escrow_recovery_authorization(typed::recovery_core()).unwrap();
    for (payload, admissible) in [
        (&escrow, [false, true, false, false]),
        (&approval, [false, true, false, false]),
        (&recovery, [false, false, true, true]),
    ] {
        for (count, expected) in admissible.into_iter().enumerate() {
            let signatures = (0..count)
                .map(|index| typed::signature(payload, u8::try_from(index).unwrap()))
                .collect::<Vec<_>>();
            let built = TrustObjectV1::new(payload.clone(), signatures);
            assert_eq!(
                built.is_ok(),
                expected,
                "{} with {count} signatures",
                payload.subtype().as_str()
            );
            if !expected {
                assert_eq!(built.err().unwrap(), FormatError::Shape);
            }
            let decoded = decode_exact_object(&hand::object(
                payload.subtype().as_str(),
                payload.exact_payload(),
                u8::try_from(count).unwrap(),
            ));
            assert_eq!(decoded.is_ok(), expected);
            if !expected {
                assert_eq!(decoded.unwrap_err(), FormatError::Shape);
            }
        }
    }
}

/// Arität 14 / 16 / 17: eine Position zu wenig, eine zu viel und ein
/// fehlender Extension-Slot fallen mit `EA-FORMAT-SHAPE`; die Escrow-Nutzlast
/// ist zweielementig.
#[test]
fn every_core_rejects_a_wrong_arity_and_a_missing_extension_slot() {
    for (literal, items, signatures, wrap) in [
        ("readerKeyEscrow", hand::escrow_core_items(), 1, true),
        (
            "readerKeyEscrowApproval",
            hand::approval_core_items(),
            1,
            false,
        ),
        (
            "readerKeyEscrowRecoveryAuthorization",
            hand::recovery_core_items(),
            2,
            false,
        ),
    ] {
        let last = items.len() - 1;
        let mut shorter = items.clone();
        shorter.remove(last - 1);
        let mut longer = items.clone();
        longer.insert(last, Item::Uint(0));
        let mut without_slot = items.clone();
        without_slot.pop();
        for (label, variant) in [
            ("shorter", shorter),
            ("longer", longer),
            ("without extension slot", without_slot),
        ] {
            let core = hand::encode(&variant);
            let payload = if wrap {
                hand::escrow_payload(&core)
            } else {
                core
            };
            assert_eq!(
                decode_exact_object(&hand::object(literal, &payload, signatures)).unwrap_err(),
                FormatError::Shape,
                "{literal} {label}"
            );
        }
    }
    let mut three = vec![0x83];
    three.extend_from_slice(&hand::escrow_core());
    three.extend_from_slice(&hand::cbor_bytes(&[0x3c; 32]));
    three.extend_from_slice(&hand::cbor_bytes(&[0x3d; 32]));
    assert_eq!(
        decode_exact_object(&hand::object("readerKeyEscrow", &three, 1)).unwrap_err(),
        FormatError::Shape
    );
    // Ein Freigabehash falscher Länge.
    let mut short_hash = vec![0x82];
    short_hash.extend_from_slice(&hand::escrow_core());
    short_hash.extend_from_slice(&hand::cbor_bytes(&[0x3c; 31]));
    assert_eq!(
        decode_exact_object(&hand::object("readerKeyEscrow", &short_hash, 1)).unwrap_err(),
        FormatError::Shape
    );
}

/// Jede Bytefolge fester Länge fällt mit einem Byte zu wenig; Version 2 ist
/// eine unbekannte Version.
#[test]
fn every_fixed_length_field_and_the_version_are_checked() {
    for (literal, items, signatures, wrap) in [
        ("readerKeyEscrow", hand::escrow_core_items(), 1, true),
        (
            "readerKeyEscrowApproval",
            hand::approval_core_items(),
            1,
            false,
        ),
        (
            "readerKeyEscrowRecoveryAuthorization",
            hand::recovery_core_items(),
            2,
            false,
        ),
    ] {
        let payload_of = |variant: &[Item]| {
            let core = hand::encode(variant);
            if wrap {
                hand::escrow_payload(&core)
            } else {
                core
            }
        };
        let mut checked = 0;
        for (position, item) in items.iter().enumerate() {
            let Item::Bytes(value) = item else { continue };
            let mut variant = items.clone();
            variant[position] = Item::Bytes(value[1..].to_vec());
            assert_eq!(
                decode_exact_object(&hand::object(literal, &payload_of(&variant), signatures))
                    .unwrap_err(),
                FormatError::Shape,
                "{literal} position {position}"
            );
            checked += 1;
        }
        assert!(checked >= 8, "{literal} checks its fixed length fields");
        let mut version_two = items.clone();
        version_two[0] = Item::Uint(2);
        assert_eq!(
            decode_exact_object(&hand::object(
                literal,
                &payload_of(&version_two),
                signatures
            ))
            .unwrap_err(),
            FormatError::UnknownVersion,
            "{literal} version 2"
        );
    }
}

/// `purpose: 0` ist der einzige Operationscode der Öffnung.
#[test]
fn the_recovery_purpose_is_closed_to_zero() {
    let mut items = hand::recovery_core_items();
    items[12] = Item::Uint(1);
    assert_eq!(
        decode_exact_object(&hand::object(
            "readerKeyEscrowRecoveryAuthorization",
            &hand::encode(&items),
            2
        ))
        .unwrap_err(),
        FormatError::TagMismatch
    );
}

/// Ruling R5: `expires − issued ∈ 1..=MAX`, gerechnet mit `checked_sub`.
///
/// Der Randwert genau `MAX` wird angenommen; `MAX + 1`, Null, eine negative
/// Dauer und ein Überlauf fallen mit `EA-FORMAT-SHAPE`. Die Randsemantik
/// `now > expiresAt` gehört nicht in den Codec, sondern in den Trust-Kern.
#[test]
fn the_lifetime_of_both_authorizations_is_bounded() {
    assert_eq!(READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS, 300_000);
    assert_eq!(
        READER_KEY_ESCROW_RECOVERY_AUTHORIZATION_MAX_LIFETIME_MS,
        900_000
    );
    for (literal, items, signatures, issued_position, max) in [
        (
            "readerKeyEscrowApproval",
            hand::approval_core_items(),
            1,
            12,
            READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS,
        ),
        (
            "readerKeyEscrowRecoveryAuthorization",
            hand::recovery_core_items(),
            2,
            13,
            READER_KEY_ESCROW_RECOVERY_AUTHORIZATION_MAX_LIFETIME_MS,
        ),
    ] {
        for (issued, expires, accepted) in [
            (1_000, 1_000 + max, true),
            (1_000, 1_001, true),
            (1_000, 1_000 + max + 1, false),
            (1_000, 1_000, false),
            (1_000, 999, false),
            (i64::MIN, i64::MAX, false),
            (i64::MAX, i64::MIN, false),
        ] {
            let mut variant = items.clone();
            variant[issued_position] = Item::Int(issued);
            variant[issued_position + 1] = Item::Int(expires);
            let decoded =
                decode_exact_object(&hand::object(literal, &hand::encode(&variant), signatures));
            assert_eq!(
                decoded.is_ok(),
                accepted,
                "{literal} issued {issued} expires {expires}"
            );
            if !accepted {
                assert_eq!(decoded.unwrap_err(), FormatError::Shape);
            }
        }
    }

    // Der Kodierer hält dieselbe Grenze.
    let mut approval = typed::approval_core();
    approval.expires_at =
        UnixMillis::new(approval.issued_at.get() + READER_KEY_ESCROW_APPROVAL_MAX_LIFETIME_MS + 1);
    assert_eq!(
        TrustPayloadV1::reader_key_escrow_approval(approval)
            .err()
            .unwrap(),
        FormatError::Shape
    );
    let mut recovery = typed::recovery_core();
    recovery.expires_at = recovery.issued_at;
    assert_eq!(
        TrustPayloadV1::reader_key_escrow_recovery_authorization(recovery)
            .err()
            .unwrap(),
        FormatError::Shape
    );
}

/// Keines der drei Literale ist ein zulässiges Ziel einer
/// Admin-Autorisierung — beim Kodieren und beim Dekodieren.
#[test]
fn no_escrow_subtype_is_admissible_as_an_administrative_target() {
    for subtype in [
        TrustSubtypeV1::ReaderKeyEscrow,
        TrustSubtypeV1::ReaderKeyEscrowApproval,
        TrustSubtypeV1::ReaderKeyEscrowRecoveryAuthorization,
    ] {
        assert_eq!(
            TrustPayloadV1::organization_admin_authorization(typed::admin_fields(subtype))
                .err()
                .unwrap(),
            FormatError::Shape
        );
        let mut items = vec![
            Item::Uint(1),
            Item::Bytes(vec![0x94; 16]),
            Item::Bytes(vec![0x31; 16]),
            Item::Uint(1),
            Item::Bytes(vec![0x95; 32]),
            Item::Bytes(vec![0x96; 32]),
            Item::Bytes(vec![0x97; 32]),
            Item::Bytes(vec![0x98; 32]),
            Item::Uint(2),
            Item::Text("registryEvent"),
            Item::Bytes(vec![0x99; 32]),
            Item::Int(100),
            Item::Int(1_100),
            Item::Bytes(vec![0x9a; 32]),
            Item::Empty,
        ];
        assert!(
            decode_exact_object(&hand::object(
                "organizationAdminAuthorization",
                &hand::encode(&items),
                1
            ))
            .is_ok(),
            "the control object with a legal target decodes"
        );
        items[9] = Item::Text(subtype.as_str());
        assert_eq!(
            decode_exact_object(&hand::object(
                "organizationAdminAuthorization",
                &hand::encode(&items),
                1
            ))
            .unwrap_err(),
            FormatError::TagMismatch
        );
    }
}

/// Die Kontexte nach Profil §4, byte-genau gegen eine Handkodierung:
/// Suite-Literal im CBOR und leerer Extension-Slot, Felder aus dem Core bzw.
/// der Autorisierung abgeleitet.
#[test]
fn both_hpke_contexts_encode_the_profile_form() {
    assert_eq!(
        READER_KEY_ESCROW_SUITE_ID,
        "EINSATZARCHIV-READER-KEY-ESCROW-1"
    );
    assert_eq!(
        READER_KEY_ESCROW_RESTORE_SUITE_ID,
        "EINSATZARCHIV-READER-KEY-ESCROW-RESTORE-1"
    );
    let context = ReaderKeyEscrowHpkeContextV1::from_escrow_core(&typed::escrow_core());
    assert_eq!(
        context.encode(),
        hand::encode(&[
            Item::Uint(1),
            Item::Bytes(vec![0x31; 16]),
            Item::Bytes(vec![0x32; 32]),
            Item::Bytes(vec![0x33; 16]),
            Item::Uint(4),
            Item::Bytes(vec![0x35; 32]),
            Item::Bytes(vec![0x37; 32]),
            Item::Bytes(vec![0x38; 32]),
            Item::Text("EINSATZARCHIV-READER-KEY-ESCROW-1"),
            Item::Empty,
        ])
    );
    let restore = ReaderKeyEscrowRestoreContextV1::from_recovery_authorization(
        &typed::recovery_core(),
        typed::hash(0x5d),
    );
    assert_eq!(
        restore.encode(),
        hand::encode(&[
            Item::Uint(1),
            Item::Bytes(vec![0x31; 16]),
            Item::Bytes(vec![0x5d; 32]),
            Item::Bytes(vec![0x56; 32]),
            Item::Bytes(vec![0x32; 32]),
            Item::Bytes(vec![0x33; 16]),
            Item::Bytes(vec![0x5b; 32]),
            Item::Text("EINSATZARCHIV-READER-KEY-ESCROW-RESTORE-1"),
            Item::Empty,
        ])
    );
}

/// Typisierte Gegenstücke zu [`hand`]; dieselben Feldwerte.
mod typed {
    use super::{
        AuthorizationId, CertificateHash, ChainSequence, DecodedTrustPayloadV1, Hash32,
        KeyThumbprint, ObjectHash, OrganizationAdminAuthorizationFieldsV1, OrganizationId,
        ParsedArchiveObject, ReaderKeyEscrowApprovalCoreV1, ReaderKeyEscrowCoreV1,
        ReaderKeyEscrowRecoveryAuthorizationCoreV1, RegistryVersion, SubjectId, TrustPayloadV1,
        TrustSubtypeV1, UnixMillis, decode_exact_object, hand,
    };

    pub fn hash(fill: u8) -> ObjectHash {
        ObjectHash::try_from([fill; 32].as_slice()).unwrap()
    }

    fn certificate(fill: u8) -> CertificateHash {
        CertificateHash::try_from([fill; 32].as_slice()).unwrap()
    }

    fn hash32(fill: u8) -> Hash32 {
        Hash32::try_from([fill; 32].as_slice()).unwrap()
    }

    fn thumbprint(fill: u8) -> KeyThumbprint {
        KeyThumbprint::try_from([fill; 32].as_slice()).unwrap()
    }

    fn organization() -> OrganizationId {
        OrganizationId::try_from([0x31; 16].as_slice()).unwrap()
    }

    fn subject() -> SubjectId {
        SubjectId::try_from([0x33; 16].as_slice()).unwrap()
    }

    pub fn escrow_core() -> ReaderKeyEscrowCoreV1 {
        ReaderKeyEscrowCoreV1 {
            organization_id: organization(),
            reader_certificate_object_hash: certificate(0x32),
            reader_subject_id: subject(),
            enrollment_registry_version: RegistryVersion::new(4),
            enrollment_registry_head_hash: hash32(0x35),
            enrollment_sequence: ChainSequence::new(6),
            recovery_certificate_object_hash: certificate(0x37),
            recovery_kem_key_thumbprint: thumbprint(0x38),
            encapsulated_key: [0x39; 32],
            encrypted_reader_kem_key: [0x3a; 48],
            issued_at: UnixMillis::new(1_700_000_000_000),
            root_key_thumbprint: thumbprint(0x3b),
        }
    }

    pub fn approval_core() -> ReaderKeyEscrowApprovalCoreV1 {
        ReaderKeyEscrowApprovalCoreV1 {
            authorization_id: AuthorizationId::try_from([0x41; 16].as_slice()).unwrap(),
            organization_id: organization(),
            registry_version: RegistryVersion::new(3),
            registry_head_hash: hash32(0x44),
            authorization_sequence: 5,
            admin_key_thumbprint: thumbprint(0x46),
            admin_certificate_object_hash: certificate(0x47),
            admin_operator_binding_object_hash: hash(0x48),
            escrow_core_hash: hash32(0x49),
            reader_certificate_object_hash: certificate(0x32),
            reader_subject_id: subject(),
            issued_at: UnixMillis::new(1_700_000_000_000),
            expires_at: UnixMillis::new(1_700_000_300_000),
            nonce: [0x4a; 32],
        }
    }

    pub fn recovery_core() -> ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
        ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
            authorization_id: AuthorizationId::try_from([0x51; 16].as_slice()).unwrap(),
            organization_id: organization(),
            registry_version: RegistryVersion::new(3),
            registry_head_hash: hash32(0x54),
            authorization_sequence: 5,
            escrow_object_hash: hash(0x56),
            reader_certificate_object_hash: certificate(0x32),
            reader_subject_id: subject(),
            enrollment_registry_version: RegistryVersion::new(4),
            enrollment_registry_head_hash: hash32(0x35),
            target_transport_key_thumbprint: thumbprint(0x5b),
            issued_at: UnixMillis::new(1_700_000_000_000),
            expires_at: UnixMillis::new(1_700_000_900_000),
            nonce: [0x5c; 32],
        }
    }

    pub fn admin_fields(target: TrustSubtypeV1) -> OrganizationAdminAuthorizationFieldsV1 {
        OrganizationAdminAuthorizationFieldsV1 {
            authorization_id: AuthorizationId::try_from([0x94; 16].as_slice()).unwrap(),
            organization_id: organization(),
            registry_version: RegistryVersion::new(1),
            registry_head_hash: hash32(0x95),
            admin_key_thumbprint: thumbprint(0x96),
            admin_certificate_hash: certificate(0x97),
            admin_operator_binding_object_hash: hash(0x98),
            action_code: 2,
            target_trust_subtype: target,
            authorized_trust_core_hash: hash32(0x99),
            issued_at: UnixMillis::new(100),
            expires_at: UnixMillis::new(1_100),
            nonce: [0x9a; 32],
        }
    }

    /// Eine Signatur über den Digest-Eingang genau dieser Nutzlast.
    pub fn signature(payload: &TrustPayloadV1, index: u8) -> Vec<u8> {
        hand::signed_normal([0x60 + index; 32], payload.exact_digest_input())
    }

    pub fn decode(bytes: &[u8], subtype: TrustSubtypeV1) -> DecodedTrustPayloadV1 {
        let ParsedArchiveObject::Trust(parsed) = decode_exact_object(bytes).unwrap() else {
            panic!("a trust object")
        };
        assert_eq!(parsed.value().subtype(), subtype);
        parsed.value().decoded_payload().unwrap()
    }
}

/// Handgebaute Objekte. Jede Position ist ein [`Item`], damit ein Negativ
/// genau eine Position ändert.
mod hand {
    use super::{
        CanonicalPublicCoseKey, CertificateHash, ContentType, Encoder, ProtectedHeader,
        TEST_ENTROPY_ROOT_ED25519_SEED, ed25519_public_key, ed25519_sign_raw, trust_digest,
    };

    /// Eine CBOR-Position.
    #[derive(Clone)]
    pub enum Item {
        Uint(u64),
        Int(i64),
        Bytes(Vec<u8>),
        Text(&'static str),
        Empty,
    }

    pub fn encode(items: &[Item]) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(items.len() as u64).unwrap();
        for item in items {
            match item {
                Item::Uint(value) => encoder.u64(*value).unwrap(),
                Item::Int(value) => encoder.i64(*value).unwrap(),
                Item::Bytes(value) => encoder.bytes(value).unwrap(),
                Item::Text(value) => encoder.str(value).unwrap(),
                Item::Empty => encoder.array(0).unwrap(),
            };
        }
        encoder.into_writer()
    }

    pub fn escrow_core_items() -> Vec<Item> {
        vec![
            Item::Uint(1),
            Item::Bytes(vec![0x31; 16]),
            Item::Bytes(vec![0x32; 32]),
            Item::Bytes(vec![0x33; 16]),
            Item::Uint(4),
            Item::Bytes(vec![0x35; 32]),
            Item::Uint(6),
            Item::Bytes(vec![0x37; 32]),
            Item::Bytes(vec![0x38; 32]),
            Item::Bytes(vec![0x39; 32]),
            Item::Bytes(vec![0x3a; 48]),
            Item::Int(1_700_000_000_000),
            Item::Bytes(vec![0x3b; 32]),
            Item::Empty,
        ]
    }

    pub fn approval_core_items() -> Vec<Item> {
        vec![
            Item::Uint(1),
            Item::Bytes(vec![0x41; 16]),
            Item::Bytes(vec![0x31; 16]),
            Item::Uint(3),
            Item::Bytes(vec![0x44; 32]),
            Item::Uint(5),
            Item::Bytes(vec![0x46; 32]),
            Item::Bytes(vec![0x47; 32]),
            Item::Bytes(vec![0x48; 32]),
            Item::Bytes(vec![0x49; 32]),
            Item::Bytes(vec![0x32; 32]),
            Item::Bytes(vec![0x33; 16]),
            Item::Int(1_700_000_000_000),
            Item::Int(1_700_000_300_000),
            Item::Bytes(vec![0x4a; 32]),
            Item::Empty,
        ]
    }

    pub fn recovery_core_items() -> Vec<Item> {
        vec![
            Item::Uint(1),
            Item::Bytes(vec![0x51; 16]),
            Item::Bytes(vec![0x31; 16]),
            Item::Uint(3),
            Item::Bytes(vec![0x54; 32]),
            Item::Uint(5),
            Item::Bytes(vec![0x56; 32]),
            Item::Bytes(vec![0x32; 32]),
            Item::Bytes(vec![0x33; 16]),
            Item::Uint(4),
            Item::Bytes(vec![0x35; 32]),
            Item::Bytes(vec![0x5b; 32]),
            Item::Uint(0),
            Item::Int(1_700_000_000_000),
            Item::Int(1_700_000_900_000),
            Item::Bytes(vec![0x5c; 32]),
            Item::Empty,
        ]
    }

    pub fn escrow_core() -> Vec<u8> {
        encode(&escrow_core_items())
    }

    pub fn approval_core() -> Vec<u8> {
        encode(&approval_core_items())
    }

    pub fn recovery_core() -> Vec<u8> {
        encode(&recovery_core_items())
    }

    /// Die zweielementige Escrow-Nutzlast `[core, approval-object-hash]`.
    pub fn escrow_payload(exact_core: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x82];
        payload.extend_from_slice(exact_core);
        payload.extend_from_slice(&cbor_bytes(&[0x3c; 32]));
        payload
    }

    fn root_public_key() -> CanonicalPublicCoseKey {
        CanonicalPublicCoseKey::ed25519(ed25519_public_key(&TEST_ENTROPY_ROOT_ED25519_SEED))
            .expect("a declared Ed25519 seed yields a canonical public key")
    }

    /// Eine COSE_Sign1 im Normalprofil über den Digest-Eingang, von Hand.
    ///
    /// Von Hand, weil `CoseSigner` für diese Familien bewusst keine
    /// Signiermethode führt (keine Emission vor Scheibe f).
    pub fn signed_normal(certificate_hash: [u8; 32], exact_digest_input: &[u8]) -> Vec<u8> {
        let digest = trust_digest(exact_digest_input);
        let protected = ProtectedHeader::normal(
            ContentType::TrustDigest,
            root_public_key().thumbprint(),
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

    /// Der Digest-Eingang `[subtype, nutzlast]`, von Hand.
    pub fn digest_input(literal: &str, exact_payload: &[u8]) -> Vec<u8> {
        let mut input = vec![0x82];
        input.extend_from_slice(&cbor_text(literal));
        input.extend_from_slice(exact_payload);
        input
    }

    /// Das fertige Objekt mit `signatures` wohlgeformten Signaturen über den
    /// Digest-Eingang genau dieses Literals.
    pub fn object(literal: &str, exact_payload: &[u8], signatures: u8) -> Vec<u8> {
        let input = digest_input(literal, exact_payload);
        let signatures = (0..signatures)
            .map(|index| signed_normal([0x60 + index; 32], &input))
            .collect::<Vec<_>>();
        object_with(literal, exact_payload, &signatures)
    }

    /// Das fertige Objekt `präfix || [subtype, nutzlast, [signaturen]]`.
    pub fn object_with(literal: &str, exact_payload: &[u8], signatures: &[Vec<u8>]) -> Vec<u8> {
        let mut object = vec![0x85, 0x44, b'E', b'A', b'1', 0, 5, 1, 0x80];
        object.push(0x83);
        object.extend_from_slice(&cbor_text(literal));
        object.extend_from_slice(exact_payload);
        object.push(0x80 | u8::try_from(signatures.len()).expect("fewer than 24"));
        for signature in signatures {
            object.extend_from_slice(signature);
        }
        object
    }

    pub fn cbor_bytes(value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes).bytes(value).unwrap();
        bytes
    }

    pub fn cbor_text(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes).str(value).unwrap();
        bytes
    }
}
