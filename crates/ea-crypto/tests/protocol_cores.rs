//! Kodierer und getippte Dekodierer der drei signierten Protokollkerne.
//!
//! Die Feldfolge steht in `schemas/protocol/v1/signed-protocol.cddl`:5-13,
//! :15-24 und :26-34. Geprueft wird sie weiterhin von den vorhandenen
//! Formwaechtern hinter [`validate_unsigned_protocol_core`]; dieser Test misst,
//! dass Kodierer und Dekodierer GENAU deren Bytes erzeugen und annehmen.
//!
//! Die drei `*_CORE_HEX` sind die eingefrorenen normativen Bytes aus
//! `crates/ea-crypto/tests/cose_profile.rs`, wo sie zusammen mit ihren
//! COSE-Signaturen und Huellen stehen. Sie stehen hier ein zweites Mal, weil
//! ein Kodierer, der bloss VALIDIERBARE Bytes liefert, noch keine gemeinsame
//! Implementierung ist: er muss DIESE Bytes liefern.

use ea_crypto::{
    CanonicalPublicCoseKey, ChallengeResponseCoreV1, ContentType, DeviceRegistrationRequestCoreV1,
    ReaderAckCoreV1, decode_challenge_response_core, decode_device_registration_request_core,
    decode_reader_ack_core, encode_challenge_response_core,
    encode_device_registration_request_core, encode_reader_ack_core,
    validate_unsigned_protocol_core,
};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, DeviceId, EntryHash, OrganizationId, UnixMillis,
};
use minicbor::Encoder;

const CHALLENGE_CORE_HEX: &str = "870150000102030405060708090a0b0c0d0e0f5820202020202020202020202020202020202020202020202020202020202020202018183903e75820303030303030303030303030303030303030303030303030303030303030303080";
const REGISTRATION_CORE_HEX: &str = "890150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f005828a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8f68101817545494e5341545a4152434849562d53554954452d3180";
const READER_ACK_CORE_HEX: &str = "880150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f582040404040404040404040404040404040404040404040404040404040404040401818582050505050505050505050505050505050505050505050505050505050505050503903e780";

mod fixtures {
    use super::{
        CanonicalPublicCoseKey, CertificateHash, ChainId, ChainSequence, ChallengeResponseCoreV1,
        DeviceId, DeviceRegistrationRequestCoreV1, Encoder, EntryHash, OrganizationId,
        ReaderAckCoreV1, UnixMillis,
    };

    /// Sechzehn aufsteigende Bytes ab `base` — dieselbe Kennungsform wie in
    /// `crates/ea-crypto/tests/cose_profile.rs`.
    fn id16(base: u8) -> [u8; 16] {
        std::array::from_fn(|index| base.wrapping_add(index as u8))
    }

    fn hash32(value: u8) -> [u8; 32] {
        [value; 32]
    }

    /// Die Felder hinter `CHALLENGE_CORE_HEX`.
    pub fn challenge_core() -> ChallengeResponseCoreV1 {
        ChallengeResponseCoreV1 {
            organization_id: OrganizationId::try_from(id16(0).as_slice()).unwrap(),
            nonce: hash32(0x20),
            issued_at_server: UnixMillis::new(24),
            expires_at: UnixMillis::new(-1000),
            server_certificate_hash: CertificateHash::try_from(hash32(0x30).as_slice()).unwrap(),
        }
    }

    /// Die Felder hinter `REGISTRATION_CORE_HEX`.
    pub fn registration_core() -> DeviceRegistrationRequestCoreV1 {
        let signing =
            hex::decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
                .unwrap();
        DeviceRegistrationRequestCoreV1 {
            organization_id: OrganizationId::try_from(id16(0).as_slice()).unwrap(),
            device_id: DeviceId::try_from(id16(16).as_slice()).unwrap(),
            requested_role: 0,
            signing_public_cose_key: CanonicalPublicCoseKey::ed25519(signing.try_into().unwrap())
                .unwrap(),
            kem_public_cose_key: None,
            supported_format_versions: vec![1],
            supported_suite_ids: vec![ea_crypto::SUITE_ID.to_owned()],
        }
    }

    /// Die Felder hinter `READER_ACK_CORE_HEX`.
    pub fn reader_ack_core() -> ReaderAckCoreV1 {
        ReaderAckCoreV1 {
            organization_id: OrganizationId::try_from(id16(0).as_slice()).unwrap(),
            chain_id: ChainId::try_from(id16(16).as_slice()).unwrap(),
            reader_certificate_hash: CertificateHash::try_from(hash32(0x40).as_slice()).unwrap(),
            through_sequence: ChainSequence::new(24),
            head_entry_hash: EntryHash::try_from(hash32(0x50).as_slice()).unwrap(),
            acknowledged_at_device: UnixMillis::new(-1000),
        }
    }

    /// Ein formgleicher Herausforderungskern mit 16 statt 32 Byte Nonce.
    ///
    /// Der aeussere Rahmen ist ABSICHTLICH heil: nur so schlaegt der
    /// Feldwaechter zu und nicht der Arraywaechter, dessen Code ein anderer
    /// ist.
    pub fn challenge_core_short_nonce() -> Vec<u8> {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .array(7)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.bytes(&id16(0)))
            .and_then(|encoder| encoder.bytes(&[0x20_u8; 16]))
            .and_then(|encoder| encoder.i64(24))
            .and_then(|encoder| encoder.i64(-1000))
            .and_then(|encoder| encoder.bytes(&hash32(0x30)))
            .and_then(|encoder| encoder.array(0))
            .unwrap();
        bytes
    }

    /// Ein Registrierungskern mit einer Rolle ausserhalb von `0..2`.
    pub fn registration_core_unknown_role() -> Vec<u8> {
        let signing = CanonicalPublicCoseKey::ed25519(
            hex::decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap()
        .to_deterministic_cbor();
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .array(9)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.bytes(&id16(0)))
            .and_then(|encoder| encoder.bytes(&id16(16)))
            .and_then(|encoder| encoder.u8(3))
            .and_then(|encoder| encoder.bytes(&signing))
            .and_then(|encoder| encoder.null())
            .and_then(|encoder| encoder.array(1))
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.array(1))
            .and_then(|encoder| encoder.str(ea_crypto::SUITE_ID))
            .and_then(|encoder| encoder.array(0))
            .unwrap();
        bytes
    }

    /// Eine Leserquittung mit 16 statt 32 Byte Kopf-Eintragshash.
    pub fn reader_ack_core_short_head() -> Vec<u8> {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .array(8)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.bytes(&id16(0)))
            .and_then(|encoder| encoder.bytes(&id16(16)))
            .and_then(|encoder| encoder.bytes(&hash32(0x40)))
            .and_then(|encoder| encoder.u8(24))
            .and_then(|encoder| encoder.bytes(&[0x50_u8; 16]))
            .and_then(|encoder| encoder.i64(-1000))
            .and_then(|encoder| encoder.array(0))
            .unwrap();
        bytes
    }
}

#[test]
fn every_protocol_core_encodes_validates_and_decodes() {
    let bytes = encode_challenge_response_core(&fixtures::challenge_core()).unwrap();
    validate_unsigned_protocol_core(ContentType::ChallengeResponseCbor, &bytes).unwrap();
    assert_eq!(
        decode_challenge_response_core(&bytes).unwrap(),
        fixtures::challenge_core()
    );
    assert_eq!(
        decode_challenge_response_core(&fixtures::challenge_core_short_nonce())
            .unwrap_err()
            .code(),
        "EA-CRYPTO-INVALID-PROTOCOL-CORE"
    );

    let bytes = encode_device_registration_request_core(&fixtures::registration_core()).unwrap();
    validate_unsigned_protocol_core(ContentType::DeviceRegistrationRequestCbor, &bytes).unwrap();
    assert_eq!(
        decode_device_registration_request_core(&bytes).unwrap(),
        fixtures::registration_core()
    );
    assert_eq!(
        decode_device_registration_request_core(&fixtures::registration_core_unknown_role())
            .unwrap_err()
            .code(),
        "EA-CRYPTO-INVALID-PROTOCOL-CORE"
    );

    let bytes = encode_reader_ack_core(&fixtures::reader_ack_core()).unwrap();
    validate_unsigned_protocol_core(ContentType::ReaderAckCbor, &bytes).unwrap();
    assert_eq!(
        decode_reader_ack_core(&bytes).unwrap(),
        fixtures::reader_ack_core()
    );
    assert_eq!(
        decode_reader_ack_core(&fixtures::reader_ack_core_short_head())
            .unwrap_err()
            .code(),
        "EA-CRYPTO-INVALID-PROTOCOL-CORE"
    );
}

#[test]
fn the_three_cores_reproduce_their_frozen_normative_bytes() {
    let challenge = hex::decode(CHALLENGE_CORE_HEX).unwrap();
    assert_eq!(
        decode_challenge_response_core(&challenge).unwrap(),
        fixtures::challenge_core()
    );
    assert_eq!(
        encode_challenge_response_core(&fixtures::challenge_core()).unwrap(),
        challenge
    );

    let registration = hex::decode(REGISTRATION_CORE_HEX).unwrap();
    assert_eq!(
        decode_device_registration_request_core(&registration).unwrap(),
        fixtures::registration_core()
    );
    assert_eq!(
        encode_device_registration_request_core(&fixtures::registration_core()).unwrap(),
        registration
    );

    let reader_ack = hex::decode(READER_ACK_CORE_HEX).unwrap();
    assert_eq!(
        decode_reader_ack_core(&reader_ack).unwrap(),
        fixtures::reader_ack_core()
    );
    assert_eq!(
        encode_reader_ack_core(&fixtures::reader_ack_core()).unwrap(),
        reader_ack
    );
}

#[test]
fn a_signed_wrapper_is_no_unsigned_core_for_any_of_the_three_decoders() {
    // Die Huelle `[core, signature]` traegt denselben Inhaltstyp; ein
    // Dekodierer, der sie annaehme, oeffnete dem Server eine unsignierte Tuer.
    let challenge = hex::decode(CHALLENGE_CORE_HEX).unwrap();
    let mut wrapper = vec![0x82];
    wrapper.extend_from_slice(&challenge);
    wrapper.extend_from_slice(&challenge);
    assert_eq!(
        decode_challenge_response_core(&wrapper).unwrap_err().code(),
        "EA-CRYPTO-INVALID-PROTOCOL-CORE"
    );
}
