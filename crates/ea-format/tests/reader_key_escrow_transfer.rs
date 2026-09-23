//! Die drei Übergabedateien des Reader-Key-Escrows (Profil §5/§6, Ruling U3):
//! exakte Bytes, deterministisch, ohne unbekannte Felder, ohne Rest, begrenzt.

use ea_format::{
    FormatError, READER_KEY_ESCROW_ENVELOPE_LITERAL, READER_KEY_ESCROW_PACKAGE_LITERAL,
    READER_KEY_ESCROW_TRANSFER_MAX_BYTES, READER_KEY_ESCROW_TRANSPORT_LITERAL,
    ReaderKeyEscrowCoreV1, ReaderKeyEscrowEnvelopeV1, ReaderKeyEscrowRestoreContextV1,
    ReaderKeyEscrowTransferKindV1, ReaderKeyEscrowTransportRequestV1,
    decode_reader_key_escrow_envelope, decode_reader_key_escrow_package,
    decode_reader_key_escrow_transport_request, encode_reader_key_escrow_envelope,
    encode_reader_key_escrow_package, encode_reader_key_escrow_transport_request,
    reader_key_escrow_transfer_file_name,
};
use ea_types::{
    CertificateHash, ChainSequence, Hash32, KeyThumbprint, ObjectHash, OrganizationId,
    RegistryVersion, SubjectId, UnixMillis,
};
use minicbor::Encoder;

fn core() -> ReaderKeyEscrowCoreV1 {
    ReaderKeyEscrowCoreV1 {
        organization_id: OrganizationId::try_from([0x11; 16].as_slice()).unwrap(),
        reader_certificate_object_hash: CertificateHash::try_from([0x12; 32].as_slice()).unwrap(),
        reader_subject_id: SubjectId::try_from([0x13; 16].as_slice()).unwrap(),
        enrollment_registry_version: RegistryVersion::new(7),
        enrollment_registry_head_hash: Hash32::try_from([0x14; 32].as_slice()).unwrap(),
        enrollment_sequence: ChainSequence::new(3),
        recovery_certificate_object_hash: CertificateHash::try_from([0x15; 32].as_slice()).unwrap(),
        recovery_kem_key_thumbprint: KeyThumbprint::try_from([0x16; 32].as_slice()).unwrap(),
        encapsulated_key: [0x17; 32],
        encrypted_reader_kem_key: [0x18; 48],
        issued_at: UnixMillis::new(1_700_000_000_000),
        root_key_thumbprint: KeyThumbprint::try_from([0x19; 32].as_slice()).unwrap(),
    }
}

fn transport() -> ReaderKeyEscrowTransportRequestV1 {
    ReaderKeyEscrowTransportRequestV1 {
        organization_id: OrganizationId::try_from([0x21; 16].as_slice()).unwrap(),
        escrow_object_hash: ObjectHash::try_from([0x22; 32].as_slice()).unwrap(),
        target_transport_public_key: [0x23; 32],
    }
}

fn envelope() -> ReaderKeyEscrowEnvelopeV1 {
    ReaderKeyEscrowEnvelopeV1 {
        restore_context: ReaderKeyEscrowRestoreContextV1 {
            organization_id: OrganizationId::try_from([0x31; 16].as_slice()).unwrap(),
            authorization_object_hash: ObjectHash::try_from([0x32; 32].as_slice()).unwrap(),
            escrow_object_hash: ObjectHash::try_from([0x33; 32].as_slice()).unwrap(),
            reader_certificate_object_hash: CertificateHash::try_from([0x34; 32].as_slice())
                .unwrap(),
            reader_subject_id: SubjectId::try_from([0x35; 16].as_slice()).unwrap(),
            target_transport_key_thumbprint: KeyThumbprint::try_from([0x36; 32].as_slice())
                .unwrap(),
        },
        encapsulated_key: [0x37; 32],
        sealed_reader_kem_key: [0x38; 48],
    }
}

#[test]
fn every_transfer_file_round_trips_through_its_exact_bytes() {
    let package = encode_reader_key_escrow_package(&core()).unwrap();
    let decoded = decode_reader_key_escrow_package(&package).unwrap();
    assert!(*decoded.core() == core());
    // Die Core-Bytes stehen unverändert in der Datei: das Paket rechnet nie
    // neu, es gibt einen Ausschnitt seiner eigenen Bytes heraus.
    let start = package
        .windows(decoded.exact_core().len())
        .position(|window| window == decoded.exact_core())
        .expect("the exact core is a slice of the file");
    assert!(start > 0);

    let request = encode_reader_key_escrow_transport_request(&transport()).unwrap();
    assert!(decode_reader_key_escrow_transport_request(&request).unwrap() == transport());

    let sealed = encode_reader_key_escrow_envelope(&envelope()).unwrap();
    let decoded = decode_reader_key_escrow_envelope(&sealed).unwrap();
    assert!(decoded == envelope());
    // Die Bindung in der Datei ist Byte für Byte die Hausform des Kontexts,
    // aus der `hpke_info`/`hpke_aad` entstehen.
    let restore = envelope().restore_context.encode();
    assert!(
        sealed
            .windows(restore.len())
            .any(|window| window == restore)
    );

    for bytes in [&package, &request, &sealed] {
        assert!(bytes.len() <= READER_KEY_ESCROW_TRANSFER_MAX_BYTES);
    }
}

/// Jede Datei trägt ihr eigenes Literal; die Datei eines Nachbarn wird nie als
/// diese gelesen.
#[test]
fn no_transfer_file_is_read_as_its_neighbour() {
    let package = encode_reader_key_escrow_package(&core()).unwrap();
    let request = encode_reader_key_escrow_transport_request(&transport()).unwrap();
    let sealed = encode_reader_key_escrow_envelope(&envelope()).unwrap();
    assert!(decode_reader_key_escrow_package(&request).is_err());
    assert!(decode_reader_key_escrow_package(&sealed).is_err());
    assert!(decode_reader_key_escrow_transport_request(&package).is_err());
    assert!(decode_reader_key_escrow_transport_request(&sealed).is_err());
    assert!(decode_reader_key_escrow_envelope(&package).is_err());
    assert!(decode_reader_key_escrow_envelope(&request).is_err());
}

/// Ein Zusatzfeld, ein fehlendes Feld, ein Rest hinter der Datei und eine
/// falsche Feldlänge scheitern.
#[test]
fn a_transfer_file_carries_no_unknown_field_and_no_rest() {
    let transport = transport();
    let with_fields = |fields: u64, extra: bool, key: &[u8]| {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .array(fields)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.str(READER_KEY_ESCROW_TRANSPORT_LITERAL))
            .and_then(|encoder| encoder.bytes(transport.organization_id.as_bytes()))
            .and_then(|encoder| encoder.bytes(transport.escrow_object_hash.as_bytes()))
            .and_then(|encoder| encoder.bytes(key))
            .unwrap();
        if extra {
            encoder.u8(0).unwrap();
        }
        encoder.array(0).unwrap();
        bytes
    };
    // Die Gegenprobe: dieselbe Handkodierung mit sechs Feldern IST die Datei.
    assert_eq!(
        with_fields(6, false, &[0x23; 32]),
        encode_reader_key_escrow_transport_request(&transport).unwrap()
    );
    assert!(
        decode_reader_key_escrow_transport_request(&with_fields(7, true, &[0x23; 32])).is_err()
    );
    assert!(
        decode_reader_key_escrow_transport_request(&with_fields(6, false, &[0x23; 31])).is_err()
    );
    let mut trailing = encode_reader_key_escrow_transport_request(&transport).unwrap();
    trailing.push(0x00);
    assert!(decode_reader_key_escrow_transport_request(&trailing).is_err());
    let mut extension = encode_reader_key_escrow_transport_request(&transport).unwrap();
    let last = extension.len() - 1;
    assert_eq!(
        extension[last], 0x80,
        "the empty extension slot closes the file"
    );
    extension[last] = 0x81;
    extension.push(0x00);
    assert_eq!(
        decode_reader_key_escrow_transport_request(&extension).unwrap_err(),
        FormatError::CriticalExtension
    );
}

/// Nicht deterministisches CBOR (eine nicht minimale Versionsangabe) scheitert,
/// obwohl der Wert derselbe ist: sonst ergäbe die Neukodierung des Cores andere
/// Bytes als die Datei.
#[test]
fn a_non_deterministic_transfer_file_is_refused() {
    let package = encode_reader_key_escrow_package(&core()).unwrap();
    assert_eq!(
        package[1], 0x01,
        "the version literal follows the array head"
    );
    let mut widened = vec![package[0], 0x18, 0x01];
    widened.extend_from_slice(&package[2..]);
    assert!(matches!(
        decode_reader_key_escrow_package(&widened).unwrap_err(),
        FormatError::Cbor(_)
    ));
}

#[test]
fn a_transfer_file_is_bounded() {
    let mut oversized = Vec::new();
    let padding = vec![0; READER_KEY_ESCROW_TRANSFER_MAX_BYTES];
    Encoder::new(&mut oversized)
        .array(4)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str(READER_KEY_ESCROW_PACKAGE_LITERAL))
        .and_then(|encoder| encoder.bytes(&padding))
        .and_then(|encoder| encoder.array(0))
        .unwrap();
    assert!(oversized.len() > READER_KEY_ESCROW_TRANSFER_MAX_BYTES);
    assert_eq!(
        decode_reader_key_escrow_package(&oversized).unwrap_err(),
        FormatError::Shape
    );
}

/// Die Restore-Bindung im Umschlag trägt IHR Suite-Literal; das der
/// Escrow-Kapselung ist keines.
#[test]
fn an_envelope_binds_the_restore_suite_literal() {
    let sealed = encode_reader_key_escrow_envelope(&envelope()).unwrap();
    let restore = b"EINSATZARCHIV-READER-KEY-ESCROW-RESTORE-1";
    let foreign = b"EINSATZARCHIV-READER-KEY-ESCROW-RESTORX-1";
    let position = sealed
        .windows(restore.len())
        .position(|window| window == restore)
        .unwrap();
    let mut tampered = sealed.clone();
    tampered[position..position + restore.len()].copy_from_slice(foreign);
    assert_eq!(
        decode_reader_key_escrow_envelope(&tampered).unwrap_err(),
        FormatError::Shape
    );
    assert!(READER_KEY_ESCROW_ENVELOPE_LITERAL.ends_with("-ENVELOPE-1"));
}

/// Der Dateiname ist allein der Hash der Bytes plus Suffix — kein Geheimnis,
/// keine Subject-ID, kein Pfad.
#[test]
fn a_transfer_file_name_is_only_the_hash_of_its_bytes() {
    let request = encode_reader_key_escrow_transport_request(&transport()).unwrap();
    let name = reader_key_escrow_transfer_file_name(
        ReaderKeyEscrowTransferKindV1::TransportRequest,
        &request,
    );
    let (stem, suffix) = name.split_at(64);
    assert_eq!(suffix, ".reader-key-escrow-transport.cbor");
    assert_eq!(
        stem,
        hex::encode(ea_crypto::object_hash(&request).as_bytes())
    );
    let package = encode_reader_key_escrow_package(&core()).unwrap();
    assert!(
        reader_key_escrow_transfer_file_name(ReaderKeyEscrowTransferKindV1::Package, &package)
            .ends_with(".reader-key-escrow-package.cbor")
    );
    assert!(
        reader_key_escrow_transfer_file_name(ReaderKeyEscrowTransferKindV1::Envelope, &package)
            .ends_with(".reader-key-escrow-envelope.cbor")
    );
    let subject = hex::encode([0x13; 16]);
    assert!(!name.contains(&subject));
}
