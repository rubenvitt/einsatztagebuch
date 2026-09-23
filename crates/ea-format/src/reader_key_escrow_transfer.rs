//! Die drei Übergabedateien des Reader-Key-Escrows (Profil §5/§6, Ruling U3).
//!
//! Browser und native Administration tauschen Escrow-Material als DATEI über
//! eine eigene Escrow-Inbox aus, nach dem Muster der Registrierungsanträge.
//! Diese Dateien sind KEINE Archivobjekte und keine Trust-Familie; ihre
//! Grammatik steht in `schemas/archive/v1/trust.cddl` unter „Übergabedateien".
//!
//! - [`ReaderKeyEscrowPackageV1`] (Zeremonie A, Browser → nativ): der Core mit
//!   genau den Bytes, deren Hash `escrow-core-hash` wird.
//! - [`ReaderKeyEscrowTransportRequestV1`] (Zeremonie B, Browser → nativ): der
//!   rohe X25519-Ziel-Transport-Schlüssel.
//! - [`ReaderKeyEscrowEnvelopeV1`] (Zeremonie B, nativ → Browser): die
//!   öffentliche Restore-Bindung und der versiegelte Reader-KEM.
//!
//! Der Codec arbeitet über exakten Bytes: deterministisches CBOR
//! (`ea_cbor::validate`), keine unbekannten Felder, kein Rest, höchstens
//! [`READER_KEY_ESCROW_TRANSFER_MAX_BYTES`]. Er ist wasm32-fähig, damit der
//! Browser (Scheibe e) dieselbe Kodierung benutzt. Der Dateiname ist allein
//! `hex(object_hash(datei))` plus Suffix ([`reader_key_escrow_transfer_file_name`])
//! — er trägt weder Geheimnis noch Subject-ID noch Pfad.

use ea_cbor::{ParserLimits, validate};
use ea_crypto::object_hash;
use ea_types::{KeyThumbprint, ObjectHash, OrganizationId};
use minicbor::{Decoder, Encoder};

use crate::{
    FormatError, ReaderKeyEscrowCoreV1, ReaderKeyEscrowRestoreContextV1,
    etb::{expect_version, typed_bytes},
    object::{bytes_exact, exact_item, expect_array_length, expect_empty_array, finish},
    reader_key_escrow::{
        READER_KEY_ESCROW_RESTORE_SUITE_ID, decode_reader_key_escrow_core,
        encode_reader_key_escrow_core,
    },
};

/// Die Höchstgröße jeder Übergabedatei in Byte.
pub const READER_KEY_ESCROW_TRANSFER_MAX_BYTES: usize = 4096;

/// Das Literal der Paketdatei (Zeremonie A).
pub const READER_KEY_ESCROW_PACKAGE_LITERAL: &str = "EINSATZARCHIV-READER-KEY-ESCROW-PACKAGE-1";

/// Das Literal der Transportdatei (Zeremonie B).
pub const READER_KEY_ESCROW_TRANSPORT_LITERAL: &str = "EINSATZARCHIV-READER-KEY-ESCROW-TRANSPORT-1";

/// Das Literal der Umschlagdatei (Zeremonie B).
pub const READER_KEY_ESCROW_ENVELOPE_LITERAL: &str = "EINSATZARCHIV-READER-KEY-ESCROW-ENVELOPE-1";

/// Welche der drei Übergabedateien.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderKeyEscrowTransferKindV1 {
    Package,
    TransportRequest,
    Envelope,
}

impl ReaderKeyEscrowTransferKindV1 {
    /// Das feste Dateisuffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Package => ".reader-key-escrow-package.cbor",
            Self::TransportRequest => ".reader-key-escrow-transport.cbor",
            Self::Envelope => ".reader-key-escrow-envelope.cbor",
        }
    }
}

/// Der Dateiname einer Übergabedatei: `hex(object_hash(bytes))` plus Suffix.
///
/// Derselbe Stamm wie bei den Registrierungsanträgen der Admin-Inbox. Der Name
/// ist eine Funktion der Bytes und sonst von nichts.
#[must_use]
pub fn reader_key_escrow_transfer_file_name(
    kind: ReaderKeyEscrowTransferKindV1,
    exact_bytes: &[u8],
) -> String {
    let hash = object_hash(exact_bytes);
    let mut name = String::with_capacity(64 + kind.suffix().len());
    for byte in hash.as_bytes() {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(kind.suffix());
    name
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Das Paket der Zeremonie A: ein Escrow-Core, noch ohne Freigabe und ohne
/// Root-Signatur.
///
/// [`Self::exact_core`] sind die Bytes AUS der Datei; sie werden nie neu
/// gerechnet. Weil die Datei deterministisches CBOR sein muss, ergibt jede
/// Neukodierung des dekodierten Cores dieselben Bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowPackageV1 {
    core: ReaderKeyEscrowCoreV1,
    exact_core: Vec<u8>,
}

impl ReaderKeyEscrowPackageV1 {
    #[must_use]
    pub const fn core(&self) -> &ReaderKeyEscrowCoreV1 {
        &self.core
    }

    /// Die exakten Core-Bytes, Urbild von `escrow-core-hash`.
    #[must_use]
    pub fn exact_core(&self) -> &[u8] {
        &self.exact_core
    }
}

/// Die Transportdatei der Zeremonie B.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowTransportRequestV1 {
    pub organization_id: OrganizationId,
    pub escrow_object_hash: ObjectHash,
    /// Der rohe X25519-Schlüssel. Ob er kanonisch ist und zum autorisierten
    /// Abdruck passt, prüft der Trust-Kern, nicht der Codec.
    pub target_transport_public_key: [u8; 32],
}

/// Die Umschlagdatei der Zeremonie B.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderKeyEscrowEnvelopeV1 {
    /// Die öffentliche Bindung: Quelle von `hpke_info` und `hpke_aad`.
    pub restore_context: ReaderKeyEscrowRestoreContextV1,
    pub encapsulated_key: [u8; 32],
    /// 32 Byte Reader-KEM plus 16 Byte AEAD-Tag.
    pub sealed_reader_kem_key: [u8; 48],
}

// Undurchsichtig wie `LocalAuditEventV1`: Übergabematerial gehört nicht in
// eine Protokollzeile. Die Rümpfe existieren, damit `Result::unwrap_err` an
// diesen Typen aufrufbar ist.
impl core::fmt::Debug for ReaderKeyEscrowPackageV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReaderKeyEscrowPackageV1(<exact>)")
    }
}

impl core::fmt::Debug for ReaderKeyEscrowTransportRequestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReaderKeyEscrowTransportRequestV1(<exact>)")
    }
}

impl core::fmt::Debug for ReaderKeyEscrowEnvelopeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReaderKeyEscrowEnvelopeV1(<sealed>)")
    }
}

/// Kodiert die Paketdatei um einen Core.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn das Kodieren scheitert.
pub fn encode_reader_key_escrow_package(
    core: &ReaderKeyEscrowCoreV1,
) -> Result<Vec<u8>, FormatError> {
    let exact_core = encode_reader_key_escrow_core(core)?;
    let mut exact = Vec::with_capacity(exact_core.len().saturating_add(64));
    Encoder::new(&mut exact)
        .array(4)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str(READER_KEY_ESCROW_PACKAGE_LITERAL))
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(&exact_core);
    Encoder::new(&mut exact)
        .array(0)
        .map_err(|_| FormatError::Shape)?;
    bounded(exact)
}

/// Dekodiert eine Paketdatei aus ihren exakten Bytes.
///
/// # Errors
///
/// [`FormatError::Shape`] für jede Gestaltabweichung, eine Größe über
/// [`READER_KEY_ESCROW_TRANSFER_MAX_BYTES`] oder ein fremdes Literal;
/// [`FormatError::UnknownVersion`], [`FormatError::CriticalExtension`] und
/// [`FormatError::Cbor`] für nicht deterministisches CBOR.
pub fn decode_reader_key_escrow_package(
    exact_bytes: &[u8],
) -> Result<ReaderKeyEscrowPackageV1, FormatError> {
    let mut decoder = open(exact_bytes, READER_KEY_ESCROW_PACKAGE_LITERAL)?;
    let exact_core = exact_item(exact_bytes, &mut decoder)?;
    let core = decode_reader_key_escrow_core(exact_core)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, exact_bytes)?;
    Ok(ReaderKeyEscrowPackageV1 {
        core,
        exact_core: exact_core.to_vec(),
    })
}

/// Kodiert die Transportdatei.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn das Kodieren scheitert.
pub fn encode_reader_key_escrow_transport_request(
    request: &ReaderKeyEscrowTransportRequestV1,
) -> Result<Vec<u8>, FormatError> {
    let mut exact = Vec::with_capacity(160);
    Encoder::new(&mut exact)
        .array(6)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str(READER_KEY_ESCROW_TRANSPORT_LITERAL))
        .and_then(|encoder| encoder.bytes(request.organization_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(request.escrow_object_hash.as_bytes()))
        .and_then(|encoder| encoder.bytes(&request.target_transport_public_key))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    bounded(exact)
}

/// Dekodiert eine Transportdatei aus ihren exakten Bytes.
///
/// # Errors
///
/// Wie [`decode_reader_key_escrow_package`].
pub fn decode_reader_key_escrow_transport_request(
    exact_bytes: &[u8],
) -> Result<ReaderKeyEscrowTransportRequestV1, FormatError> {
    let mut decoder = open(exact_bytes, READER_KEY_ESCROW_TRANSPORT_LITERAL)?;
    let organization_id = typed_bytes(&mut decoder, 16)?;
    let escrow_object_hash = typed_bytes(&mut decoder, 32)?;
    let target_transport_public_key = fixed_bytes(&mut decoder)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, exact_bytes)?;
    Ok(ReaderKeyEscrowTransportRequestV1 {
        organization_id,
        escrow_object_hash,
        target_transport_public_key,
    })
}

/// Kodiert die Umschlagdatei.
///
/// # Errors
///
/// [`FormatError::Shape`], wenn das Kodieren scheitert.
pub fn encode_reader_key_escrow_envelope(
    envelope: &ReaderKeyEscrowEnvelopeV1,
) -> Result<Vec<u8>, FormatError> {
    let restore = envelope.restore_context.encode();
    let mut exact = Vec::with_capacity(restore.len().saturating_add(160));
    Encoder::new(&mut exact)
        .array(6)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str(READER_KEY_ESCROW_ENVELOPE_LITERAL))
        .map_err(|_| FormatError::Shape)?;
    exact.extend_from_slice(&restore);
    Encoder::new(&mut exact)
        .bytes(&envelope.encapsulated_key)
        .and_then(|encoder| encoder.bytes(&envelope.sealed_reader_kem_key))
        .and_then(|encoder| encoder.array(0))
        .map_err(|_| FormatError::Shape)?;
    bounded(exact)
}

/// Dekodiert eine Umschlagdatei aus ihren exakten Bytes.
///
/// # Errors
///
/// Wie [`decode_reader_key_escrow_package`]; zusätzlich [`FormatError::Shape`]
/// für eine Restore-Bindung mit fremdem Suite-Literal.
pub fn decode_reader_key_escrow_envelope(
    exact_bytes: &[u8],
) -> Result<ReaderKeyEscrowEnvelopeV1, FormatError> {
    let mut decoder = open(exact_bytes, READER_KEY_ESCROW_ENVELOPE_LITERAL)?;
    let restore_context = decode_restore_context(&mut decoder)?;
    let encapsulated_key = fixed_bytes(&mut decoder)?;
    let sealed_reader_kem_key = fixed_bytes(&mut decoder)?;
    expect_empty_array(&mut decoder)?;
    finish(&decoder, exact_bytes)?;
    Ok(ReaderKeyEscrowEnvelopeV1 {
        restore_context,
        encapsulated_key,
        sealed_reader_kem_key,
    })
}

/// Größe, Determinismus, Außengestalt, Version und Literal — die gemeinsame
/// Pforte aller drei Dekodierer. Zurück kommt der Dekodierer hinter dem
/// Literal.
fn open<'a>(exact_bytes: &'a [u8], literal: &str) -> Result<Decoder<'a>, FormatError> {
    if exact_bytes.len() > READER_KEY_ESCROW_TRANSFER_MAX_BYTES {
        return Err(FormatError::Shape);
    }
    validate(exact_bytes, ParserLimits::V1)?;
    let mut decoder = Decoder::new(exact_bytes);
    let length = match literal {
        READER_KEY_ESCROW_PACKAGE_LITERAL => 4,
        _ => 6,
    };
    expect_array_length(&mut decoder, length)?;
    expect_version(&mut decoder)?;
    if decoder.str().map_err(|_| FormatError::Shape)? != literal {
        return Err(FormatError::Shape);
    }
    Ok(decoder)
}

fn bounded(exact: Vec<u8>) -> Result<Vec<u8>, FormatError> {
    if exact.len() > READER_KEY_ESCROW_TRANSFER_MAX_BYTES {
        return Err(FormatError::Shape);
    }
    Ok(exact)
}

fn decode_restore_context(
    decoder: &mut Decoder<'_>,
) -> Result<ReaderKeyEscrowRestoreContextV1, FormatError> {
    expect_array_length(decoder, 9)?;
    expect_version(decoder)?;
    let organization_id = typed_bytes(decoder, 16)?;
    let authorization_object_hash = typed_bytes(decoder, 32)?;
    let escrow_object_hash = typed_bytes(decoder, 32)?;
    let reader_certificate_object_hash = typed_bytes(decoder, 32)?;
    let reader_subject_id = typed_bytes(decoder, 16)?;
    let target_transport_key_thumbprint: KeyThumbprint = typed_bytes(decoder, 32)?;
    if decoder.str().map_err(|_| FormatError::Shape)? != READER_KEY_ESCROW_RESTORE_SUITE_ID {
        return Err(FormatError::Shape);
    }
    expect_empty_array(decoder)?;
    Ok(ReaderKeyEscrowRestoreContextV1 {
        organization_id,
        authorization_object_hash,
        escrow_object_hash,
        reader_certificate_object_hash,
        reader_subject_id,
        target_transport_key_thumbprint,
    })
}

fn fixed_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], FormatError> {
    bytes_exact(decoder, N)?
        .try_into()
        .map_err(|_| FormatError::Shape)
}
