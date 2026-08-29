//! Die drei signierten Protokollkoerper, die die Leitung unveraendert aus
//! `schemas/protocol/v1/signed-protocol.cddl` uebernimmt.
//!
//! Kodiert und dekodiert wird AUSSCHLIESSLICH mit den Codecs von `ea-crypto`.
//! Diese Datei traegt nur die Huelle `[core, #6.18(COSE-Sign1)]` und die
//! Bytegrenze des Endpunkts; sie baut weder einen Core noch eine
//! COSE-Struktur nach.

use core::fmt;

use ea_crypto::{
    ChallengeResponseCoreV1, ContentType, DeviceRegistrationRequestCoreV1, ReaderAckCoreV1,
    decode_challenge_response_core, decode_device_registration_request_core,
    decode_reader_ack_core, encode_challenge_response_core,
    encode_device_registration_request_core, encode_reader_ack_core,
    encode_signed_protocol_wrapper,
};
use minicbor::Decoder;

use crate::{MAX_SMALL_BODY_BYTES_V1, PROTOCOL_PARSER_LIMITS_V1, SyncProtocolError, cbor_read};

/// Zerlegt `[core, #6.18(COSE-Sign1)]` in seine beiden exakten Teile.
fn split_wrapper(bytes: &[u8]) -> Result<(&[u8], &[u8]), SyncProtocolError> {
    if bytes.len() > MAX_SMALL_BODY_BYTES_V1 {
        return Err(SyncProtocolError::BodyLimit);
    }
    ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
    let mut decoder = Decoder::new(bytes);
    cbor_read::expect_array(&mut decoder, 2)?;
    let core = cbor_read::exact_item(bytes, &mut decoder)?;
    let cose = cbor_read::exact_item(bytes, &mut decoder)?;
    cbor_read::finish(&decoder, bytes)?;
    Ok((core, cose))
}

macro_rules! signed_protocol_body {
    ($name:ident, $core:ty, $content_type:expr, $encode:path, $decode:path, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            core: $core,
            exact: Vec<u8>,
        }

        impl $name {
            /// Rahmt einen bereits kodierten Core mit seiner Signatur.
            ///
            /// `encode_signed_protocol_wrapper` prueft dabei Profil, Content
            /// Type und die Bindung der Signatur an genau diesen Core.
            pub fn new(core: $core, cose_sign1: &[u8]) -> Result<Self, SyncProtocolError> {
                let exact_core = $encode(&core)?;
                let exact = encode_signed_protocol_wrapper($content_type, &exact_core, cose_sign1)?;
                if exact.len() > MAX_SMALL_BODY_BYTES_V1 {
                    return Err(SyncProtocolError::BodyLimit);
                }
                Ok(Self { core, exact })
            }

            pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
                let (exact_core, cose_sign1) = split_wrapper(bytes)?;
                let core = $decode(exact_core)?;
                let body = Self::new(core, cose_sign1)?;
                if body.exact != bytes {
                    return Err(SyncProtocolError::FrameShape);
                }
                Ok(body)
            }

            #[must_use]
            pub fn exact_bytes(&self) -> &[u8] {
                &self.exact
            }

            #[must_use]
            pub const fn core(&self) -> &$core {
                &self.core
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<bound>)"))
            }
        }
    };
}

signed_protocol_body!(
    ChallengeResponseV1,
    ChallengeResponseCoreV1,
    ContentType::ChallengeResponseCbor,
    encode_challenge_response_core,
    decode_challenge_response_core,
    "`challenge-response-v1` — die Antwort des rate-limitierten Challenge-Endpunkts."
);
signed_protocol_body!(
    DeviceRegistrationRequestV1,
    DeviceRegistrationRequestCoreV1,
    ContentType::DeviceRegistrationRequestCbor,
    encode_device_registration_request_core,
    decode_device_registration_request_core,
    "`device-registration-request-v1` — der Koerper von `POST /v1/device-registrations`, \
     mit dem beantragten Schluessel als Proof of Possession."
);
signed_protocol_body!(
    ReaderAckV1,
    ReaderAckCoreV1,
    ContentType::ReaderAckCbor,
    encode_reader_ack_core,
    decode_reader_ack_core,
    "`reader-ack-v1` — der Koerper von `POST /v1/reader-acks`."
);
