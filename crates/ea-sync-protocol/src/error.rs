//! Der Fehlerbefund des Sync-Protokolls und sein Wire-Koerper.
//!
//! Jeder unterscheidbare Verstoss traegt einen STABILEN Code und genau eine
//! HTTP-Abbildung. Kein Code, keine Meldung und kein Feld traegt ein Fragment
//! des gelieferten Koerpers: `protocol-error-v1` ist klartextfrei.

use core::fmt;

use ea_cbor::CborError;
use ea_crypto::CryptoError;
use ea_format::FormatError;
use ea_types::{Hash32, RegistryVersion};
use minicbor::Decoder;

use crate::{
    MAX_SMALL_BODY_BYTES_V1, PROTOCOL_PARSER_LIMITS_V1, cbor, cbor_read,
    http_signature::RequestIdV1,
};

/// Jeder Befund, den die Protokollschicht kennt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SyncProtocolError {
    // --- RFC-9421-Requestpruefung ---
    /// Die Signatur deckt nicht jede geforderte Komponente ab.
    SignatureCoverage,
    /// Die abgedeckte Komponentenliste nennt eine Komponente zweimal.
    SignatureDuplicateComponent,
    /// `Signature-Input` oder `Signature` sind nicht lesbar.
    SignatureMalformed,
    /// Die Signatur passt nicht zur Signaturbasis.
    SignatureInvalid,
    /// `alg` ist nicht `ed25519`.
    UnsupportedAlgorithm,
    /// Der Medientyp des Requestkoerpers passt nicht zum Endpunkt.
    ContentTypeMismatch,
    /// Der `content-digest`-Header passt nicht zu den empfangenen Bytes.
    ContentDigestMismatch,
    /// Der Request nennt eine fremde Autoritaet.
    AuthorityMismatch,
    /// Die Ziel-URI gehoert nicht zu diesem Endpunkt.
    TargetUriMismatch,
    /// Das `tag` bindet an eine andere Organisation.
    TagMismatch,
    /// `created < expires` verletzt oder das Fenster ueberschreitet
    /// [`crate::MAX_SIGNATURE_WINDOW_SECONDS_V1`].
    WindowInvalid,
    /// Die Serverzeit liegt hinter `expires`.
    RequestExpired,
    /// Die Nonce wurde bereits verbraucht.
    NonceReplay,
    /// Die Request-ID wurde bereits verbraucht.
    RequestIdReplay,
    /// `keyid` benennt kein bekanntes Geraetezertifikat.
    KeyUnresolved,
    /// Das Zertifikat traegt die geforderte Capability nicht.
    CapabilityMissing,
    /// Das Zertifikat gehoert zu einer anderen Organisation.
    OrganizationMismatch,

    // --- Rahmen, Grenzen und Cursor ---
    /// Der Rahmen verletzt seine Form.
    FrameShape,
    /// Der Rahmen traegt eine andere Version als 1.
    FrameVersion,
    /// Der Medientyp ist keiner der beiden v1-Medientypen.
    MediaType,
    /// Der Koerper ueberschreitet die Bytedecke seines Endpunkts.
    BodyLimit,
    /// Eine Liste ueberschreitet ihre Satzdecke.
    ItemLimit,
    /// Ein `.eag` ueberschreitet [`crate::MAX_GRANT_OBJECT_BYTES_V1`].
    GrantLimit,
    /// Zwei Saetze nennen denselben `objectHash`.
    DuplicateObject,
    /// Eine Objektliste ist nicht bytweise sortiert.
    UnsortedObjects,
    /// Das gelieferte Objekt gehoert nicht zu der Objektfamilie, die dieser
    /// Endpunkt annimmt.
    ObjectTypeMismatch,
    /// Der technische Cursor ist nicht lesbar oder nicht authentisch.
    CursorInvalid,
    /// Der technische Cursor ist abgelaufen.
    CursorExpired,
    /// Der technische Cursor gehoert zu einem anderen Endpunkt oder zu einer
    /// anderen Organisation.
    CursorScope,

    // --- Dienstbefunde, die der Serverpfad als `protocol-error-v1` ausgibt ---
    /// Objekt, Kette, Eintrag oder Vernichtungsvorgang ist unbekannt.
    NotFound,
    /// Fork, Kopfabweichung, Bytekonflikt oder nicht idempotenter Replay.
    Conflict,
    /// Challenge- oder Ratenlimit.
    RateLimited,
    /// Interner Fehler ohne fachliche Ursache.
    Internal,
    /// Datenbank, Object Store oder TSA sind voruebergehend nicht erreichbar.
    DependencyUnavailable,

    // --- durchgereichte Befunde der geteilten Kernbibliotheken ---
    Format(FormatError),
    Crypto(CryptoError),
    Cbor(CborError),
}

impl SyncProtocolError {
    /// Jeder eigene Befund dieser Crate.
    ///
    /// Die durchgereichten Befunde von `ea-format`, `ea-crypto` und `ea-cbor`
    /// stehen NICHT darin: ihre Codes und ihre Eindeutigkeit gehoeren den
    /// Crates, die sie erzeugen.
    pub const ALL: [Self; 34] = [
        Self::SignatureCoverage,
        Self::SignatureDuplicateComponent,
        Self::SignatureMalformed,
        Self::SignatureInvalid,
        Self::UnsupportedAlgorithm,
        Self::ContentTypeMismatch,
        Self::ContentDigestMismatch,
        Self::AuthorityMismatch,
        Self::TargetUriMismatch,
        Self::TagMismatch,
        Self::WindowInvalid,
        Self::RequestExpired,
        Self::NonceReplay,
        Self::RequestIdReplay,
        Self::KeyUnresolved,
        Self::CapabilityMissing,
        Self::OrganizationMismatch,
        Self::FrameShape,
        Self::FrameVersion,
        Self::MediaType,
        Self::BodyLimit,
        Self::ItemLimit,
        Self::GrantLimit,
        Self::DuplicateObject,
        Self::UnsortedObjects,
        Self::ObjectTypeMismatch,
        Self::CursorInvalid,
        Self::CursorExpired,
        Self::CursorScope,
        Self::NotFound,
        Self::Conflict,
        Self::RateLimited,
        Self::Internal,
        Self::DependencyUnavailable,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SignatureCoverage => "EA-HTTP-SIGNATURE-COVERAGE",
            Self::SignatureDuplicateComponent => "EA-HTTP-SIGNATURE-DUPLICATE-COMPONENT",
            Self::SignatureMalformed => "EA-HTTP-SIGNATURE-MALFORMED",
            Self::SignatureInvalid => "EA-HTTP-SIGNATURE-INVALID",
            Self::UnsupportedAlgorithm => "EA-HTTP-UNSUPPORTED-ALGORITHM",
            Self::ContentTypeMismatch => "EA-HTTP-CONTENT-TYPE",
            Self::ContentDigestMismatch => "EA-HTTP-CONTENT-DIGEST",
            Self::AuthorityMismatch => "EA-HTTP-AUTHORITY-MISMATCH",
            Self::TargetUriMismatch => "EA-HTTP-TARGET-URI-MISMATCH",
            Self::TagMismatch => "EA-HTTP-TAG-MISMATCH",
            Self::WindowInvalid => "EA-HTTP-WINDOW-INVALID",
            Self::RequestExpired => "EA-HTTP-REQUEST-EXPIRED",
            Self::NonceReplay => "EA-HTTP-NONCE-REPLAY",
            Self::RequestIdReplay => "EA-HTTP-REQUEST-ID-REPLAY",
            Self::KeyUnresolved => "EA-HTTP-KEY-UNRESOLVED",
            Self::CapabilityMissing => "EA-HTTP-CAPABILITY-MISSING",
            Self::OrganizationMismatch => "EA-HTTP-ORGANIZATION-MISMATCH",
            Self::FrameShape => "EA-SYNC-FRAME-SHAPE",
            Self::FrameVersion => "EA-SYNC-FRAME-VERSION",
            Self::MediaType => "EA-SYNC-MEDIA-TYPE",
            Self::BodyLimit => "EA-SYNC-BODY-LIMIT",
            Self::ItemLimit => "EA-SYNC-ITEM-LIMIT",
            Self::GrantLimit => "EA-SYNC-GRANT-LIMIT",
            Self::DuplicateObject => "EA-SYNC-DUPLICATE-OBJECT",
            Self::UnsortedObjects => "EA-SYNC-UNSORTED-OBJECTS",
            Self::ObjectTypeMismatch => "EA-SYNC-OBJECT-TYPE",
            Self::CursorInvalid => "EA-SYNC-CURSOR-INVALID",
            Self::CursorExpired => "EA-SYNC-CURSOR-EXPIRED",
            Self::CursorScope => "EA-SYNC-CURSOR-SCOPE",
            Self::NotFound => "EA-SYNC-NOT-FOUND",
            Self::Conflict => "EA-SYNC-CONFLICT",
            Self::RateLimited => "EA-HTTP-RATE-LIMITED",
            Self::Internal => "EA-SYNC-INTERNAL",
            Self::DependencyUnavailable => "EA-SYNC-DEPENDENCY-UNAVAILABLE",
            Self::Format(error) => error.code(),
            Self::Crypto(error) => error.code(),
            Self::Cbor(error) => error.code(),
        }
    }

    /// Die HTTP-Abbildung des Addendums, Zeile fuer Zeile.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::FrameShape
            | Self::FrameVersion
            | Self::MediaType
            | Self::ContentTypeMismatch
            | Self::ContentDigestMismatch
            | Self::CursorInvalid
            | Self::CursorExpired
            | Self::CursorScope => 400,
            Self::SignatureCoverage
            | Self::SignatureDuplicateComponent
            | Self::SignatureMalformed
            | Self::SignatureInvalid
            | Self::UnsupportedAlgorithm
            | Self::AuthorityMismatch
            | Self::TargetUriMismatch
            | Self::TagMismatch
            | Self::WindowInvalid
            | Self::RequestExpired
            | Self::NonceReplay
            | Self::RequestIdReplay
            | Self::KeyUnresolved => 401,
            Self::CapabilityMissing | Self::OrganizationMismatch => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::BodyLimit | Self::ItemLimit | Self::GrantLimit => 413,
            Self::DuplicateObject | Self::UnsortedObjects | Self::ObjectTypeMismatch => 422,
            Self::RateLimited => 429,
            Self::Internal => 500,
            Self::DependencyUnavailable => 503,
            Self::Format(error) => format_status(error),
            Self::Crypto(_) => 422,
            Self::Cbor(error) => cbor_status(error),
        }
    }

    /// `retryable` gilt AUSSCHLIESSLICH fuer technische Fehler: 429, 500, 503.
    /// Ein Format-, Signatur-, Fork- oder Autorisierungsfehler wird nie
    /// automatisch wiederholt (`design.md` §13.5).
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self.http_status(), 429 | 500 | 503)
    }
}

/// Eine gerissene Rohgrenze ist ein Byte-Limit (413), jede andere
/// Formatabweichung ein wohlgeformter, aber unzulaessiger Inhalt (422); ein
/// CBOR-Befund wird wie unten getrennt.
const fn format_status(error: FormatError) -> u16 {
    match error {
        FormatError::GlobalRawLimit
        | FormatError::EipRawLimit
        | FormatError::EagRawLimit
        | FormatError::EsrRawLimit
        | FormatError::EcpRawLimit
        | FormatError::EtbRawLimit
        | FormatError::EdsRawLimit => 413,
        FormatError::Cbor(error) => cbor_status(error),
        _ => 422,
    }
}

/// Ein CBOR-Befund ist entweder eine gerissene PARSERGRENZE oder eine
/// fehlerhafte Rahmung, und die Trennung ist nicht kosmetisch: die
/// HTTP-Abbildung des Addendums bindet Byte-, Zaehl- UND Parsergrenzen auf
/// `413`, waehrend `400` der fehlerhaften Rahmung vorbehalten bleibt. Ein
/// gerissenes Tiefen-, Element-, Container- oder Tokenbudget als `400`
/// auszugeben, verschoebe genau diese Zeile der Abbildung.
const fn cbor_status(error: CborError) -> u16 {
    match error {
        CborError::ItemLimit
        | CborError::DepthLimit
        | CborError::ContainerLimit
        | CborError::TokenLimit => 413,
        _ => 400,
    }
}

impl From<FormatError> for SyncProtocolError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

impl From<CryptoError> for SyncProtocolError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<CborError> for SyncProtocolError {
    fn from(value: CborError) -> Self {
        Self::Cbor(value)
    }
}

impl fmt::Display for SyncProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for SyncProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for SyncProtocolError {}

/// Der einzige Fehlerkoerper des Protokolls.
///
/// `request-id` steht an ihrer CDDL-Position und bleibt dort. Sie ist die
/// EINZIGE Position, in der sich zwei Antworten auf denselben Befund
/// unterscheiden duerfen; [`ProtocolErrorV1::equals_modulo_request_id`] macht
/// genau diesen Vergleich moeglich, ohne an den Bytes zu schneiden.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtocolErrorV1 {
    error_code: String,
    request_id: RequestIdV1,
    retryable: bool,
    required_registry_version: Option<RegistryVersion>,
    required_registry_head_hash: Option<Hash32>,
    exact: Vec<u8>,
}

impl ProtocolErrorV1 {
    #[must_use]
    pub fn new(
        error: SyncProtocolError,
        request_id: RequestIdV1,
        required_registry_version: Option<RegistryVersion>,
        required_registry_head_hash: Option<Hash32>,
    ) -> Self {
        Self::with_code(
            error.code(),
            request_id,
            error.retryable(),
            required_registry_version,
            required_registry_head_hash,
        )
    }

    /// Derselbe Koerper fuer einen Befund, den DIESE Crate nicht kennt.
    ///
    /// Die Dienstschicht ueber dem Protokoll — `crates/ea-sync-server` — traegt
    /// eigene stabile Codes (`EA-AUTH-…`, `EA-TRUST-EVENT-…`) fuer Verstoesse,
    /// die es erst gibt, wenn ein Dienst hinter dem Rahmen steht: eine
    /// verbrauchte Challenge, ein widersprechender Registrierungsantrag, ein
    /// abgewiesenes Trust-Ereignis. Sie hier als `SyncProtocolError`-Arme zu
    /// fuehren, zoege die Dienstsemantik in die Rahmenschicht; sie neben
    /// `protocol-error-v1` als zweiten Fehlerkoerper zu fuehren, zerbraeche die
    /// Zusage des Addendums, dass es GENAU EINEN gibt. Also derselbe Koerper,
    /// derselbe Kodierer, nur ein Code, den der Aufrufer mitbringt.
    ///
    /// `retryable` bleibt an die Abbildung des Addendums gebunden — 429, 500
    /// und 503 —, und der Aufrufer bringt es aus DERSELBEN Quelle mit wie den
    /// Status.
    #[must_use]
    pub fn with_code(
        error_code: &str,
        request_id: RequestIdV1,
        retryable: bool,
        required_registry_version: Option<RegistryVersion>,
        required_registry_head_hash: Option<Hash32>,
    ) -> Self {
        let error_code = error_code.to_owned();
        let exact = encode(
            &error_code,
            request_id,
            retryable,
            required_registry_version,
            required_registry_head_hash.as_ref(),
        );
        Self {
            error_code,
            request_id,
            retryable,
            required_registry_version,
            required_registry_head_hash,
            exact,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncProtocolError> {
        if bytes.len() > MAX_SMALL_BODY_BYTES_V1 {
            return Err(SyncProtocolError::BodyLimit);
        }
        ea_cbor::validate(bytes, PROTOCOL_PARSER_LIMITS_V1)?;
        let mut decoder = Decoder::new(bytes);
        cbor_read::expect_array(&mut decoder, 7)?;
        cbor_read::expect_version(&mut decoder)?;
        let error_code = cbor_read::text(&mut decoder)?.to_owned();
        let request_id = RequestIdV1::try_from(cbor_read::bytes_exact(&mut decoder, 16)?)
            .map_err(|_| SyncProtocolError::FrameShape)?;
        let retryable = cbor_read::boolean(&mut decoder)?;
        let required_registry_version = optional_uint(&mut decoder)?.map(RegistryVersion::new);
        let required_registry_head_hash = cbor_read::optional_bytes_exact(&mut decoder, 32)?
            .map(Hash32::try_from)
            .transpose()
            .map_err(|_| SyncProtocolError::FrameShape)?;
        cbor_read::expect_empty_extension(&mut decoder)?;
        cbor_read::finish(&decoder, bytes)?;
        let exact = encode(
            &error_code,
            request_id,
            retryable,
            required_registry_version,
            required_registry_head_hash.as_ref(),
        );
        if exact != bytes {
            return Err(SyncProtocolError::FrameShape);
        }
        Ok(Self {
            error_code,
            request_id,
            retryable,
            required_registry_version,
            required_registry_head_hash,
            exact,
        })
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    #[must_use]
    pub fn error_code(&self) -> &str {
        &self.error_code
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestIdV1 {
        self.request_id
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub const fn required_registry_version(&self) -> Option<RegistryVersion> {
        self.required_registry_version
    }

    #[must_use]
    pub const fn required_registry_head_hash(&self) -> Option<Hash32> {
        self.required_registry_head_hash
    }

    /// Zwei Fehlerkoerper sind gleich, wenn sie sich hoechstens in der
    /// global eindeutigen `request-id` unterscheiden.
    #[must_use]
    pub fn equals_modulo_request_id(&self, other: &Self) -> bool {
        self.error_code == other.error_code
            && self.retryable == other.retryable
            && self.required_registry_version == other.required_registry_version
            && self.required_registry_head_hash == other.required_registry_head_hash
    }
}

impl fmt::Debug for ProtocolErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ProtocolErrorV1({})", self.error_code)
    }
}

fn encode(
    error_code: &str,
    request_id: RequestIdV1,
    retryable: bool,
    required_registry_version: Option<RegistryVersion>,
    required_registry_head_hash: Option<&Hash32>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    cbor::array(&mut out, 7);
    cbor::uint(&mut out, 1);
    cbor::text(&mut out, error_code);
    cbor::bytes(&mut out, request_id.as_bytes());
    cbor::boolean(&mut out, retryable);
    match required_registry_version {
        Some(version) => cbor::uint(&mut out, version.get()),
        None => cbor::null(&mut out),
    }
    match required_registry_head_hash {
        Some(hash) => cbor::bytes(&mut out, hash.as_bytes()),
        None => cbor::null(&mut out),
    }
    cbor::empty_extension(&mut out);
    out
}

fn optional_uint(decoder: &mut Decoder<'_>) -> Result<Option<u64>, SyncProtocolError> {
    if decoder
        .datatype()
        .map_err(|_| SyncProtocolError::FrameShape)?
        == minicbor::data::Type::Null
    {
        decoder.null().map_err(|_| SyncProtocolError::FrameShape)?;
        return Ok(None);
    }
    cbor_read::uint(decoder).map(Some)
}
