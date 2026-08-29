//! Das normative v1-Sync-Protokoll: Rahmen, Grenzen und die
//! RFC-9421-Requestpruefung.
//!
//! Die Crate ist SYNCHRON und kennt weder eine Tokio-Laufzeit noch das
//! Wirtsbetriebssystem: `RequestSigner` signiert im Browser mit dem
//! Ed25519-Schluessel des Lesers
//! (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md`
//! §6.6), und ein Uhrzeit- oder Zufallszugriff waere dort eine Wirtsentscheidung
//! und keine Entscheidung dieser Bibliothek. Jede Zeit, jede Nonce und jede
//! Request-ID kommt deshalb als PARAMETER herein.
//!
//! Das normative Dokument dieser Crate ist
//! `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-sync-wire-addendum.md`
//! samt `schemas/protocol/v1/entry-commit.cddl` und
//! `schemas/protocol/v1/reader-batch.cddl`. Objektbytes, Grant-Plaene und
//! Protokoll-Cores werden AUSSCHLIESSLICH ueber `ea-format` und `ea-crypto`
//! kodiert; diese Crate baut keine zweite Kodierung.

#![forbid(unsafe_code)]

mod challenge;
mod commit;
mod error;
mod http_signature;
mod reader;

pub use challenge::{ChallengeResponseV1, DeviceRegistrationRequestV1, ReaderAckV1};
pub use commit::{
    DestructionRequestV1, EntryCommitIdentity, EntryCommitOutcome, EntryCommitRequestV1,
    EntryCommitResponseV1, HistoricalGrantUploadV1, TrustEventUploadV1,
};
pub use error::{ProtocolErrorV1, SyncProtocolError};
pub use http_signature::{
    AuthenticatedDevice, DeviceDirectory, HttpMethod, MAX_SIGNATURE_WINDOW_SECONDS_V1,
    REQUEST_ID_HEADER_V1, ReceivedRequestV1, RegisteredDevice, ReplayStore, RequestIdV1,
    RequestParts, RequestSigner, RequestVerifier, SIGNATURE_ALGORITHM_V1, SIGNATURE_LABEL_V1,
    SignatureComponent, SignatureParametersV1, SignedRequestV1, body_digest, organization_tag,
};
pub use reader::{
    ArchiveExportManifestV1, CheckpointListResponseV1, DestructionStatusResponseV1,
    ExportObjectRecordV1, GrantListResponseV1, MAX_DESTRUCTION_STATE_V1, ObjectRecordV1,
    ReaderBatchV1, TECHNICAL_CURSOR_DOMAIN_V1, TechnicalCursorFieldsV1, TechnicalCursorSigner,
    TechnicalCursorV1, TechnicalCursorVerifier, TrustEventRecordV1, TrustRegistryResponseV1,
    technical_cursor_digest,
};

/// Der Medientyp jedes strukturierten Rahmens dieser Version.
pub const STRUCTURED_MEDIA_TYPE_V1: &str = "application/einsatzarchiv+cbor;v=1";

/// Der Medientyp der rohen Objektantwort. `GET /v1/objects/{objectHash}`
/// traegt KEINEN CBOR-Rahmen: die Antwort sind die exakt archivierten Bytes
/// (`design.md` §13.2, „Objektantworten liefern exakte archivierte Bytes“).
pub const OBJECT_MEDIA_TYPE_V1: &str = "application/einsatzarchiv-object";

/// Die Parsergrenzen jedes strukturierten Rahmens.
///
/// Tiefe und Containerbreite sind die der Stufe 1. Die BEIDEN gehobenen Werte
/// sind begruendet und nicht gewaehlt: `max_text_or_bytes` traegt ein
/// vollstaendiges Archivobjekt als EINEN `bstr`
/// (`ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1`), und `max_total_items` traegt
/// eine volle Seite aus Containerbreite mal Satzbreite. Beide Grenzen weiten
/// die Stufe-1-Grenzen NICHT: eingebettete Archivobjekte und der eingebettete
/// `grant-plan-v1` werden zusaetzlich von `ea-format` unter
/// `ea_cbor::ParserLimits::V1` geprueft, und die engere Grenze gewinnt.
pub const PROTOCOL_PARSER_LIMITS_V1: ea_cbor::ParserLimits = ea_cbor::ParserLimits {
    max_depth: 16,
    max_container_items: 10_000,
    max_total_items: 100_000,
    max_text_or_bytes: ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1,
};

/// Das `.eip` eines Commits — unveraendert die Stufe-1-Familiengrenze.
pub const MAX_ENTRY_OBJECT_BYTES_V1: usize = ea_format::EIP_MAX_RAW_BYTES_V1;

/// Die `.eag`-Decke eines Commits.
///
/// `grant-body-v1` ist in `schemas/archive/v1/archive.cddl` ein geschlossenes
/// Array aus `grant-context-v1`, `bstr .size 32` und `bstr .size 48`, und
/// `grant-context-v1` besteht aus Hashes, Bezeichnern, wenigen begrenzten
/// Ganzzahlen und einer Capability-Zeichenkette. Die sechs eingefrorenen
/// Vektoren unter `vectors/grants/v1/grant/` messen 641 bis 710 Byte,
/// `vectors/format/v1/valid/eag/valid.bin` genau 641 Byte — 2 KiB liegt knapp
/// unter dem Dreifachen des gemessenen Maximums.
pub const MAX_GRANT_OBJECT_BYTES_V1: usize = 2 * 1024;

/// Hoechstzahl der Elemente eines Grant-Plans und der initialen Grants eines
/// Commits.
pub const MAX_GRANT_PLAN_ITEMS_V1: usize = 10_000;

/// 2 MiB Entry plus 10 000 mal 2 KiB Grant-Decke plus begrenzter Rahmen.
pub const MAX_ENTRY_COMMIT_BODY_BYTES_V1: usize = 24 * 1024 * 1024;

/// Objektsaetze je Lesestapel- oder Exportseite.
pub const MAX_READER_PAGE_OBJECTS_V1: usize = 1_000;

/// Bytes je Lesestapel- oder Exportseite.
pub const MAX_READER_PAGE_BYTES_V1: usize = 64 * 1024 * 1024;

/// `.etb`-Saetze je Trust-Seite.
pub const MAX_TRUST_PAGE_EVENTS_V1: usize = 1_000;

/// Objektsaetze je Grant-Liste.
pub const MAX_GRANT_PAGE_OBJECTS_V1: usize = 10_000;

/// Objektsaetze je Checkpoint-Seite.
pub const MAX_CHECKPOINT_PAGE_OBJECTS_V1: usize = 1_000;

/// Challenge-, Registrierungs- und Fehlerkoerper.
pub const MAX_SMALL_BODY_BYTES_V1: usize = 64 * 1024;

/// Wie ein Endpunkt seinen Aufrufer authentisiert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointAuthentication {
    /// RFC-9421-signiert mit einem bereits freigegebenen Schluessel.
    Signed,
    /// RFC-9421-signiert mit dem BEANTRAGTEN, noch nicht freigegebenen
    /// Geraeteschluessel (`design.md` §13.1). Das ist keine
    /// Signaturausnahme, sondern eine andere Identitaetsquelle.
    ProofOfPossession,
    /// Ohne RFC-9421-Signatur. Genau zwei Endpunkte: der rate-limitierte
    /// Challenge-Endpunkt und `POST /v1/vault-blobs/retrievals`.
    Unsigned,
}

/// Die geschlossene Endpunktmenge der v1-API (`design.md` §13.2).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EndpointV1 {
    AuthChallenges,
    DeviceRegistrations,
    WebauthnCredentials,
    VaultBlobs,
    VaultBlobRetrievals,
    TrustRegistry,
    TrustEvents,
    EntryCommits,
    ChainEntries,
    Objects,
    HistoricalGrants,
    EntryGrants,
    ReaderAcks,
    Checkpoints,
    ArchiveExports,
    Destructions,
    DestructionStatus,
}

impl EndpointV1 {
    /// Die siebzehn Zeilen von `design.md` §13.2 in ihrer Reihenfolge.
    ///
    /// Die Liste steht hier, damit jede Pruefung ueber die Menge LAEUFT statt
    /// sie abzuschreiben; ein achtzehnter Endpunkt faellt dadurch laut auf.
    pub const ALL: [Self; 17] = [
        Self::AuthChallenges,
        Self::DeviceRegistrations,
        Self::WebauthnCredentials,
        Self::VaultBlobs,
        Self::VaultBlobRetrievals,
        Self::TrustRegistry,
        Self::TrustEvents,
        Self::EntryCommits,
        Self::ChainEntries,
        Self::Objects,
        Self::HistoricalGrants,
        Self::EntryGrants,
        Self::ReaderAcks,
        Self::Checkpoints,
        Self::ArchiveExports,
        Self::Destructions,
        Self::DestructionStatus,
    ];

    #[must_use]
    pub const fn method(self) -> HttpMethod {
        match self {
            Self::TrustRegistry
            | Self::ChainEntries
            | Self::Objects
            | Self::EntryGrants
            | Self::Checkpoints
            | Self::ArchiveExports
            | Self::DestructionStatus => HttpMethod::Get,
            Self::VaultBlobs => HttpMethod::Put,
            _ => HttpMethod::Post,
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::AuthChallenges => "/v1/auth/challenges",
            Self::DeviceRegistrations => "/v1/device-registrations",
            Self::WebauthnCredentials => "/v1/webauthn-credentials",
            Self::VaultBlobs => "/v1/vault-blobs",
            Self::VaultBlobRetrievals => "/v1/vault-blobs/retrievals",
            Self::TrustRegistry => "/v1/trust/registry",
            Self::TrustEvents => "/v1/trust/events",
            Self::EntryCommits => "/v1/chains/{chainId}/entry-commits",
            Self::ChainEntries => "/v1/chains/{chainId}/entries",
            Self::Objects => "/v1/objects/{objectHash}",
            Self::HistoricalGrants => "/v1/entries/{entryHash}/historical-grants",
            Self::EntryGrants => "/v1/entries/{entryHash}/grants",
            Self::ReaderAcks => "/v1/reader-acks",
            Self::Checkpoints => "/v1/checkpoints",
            Self::ArchiveExports => "/v1/archive-exports/current",
            Self::Destructions => "/v1/destructions",
            Self::DestructionStatus => "/v1/destructions/{destructionId}",
        }
    }

    /// Der Endpunktcode, den ein technischer Cursor traegt.
    ///
    /// Er bindet das Weiterblaettern an genau den Endpunkt, der den Cursor
    /// ausgestellt hat; die Zahlen sind Positionen in [`Self::ALL`] und tragen
    /// keine fachliche Bedeutung.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::AuthChallenges => 1,
            Self::DeviceRegistrations => 2,
            Self::WebauthnCredentials => 3,
            Self::VaultBlobs => 4,
            Self::VaultBlobRetrievals => 5,
            Self::TrustRegistry => 6,
            Self::TrustEvents => 7,
            Self::EntryCommits => 8,
            Self::ChainEntries => 9,
            Self::Objects => 10,
            Self::HistoricalGrants => 11,
            Self::EntryGrants => 12,
            Self::ReaderAcks => 13,
            Self::Checkpoints => 14,
            Self::ArchiveExports => 15,
            Self::Destructions => 16,
            Self::DestructionStatus => 17,
        }
    }

    #[must_use]
    pub const fn authentication(self) -> EndpointAuthentication {
        match self {
            Self::AuthChallenges | Self::VaultBlobRetrievals => EndpointAuthentication::Unsigned,
            Self::DeviceRegistrations => EndpointAuthentication::ProofOfPossession,
            _ => EndpointAuthentication::Signed,
        }
    }

    /// Die Capability, die das Zertifikat des Aufrufers tragen MUSS.
    ///
    /// `None` heisst „jedes freigegebene Geraet dieser Organisation“, nicht
    /// „ohne Autoritaet“: die Organisationsbindung prueft der Verifier immer.
    #[must_use]
    pub const fn required_capability(self) -> Option<ea_crypto::CertificateCapability> {
        match self {
            Self::EntryCommits => Some(ea_crypto::CertificateCapability::InitialGrant),
            Self::TrustEvents => Some(ea_crypto::CertificateCapability::OrganizationAdminApprove),
            Self::HistoricalGrants => Some(ea_crypto::CertificateCapability::HistoricalGrant),
            Self::Destructions => Some(ea_crypto::CertificateCapability::DestructionApprove),
            _ => None,
        }
    }

    /// Der Medientyp des Requestkoerpers, oder `None` fuer einen Endpunkt ohne
    /// Koerper. Ohne Koerper deckt die Signatur weder `content-type` noch
    /// `content-digest` ab.
    #[must_use]
    pub const fn request_media_type(self) -> Option<&'static str> {
        match self {
            Self::TrustRegistry
            | Self::ChainEntries
            | Self::Objects
            | Self::EntryGrants
            | Self::Checkpoints
            | Self::ArchiveExports
            | Self::DestructionStatus => None,
            _ => Some(STRUCTURED_MEDIA_TYPE_V1),
        }
    }

    /// Der Medientyp der Erfolgsantwort, oder `None` fuer eine Antwort ohne
    /// Koerper.
    #[must_use]
    pub const fn response_media_type(self) -> Option<&'static str> {
        match self {
            Self::DeviceRegistrations
            | Self::WebauthnCredentials
            | Self::VaultBlobs
            | Self::TrustEvents
            | Self::HistoricalGrants
            | Self::ReaderAcks => None,
            Self::Objects => Some(OBJECT_MEDIA_TYPE_V1),
            _ => Some(STRUCTURED_MEDIA_TYPE_V1),
        }
    }

    #[must_use]
    pub const fn success_status(self) -> u16 {
        match self {
            Self::WebauthnCredentials
            | Self::VaultBlobs
            | Self::TrustEvents
            | Self::HistoricalGrants => 201,
            Self::DeviceRegistrations | Self::Destructions => 202,
            Self::ReaderAcks => 204,
            _ => 200,
        }
    }

    /// Prueft einen empfangenen Pfad gegen die Vorlage dieses Endpunkts.
    ///
    /// Ein Platzhalter deckt genau EIN nicht leeres Segment; eine
    /// Abfragezeichenkette gehoert nicht zum Pfad und wird vorher abgetrennt.
    #[must_use]
    pub fn matches_path(self, path: &str) -> bool {
        let path = path.split('?').next().unwrap_or(path);
        let mut template = self.path_template().split('/');
        let mut actual = path.split('/');
        loop {
            match (template.next(), actual.next()) {
                (None, None) => return true,
                (Some(expected), Some(segment)) => {
                    let matched = if expected.starts_with('{') && expected.ends_with('}') {
                        !segment.is_empty()
                    } else {
                        expected == segment
                    };
                    if !matched {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    }
}

/// Deterministische CBOR-Schreibhilfen der Protokollrahmen.
///
/// Sie schreiben AUSSCHLIESSLICH die kanonische Kopfform nach Design §10.1 und
/// koennen deshalb nicht fehlschlagen; das haelt die Rahmenkodierung frei von
/// einem `Result`, das nie ein `Err` traegt. Gelesen wird mit `minicbor` und
/// `ea_cbor::validate`, also mit demselben Parser wie ueberall sonst.
pub(crate) mod cbor {
    pub(crate) fn head(out: &mut Vec<u8>, major: u8, argument: u64) {
        let major = major << 5;
        match argument {
            0..=23 => out.push(major | u8::try_from(argument).unwrap_or(0)),
            24..=0xff => {
                out.push(major | 24);
                out.push(u8::try_from(argument).unwrap_or(0));
            }
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend_from_slice(&u16::try_from(argument).unwrap_or(0).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(major | 26);
                out.extend_from_slice(&u32::try_from(argument).unwrap_or(0).to_be_bytes());
            }
            _ => {
                out.push(major | 27);
                out.extend_from_slice(&argument.to_be_bytes());
            }
        }
    }

    pub(crate) fn array(out: &mut Vec<u8>, length: u64) {
        head(out, 4, length);
    }

    pub(crate) fn uint(out: &mut Vec<u8>, value: u64) {
        head(out, 0, value);
    }

    pub(crate) fn int(out: &mut Vec<u8>, value: i64) {
        if value < 0 {
            head(out, 1, u64::try_from(-(value + 1)).unwrap_or(0));
        } else {
            head(out, 0, u64::try_from(value).unwrap_or(0));
        }
    }

    pub(crate) fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        head(out, 2, value.len() as u64);
        out.extend_from_slice(value);
    }

    pub(crate) fn text(out: &mut Vec<u8>, value: &str) {
        head(out, 3, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn boolean(out: &mut Vec<u8>, value: bool) {
        out.push(if value { 0xf5 } else { 0xf4 });
    }

    pub(crate) fn null(out: &mut Vec<u8>) {
        out.push(0xf6);
    }

    /// Der leere Erweiterungsplatz, den jeder v1-Rahmen als letzte Position
    /// traegt.
    pub(crate) fn empty_extension(out: &mut Vec<u8>) {
        array(out, 0);
    }
}

/// Deterministische CBOR-Lesehilfen der Protokollrahmen.
///
/// Sie stehen neben den Schreibhilfen, weil jede Position eines Rahmens genau
/// EIN Paar aus Schreiber und Leser hat. Jeder Befund ist
/// [`SyncProtocolError::FrameShape`]: ein Rahmen, der die Form verletzt, ist
/// nie halb gueltig.
pub(crate) mod cbor_read {
    use minicbor::Decoder;

    use crate::SyncProtocolError;

    pub(crate) fn array(decoder: &mut Decoder<'_>) -> Result<u64, SyncProtocolError> {
        decoder
            .array()
            .map_err(|_| SyncProtocolError::FrameShape)?
            .ok_or(SyncProtocolError::FrameShape)
    }

    pub(crate) fn expect_array(
        decoder: &mut Decoder<'_>,
        expected: u64,
    ) -> Result<(), SyncProtocolError> {
        if array(decoder)? == expected {
            Ok(())
        } else {
            Err(SyncProtocolError::FrameShape)
        }
    }

    /// Die Versionsposition jedes v1-Rahmens.
    pub(crate) fn expect_version(decoder: &mut Decoder<'_>) -> Result<(), SyncProtocolError> {
        if uint(decoder)? == 1 {
            Ok(())
        } else {
            Err(SyncProtocolError::FrameVersion)
        }
    }

    pub(crate) fn uint(decoder: &mut Decoder<'_>) -> Result<u64, SyncProtocolError> {
        decoder.u64().map_err(|_| SyncProtocolError::FrameShape)
    }

    pub(crate) fn int(decoder: &mut Decoder<'_>) -> Result<i64, SyncProtocolError> {
        decoder.i64().map_err(|_| SyncProtocolError::FrameShape)
    }

    pub(crate) fn boolean(decoder: &mut Decoder<'_>) -> Result<bool, SyncProtocolError> {
        decoder.bool().map_err(|_| SyncProtocolError::FrameShape)
    }

    pub(crate) fn text<'a>(decoder: &mut Decoder<'a>) -> Result<&'a str, SyncProtocolError> {
        decoder.str().map_err(|_| SyncProtocolError::FrameShape)
    }

    pub(crate) fn bytes<'a>(decoder: &mut Decoder<'a>) -> Result<&'a [u8], SyncProtocolError> {
        decoder.bytes().map_err(|_| SyncProtocolError::FrameShape)
    }

    pub(crate) fn bytes_exact<'a>(
        decoder: &mut Decoder<'a>,
        length: usize,
    ) -> Result<&'a [u8], SyncProtocolError> {
        let value = bytes(decoder)?;
        if value.len() == length {
            Ok(value)
        } else {
            Err(SyncProtocolError::FrameShape)
        }
    }

    /// `bstr / null` an einer Position, die eine feste Laenge fordert.
    pub(crate) fn optional_bytes_exact<'a>(
        decoder: &mut Decoder<'a>,
        length: usize,
    ) -> Result<Option<&'a [u8]>, SyncProtocolError> {
        if decoder
            .datatype()
            .map_err(|_| SyncProtocolError::FrameShape)?
            == minicbor::data::Type::Null
        {
            decoder.null().map_err(|_| SyncProtocolError::FrameShape)?;
            return Ok(None);
        }
        bytes_exact(decoder, length).map(Some)
    }

    /// `bstr / null` an einer Position ohne feste Laenge — der opake Cursor.
    pub(crate) fn optional_bytes<'a>(
        decoder: &mut Decoder<'a>,
    ) -> Result<Option<&'a [u8]>, SyncProtocolError> {
        if decoder
            .datatype()
            .map_err(|_| SyncProtocolError::FrameShape)?
            == minicbor::data::Type::Null
        {
            decoder.null().map_err(|_| SyncProtocolError::FrameShape)?;
            return Ok(None);
        }
        bytes(decoder).map(Some)
    }

    pub(crate) fn expect_empty_extension(
        decoder: &mut Decoder<'_>,
    ) -> Result<(), SyncProtocolError> {
        expect_array(decoder, 0)
    }

    /// Die exakten Bytes des naechsten Elements, ohne es zu deuten.
    ///
    /// Der eingebettete `grant-plan-v1` wird so an `ea_format::decode_grant_plan`
    /// weitergereicht, statt hier ein zweites Mal dekodiert zu werden.
    pub(crate) fn exact_item<'a>(
        input: &'a [u8],
        decoder: &mut Decoder<'a>,
    ) -> Result<&'a [u8], SyncProtocolError> {
        let start = decoder.position();
        decoder.skip().map_err(|_| SyncProtocolError::FrameShape)?;
        input
            .get(start..decoder.position())
            .ok_or(SyncProtocolError::FrameShape)
    }

    pub(crate) fn finish(decoder: &Decoder<'_>, input: &[u8]) -> Result<(), SyncProtocolError> {
        if decoder.position() == input.len() {
            Ok(())
        } else {
            Err(SyncProtocolError::FrameShape)
        }
    }
}
