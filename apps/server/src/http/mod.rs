//! Die Axum-Kante des Servers.
//!
//! Hier — und nur hier — wird aus einem HTTP-Request ein
//! [`ea_sync_protocol::SignedRequestV1`] und aus einem Dienstbefund eine
//! Antwort. Die Dienste selbst liegen in `crates/ea-sync-server` und kennen
//! weder Axum noch sqlx; diese Schicht kennt kein SQL.
//!
//! # Der Fehlerkoerper
//!
//! Es gibt GENAU EINEN: `protocol-error-v1`. Er traegt kein Fragment der
//! gelieferten Nutzdaten — nicht im Code, nicht in einem Text, nicht in einem
//! Header. `retryable` ist ausschliesslich bei 429, 500 und 503 gesetzt, und
//! der Wert kommt aus derselben Quelle wie der Status.
//!
//! # Die Request-ID im Fehlerkoerper
//!
//! `protocol-error-v1` fuehrt sie an einer PFLICHTPOSITION. Ein Request, dessen
//! `ea-request-id`-Header fehlt oder unlesbar ist, hat aber keine. Er bekommt
//! die Nullkennung — sichtbar leer statt erfunden.

pub mod challenges;
pub mod device_registrations;
pub mod trust;
pub mod webauthn_credentials;

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::Request,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{
    EndpointV1, HttpMethod, ProtocolErrorV1, REQUEST_ID_HEADER_V1, ReceivedRequestV1, RequestIdV1,
    STRUCTURED_MEDIA_TYPE_V1, SignedRequestV1, SyncProtocolError, body_digest,
};
use ea_sync_server::{
    ObjectStore, ServerClock, ServerSigner,
    auth::{AuthPorts, AuthServiceError},
    trust::TrustPorts,
};

use crate::adapters::{postgres::PostgresRepository, trust_authority::PostgresTrustAuthority};

/// Der Header, unter dem RFC 9421 seine Signaturparameter liefert.
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";
/// Der Header, unter dem RFC 9421 die Signatur selbst liefert.
pub const SIGNATURE_HEADER: &str = "signature";
/// Der Header, unter dem RFC 9530 den Koerperdigest liefert.
pub const CONTENT_DIGEST_HEADER: &str = "content-digest";

/// Alles, was ein Handler an echten Diensten braucht.
///
/// Die Ports stehen als `Arc<dyn …>` da und nicht als konkrete Typen: der
/// Handler soll den Adapter nicht kennen, und der Wechsel eines Adapters soll
/// keine Handlerzeile beruehren.
pub struct AppState {
    /// Die Autoritaet, gegen die jede Signatur `@authority` und `@target-uri`
    /// stellt. Sie ist KONFIGURIERT und wird nicht aus dem Request gelesen —
    /// ein Angreifer, der den `Host`-Header setzt, setzt sonst zugleich die
    /// Erwartung, gegen die er geprueft wird.
    pub authority: String,
    pub clock: Arc<dyn ServerClock>,
    pub signer: Arc<dyn ServerSigner>,
    pub objects: Arc<dyn ObjectStore>,
    pub repository: Arc<PostgresRepository>,
    pub trust_authority: Arc<PostgresTrustAuthority>,
}

impl AppState {
    #[must_use]
    pub fn auth_ports(&self) -> AuthPorts<'_> {
        AuthPorts {
            clock: self.clock.as_ref(),
            challenges: self.repository.as_ref(),
            request_ids: self.repository.as_ref(),
            directory: self.trust_authority.as_ref(),
        }
    }

    #[must_use]
    pub fn trust_ports(&self) -> TrustPorts<'_> {
        TrustPorts {
            clock: self.clock.as_ref(),
            objects: self.objects.as_ref(),
            events: self.repository.as_ref(),
            validator: self.trust_authority.as_ref(),
        }
    }

    /// Eine frische 32-Byte-Nonce aus dem CSPRNG des TLS-Anbieters.
    ///
    /// `rustls` ist bereits die Zufallsquelle dieses Prozesses — sein
    /// `SecureRandom` ist der Systemzufall des `ring`-Anbieters. Eine zweite
    /// Zufallskiste daneben waere eine zweite Quelle mit eigener Pflegelast
    /// und eigenem Fehlerverhalten.
    pub fn fresh_nonce() -> Result<[u8; 32], AuthServiceError> {
        let mut nonce = [0_u8; 32];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut nonce)
            .map_err(|_| AuthServiceError::Internal)?;
        Ok(nonce)
    }
}

/// Die Request-ID dieses Requests, oder die Nullkennung.
#[must_use]
pub fn request_id_or_zero(headers: &HeaderMap) -> RequestIdV1 {
    headers
        .get(REQUEST_ID_HEADER_V1)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| hex::decode(value).ok())
        .and_then(|bytes| RequestIdV1::try_from(bytes.as_slice()).ok())
        .unwrap_or_else(|| {
            RequestIdV1::try_from(&[0_u8; 16][..]).unwrap_or_else(|_| unreachable!())
        })
}

/// Der eine Fehlerkoerper, mit Status und `retryable` aus derselben Quelle.
#[must_use]
pub fn error_response(
    code: &str,
    status: u16,
    retryable: bool,
    request_id: RequestIdV1,
) -> Response {
    let body = ProtocolErrorV1::with_code(code, request_id, retryable, None, None);
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
        body.exact_bytes().to_vec(),
    )
        .into_response()
}

/// Ein Dienstbefund der Auth-Schicht als `protocol-error-v1`.
///
/// Eine freie Funktion und keine `impl`-Methode: [`AuthServiceError`] gehoert
/// `crates/ea-sync-server`, und diese Crate haengt HTTP an ihn, nicht
/// umgekehrt. Der Dienst soll `axum` nicht kennen.
#[must_use]
pub fn auth_error_response(error: AuthServiceError, request_id: RequestIdV1) -> Response {
    error_response(
        error.code(),
        error.http_status(),
        error.retryable(),
        request_id,
    )
}

/// Ein `SignedRequestV1` aus den empfangenen Kopfzeilen.
///
/// Die Autoritaet kommt aus [`AppState::authority`] und NICHT aus dem
/// `Host`-Header: der Pruefer soll die konfigurierte Erwartung gegen die vom
/// Klienten SIGNIERTE `@authority` stellen. Genommen wird deshalb, was der
/// Klient signiert hat — der Header —, und verglichen wird gegen die
/// Konfiguration.
pub fn signed_request(
    endpoint: EndpointV1,
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<SignedRequestV1, SyncProtocolError> {
    let method = match *method {
        Method::GET => HttpMethod::Get,
        Method::POST => HttpMethod::Post,
        Method::PUT => HttpMethod::Put,
        _ => return Err(SyncProtocolError::TargetUriMismatch),
    };
    let authority = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map_or_else(
            || {
                uri.authority()
                    .map_or_else(|| state.authority.clone(), ToString::to_string)
            },
            ToOwned::to_owned,
        );
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_owned(), std::string::ToString::to_string);
    let carries_body = endpoint.request_media_type().is_some();
    let received = ReceivedRequestV1 {
        method,
        authority: authority.clone(),
        target_uri: format!("https://{authority}{path_and_query}"),
        content_type: header_text(headers, header::CONTENT_TYPE.as_str()),
        content_digest: header_text(headers, CONTENT_DIGEST_HEADER),
        request_id: header_text(headers, REQUEST_ID_HEADER_V1),
        body_digest: carries_body.then(|| body_digest(body)),
    };
    let signature_input = header_text(headers, SIGNATURE_INPUT_HEADER)
        .ok_or(SyncProtocolError::SignatureMalformed)?;
    let signature =
        header_text(headers, SIGNATURE_HEADER).ok_or(SyncProtocolError::SignatureMalformed)?;
    SignedRequestV1::parse(&received, &signature_input, &signature)
}

/// Zerlegt einen Request in Methode, URI, Kopfzeilen und GROESSENBEGRENZTEN
/// Koerper.
///
/// Die Decke wird VOR dem Sammeln gesetzt und nicht danach geprueft: ein
/// Koerper, der sie reisst, wird gar nicht erst vollstaendig gelesen. Das ist
/// die Zusage „der Server setzt die gestreamte Bytegrenze durch, bevor er
/// akkumuliert“ aus dem Sync-Wire-Nachtrag.
pub async fn split_request(
    request: Request,
    body_limit: usize,
) -> Result<(Method, Uri, HeaderMap, Bytes), SyncProtocolError> {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, body_limit)
        .await
        .map_err(|_| SyncProtocolError::BodyLimit)?;
    Ok((parts.method, parts.uri, parts.headers, bytes))
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

/// Weist einen Koerper zurueck, dessen Medientyp nicht der des Endpunkts ist.
///
/// Der Pruefer stellt denselben Vergleich noch einmal ueber die SIGNIERTE
/// Komponente; diese Stelle faengt den unsignierten Endpunkt, den er nicht
/// sieht.
pub fn require_structured_media_type(headers: &HeaderMap) -> Result<(), SyncProtocolError> {
    if header_text(headers, header::CONTENT_TYPE.as_str()).as_deref()
        == Some(STRUCTURED_MEDIA_TYPE_V1)
    {
        Ok(())
    } else {
        Err(SyncProtocolError::ContentTypeMismatch)
    }
}
