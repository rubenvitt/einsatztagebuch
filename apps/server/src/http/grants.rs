//! `GET /v1/entries/{entryHash}/grants`.
//!
//! Der Endpunkt verlangt KEINE Capability: jedes freigegebene Geraet der
//! Organisation darf die Grants eines Eintrags derselben Organisation lesen.
//! Was ausgeliefert wird, entscheidet trotzdem nicht die Identitaet des
//! Aufrufers, sondern der Zustand des Eintrags — ein laufender
//! Vernichtungsvorgang sperrt die Auslieferung, und ein abgelaufener
//! historischer Grant wird nicht ausgeliefert.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{EndpointV1, STRUCTURED_MEDIA_TYPE_V1, SyncProtocolError};
use ea_sync_server::reader_sync::grant_list;
use ea_types::EntryHash;

use crate::http::{
    AppState, auth_error_response, error_response, hash32_from_hex, request_id_or_zero,
    signed_request, split_request,
};

pub async fn list_entry_grants(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, _) = match split_request(request, 0).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::EntryGrants;

    let signed = match signed_request(endpoint, &state, &method, &uri, &headers, &Bytes::new()) {
        Ok(signed) => signed,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    let ports = state.auth_ports();
    let authenticated =
        match ea_sync_server::auth::authenticate(endpoint, &state.authority, &signed, &ports, None)
            .await
        {
            Ok(authenticated) => authenticated,
            Err(error) => return auth_error_response(error, request_id),
        };

    let entry_hash = match entry_hash_of(uri.path(), "/grants") {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };

    let reader_ports = state.reader_ports();
    match grant_list(authenticated.organization_id, entry_hash, &reader_ports).await {
        Ok(page) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
            page.exact_bytes().to_vec(),
        )
            .into_response(),
        Err(error) => error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        ),
    }
}

/// Der `entryHash` aus `/v1/entries/{entryHash}{suffix}`.
///
/// Die Funktion ist `pub(crate)`, weil der historische Grant denselben Pfad
/// mit einem anderen Suffix traegt und zwei Kopien derselben Zerlegung zwei
/// Gelegenheiten waeren, das Segment verschieden zu lesen.
pub(crate) fn entry_hash_of(path: &str, suffix: &str) -> Result<EntryHash, SyncProtocolError> {
    let segment = path
        .strip_prefix("/v1/entries/")
        .and_then(|rest| rest.strip_suffix(suffix))
        .ok_or(SyncProtocolError::TargetUriMismatch)?;
    hash32_from_hex(segment).map(EntryHash::from)
}

/// Die Koerperdecke des historischen Re-Grants: ein `.eag` plus
/// Rahmenaufschlag. Sie ist die 2-KiB-Objektdecke des Nachtrags und nicht die
/// 64-KiB-Familiengrenze von `ea-format` — der Rahmen misst das Objekt.
const HISTORICAL_GRANT_BODY_LIMIT: usize = ea_sync_protocol::MAX_GRANT_OBJECT_BYTES_V1 + 1_024;

/// `POST /v1/entries/{entryHash}/historical-grants`.
///
/// Der Endpunkt verlangt `historicalGrant` — der Pruefer setzt das ueber
/// [`EndpointV1::required_capability`] durch, und die Capability stammt aus
/// dem Zertifikat, das die GETEILTE Trust-Pruefung als aktiv ausgewiesen hat.
/// Die Antwort ist `201` und ohne Koerper (Sync-Wire-Nachtrag, „Antworten ohne
/// Inhalt“).
pub async fn create_historical_grant(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Response {
    use ea_sync_protocol::{AuthenticatedDevice, HistoricalGrantUploadV1};
    use ea_sync_server::historical_grant::accept_historical_grant;

    use crate::http::error_response_requiring;

    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) =
        match split_request(request, HISTORICAL_GRANT_BODY_LIMIT).await {
            Ok(parts) => parts,
            Err(error) => {
                return error_response(error.code(), error.http_status(), error.retryable(), zero);
            }
        };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::HistoricalGrants;

    let signed = match signed_request(endpoint, &state, &method, &uri, &headers, &body) {
        Ok(signed) => signed,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    let ports = state.auth_ports();
    let authenticated =
        match ea_sync_server::auth::authenticate(endpoint, &state.authority, &signed, &ports, None)
            .await
        {
            Ok(authenticated) => authenticated,
            Err(error) => return auth_error_response(error, request_id),
        };
    let AuthenticatedDevice::Certified {
        certificate_hash, ..
    } = authenticated.device
    else {
        let error = SyncProtocolError::KeyUnresolved;
        return error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        );
    };

    let entry_hash = match entry_hash_of(uri.path(), "/historical-grants") {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    let upload = match HistoricalGrantUploadV1::decode(&body) {
        Ok(upload) => upload,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };

    let grant_ports = state.historical_grant_ports();
    match accept_historical_grant(
        authenticated.organization_id,
        certificate_hash,
        entry_hash,
        upload.exact_eag_bytes(),
        &grant_ports,
    )
    .await
    {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(failure) => error_response_requiring(
            failure.error.code(),
            failure.error.http_status(),
            failure.error.retryable(),
            request_id,
            failure.required_registry_version,
            failure.required_registry_head_hash,
        ),
    }
}
