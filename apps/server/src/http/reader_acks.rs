//! `POST /v1/reader-acks` — die signierte Lesequittung.
//!
//! Die Antwort ist `204` und ohne Koerper (Sync-Wire-Nachtrag,
//! „Antworten ohne Inhalt“). Der Koerper des Requests ist ein SIGNIERTES
//! technisches Objekt: `[reader-ack-core-v1, COSE-Sign1]`, gerahmt von
//! [`ea_sync_protocol::ReaderAckV1`] und ueber die `ea-crypto`-Codecs
//! kodiert. Die Bindung der Signatur an genau diesen Kern prueft der Rahmen
//! selbst; dieser Handler prueft danach die Zuordnung zum AUFRUFER.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{
    AuthenticatedDevice, EndpointV1, MAX_SMALL_BODY_BYTES_V1, ReaderAckV1, SyncProtocolError,
};
use ea_sync_server::reader_sync::record_reader_ack;

use crate::http::{
    AppState, auth_error_response, error_response, request_id_or_zero, signed_request,
    split_request,
};

pub async fn create_reader_ack(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) = match split_request(request, MAX_SMALL_BODY_BYTES_V1).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::ReaderAcks;

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
    // Der Proof-of-Possession-Pfad erreicht diesen Endpunkt nie — er gilt
    // ausschliesslich fuer `POST /v1/device-registrations`. Die Alternative
    // ist trotzdem ausgeschrieben statt weggelassen: ein Aufrufer ohne
    // Zertifikat hat keinen Zertifikatshash, und eine Quittung ohne ihn waere
    // eine Quittung von niemandem.
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

    let ack = match ReaderAckV1::decode(&body) {
        Ok(ack) => ack,
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
    match record_reader_ack(
        authenticated.organization_id,
        certificate_hash,
        &ack,
        &reader_ports,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        ),
    }
}
