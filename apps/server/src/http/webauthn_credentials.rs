//! `POST /v1/webauthn-credentials` — die technische Credentialtabelle.
//!
//! Regulaer RFC-9421-signiert: der Leser besitzt seinen Schluessel zum
//! Zeitpunkt der Registrierung. Die pseudonyme `subjectId` ist der
//! `userHandle`. Die Registrierung verschafft dem Server KEINE Rolle, KEINE
//! Capability und KEINE Geraeteautoritaet und legt kein Trust-Objekt an
//! (`web-reader-design.md` §6.4.1).

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{EndpointV1, MAX_SMALL_BODY_BYTES_V1, WebauthnCredentialRegistrationV1};
use ea_sync_server::auth::{authenticate, register_webauthn_credential};

use crate::http::{
    AppState, auth_error_response, error_response, request_id_or_zero, signed_request,
    split_request,
};

pub async fn register_credential(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) = match split_request(request, MAX_SMALL_BODY_BYTES_V1).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::WebauthnCredentials;

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
    let authenticated = match authenticate(endpoint, &state.authority, &signed, &ports, None).await
    {
        Ok(authenticated) => authenticated,
        Err(error) => return auth_error_response(error, request_id),
    };

    let registration = match WebauthnCredentialRegistrationV1::decode(&body) {
        Ok(registration) => registration,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    match register_webauthn_credential(
        &registration,
        authenticated.organization_id,
        state.clock.as_ref(),
        state.repository.as_ref(),
    )
    .await
    {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(error) => auth_error_response(error, request_id),
    }
}
