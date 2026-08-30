//! `POST /v1/device-registrations` — Proof of Possession, Antrag, sonst nichts.
//!
//! Der Request ist RFC-9421-signiert, aber mit dem BEANTRAGTEN, noch nicht
//! freigegebenen Geraeteschluessel. Der Pruefer bekommt diesen Schluessel
//! ausdruecklich uebergeben; ohne ihn scheitert der Pfad mit
//! `EA-HTTP-KEY-UNRESOLVED` statt still zu bestehen. Die Antwort ist `202` und
//! ohne Koerper: der Antrag ist angenommen, nicht freigegeben.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{DeviceRegistrationRequestV1, EndpointV1, MAX_SMALL_BODY_BYTES_V1};
use ea_sync_server::auth::{authenticate, register_device};

use crate::http::{
    AppState, auth_error_response, error_response, request_id_or_zero, signed_request,
    split_request,
};

pub async fn create_device_registration(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) = match split_request(request, MAX_SMALL_BODY_BYTES_V1).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::DeviceRegistrations;

    // Der beantragte Schluessel steht im KOERPER und muss deshalb VOR der
    // Signaturpruefung gelesen werden. Gelesen wird er mit dem Codec des
    // Protokolls, nicht von Hand: ein zweiter Dekodierer waere eine zweite
    // Auslegung derselben Bytes.
    let registration = match DeviceRegistrationRequestV1::decode(&body) {
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
    let requested_key = registration.core().signing_public_cose_key.clone();

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
    let authenticated = match authenticate(
        endpoint,
        &state.authority,
        &signed,
        &ports,
        Some(requested_key),
    )
    .await
    {
        Ok(authenticated) => authenticated,
        Err(error) => return auth_error_response(error, request_id),
    };

    match register_device(
        &registration,
        &authenticated.device,
        authenticated.organization_id,
        state.clock.as_ref(),
        state.repository.as_ref(),
    )
    .await
    {
        Ok(_) => StatusCode::ACCEPTED.into_response(),
        Err(error) => auth_error_response(error, request_id),
    }
}
