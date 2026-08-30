//! `POST /v1/auth/challenges` — ohne Signatur, ratenbegrenzt.
//!
//! Die eine Signaturausnahme neben `POST /v1/vault-blobs/retrievals`
//! (`design.md` §13.1). Weil hier kein `tag` steht, aus dem die Organisation
//! kaeme, traegt der Koerper sie: `challenge-request-v1`.

use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{ChallengeRequestV1, MAX_SMALL_BODY_BYTES_V1, STRUCTURED_MEDIA_TYPE_V1};
use ea_sync_server::auth::{issue_challenge, rate_key_digest};

use crate::{
    http::{
        AppState, auth_error_response, error_response, request_id_or_zero,
        require_structured_media_type, split_request,
    },
    router::PeerAddress,
};

pub async fn create_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<PeerAddress>,
    request: Request,
) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (_, _, headers, body) = match split_request(request, MAX_SMALL_BODY_BYTES_V1).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    if let Err(error) = require_structured_media_type(&headers) {
        return error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        );
    }
    let request = match ChallengeRequestV1::decode(&body) {
        Ok(request) => request,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    let nonce = match AppState::fresh_nonce() {
        Ok(nonce) => nonce,
        Err(error) => return auth_error_response(error, request_id),
    };
    // Der Zaehlschluessel kommt aus der VERBINDUNG, nicht aus dem Koerper: die
    // `organizationId` steht hier unsigniert da, und eine Begrenzung darauf
    // liesse jeden Fremden eine Organisation aussperren.
    let rate_key = rate_key_digest(peer_identity(&peer).as_slice());
    match issue_challenge(
        &request,
        nonce,
        rate_key,
        state.clock.as_ref(),
        state.repository.as_ref(),
        state.signer.as_ref(),
    )
    .await
    {
        Ok(response) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
            response.exact_bytes().to_vec(),
        )
            .into_response(),
        Err(error) => auth_error_response(error, request_id),
    }
}

/// Die Adressbytes, ueber die der Zaehlschluessel gebildet wird.
///
/// NUR die Adresse, nicht der Port: ein Angreifer bekommt bei jeder neuen
/// Verbindung einen neuen Quellport, also waere ein portabhaengiger Schluessel
/// keine Begrenzung.
fn peer_identity(peer: &PeerAddress) -> Vec<u8> {
    match peer.0.ip() {
        std::net::IpAddr::V4(address) => address.octets().to_vec(),
        std::net::IpAddr::V6(address) => address.octets().to_vec(),
    }
}
