//! `POST /v1/chains/{chainId}/entry-commits`.
//!
//! Der Endpunkt verlangt `initialGrant`
//! ([`ea_sync_protocol::EndpointV1::required_capability`]), und der Pruefer
//! setzt das VOR diesem Handler durch. Ein Aufrufer ohne diese Capability
//! erreicht die neun Schritte gar nicht.
//!
//! # Die Kettenkennung des Pfades
//!
//! Sie ist die EINZIGE Angabe dieses Endpunkts, die nicht im Koerper steht,
//! und sie ist zugleich signiert: RFC 9421 deckt `@target-uri` ab, also hat
//! der Aufrufer sie mitunterschrieben. Der Dienst stellt sie gegen die
//! Kettenkennung des Manifests UND gegen die des Ankers
//! (`crates/ea-sync-server/src/validation.rs`) — drei signierte Quellen, und
//! nur wenn alle drei dieselbe nennen, wird geschrieben.
//!
//! # Die Koerpergrenze steht VOR dem Sammeln
//!
//! [`split_request`] bekommt [`MAX_ENTRY_COMMIT_BODY_BYTES_V1`] als Decke; ein
//! Koerper, der sie reisst, wird nicht erst vollstaendig gelesen. Danach
//! begrenzt der Dienst jedes EINZELNE Objekt noch einmal beim Stromen in den
//! temporaeren Schluessel.

use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{
    AuthenticatedDevice, EndpointV1, EntryCommitRequestV1, EntryCommitResponseV1,
    MAX_ENTRY_COMMIT_BODY_BYTES_V1, STRUCTURED_MEDIA_TYPE_V1, SyncProtocolError,
};
use ea_sync_server::commit::commit_entry;
use ea_types::{ChainId, Id16};

use crate::http::{
    AppState, auth_error_response, error_response, error_response_requiring, request_id_or_zero,
    signed_request, split_request,
};

pub async fn create_entry_commit(
    State(state): State<Arc<AppState>>,
    Path(chain_id): Path<String>,
    request: Request,
) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) =
        match split_request(request, MAX_ENTRY_COMMIT_BODY_BYTES_V1).await {
            Ok(parts) => parts,
            Err(error) => {
                return error_response(error.code(), error.http_status(), error.retryable(), zero);
            }
        };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::EntryCommits;

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
    // Nur ein freigegebenes Geraet schreibt. Der Proof-of-Possession-Pfad
    // traegt weder Zertifikat noch Capability; er erreicht diesen Endpunkt
    // ueber [`ea_sync_protocol::EndpointAuthentication`] ohnehin nicht, und
    // dieser Zweig sagt das noch einmal, statt es zu unterstellen.
    let AuthenticatedDevice::Certified {
        certificate_hash, ..
    } = authenticated.device
    else {
        let error = SyncProtocolError::CapabilityMissing;
        return error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        );
    };

    let Some(chain_id) = parse_chain_id(&chain_id) else {
        // Eine unlesbare Kettenkennung ist eine UNBEKANNTE Kette, kein
        // Rahmenfehler: der Pfad ist wohlgeformt, er benennt nur nichts.
        let error = SyncProtocolError::NotFound;
        return error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        );
    };

    let commit_request = match EntryCommitRequestV1::decode(&body) {
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

    let commit_ports = state.commit_ports();
    match commit_entry(
        &commit_request,
        authenticated.organization_id,
        chain_id,
        certificate_hash,
        &commit_ports,
    )
    .await
    {
        Ok(outcome) => {
            // `checkpoint-bytes` traegt den Standard-Checkpoint aus
            // `design.md` §15.2 — den GESPEICHERTEN, zurueckgelesenen. Er
            // beruehrt dabei kein Receipt-Byte: die Quittung ist zu diesem
            // Zeitpunkt signiert, abgelegt und in derselben Transaktion
            // sichtbar geworden wie der Anker.
            let response = EntryCommitResponseV1::new(
                outcome.wire_outcome(),
                outcome.receipt_bytes().to_vec(),
                Some(outcome.checkpoint_bytes().to_vec()),
            );
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
                response.exact_bytes().to_vec(),
            )
                .into_response()
        }
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

/// Die Kettenkennung aus dem Pfad — 32 Hexzeichen und nichts anderes.
///
/// Kein `to_lowercase` und keine Bindestriche: die Kennung reist im gesamten
/// Protokoll als 16 Byte, und eine zweite Schreibweise waere eine zweite
/// Kennung fuer dieselbe Kette.
fn parse_chain_id(raw: &str) -> Option<ChainId> {
    let bytes = hex::decode(raw).ok()?;
    Id16::try_from(bytes.as_slice()).ok().map(ChainId::from)
}
