//! `POST /v1/destructions` und `GET /v1/destructions/{destructionId}`.
//!
//! Das Anlegen verlangt `destructionApprove` — der Pruefer setzt das ueber
//! [`ea_sync_protocol::EndpointV1::required_capability`] durch. Das ist die
//! Capability des AUFRUFERS und ersetzt die Mehr-Augen-Pruefung nicht: die
//! zwei UNTERSCHIEDLICHEN Approver stecken in den Signaturen der
//! `DestructionAuthorization` und werden im Dienst geprueft.
//!
//! Die Antwort auf das Anlegen ist `202` MIT Koerper: der Vorgang ist
//! angenommen, nicht ausgefuehrt (Sync-Wire-Nachtrag, Feldtabelle).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{
    DestructionRequestV1, EndpointV1, STRUCTURED_MEDIA_TYPE_V1, SyncProtocolError,
};
use ea_sync_server::destruction::{accept_destruction_request, destruction_status};
use ea_types::DestructionId;

use crate::http::{
    AppState, auth_error_response, error_response, id16_from_hex, request_id_or_zero,
    signed_request, split_request,
};

/// Die Koerperdecke dieses Endpunkts: ein `.etb` plus Rahmenaufschlag.
const DESTRUCTION_BODY_LIMIT: usize = ea_format::ETB_MAX_RAW_BYTES_V1 + 1_024;

pub async fn create_destruction(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) = match split_request(request, DESTRUCTION_BODY_LIMIT).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::Destructions;

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

    let upload = match DestructionRequestV1::decode(&body) {
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
    let destruction_ports = state.destruction_ports();
    match accept_destruction_request(
        authenticated.organization_id,
        upload.exact_authorization_etb_bytes(),
        &destruction_ports,
    )
    .await
    {
        Ok(status) => (
            StatusCode::ACCEPTED,
            [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
            status.exact_bytes().to_vec(),
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

pub async fn read_destruction(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, _) = match split_request(request, 0).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::DestructionStatus;

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

    let destruction_id = match uri
        .path()
        .strip_prefix("/v1/destructions/")
        .ok_or(SyncProtocolError::TargetUriMismatch)
        .and_then(id16_from_hex)
        .and_then(|bytes| {
            DestructionId::try_from(&bytes[..]).map_err(|_| SyncProtocolError::FrameShape)
        }) {
        Ok(id) => id,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };

    let destruction_ports = state.destruction_ports();
    match destruction_status(
        authenticated.organization_id,
        destruction_id,
        &destruction_ports,
    )
    .await
    {
        Ok(status) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
            status.exact_bytes().to_vec(),
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

pub async fn create_event(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) = match split_request(request, DESTRUCTION_BODY_LIMIT).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::DestructionEvents;

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

    let id = uri
        .path()
        .strip_prefix("/v1/destructions/")
        .and_then(|p| p.strip_suffix("/events"))
        .ok_or(SyncProtocolError::TargetUriMismatch)
        .and_then(id16_from_hex)
        .and_then(|bytes| {
            DestructionId::try_from(&bytes[..]).map_err(|_| SyncProtocolError::FrameShape)
        });
    let destruction_id = match id {
        Ok(id) => id,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    let ea_sync_protocol::AuthenticatedDevice::Certified {
        certificate_hash, ..
    } = authenticated.device
    else {
        return error_response(
            "EA-DESTRUCTION-AUTHORIZATION-UNVERIFIABLE",
            422,
            false,
            request_id,
        );
    };
    let destruction_ports = state.destruction_ports();
    let is_attestation = matches!(ea_format::decode_exact_object(&body),
        Ok(ea_format::ParsedArchiveObject::Trust(ref t)) if t.value().subtype()==ea_format::TrustSubtypeV1::DeletionAttestation);
    let accepted = if is_attestation {
        ea_sync_server::managed_destruction::accept_attestation(
            authenticated.organization_id,
            certificate_hash,
            destruction_id,
            &body,
            &destruction_ports,
        )
        .await
    } else {
        ea_sync_server::managed_destruction::accept_event(
            authenticated.organization_id,
            certificate_hash,
            destruction_id,
            &body,
            &destruction_ports,
        )
        .await
    };
    let accepted = match accepted {
        Ok(status) if status.state() == 1 && !is_attestation => {
            match state.deletion_component.as_deref() {
                Some(component) => {
                    ea_sync_server::server_destruction::execute_server(
                        authenticated.organization_id,
                        destruction_id,
                        certificate_hash,
                        component,
                        state.signer.as_ref(),
                        &destruction_ports,
                    )
                    .await
                }
                None => {
                    Err(ea_sync_server::destruction::DestructionError::AuthorizationUnverifiable)
                }
            }
        }
        other => other,
    };
    match accepted {
        Ok(status) => (
            StatusCode::ACCEPTED,
            [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
            status.exact_bytes().to_vec(),
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

pub async fn create_job(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) =
        match split_request(request, ea_sync_protocol::MAX_READER_PAGE_BYTES_V1).await {
            Ok(parts) => parts,
            Err(error) => {
                return error_response(error.code(), error.http_status(), error.retryable(), zero);
            }
        };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::DestructionJobs;

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

    let id = uri
        .path()
        .strip_prefix("/v1/destructions/")
        .and_then(|p| p.strip_suffix("/jobs"))
        .ok_or(SyncProtocolError::TargetUriMismatch)
        .and_then(id16_from_hex)
        .and_then(|bytes| {
            DestructionId::try_from(&bytes[..]).map_err(|_| SyncProtocolError::FrameShape)
        });
    let destruction_id = match id {
        Ok(id) => id,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    let ea_sync_protocol::AuthenticatedDevice::Certified {
        certificate_hash, ..
    } = authenticated.device
    else {
        return error_response(
            "EA-DESTRUCTION-AUTHORIZATION-UNVERIFIABLE",
            422,
            false,
            request_id,
        );
    };
    let upload = match ea_sync_protocol::DestructionJobUploadV1::decode(&body) {
        Ok(value) => value,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    let destruction_ports = state.destruction_ports();
    let accepted = ea_sync_server::managed_destruction::accept_job(
        authenticated.organization_id,
        certificate_hash,
        destruction_id,
        &upload,
        &destruction_ports,
    )
    .await;
    let accepted = match accepted {
        Ok(status) if matches!(status.state(), 1 | 2 | 4) => {
            match state.deletion_component.as_deref() {
                Some(component) => {
                    ea_sync_server::server_destruction::execute_server(
                        authenticated.organization_id,
                        destruction_id,
                        certificate_hash,
                        component,
                        state.signer.as_ref(),
                        &destruction_ports,
                    )
                    .await
                }
                None => {
                    Err(ea_sync_server::destruction::DestructionError::AuthorizationUnverifiable)
                }
            }
        }
        other => other,
    };
    match accepted {
        Ok(status) => (
            StatusCode::ACCEPTED,
            [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
            status.exact_bytes().to_vec(),
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
