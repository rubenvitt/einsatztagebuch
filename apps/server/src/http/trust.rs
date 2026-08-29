//! `POST /v1/trust/events` und `GET /v1/trust/registry?afterVersion={n}`.
//!
//! Das Hochladen verlangt `organizationAdminApprove` — der Pruefer setzt das
//! ueber [`ea_sync_protocol::EndpointV1::required_capability`] durch, und die
//! Capability stammt aus dem Zertifikat, das die GETEILTE Trust-Pruefung als
//! zur vorgeschlagenen Sequenz aktiv ausgewiesen hat. Ein pending, nicht
//! gepinnter, widerrufener, organisationsfremder, veralteter oder ohne
//! Capability auftretender Aufrufer erreicht diesen Handler deshalb nicht.
//!
//! Das Lesen liefert EXAKTE Objektbytes. Es setzt keine Trust-Aussage aus
//! Datenbankzeilen zusammen: der Index sagt nur, welche Objekte in welcher
//! Reihenfolge, und die Bytes kommen aus dem Object Store.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{
    EndpointV1, STRUCTURED_MEDIA_TYPE_V1, SyncProtocolError, TrustEventUploadV1,
};
use ea_sync_server::trust::{publish_trust_event, registry_page};
use ea_types::RegistryVersion;

use crate::http::{
    AppState, auth_error_response, error_response, request_id_or_zero, signed_request,
    split_request,
};

/// Die Koerperdecke dieses Endpunkts: ein `.etb` plus Rahmenaufschlag.
const TRUST_EVENT_BODY_LIMIT: usize = ea_format::ETB_MAX_RAW_BYTES_V1 + 1_024;

pub async fn upload_trust_event(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) = match split_request(request, TRUST_EVENT_BODY_LIMIT).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::TrustEvents;

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

    let upload = match TrustEventUploadV1::decode(&body) {
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
    let trust_ports = state.trust_ports();
    match publish_trust_event(
        upload.exact_etb_bytes(),
        authenticated.organization_id,
        &trust_ports,
    )
    .await
    {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(error) => error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        ),
    }
}

pub async fn list_trust_registry(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    // Eine Leseanfrage traegt keinen Koerper; die Decke ist null.
    let (method, uri, headers, _) = match split_request(request, 0).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::TrustRegistry;

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

    let Some(after_version) = after_version(&uri) else {
        let error = SyncProtocolError::FrameShape;
        return error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        );
    };
    let trust_ports = state.trust_ports();
    match registry_page(authenticated.organization_id, after_version, &trust_ports).await {
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

/// `afterVersion` ist PFLICHT (`schemas/protocol/v1/openapi.yaml`).
///
/// Ohne Abfrageparameter gibt es keine stillschweigende Null: eine fehlende
/// Blaetterposition ist ein Rahmenfehler und keine Vollabfrage.
fn after_version(uri: &Uri) -> Option<RegistryVersion> {
    uri.query()?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == "afterVersion")
            .then(|| value.parse::<u64>().ok())
            .flatten()
            .map(RegistryVersion::new)
    })
}
