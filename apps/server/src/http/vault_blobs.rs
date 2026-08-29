//! `PUT /v1/vault-blobs` und `POST /v1/vault-blobs/retrievals`.
//!
//! Die beiden Endpunkte gehoeren derselben Flaeche und laufen trotzdem auf
//! ZWEI verschiedenen Autoritaeten, und das ist die ganze Pointe von §6.4.1:
//!
//! * Die ABLAGE ist regulaer RFC-9421-signiert. Sie geschieht beim Enrollment
//!   ueber das Geraet des Lesers, sein Ed25519-Schluessel liegt in diesem
//!   Moment vor, also gibt es keinen Grund fuer eine Ausnahme.
//! * Der ABRUF laeuft aus einem frischen Browser, dessen Vault — und darin der
//!   Signaturschluessel — noch verschlossen ist (:213-216). Er traegt KEINE
//!   Signatur, KEINEN [`ea_sync_protocol::AuthenticatedDevice`] und ueberhaupt
//!   keine Geraeteidentitaet; seine alleinige Autoritaet ist eine
//!   WebAuthn-Assertion.
//!
//! Die Ausnahmeliste der Globalen Randbedingungen bleibt damit bei GENAU ZWEI
//! Eintraegen: dem ratenbegrenzten Challenge-Endpunkt und diesem Abruf.
//!
//! # Kein Extraktor auf dem Abrufpfad
//!
//! Der Abruf ruft [`ea_sync_server::auth::authenticate`] nicht auf. Das ist
//! die „andere Routenzeile" der Aufgabe: der Server authentisiert INNERHALB
//! des Handlers, es gibt also gar keine Pruefschicht, an der vorbeigeroutet
//! werden muesste — ein Handler, der `authenticate` nicht ruft, IST der
//! signaturfreie Zweig.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{
    EndpointV1, MAX_SMALL_BODY_BYTES_V1, STRUCTURED_MEDIA_TYPE_V1, VaultBlobRetrievalRequestV1,
    VaultBlobUploadV1,
};
use ea_sync_server::{
    auth::authenticate,
    vault_blob::{VaultServiceError, release_vault_blobs, store_vault_blob},
};

use crate::http::{
    AppState, auth_error_response, error_response, request_id_or_zero,
    require_structured_media_type, signed_request, split_request,
};

/// `PUT /v1/vault-blobs` — ein opakes Chiffrat, create-if-absent.
pub async fn put_vault_blob(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, body) = match split_request(request, MAX_SMALL_BODY_BYTES_V1).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::VaultBlobs;

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
    if let Err(error) = authenticate(endpoint, &state.authority, &signed, &ports, None).await {
        return auth_error_response(error, request_id);
    }

    let upload = match VaultBlobUploadV1::decode(&body) {
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
    match store_vault_blob(&upload, state.clock.as_ref(), state.repository.as_ref()).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(error) => vault_error_response(error, request_id),
    }
}

/// `POST /v1/vault-blobs/retrievals` — die Herausgabe gegen eine Assertion.
///
/// Ohne Signatur, ohne `AuthenticatedDevice`, ohne Capability. Was hier
/// geprueft wird, prueft [`ea_sync_server::vault_blob::release_vault_blobs`];
/// diese Funktion baut nur Rahmen und Antwort.
pub async fn create_vault_blob_retrieval(
    State(state): State<Arc<AppState>>,
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
    let retrieval = match VaultBlobRetrievalRequestV1::decode(&body) {
        Ok(retrieval) => retrieval,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    match release_vault_blobs(&retrieval, &state.relying_party, &state.vault_ports()).await {
        Ok(response) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
            response.exact_bytes().to_vec(),
        )
            .into_response(),
        Err(error) => vault_error_response(error, request_id),
    }
}

/// Ein Dienstbefund der Vault-Flaeche als `protocol-error-v1`.
///
/// Eine freie Funktion und keine `impl`-Methode, aus demselben Grund wie
/// [`auth_error_response`]: [`VaultServiceError`] gehoert
/// `crates/ea-sync-server`, und diese Crate haengt HTTP an ihn.
#[must_use]
fn vault_error_response(
    error: VaultServiceError,
    request_id: ea_sync_protocol::RequestIdV1,
) -> Response {
    error_response(
        error.code(),
        error.http_status(),
        error.retryable(),
        request_id,
    )
}
