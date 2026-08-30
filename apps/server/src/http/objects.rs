//! `GET /v1/objects/{objectHash}` — der rohe Objektabruf.
//!
//! Die Antwort traegt KEINEN CBOR-Rahmen: sie ist der exakt archivierte
//! Bytestrom mit `Content-Type: application/einsatzarchiv-object`,
//! `Content-Length` und einem RFC-9530-`content-digest` ueber genau diese
//! Bytes (Sync-Wire-Nachtrag, Abschnitt „Medientypen“).
//!
//! # Der Koerper wird nicht gepuffert
//!
//! Der Digest muss VOR dem ersten Koerperbyte in den Kopfzeilen stehen, und
//! er ist nicht der `objectHash`: jener ist domaenengetrennt, RFC 9530 misst
//! blank. Der Handler laeuft den Strom deshalb ZWEIMAL — einmal durch die
//! Hasher, einmal zum Klienten — statt ihn einmal zu lesen und zu halten. Ein
//! Objekt misst nach `ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1` bis zu 4 MiB;
//! die zu puffern waere je gleichzeitiger Anfrage ein Vielfaches davon im
//! Speicher, und genau das verbietet die Streaming-Zusage.

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{EndpointV1, OBJECT_MEDIA_TYPE_V1, SyncProtocolError};
use ea_sync_server::reader_sync::{ReaderError, object_response_head};
use ea_types::ObjectHash;

use crate::http::{
    AppState, CONTENT_DIGEST_HEADER, auth_error_response, error_response, hash32_from_hex,
    request_id_or_zero, signed_request, split_request,
};

pub async fn read_object(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, _) = match split_request(request, 0).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::Objects;

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

    let object_hash = match uri
        .path()
        .strip_prefix("/v1/objects/")
        .ok_or(SyncProtocolError::TargetUriMismatch)
        .and_then(hash32_from_hex)
        .map(ObjectHash::from)
    {
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
    let head = match object_response_head(authenticated.organization_id, object_hash, &reader_ports)
        .await
    {
        Ok(head) => head,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };

    // Der zweite Durchlauf. Er faellt nur aus, wenn der Object Store zwischen
    // den beiden Durchlaeufen ausfaellt — und dann ist es ein `503` und keine
    // halbe Antwort.
    let stream = match state
        .objects
        .get_exact_in(head.object_type, object_hash)
        .await
    {
        Ok(stream) => stream,
        Err(_) => {
            let error = ReaderError::DependencyUnavailable;
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, OBJECT_MEDIA_TYPE_V1.to_owned()),
            (header::CONTENT_LENGTH, head.byte_length.to_string()),
            (
                header::HeaderName::from_static(CONTENT_DIGEST_HEADER),
                content_digest_header(head.content_digest),
            ),
        ],
        Body::new(stream.into_inner()),
    )
        .into_response()
}

/// `sha-256=:<base64>:` — RFC 9530 mit GENAU einem Digest, genau `sha-256`
/// und ohne Parameter.
///
/// Der Kodierer ist DER des Protokollrahmens
/// ([`ea_sync_protocol::content_digest_header`]) und nicht ein zweiter: hier
/// stand einmal eine eigene Base64-Abbildung, und zwei Umsetzungen derselben
/// RFC-Zeile sind zwei Stellen, an denen sie auseinanderlaufen koennen. Der
/// Server signiert und der Klient prueft ueber DENSELBEN Kodierer.
#[must_use]
fn content_digest_header(digest: ea_types::Hash32) -> String {
    ea_sync_protocol::content_digest_header(digest.as_bytes())
}
