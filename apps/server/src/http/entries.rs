//! `GET /v1/chains/{chainId}/entries?afterSequence&afterEntryHash&cursor`.
//!
//! Der Endpunkt verlangt KEINE Capability
//! ([`EndpointV1::required_capability`] ist `None`): jedes freigegebene
//! Geraet der Organisation darf die eigene Kette lesen. Die
//! Organisationsbindung setzt der Pruefer trotzdem durch, und der gelieferte
//! Stapel kommt AUSSCHLIESSLICH aus der authentisierten Organisation — nicht
//! aus einer im Pfad oder in einem Cursor behaupteten.
//!
//! `afterSequence` und `afterEntryHash` sind BEIDE Pflicht. Ein Leser ohne
//! verifizierten Kopf nennt Sequenz null und den Nullhash; das ist der
//! Kettenanfang und keine Kopfbehauptung.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{EndpointV1, STRUCTURED_MEDIA_TYPE_V1, SyncProtocolError};
use ea_sync_server::reader_sync::{ReaderBatchRequestV1, reader_batch};
use ea_types::{ChainId, EntryHash};

use crate::http::{
    AppState, auth_error_response, error_response, fresh_cursor_nonce, hash32_from_hex,
    id16_from_hex, query_value, request_id_or_zero, signed_request, split_request,
};

pub async fn list_chain_entries(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    // Eine Leseanfrage traegt keinen Koerper; die Decke ist null.
    let (method, uri, headers, _) = match split_request(request, 0).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::ChainEntries;

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

    let query = match batch_query(&uri) {
        Ok(query) => query,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };
    let Ok(cursor_nonce) = fresh_cursor_nonce() else {
        let error = SyncProtocolError::Internal;
        return error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        );
    };

    let reader_ports = state.reader_ports();
    match reader_batch(
        ReaderBatchRequestV1 {
            organization_id: authenticated.organization_id,
            chain_id: query.chain_id,
            after_sequence: query.after_sequence,
            after_entry_hash: query.after_entry_hash,
            cursor_token: query.cursor.as_deref(),
            cursor_nonce,
        },
        &reader_ports,
    )
    .await
    {
        Ok(batch) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
            batch.exact_bytes().to_vec(),
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

/// Pfad und Abfrage eines Lesestapels.
struct BatchQuery {
    chain_id: ChainId,
    after_sequence: u64,
    after_entry_hash: EntryHash,
    cursor: Option<Vec<u8>>,
}

/// Liest Kettenkennung, Startposition und Cursor aus der Ziel-URI.
///
/// Kein Axum-`Path`-Extraktor: der Pfad steht ohnehin schon in der
/// SIGNIERTEN `@target-uri`, und eine zweite Quelle fuer dasselbe Segment
/// waere eine Gelegenheit, gegen das eine zu pruefen und das andere zu
/// benutzen.
fn batch_query(uri: &Uri) -> Result<BatchQuery, SyncProtocolError> {
    let chain_segment = uri
        .path()
        .strip_prefix("/v1/chains/")
        .and_then(|rest| rest.strip_suffix("/entries"))
        .ok_or(SyncProtocolError::TargetUriMismatch)?;
    let chain_id = ChainId::try_from(&id16_from_hex(chain_segment)?[..])
        .map_err(|_| SyncProtocolError::FrameShape)?;
    let after_sequence = query_value(uri, "afterSequence")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(SyncProtocolError::FrameShape)?;
    let after_entry_hash = EntryHash::from(hash32_from_hex(
        query_value(uri, "afterEntryHash").ok_or(SyncProtocolError::FrameShape)?,
    )?);
    // Ein FEHLENDER Cursor ist die erste Seite und kein Rahmenfehler; ein
    // vorhandener, aber unlesbarer ist ein fremder Cursor.
    let cursor = match query_value(uri, "cursor") {
        Some(value) => Some(hex::decode(value).map_err(|_| SyncProtocolError::CursorInvalid)?),
        None => None,
    };
    Ok(BatchQuery {
        chain_id,
        after_sequence,
        after_entry_hash,
        cursor,
    })
}
