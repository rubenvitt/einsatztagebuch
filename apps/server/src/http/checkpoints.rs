//! `GET /v1/checkpoints?after={cursor}`.
//!
//! Der Endpunkt verlangt KEINE Capability
//! ([`ea_sync_protocol::EndpointV1::required_capability`] ist `None`): jedes
//! freigegebene Geraet der Organisation darf die Anker seiner eigenen
//! Organisation lesen. Die Organisationsbindung setzt der Pruefer trotzdem
//! durch, und die gelieferte Seite kommt AUSSCHLIESSLICH aus der
//! authentisierten Organisation — nicht aus einer im Pfad oder in einem
//! Cursor behaupteten.
//!
//! # Der Cursor reist als Hex
//!
//! `next-cursor` ist auf der Leitung ein `bstr`, der Abfrageparameter `after`
//! eine Zeichenkette. Dazwischen steht die Hexdarstellung — dieselbe
//! Schreibweise, in der schon die Kettenkennung im Pfad und die Request-ID im
//! Header reisen. Eine zweite Kodierung (Base64, Base64url) waere eine zweite
//! Schreibweise fuer dasselbe Token.
//!
//! # Die Antwort ist nicht autoritativ
//!
//! Sie liefert exakte archivierte Bytes und setzt keine Aussage aus
//! Datenbankzeilen zusammen (`design.md` §13.2). Die Reihenfolge der Kette
//! steht in den Objekten selbst, in `previous-evidence-hash`.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{EndpointV1, STRUCTURED_MEDIA_TYPE_V1, SyncProtocolError};
use ea_sync_server::checkpoint::checkpoint_page;

use crate::http::{
    AppState, auth_error_response, error_response, request_id_or_zero, signed_request,
    split_request,
};

pub async fn list_checkpoints(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    // Eine Leseanfrage traegt keinen Koerper; die Decke ist null.
    let (method, uri, headers, _) = match split_request(request, 0).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::Checkpoints;

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

    // Ein FEHLENDER `after`-Parameter ist die erste Seite und kein
    // Rahmenfehler: `checkpoint-list-response-v1` fuehrt `requested-cursor`
    // als `bstr / null`, also gibt es die leere Blaetterposition. Ein
    // vorhandener, aber unlesbarer Parameter ist dagegen ein fremder Cursor.
    let cursor = match cursor_bytes(&uri) {
        Ok(cursor) => cursor,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };

    let Ok(nonce) = AppState::fresh_nonce() else {
        let error = SyncProtocolError::Internal;
        return error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        );
    };
    let mut cursor_nonce = [0_u8; 16];
    cursor_nonce.copy_from_slice(&nonce[..16]);

    let checkpoint_ports = state.checkpoint_ports();
    match checkpoint_page(
        authenticated.organization_id,
        cursor.as_deref(),
        cursor_nonce,
        &checkpoint_ports,
    )
    .await
    {
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

/// Der technische Cursor aus dem Abfrageparameter `after`.
///
/// `Ok(None)` heisst „kein Parameter“ und damit „erste Seite“. Ein
/// vorhandener Parameter, der kein Hex ist, ist
/// [`SyncProtocolError::CursorInvalid`] — derselbe Befund wie ein
/// authentisch aussehendes, aber unlesbares Token. Der Klient darf den Token
/// ohnehin nicht deuten, also verraet der Code nichts ueber die Stelle, an
/// der die Form brach.
fn cursor_bytes(uri: &Uri) -> Result<Option<Vec<u8>>, SyncProtocolError> {
    let Some(value) = uri.query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name == "after").then_some(value)
        })
    }) else {
        return Ok(None);
    };
    hex::decode(value)
        .map(Some)
        .map_err(|_| SyncProtocolError::CursorInvalid)
}
