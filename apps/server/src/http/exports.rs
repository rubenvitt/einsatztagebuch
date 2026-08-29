//! `GET /v1/archive-exports/current` — der vollstaendige Archivexport.
//!
//! Die Antwort ist eine Folge exakter Objektbytes und schliesst mit GENAU
//! EINEM `archive-export-manifest-v1` (Sync-Wire-Nachtrag, „Medientypen“).
//! Der Medientyp ist der strukturierte: das Manifest ist der Rahmen, den der
//! Empfaenger am Ende liest.
//!
//! # Wo die Grenzen wirken — und wo der Koerper heute noch entsteht
//!
//! Die Satz- und die Bytedecke wirken in [`export_page`] und damit VOR jeder
//! Akkumulation: die Seite wird ausschliesslich aus den GROESSEN des
//! Objektindex geplant, ohne ein einziges Objektbyte gelesen zu haben. Das ist
//! die Zusage des Nachtrags — „der Server setzt sowohl die Zaehl- als auch die
//! gestreamte Bytegrenze durch, bevor er akkumuliert“.
//!
//! Der Koerper selbst wird danach allerdings VOLLSTAENDIG gebildet und erst
//! dann gesendet. Das ist eine bewusst benannte Grenze dieser Stufe und keine
//! Nachlaessigkeit: ein fortlaufender Koerper braucht einen Stromadapter
//! (`tokio-stream`, `futures-core` oder `http-body`), und jeder davon waere ein
//! NEUER Wurzelpin — den `docs/adr/0004-server-runtime-and-dependency-class.md`
//! nur mit eigener Begruendungszeile in seiner Tabelle zulaesst und den ein
//! Task nicht nebenbei zieht. Der Einzelobjektabruf
//! (`apps/server/src/http/objects.rs`) stromt dagegen ohne Puffer: dort
//! genuegt der `SdkBody` des Object Stores, weil genau EIN Objekt hinausgeht.
//!
//! Die Speicherobergrenze je gleichzeitiger Anfrage ist damit die Bytedecke
//! einer Seite. Sie wandert in dem Moment weg, in dem ein Stromadapter durch
//! die ADR-Tabelle geht; die Planung darunter aendert sich dafuer nicht.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ea_sync_protocol::{EndpointV1, STRUCTURED_MEDIA_TYPE_V1, SyncProtocolError};
use ea_sync_server::export::{ExportError, export_page};

use crate::http::{
    AppState, auth_error_response, error_response, fresh_cursor_nonce, query_value,
    request_id_or_zero, signed_request, split_request,
};

pub async fn read_current_export(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let zero = request_id_or_zero(&axum::http::HeaderMap::new());
    let (method, uri, headers, _) = match split_request(request, 0).await {
        Ok(parts) => parts,
        Err(error) => {
            return error_response(error.code(), error.http_status(), error.retryable(), zero);
        }
    };
    let request_id = request_id_or_zero(&headers);
    let endpoint = EndpointV1::ArchiveExports;

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

    let cursor = match query_value(&uri, "cursor") {
        Some(value) => match hex::decode(value) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                let error = SyncProtocolError::CursorInvalid;
                return error_response(
                    error.code(),
                    error.http_status(),
                    error.retryable(),
                    request_id,
                );
            }
        },
        None => None,
    };
    let Ok(cursor_nonce) = fresh_cursor_nonce() else {
        let error = ExportError::Internal;
        return error_response(
            error.code(),
            error.http_status(),
            error.retryable(),
            request_id,
        );
    };

    let export_ports = state.export_ports();
    let page = match export_page(
        authenticated.organization_id,
        cursor.as_deref(),
        cursor_nonce,
        &export_ports,
    )
    .await
    {
        Ok(page) => page,
        Err(error) => {
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
    };

    let content_length = page.total_byte_length();
    let mut body = Vec::with_capacity(
        usize::try_from(content_length).unwrap_or(page.manifest().exact_bytes().len()),
    );
    for object in page.objects() {
        let bytes = match state
            .objects
            .get_exact_in(object.kind, object.object_hash)
            .await
        {
            Ok(stream) => match stream.collect().await {
                Ok(bytes) => bytes.into_bytes(),
                Err(_) => return dependency_unavailable(request_id),
            },
            Err(_) => return dependency_unavailable(request_id),
        };
        // Der Beweis, dass diese Bytes DIESES Objekt sind: ihr Hash gegen den
        // Hash, unter dem sie stehen. Ein Export, der ein fremdes Objekt
        // ausliefert, waere schlimmer als einer, der abbricht.
        if ea_crypto::object_hash(&bytes) != object.object_hash {
            let error = ExportError::Internal;
            return error_response(
                error.code(),
                error.http_status(),
                error.retryable(),
                request_id,
            );
        }
        body.extend_from_slice(&bytes);
    }
    // Das Manifest schliesst den Strom ab — als letztes und nie davor.
    body.extend_from_slice(page.manifest().exact_bytes());

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, STRUCTURED_MEDIA_TYPE_V1)],
        body,
    )
        .into_response()
}

fn dependency_unavailable(request_id: ea_sync_protocol::RequestIdV1) -> Response {
    let error = ExportError::DependencyUnavailable;
    error_response(
        error.code(),
        error.http_status(),
        error.retryable(),
        request_id,
    )
}
