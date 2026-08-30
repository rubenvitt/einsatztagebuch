//! Die CORS-Schicht — eine EIGENE Zwischenschicht dieses Pakets.
//!
//! Sie steht hier und nicht in einer Kiste: dieser Task traegt keine
//! `Cargo.toml`- und keine `Cargo.lock`-Zeile, und jeder seiner Befehle laeuft
//! `--locked`. Eine frische Abhaengigkeit widerspraeche beidem, und die
//! bereits ratifizierte HTTP-Server-Klasse (ADR 0004) traegt alles, was diese
//! Schicht braucht.
//!
//! # Warum es sie ueberhaupt gibt
//!
//! `web-reader-design.md` §4.1 (:70-75) verlangt einen Auslieferungs-Origin,
//! der vom Sync-Server GETRENNT ist. Damit ist jeder Zugriff des Bundles
//! cross-origin, und ohne diese Schicht liesse der Browser ihn gar nicht erst
//! zu.
//!
//! # Was sie NICHT tut
//!
//! Sie authentisiert nichts. CORS entscheidet, ob ein Browser fragen DARF; ob
//! der Server antwortet, entscheidet die RFC-9421-Signatur — beziehungsweise,
//! auf dem einen unsignierten Abrufpfad, die WebAuthn-Assertion. Die
//! Signaturabdeckung von `@authority` und `@target-uri` bleibt unberuehrt: der
//! Klient signiert ueber die Ziel-URI des Sync-Servers, nicht ueber seinen
//! eigenen Origin.
//!
//! # Die Reihenfolge
//!
//! Die Schicht liegt ueber dem GESAMTEN Router und sieht den Request deshalb
//! VOR der Wegwahl. Nur so kann sie den Vorabflug beantworten: eine
//! `OPTIONS`-Route gibt es nicht, und ohne diese Schicht antwortete Axum
//! darauf mit `405`.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};

use crate::config::WebOriginPolicy;

/// Die Methoden, die ein Browser auf dieser API absetzen darf. Sie sind genau
/// die drei, die [`ea_sync_protocol::EndpointV1`] kennt.
const ALLOWED_METHODS_V1: &str = "GET, POST, PUT";

/// Die Kopfzeilen, die ein Vorabflug freigibt: der Medientyp, die beiden
/// RFC-9421-Kopfzeilen, der RFC-9530-Digest und die Request-ID. Kein
/// `authorization`, kein `cookie` — diese API kennt beide nicht.
const ALLOWED_HEADERS_V1: &str =
    "content-type, content-digest, signature, signature-input, ea-request-id";

/// Wie lange ein Browser den Vorabflug zwischenspeichern darf.
const PREFLIGHT_MAX_AGE_SECONDS_V1: &str = "600";

/// Die Zwischenschicht.
///
/// Drei Faelle, und der dritte ist der wichtigste:
///
/// 1. `OPTIONS` mit gelistetem `Origin` → `204` mit den Freigabekopfzeilen.
/// 2. `OPTIONS` mit nicht gelistetem oder fehlendem `Origin` → `403` und
///    UEBERHAUPT keine CORS-Kopfzeile. Nicht ein `Access-Control-Allow-Origin`
///    mit fremdem Wert, nicht ein `*` — gar keine.
/// 3. Jeder andere Request laeuft durch; seine Antwort bekommt den
///    `Access-Control-Allow-Origin` genau dann, wenn der Origin gelistet ist.
///
/// `Access-Control-Allow-Credentials` wird in keinem der drei Faelle gesetzt.
pub async fn apply_cors(
    State(policy): State<Arc<WebOriginPolicy>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|value| policy.allows(value))
        .map(ToOwned::to_owned);

    if request.method() == Method::OPTIONS {
        let Some(origin) = origin else {
            // Kein `Vary: Origin` und keine Freigabe: die Antwort haengt an
            // keinem Origin, den sie zurueckspiegeln duerfte.
            return StatusCode::FORBIDDEN.into_response();
        };
        return (
            StatusCode::NO_CONTENT,
            [
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, origin),
                (
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    ALLOWED_METHODS_V1.to_owned(),
                ),
                (
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    ALLOWED_HEADERS_V1.to_owned(),
                ),
                (
                    header::ACCESS_CONTROL_MAX_AGE,
                    PREFLIGHT_MAX_AGE_SECONDS_V1.to_owned(),
                ),
                (header::VARY, header::ORIGIN.to_string()),
            ],
        )
            .into_response();
    }

    let mut response = next.run(request).await;
    if let Some(origin) = origin
        && let Ok(value) = HeaderValue::from_str(&origin)
    {
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        headers.insert(header::VARY, HeaderValue::from_static("origin"));
    }
    response
}
