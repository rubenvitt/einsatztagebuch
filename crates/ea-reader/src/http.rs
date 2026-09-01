//! Der fertig signierte Request — das Einzige, was TypeScript noch abschickt.
//!
//! # Warum hier ein WERT steht und kein Klient
//!
//! `crates/ea-sync-client` loest dieselbe Aufgabe mit `#[async_trait]
//! SyncTransportV1` ueber Tokio und steht genau deshalb in
//! `WASM32_EXEMPT_CRATES`; eine Kante von `ea-reader` dorthin waere eine Kante
//! von der Positivliste auf die Ausnahmeliste. Im Browser ist `fetch` ausserdem
//! ein Promise, und ein async-Rust-Kern zoege eine zweite Laufzeit in das
//! WASM-Modul. `ea-reader` bleibt darum synchron wie der ganze Rust-Kern und
//! gibt einen WERT heraus.
//!
//! # Was `apps/web/src/sync/transport.ts` damit tun DARF
//!
//! `fetch` rufen und die Antwortbytes zurueckreichen. Sonst nichts: es baut
//! keine Kopfzeile, liest keinen Status als Vertrauensaussage und trifft keine
//! Entscheidung (`web-reader-design.md` §9). Beide Signaturkopfzeilen stehen
//! deshalb FERTIG in [`ReaderRequestV1::headers`] — nicht als Anleitung,
//! sondern als Ergebnis.
//!
//! # `target` ist ein PFAD, der signierte `@target-uri` ist absolut
//!
//! Zwei verschiedene Dinge, und sie zusammenzuziehen waere ein stiller
//! Fehlschlag gegen den echten Server: `apps/server/src/http/mod.rs` prueft
//! `format!("https://{authority}{path_and_query}")`. [`ReaderRequestV1::target`]
//! bleibt trotzdem der Pfad — er adressiert den Transport —, und die Herkunft
//! steht daneben in [`ReaderRequestV1::authority`]. Dieselbe Trennung fuehrt
//! `crate::EnrollmentRequestV1`.

use ea_sync_protocol::HttpMethod;

/// Ein fertig signierter Request des Readers.
///
/// Die Kopfzeilennamen sind `&'static str` und keine `String`: sie entstehen
/// ausschliesslich aus den Konstanten des Protokolls, und ein zur Laufzeit
/// gebildeter Name waere genau die Kopfzeile, die niemand signiert hat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaderRequestV1 {
    pub method: HttpMethod,
    pub authority: String,
    /// Pfad UND Abfragezeichenkette, so wie der Transport sie sendet.
    pub target: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}
