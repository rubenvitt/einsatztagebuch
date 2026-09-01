//! Der Endpunktport des Enrollments: EIN Trait ueber FERTIGE Anfragen, EINE
//! In-Memory-Doppelung daneben, EIN Fehlertyp mit stabilem `code()`.
//!
//! # Warum ein synchroner PORT und keine HTTP-Bibliothek
//!
//! `crates/ea-reader/Cargo.toml` traegt keine Wirtsabhaengigkeit, und das ist
//! keine Zufaelligkeit: `ea-reader` steht auf der wasm32-Positivliste in
//! `tools/xtask/src/main.rs`, und `tokio`, `hyper` oder `reqwest` naehmen es von
//! dort herunter. `ea-sync-client` scheidet aus demselben Grund aus — es steht
//! in `WASM32_EXEMPT_CRATES`. Dieses Modul baut deshalb dieselbe Bauform wie
//! [`crate::ReaderBlobStore`]: Rust BAUT und SIGNIERT die Anfragen und gibt sie
//! als fertige Bytes samt Kopfzeilen heraus; der Aufrufer — im Browser die
//! Bruecke, im Wirtstest die Doppelung — FUEHRT sie aus. Damit haelt
//! `web-reader-design.md` §9 woertlich: TypeScript trifft keine
//! Sicherheitsentscheidung, es traegt Bytes.
//!
//! # Was der synchrone Port im Browser kostet
//!
//! Die Analogie zu `blob_store.rs` traegt bei der BAUFORM und nicht von selbst
//! bei der Ausfuehrung. OPFS hat nach EINEM asynchronen Vorlauf ein wirklich
//! synchrones Handle, HTTP hat kein Gegenstueck — `fetch` gibt ein Promise, und
//! blockierend darauf zu warten hielte genau den Faden an, dessen
//! Ereignisschleife es erfuellen muesste. Die einzige synchrone Transportflaeche
//! eines Browsers ist ein synchrones `XMLHttpRequest`, und die gibt es
//! ausschliesslich in einem DEDIZIERTEN Worker. Die Browserfassung dieses Ports
//! steht deshalb dort, wo `OpfsBlobStore` schon steht, und aus demselben Grund.

use core::fmt;
use std::collections::BTreeMap;

use ea_sync_protocol::{HttpMethod, VaultBlobRetrievalResponseV1};

/// Ein fertig gebauter Aufruf: Bytes und Kopfzeilen, sonst nichts.
///
/// Der Port kennt WEDER Struktur NOCH Bedeutung des Koerpers — dieselbe Regel
/// wie bei [`crate::ReaderBlobStore`]. Wer hier typisiert zugriffe, haette eine
/// zweite Stelle, an der ueber Protokollform entschieden wird.
pub struct EnrollmentRequestV1 {
    method: HttpMethod,
    authority: String,
    target_uri: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    signed: bool,
}

impl EnrollmentRequestV1 {
    /// Der Bauweg aus `crate::enrollment` und sonst keiner.
    ///
    /// `pub(crate)`, damit ausserhalb dieser Crate niemand eine Anfrage
    /// zusammensetzt, die keine Signatur hinter sich hat und trotzdem
    /// `is_signed()` behauptet.
    pub(crate) const fn new(
        method: HttpMethod,
        authority: String,
        target_uri: String,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
        signed: bool,
    ) -> Self {
        Self {
            method,
            authority,
            target_uri,
            body,
            headers,
            signed,
        }
    }

    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    #[must_use]
    pub fn target_uri(&self) -> &str {
        &self.target_uri
    }

    /// Die Herkunft, die die Signatur als `@authority` BINDET.
    ///
    /// Sie steht hier, weil der Aufrufer sonst raten muesste, wohin die Bytes
    /// gehoeren: [`EnrollmentRequestV1::target_uri`] ist ein Pfad, und ein Pfad
    /// allein adressiert nichts. Sie kommt aus
    /// `crate::EnrollmentRequestContextV1`.
    ///
    /// # Der signaturfreie Abruf traegt hier LEER
    ///
    /// `crate::recover_and_unlock_vault` bekommt keinen Kontext — seine
    /// Signatur nimmt den fertigen Abrufrahmen, den Authenticator und den Port
    /// und sonst nichts (`web-reader-design.md` §6.4.1: der Signaturschluessel
    /// liegt im noch verschlossenen Tresor). Ohne Signatur gibt es keine
    /// gebundene `@authority`, und ein hier erfundener Wert waere eine
    /// Behauptung ueber eine Herkunft, die niemand geprueft hat. Der Aufrufer
    /// dieses EINEN Aufrufs adressiert ihn ueber dieselbe Konfiguration, aus
    /// der er die Herkunft der drei signierten Aufrufe nimmt.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// `content-type`, `content-digest`, `ea-request-id`, `signature-input`,
    /// `signature` — je nach Aufruf. Der Abruf traegt die letzten beiden nicht.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signed
    }
}

impl fmt::Debug for EnrollmentRequestV1 {
    /// Nennt Methode, Pfad und Signaturzustand und NIE den Koerper.
    ///
    /// Der Koerper traegt den versiegelten Tresor beziehungsweise eine
    /// WebAuthn-Assertion; ein abgeleitetes `Debug` schriebe beides in jede
    /// Fehlermeldung. Dieselbe Regel wie bei
    /// `impl fmt::Debug for SealedVaultV1`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "EnrollmentRequestV1 {{ method: {:?}, target_uri: {}, signed: {}, body_len: {} }}",
            self.method,
            self.target_uri,
            self.signed,
            self.body.len()
        )
    }
}

/// Der AUFGEZEICHNETE Aufruf, den die Doppelung herausgibt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentCallV1 {
    pub method: HttpMethod,
    pub target_uri: String,
    pub signed: bool,
}

/// Der Fehlschlag des Endpunktports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentEndpointError {
    /// Der Wirt kam nicht durch; der Text kommt von ihm.
    Host(String),
    /// Der Server hat geantwortet, aber nicht mit 2xx.
    Status(u16),
    /// Die Antwort ist keine gueltige `VaultBlobRetrievalResponseV1`.
    ResponseShape,
}

impl EnrollmentEndpointError {
    /// Der stabile Code des Fehlschlags.
    ///
    /// Zusicherungen stehen gegen ihn und nie gegen eine Formatierung —
    /// dieselbe Regel wie bei [`crate::ReaderBlobError::code`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Host(_) => "EA-READER-ENROLLMENT-ENDPOINT-HOST",
            Self::Status(_) => "EA-READER-ENROLLMENT-ENDPOINT-STATUS",
            Self::ResponseShape => "EA-READER-ENROLLMENT-ENDPOINT-RESPONSE",
        }
    }
}

impl fmt::Display for EnrollmentEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for EnrollmentEndpointError {}

/// Der Port ueber FERTIGE Anfragen.
///
/// EINE Methode und nicht drei: die REIHENFOLGE der drei Endpunkte ist eine
/// Eigenschaft von `crate::ReaderEnrollment::finish` und keine des Ports, und
/// drei benannte Methoden verschoeben sie in eine Schnittstelle, in der kein
/// Zeuge sie sieht.
pub trait EnrollmentEndpoints {
    /// # Errors
    /// Jeder Fehlschlag des Wirts, ohne den Koerper zu nennen.
    fn send(&mut self, request: &EnrollmentRequestV1) -> Result<Vec<u8>, EnrollmentEndpointError>;
}

/// Das Doppel, mit dem jeder `cargo test -p ea-reader` ohne Netz laeuft.
///
/// Bewusst NICHT hinter `cfg(test)` — dieselbe Entscheidung wie bei
/// [`crate::InMemoryReaderBlobStore`]: die Integrationstests von `ea-reader`
/// und die Systemtests unter `tests/ea-system-tests` greifen darauf zu.
///
/// # Es gibt KEINE Fallunterscheidung ueber den Pfad
///
/// Die Doppelung beantwortet JEDEN Aufruf mit der kodierten
/// `VaultBlobRetrievalResponseV1` ihrer eingestellten Chiffrate — bei
/// Voreinstellung also mit der leeren Liste. Das ist Absicht: die beiden
/// schreibenden Endpunkte tragen laut `EndpointV1::response_media_type` gar
/// keinen Antwortkoerper, `finish` liest ihn folglich nicht, und eine
/// Verzweigung ueber `target_uri` waere eine zweite Stelle mit Protokollwissen
/// — genau die, die der Kommentar von [`InMemoryEnrollmentEndpoints::fail_call`]
/// fuer den Fehlerfall ausschliesst.
#[derive(Debug, Default)]
pub struct InMemoryEnrollmentEndpoints {
    calls: Vec<EnrollmentCallV1>,
    failures: BTreeMap<usize, EnrollmentEndpointError>,
    retrieval_ciphertexts: Vec<Vec<u8>>,
}

impl InMemoryEnrollmentEndpoints {
    /// Ein leeres Doppel.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Die aufgezeichneten Aufrufe in der Reihenfolge, in der sie kamen.
    #[must_use]
    pub fn calls(&self) -> &[EnrollmentCallV1] {
        &self.calls
    }

    /// Laesst den `ordinal`-ten Aufruf (1-basiert) mit DIESEM Fehler fallen.
    ///
    /// Der Fehler und nicht sein Code: `code()` ist einwegig — es gibt keine
    /// Abbildung von `"EA-READER-ENROLLMENT-ENDPOINT-STATUS"` zurueck auf ein
    /// `Status(u16)`, und eine Doppelung, die aus einer Zeichenkette eine
    /// Variante raten muesste, waere eine zweite Stelle mit Protokollwissen.
    pub fn fail_call(&mut self, ordinal: usize, error: EnrollmentEndpointError) {
        self.failures.insert(ordinal, error);
    }

    /// Die Chiffrate, die `POST /v1/vault-blobs/retrievals` zurueckgibt.
    pub fn answer_retrieval_with(&mut self, ciphertexts: Vec<Vec<u8>>) {
        self.retrieval_ciphertexts = ciphertexts;
    }
}

impl EnrollmentEndpoints for InMemoryEnrollmentEndpoints {
    /// # Panics
    /// Wenn die eingestellten Chiffrate die Formgrenzen von
    /// `VaultBlobRetrievalResponseV1` verletzen — mehr als
    /// `MAX_VAULT_BLOBS_PER_SUBJECT_V1`, leer oder ueber
    /// `MAX_VAULT_BLOB_CIPHERTEXT_BYTES_V1`. Das ist ein Fehler des
    /// Zeugenaufbaus und keine Lage des Wirts; ein durchgereichter
    /// `ResponseShape` liesse ihn wie einen Befund ueber den Server aussehen.
    fn send(&mut self, request: &EnrollmentRequestV1) -> Result<Vec<u8>, EnrollmentEndpointError> {
        self.calls.push(EnrollmentCallV1 {
            method: request.method(),
            target_uri: request.target_uri().to_owned(),
            signed: request.is_signed(),
        });
        if let Some(error) = self.failures.get(&self.calls.len()) {
            return Err(error.clone());
        }
        Ok(
            VaultBlobRetrievalResponseV1::new(self.retrieval_ciphertexts.clone())
                .expect("die eingestellten Chiffrate MUESSEN die Formgrenzen des Rahmens halten")
                .exact_bytes()
                .to_vec(),
        )
    }
}
