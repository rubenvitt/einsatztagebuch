//! Die zwei Ausfuhren des Lesestapels — und keine dritte.
//!
//! # Die Naht liegt GENAU hier
//!
//! `readerSyncNextRequest` gibt einen FERTIG signierten Request heraus,
//! `readerSyncAcceptBatch` nimmt die Antwortbytes zurueck. Dazwischen liegt
//! `fetch`, und `apps/web/src/sync/transport.ts` tut damit nichts, als Bytes zu
//! bewegen: es baut keine Kopfzeile, liest keinen Status als Vertrauensaussage
//! und trifft keine Entscheidung (`web-reader-design.md` §9). Beide
//! Signaturkopfzeilen entstehen in `ea_sync_protocol::RequestSigner` und
//! nirgends sonst.
//!
//! Es entsteht ausdruecklich KEIN dritter Export, der Bytes ohne Cursorpruefung
//! annaehme. Eine Ausfuhr, die Objektbytes „einfach ablegte", waere genau der
//! Weg, auf dem ein Batch am Startkopfvergleich vorbei in den Cache kaeme.
//!
//! # Die Rechnung ist vom Export GETRENNT, und das ist eine Lehre
//!
//! `request_json` und `accepted_json` uebersetzen auf JEDEM Ziel und
//! stehen deshalb nicht hinter `cfg(target_arch = "wasm32")`. (OHNE
//! Verweisklammern: dieser Modulkopf wird ueber die `///`-Zeile an `pub mod
//! fetch` in `crate`s Wurzelgeltungsbereich gerendert, und dort gibt es die
//! zwei Namen nicht — dieselbe Lage, aus der `ReaderSyncError` weiter unten
//! ebenfalls unverlinkt steht.) Der Grund ist
//! gemessen und nicht stilistisch: die erste Fassung baute das
//! Kopfzeilen-Array mit `format!` und stand vollstaendig hinter dem cfg. Der
//! `signature-input`-Wert traegt nach RFC 9421 Anfuehrungszeichen — die Ausgabe
//! war kein gueltiges JSON, `JSON.parse` waere bei JEDEM Aufruf gescheitert,
//! und weil im Repositorium nichts wasm32 ausfuehrt, sah es kein Zeuge. Was
//! rechnet, gehoert vor das Tor; hinter dem Tor steht nur noch das Reichen.
//!
//! # Warum beide Ausfuhren ASYNCHRON sind — und zweimal oeffnen
//!
//! Nicht, weil `ea-reader` es waere — es ist durchgehend synchron —, sondern
//! weil `OpfsBlobStore::open` es ist: jeder OPFS-Einstieg liefert ein Promise,
//! und ein `FileSystemSyncAccessHandle` laesst sich nach dem Oeffnen des
//! Speichers nicht mehr nachreichen. Der Vorlauf braucht deshalb die
//! VOLLSTAENDIGE Schluesselmenge, und die kennt erst, wer die dauerhafte
//! Objektliste gelesen hat. Also zweimal: erst der Sync-Zustand allein, dann —
//! nach dem Fallenlassen des ersten Speichers — der ganze Bestand. Der zweite
//! Aufruf wartet sonst auf die Warteschlangenplaetze des ersten.
//!
//! # Die Sitzungsausleihe ueberquert NIE ein `await`
//!
//! `crate::vault_bridge::with_unlocked_vault` leiht aus einer `RefCell`;
//! bliebe die Ausleihe ueber ein Promise offen, faellt der naechste Aufruf mit
//! einer Doppelausleihe um. Beide Ausfuhren sind darum in Abschnitte
//! geschnitten: rechnen, `await`, rechnen.

// Jede Einfuhr, die nur die Ausfuhren brauchen, traegt ihr eigenes cfg. Auf
// einem Wirtsziel waere sie unbenutzt, und `cargo clippy --workspace
// --all-targets --all-features --locked -- -D warnings` faellt an einer
// unbenutzten Einfuhr genauso wie an einem echten Fehler — dieselbe Lage wie im
// Kopf von `crate::vault_bridge`.
#[cfg(target_arch = "wasm32")]
use ea_reader::{ReaderSyncError, ReaderSyncService, UnixMillis};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use ea_reader::{ConfirmedCursor, ReaderRequestV1};

use crate::bridge::Json;
#[cfg(target_arch = "wasm32")]
use crate::opfs_worker::OpfsBlobStore;
#[cfg(target_arch = "wasm32")]
use crate::vault_bridge::with_unlocked_vault;

/// Das OPFS-Verzeichnis der Bruecke. Zeichengleich zu
/// `crate::bridge`s `BRIDGE_BLOB_DIRECTORY`, und das ist Absicht: Cursor,
/// Objektliste, Cache und Tresor liegen in EINEM Namensraum, sonst oeffnete der
/// Lesestapel einen anderen Bestand als der Bytespeicher.
#[cfg(target_arch = "wasm32")]
const SYNC_BLOB_DIRECTORY: &str = "ea-reader";

/// Der Code fuer eine Bruecken-Eingabe, die keine Aussage des Lesestapels ist.
///
/// Eine falsche Argumentform ist ein Fehler des Aufrufers und kein Befund ueber
/// den Batch; sie bekommt deshalb einen eigenen Code und nicht einen der acht
/// Codes von `ReaderSyncError`, die eine Weigerung BEDEUTEN. Dieselbe
/// Trennung fuehrt `crate::vault_bridge` mit
/// `EA-READER-VAULT-BRIDGE-ARGUMENT`.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const BRIDGE_ARGUMENT_CODE: &str = "EA-READER-SYNC-BRIDGE-ARGUMENT";

/// Der stabile Code eines Lesestapel-Befunds als JS-Wert.
#[cfg(target_arch = "wasm32")]
fn sync_failure(error: ReaderSyncError) -> JsValue {
    JsValue::from_str(error.code())
}

/// Ob `authority` eine Autoritaet ist.
///
/// Buchstaben, Ziffern, `.`, `-` und der Portdoppelpunkt — mehr traegt ein
/// `@authority` nicht. Die Pruefung steht hier NICHT mehr, weil der JSON-Bauer
/// sie braeuchte (der escapt seit dem Befund selbst), sondern weil eine
/// Zeichenkette, die diese Form verfehlt, keine Herkunft ist und ein Request
/// dorthin ohnehin keiner waere.
// Gebaut, wo es gebraucht wird: von den Ausfuhren und von ihrem Zeugen. Auf
// einem Wirtsziel ohne Tests gaebe es keinen Aufrufer, und `-D warnings`
// faellt an totem Code genauso wie an einem echten Fehler.
#[cfg(any(target_arch = "wasm32", test))]
#[must_use]
pub(crate) fn is_host_token(authority: &str) -> bool {
    !authority.is_empty()
        && authority.len() <= 255
        && authority.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':')
        })
}

/// Der Request als DTO — dieselbe Form, die `ReaderRequestV1` traegt.
///
/// Die Kopfzeilen gehen durch `Json::string_pairs` und damit durch das
/// Escaping; ein `format!` daneben waere wieder der Fehler, den der Modulkopf
/// beschreibt. Der Bauer ist `pub(crate)`, also steht sein Name hier ohne
/// Verweisklammern — eine oeffentliche Dokumentation, die auf ein privates
/// Glied verweist, ist eine Warnung und kein Verweis.
#[must_use]
pub fn request_json(request: &ReaderRequestV1) -> String {
    let headers: Vec<(&str, &str)> = request
        .headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let mut json = Json::object();
    json.string("method", request.method.as_str())
        .string("authority", &request.authority)
        .string("target", &request.target)
        .string_pairs("headers", &headers)
        // HEX und kein Base64: der Lesestapel ist ein `GET` und traegt keinen
        // Koerper, und wo doch einer stuende, liest ihn JavaScript nicht,
        // sondern reicht ihn weiter.
        .string("bodyHex", &hex::encode(&request.body));
    json.finish()
}

/// Das Ergebnis eines angenommenen Batches als DTO.
///
/// „Geht es weiter" ist die Frage nach dem Blaetterschein, und der steht
/// danach IM bestaetigten Cursor — geschrieben und nicht behauptet.
#[must_use]
pub fn accepted_json(confirmed: &ConfirmedCursor, object_count: usize) -> String {
    let mut json = Json::object();
    json.string(
        "confirmedEntryHash",
        &hex::encode(confirmed.entry_hash().as_bytes()),
    )
    .raw("confirmedSequence", &confirmed.sequence().get().to_string())
    .raw("objectCount", &object_count.to_string())
    .bool("hasMorePages", confirmed.technical_cursor().is_some());
    json.finish()
}

// ---------------------------------------------------------------------------
// Die zwei Ausfuhren. JEDE traegt ihr eigenes `cfg(target_arch = "wasm32")`
// unmittelbar ueber dem Attribut — `every_wasm_bindgen_export_sits_behind_the
// _wasm32_cfg` liest das als Text und folgt keinem `mod`.
// ---------------------------------------------------------------------------

/// Der naechste Lesestapel-Request, FERTIG signiert.
///
/// Der bestaetigte Cursor kommt aus OPFS und nie aus JavaScript: ein von aussen
/// gereichter Cursor waere genau der Weg, den Startkopfvergleich zu umgehen.
/// Ist die Sitzung gesperrt, entsteht GAR KEIN Request —
/// `EA-READER-SESSION-LOCKED`; `os_wall_clock_ms` ist zugleich der Zeitwert,
/// gegen den `ReaderSession::vault` die Frist nachrechnet.
///
/// # Errors
/// `EA-READER-SYNC-BRIDGE-ARGUMENT` fuer eine Herkunft, die keine ist,
/// `EA-READER-SESSION-UNKNOWN` und `EA-READER-SESSION-LOCKED` fuer die
/// Sitzung, `EA-READER-BLOB-HOST` fuer den OPFS-Wirt und die stabilen Codes
/// von `ReaderSyncError`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerSyncNextRequest")]
pub async fn reader_sync_next_request(
    session: u32,
    authority: String,
    os_wall_clock_ms: f64,
) -> Result<String, JsValue> {
    if !is_host_token(&authority) {
        return Err(JsValue::from_str(BRIDGE_ARGUMENT_CODE));
    }
    let clock = UnixMillis::new(os_wall_clock_ms as i64);
    let state_keys = ReaderSyncService::sync_state_blob_keys().map_err(sync_failure)?;
    let store = OpfsBlobStore::open(SYNC_BLOB_DIRECTORY, &state_keys)
        .await
        .map_err(|error| JsValue::from_str(error.code()))?;
    with_unlocked_vault(session, clock, |vault| {
        let service = ReaderSyncService::open(vault, authority, clock);
        let cursor = service.confirmed_cursor(&store).map_err(sync_failure)?;
        let request = service.next_request(&cursor).map_err(sync_failure)?;
        Ok(request_json(&request))
    })?
}

/// Nimmt die Antwortbytes an, verifiziert und bewegt den Cursor.
///
/// JavaScript reicht KEINE Schluessel herein. Der erste Vorlauf oeffnet die
/// zwei Adressen des Sync-Zustands, `required_blob_keys` liest daraus die
/// dauerhafte Objektliste und rechnet die Adressen der neuen Objekte dazu, und
/// erst der zweite Vorlauf oeffnet den ganzen Bestand. Damit bestimmt Rust,
/// welchen Bestand `verify_archive_observed` sieht.
///
/// # Errors
/// `EA-READER-SYNC-BRIDGE-ARGUMENT` fuer eine Herkunft, die keine ist, die
/// Codes des Bytespeichers und die stabilen Codes von `ReaderSyncError` —
/// insbesondere `EA-READER-START-HEAD-MISMATCH`, `EA-READER-MISSING-OBJECT`,
/// `EA-READER-CHAIN-GAP` und `EA-READER-CHAIN-FORK`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerSyncAcceptBatch")]
pub async fn reader_sync_accept_batch(
    session: u32,
    authority: String,
    os_wall_clock_ms: f64,
    response_body: Vec<u8>,
) -> Result<String, JsValue> {
    if !is_host_token(&authority) {
        return Err(JsValue::from_str(BRIDGE_ARGUMENT_CODE));
    }
    let clock = UnixMillis::new(os_wall_clock_ms as i64);
    let state_keys = ReaderSyncService::sync_state_blob_keys().map_err(sync_failure)?;
    let required = {
        // Der erste Speicher wird VOR dem zweiten Vorlauf fallen gelassen; sonst
        // wartete der zweite auf die Warteschlangenplaetze des ersten. Der
        // Block macht das Fallenlassen zur Struktur statt zu einer Zeile, die
        // jemand streicht.
        let state_store = OpfsBlobStore::open(SYNC_BLOB_DIRECTORY, &state_keys)
            .await
            .map_err(|error| JsValue::from_str(error.code()))?;
        with_unlocked_vault(session, clock, |vault| {
            ReaderSyncService::open(vault, authority.clone(), clock)
                .required_blob_keys(&state_store, &response_body)
                .map_err(sync_failure)
        })??
    };
    let mut store = OpfsBlobStore::open(SYNC_BLOB_DIRECTORY, &required)
        .await
        .map_err(|error| JsValue::from_str(error.code()))?;
    with_unlocked_vault(session, clock, |vault| {
        let service = ReaderSyncService::open(vault, authority, clock);
        let cursor = service.confirmed_cursor(&store).map_err(sync_failure)?;
        let batch = service
            .accept_batch(&mut store, &cursor, &response_body)
            .map_err(sync_failure)?;
        let object_count = batch.object_hashes().len();
        let confirmed = service.confirm(&mut store, batch).map_err(sync_failure)?;
        Ok(accepted_json(&confirmed, object_count))
    })?
}

#[cfg(test)]
mod tests {
    use ea_reader::HttpMethod;
    use ea_reader::ReaderRequestV1;

    use super::{BRIDGE_ARGUMENT_CODE, is_host_token, request_json};

    /// Der `signature-input`-Wert, so wie `RequestSigner` ihn bildet.
    ///
    /// Die Anfuehrungszeichen sind KEIN Sonderfall: RFC 9421 §2.3 schreibt die
    /// Komponentenliste und die Parameter `keyid`, `alg` und `tag` als
    /// zitierte Zeichenketten vor. Jeder echte Request traegt sie.
    fn signature_input() -> String {
        "ea1=(\"@method\" \"@authority\" \"@target-uri\" \"ea-request-id\");created=1800000000;\
         expires=1800000060;nonce=\"AAAA\";keyid=\"abc\";alg=\"ed25519\";tag=\"ea-org\""
            .to_owned()
    }

    fn signed_request() -> ReaderRequestV1 {
        ReaderRequestV1 {
            method: HttpMethod::Get,
            authority: "sync.einsatzarchiv.invalid".to_owned(),
            target: "/v1/chains/1313/entries?afterSequence=0".to_owned(),
            headers: vec![
                ("ea-request-id", "AAAAAAAAAAAAAAAAAAAAAA".to_owned()),
                ("signature-input", signature_input()),
                ("signature", "ea1=:AAAA:".to_owned()),
            ],
            body: Vec::new(),
        }
    }

    /// Der Zeuge, den es vorher nicht gab.
    ///
    /// Die erste Fassung baute das Kopfzeilen-Array mit `format!` und stand
    /// vollstaendig hinter `cfg(target_arch = "wasm32")`. Sie erzeugte fuer
    /// JEDEN Request unparsbares JSON, und weil im Repositorium nichts wasm32
    /// ausfuehrt, faerbte sich nichts rot. Dieser Test ist der Grund, warum die
    /// Rechnung jetzt vor dem Tor steht: er PARST die Ausgabe und liest den
    /// Wert mit den Anfuehrungszeichen wieder heraus.
    #[test]
    fn the_request_dto_parses_and_round_trips_a_quoted_signature_input() {
        let rendered = request_json(&signed_request());
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("das Request-DTO MUSS gueltiges JSON sein");

        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["authority"], "sync.einsatzarchiv.invalid");
        assert_eq!(parsed["bodyHex"], "");
        let headers = parsed["headers"]
            .as_array()
            .expect("die Kopfzeilen sind ein Array");
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[1][0], "signature-input");
        // WOERTLICH zurueck, samt jedem Anfuehrungszeichen: ein Escaping, das
        // den Wert veraenderte, brauchte der Server nicht abzuweisen — er
        // wuerde ihn schlicht nicht wiedererkennen.
        assert_eq!(headers[1][1], signature_input().as_str());
        assert_eq!(headers[2][1], "ea1=:AAAA:");
    }

    /// Ein Backslash und ein Steuerzeichen sind die zwei anderen Zeichen, die
    /// RFC 8259 §7 zwingend escapt sehen will.
    #[test]
    fn the_request_dto_survives_a_backslash_and_a_control_character() {
        let mut request = signed_request();
        request.headers.push(("signature", "a\\b\tc".to_owned()));
        let parsed: serde_json::Value = serde_json::from_str(&request_json(&request))
            .expect("auch mit Backslash und Tabulator MUSS das DTO parsen");
        assert_eq!(parsed["headers"][3][1], "a\\b\tc");
    }

    /// Die Herkunft ist die EINE Eingabe dieses Moduls, die aus JavaScript
    /// kommt; sie wird auf die Form einer Autoritaet eingeschraenkt.
    #[test]
    fn only_a_host_shaped_authority_is_accepted() {
        assert!(is_host_token("sync.einsatzarchiv.invalid"));
        assert!(is_host_token("localhost:8443"));
        assert!(!is_host_token(""));
        assert!(!is_host_token("sync.invalid/../evil"));
        assert!(!is_host_token("sync.invalid\" onload=\"x"));
        // Der Code der Abweisung ist STABIL und gehoert nicht in die Familie
        // der Lesestapel-Codes: er sagt etwas ueber den Aufrufer, nicht ueber
        // den Batch.
        assert_eq!(BRIDGE_ARGUMENT_CODE, "EA-READER-SYNC-BRIDGE-ARGUMENT");
    }
}
