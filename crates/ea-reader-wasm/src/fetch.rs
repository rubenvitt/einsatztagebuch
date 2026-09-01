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
//! # Warum beide Ausfuhren ASYNCHRON sind
//!
//! Nicht, weil `ea-reader` es waere — es ist durchgehend synchron —, sondern
//! weil `OpfsBlobStore::open` es ist: jeder OPFS-Einstieg liefert ein Promise,
//! und ein `FileSystemSyncAccessHandle` laesst sich nach dem Oeffnen des
//! Speichers nicht mehr nachreichen. Der Vorlauf braucht deshalb die
//! VOLLSTAENDIGE Schluesselmenge, und die nennt
//! `ReaderSyncService::required_blob_keys` — in Rust, damit die Abbildung
//! `cache/<hex objectHash>` genau EINE Quelle behaelt.
//!
//! # Die Sitzungsausleihe ueberquert NIE ein `await`
//!
//! `crate::vault_bridge::with_unlocked_vault` leiht aus einer `RefCell`;
//! bliebe die Ausleihe ueber ein Promise offen, faellt der naechste Aufruf mit
//! einer Doppelausleihe um. Beide Ausfuhren sind darum in Abschnitte
//! geschnitten: rechnen, `await`, rechnen.

// Jede Einfuhr traegt ihr eigenes cfg. Auf einem Wirtsziel waere sie unbenutzt,
// und `cargo clippy --workspace --all-targets --all-features --locked --
// -D warnings` faellt an einer unbenutzten Einfuhr genauso wie an einem echten
// Fehler — dieselbe Lage wie im Kopf von `crate::vault_bridge`.
#[cfg(target_arch = "wasm32")]
use ea_reader::{ReaderBlobKey, ReaderSyncError, ReaderSyncService, UnixMillis};
#[cfg(target_arch = "wasm32")]
use js_sys::Array;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::bridge::Json;
#[cfg(target_arch = "wasm32")]
use crate::opfs_worker::OpfsBlobStore;
#[cfg(target_arch = "wasm32")]
use crate::vault_bridge::with_unlocked_vault;

/// Das OPFS-Verzeichnis der Bruecke. Zeichengleich zu
/// `crate::bridge`s `BRIDGE_BLOB_DIRECTORY`, und das ist Absicht: Cursor,
/// Cache und Tresor liegen in EINEM Namensraum, sonst oeffnete der Lesestapel
/// einen anderen Bestand als der Bytespeicher.
#[cfg(target_arch = "wasm32")]
const SYNC_BLOB_DIRECTORY: &str = "ea-reader";

/// Der Code fuer eine Bruecken-Eingabe, die keine Aussage des Lesestapels ist.
///
/// Eine falsche Argumentform ist ein Fehler des Aufrufers und kein Befund ueber
/// den Batch; sie bekommt deshalb einen eigenen Code und nicht einen der acht
/// Codes von [`ReaderSyncError`], die eine Weigerung BEDEUTEN. Dieselbe
/// Trennung fuehrt `crate::vault_bridge` mit
/// `EA-READER-VAULT-BRIDGE-ARGUMENT`.
#[cfg(target_arch = "wasm32")]
const BRIDGE_ARGUMENT_CODE: &str = "EA-READER-SYNC-BRIDGE-ARGUMENT";

/// Der stabile Code eines Lesestapel-Befunds als JS-Wert.
#[cfg(target_arch = "wasm32")]
fn sync_failure(error: ReaderSyncError) -> JsValue {
    JsValue::from_str(error.code())
}

/// Eine Herkunft, die in ein JSON-Feld darf.
///
/// Der Bauer in `crate::bridge` escapt nicht, und die Herkunft ist der EINE
/// Wert dieses Moduls, der aus JavaScript kommt. Statt einen Escaper daneben zu
/// stellen, wird die Eingabe auf das Alphabet einer Autoritaet eingeschraenkt —
/// Buchstaben, Ziffern, `.`, `-` und der Portdoppelpunkt. Was hier durchfaellt,
/// ist keine Autoritaet, und ein Request dorthin waere ohnehin keiner.
#[cfg(target_arch = "wasm32")]
fn host_token(authority: &str) -> Result<String, JsValue> {
    let accepted = !authority.is_empty()
        && authority.len() <= 255
        && authority.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':')
        });
    if accepted {
        Ok(authority.to_owned())
    } else {
        Err(JsValue::from_str(BRIDGE_ARGUMENT_CODE))
    }
}

/// Die Schluessel, die der Wirt schon fuehrt, aus einem JS-Array.
#[cfg(target_arch = "wasm32")]
fn resident_keys(values: &Array) -> Result<Vec<ReaderBlobKey>, JsValue> {
    values
        .iter()
        .map(|value| {
            let key = value
                .as_string()
                .ok_or_else(|| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?;
            ReaderBlobKey::new(&key).map_err(|error| JsValue::from_str(error.code()))
        })
        .collect()
}

/// Der Request als DTO — dieselbe Form, die `ReaderRequestV1` traegt.
#[cfg(target_arch = "wasm32")]
fn request_json(request: &ea_reader::ReaderRequestV1) -> String {
    let headers = request
        .headers
        .iter()
        .map(|(name, value)| format!("[\"{name}\",\"{value}\"]"))
        .collect::<Vec<String>>()
        .join(",");
    let mut json = Json::object();
    json.string("method", request.method.as_str())
        .string("authority", &request.authority)
        .string("target", &request.target)
        .raw("headers", &format!("[{headers}]"))
        // HEX und kein Base64: der Lesestapel ist ein `GET` und traegt keinen
        // Koerper, und wo doch einer stuende, liest ihn JavaScript nicht,
        // sondern reicht ihn weiter.
        .string("bodyHex", &hex::encode(&request.body));
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
/// Ist der Tresor gesperrt, entsteht GAR KEIN Request — `EA-READER-STORE`.
///
/// # Errors
/// `EA-READER-SYNC-BRIDGE-ARGUMENT` fuer eine Herkunft, die keine ist,
/// `EA-READER-BLOB-HOST` fuer den OPFS-Wirt und die stabilen Codes von
/// `ReaderSyncError`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerSyncNextRequest")]
pub async fn reader_sync_next_request(
    session: u32,
    authority: String,
    os_wall_clock_ms: f64,
) -> Result<String, JsValue> {
    let authority = host_token(&authority)?;
    let clock = UnixMillis::new(os_wall_clock_ms as i64);
    let cursor_key = ReaderBlobKey::new(ea_reader::READER_SYNC_CURSOR_BLOB_KEY_V1)
        .map_err(|error| JsValue::from_str(error.code()))?;
    let store = OpfsBlobStore::open(SYNC_BLOB_DIRECTORY, std::slice::from_ref(&cursor_key))
        .await
        .map_err(|error| JsValue::from_str(error.code()))?;
    with_unlocked_vault(session, |vault| {
        let service = ReaderSyncService::open(vault, authority, clock);
        let cursor = service.confirmed_cursor(&store).map_err(sync_failure)?;
        let request = service.next_request(&cursor).map_err(sync_failure)?;
        Ok(request_json(&request))
    })
    .ok_or_else(|| JsValue::from_str(ReaderSyncError::Store.code()))?
}

/// Nimmt die Antwortbytes an, verifiziert und bewegt den Cursor.
///
/// `resident_blob_keys` sind die Schluessel, die der Wirt bereits fuehrt; die
/// Adressen der NEUEN Objekte rechnet `ReaderSyncService::required_blob_keys`
/// dazu. Der Vorlauf oeffnet dann genau diese Menge, und erst danach laeuft der
/// synchrone Kern.
///
/// # Errors
/// `EA-READER-SYNC-BRIDGE-ARGUMENT` fuer eine Schluesselliste, die keine ist,
/// die Codes des Bytespeichers und die stabilen Codes von `ReaderSyncError` —
/// insbesondere `EA-READER-START-HEAD-MISMATCH`, `EA-READER-MISSING-OBJECT`,
/// `EA-READER-CHAIN-GAP` und `EA-READER-CHAIN-FORK`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerSyncAcceptBatch")]
pub async fn reader_sync_accept_batch(
    session: u32,
    authority: String,
    os_wall_clock_ms: f64,
    resident_blob_keys: Array,
    response_body: Vec<u8>,
) -> Result<String, JsValue> {
    let authority = host_token(&authority)?;
    let clock = UnixMillis::new(os_wall_clock_ms as i64);
    let resident = resident_keys(&resident_blob_keys)?;
    let required = with_unlocked_vault(session, |vault| {
        ReaderSyncService::open(vault, authority.clone(), clock)
            .required_blob_keys(&response_body, &resident)
            .map_err(sync_failure)
    })
    .ok_or_else(|| JsValue::from_str(ReaderSyncError::Store.code()))??;
    let mut store = OpfsBlobStore::open(SYNC_BLOB_DIRECTORY, &required)
        .await
        .map_err(|error| JsValue::from_str(error.code()))?;
    with_unlocked_vault(session, |vault| {
        let service = ReaderSyncService::open(vault, authority, clock);
        let cursor = service.confirmed_cursor(&store).map_err(sync_failure)?;
        let batch = service
            .accept_batch(&mut store, &cursor, &response_body)
            .map_err(sync_failure)?;
        let object_count = batch.object_hashes().len();
        // `confirm` VERBRAUCHT den Nachweis; das DTO entsteht deshalb aus dem
        // bestaetigten Cursor. Das ist kein Verlust, sondern die genauere
        // Auskunft: „geht es weiter" ist die Frage nach dem Blaetterschein, und
        // der steht danach IM Cursor — geschrieben und nicht behauptet.
        let confirmed = service.confirm(&mut store, batch).map_err(sync_failure)?;
        let mut json = Json::object();
        json.string(
            "confirmedEntryHash",
            &hex::encode(confirmed.entry_hash().as_bytes()),
        )
        .raw("confirmedSequence", &confirmed.sequence().get().to_string())
        .raw("objectCount", &object_count.to_string())
        .bool("hasMorePages", confirmed.technical_cursor().is_some());
        Ok(json.finish())
    })
    .ok_or_else(|| JsValue::from_str(ReaderSyncError::Store.code()))?
}
