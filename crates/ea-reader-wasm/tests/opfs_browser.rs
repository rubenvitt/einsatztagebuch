#![cfg(target_arch = "wasm32")]

//! Der zweite gegatete Zeuge und der erste `wasm-bindgen-test` des
//! Repositoriums.
//!
//! Die Kopfzeile `#![cfg(target_arch = "wasm32")]` steht in der ERSTEN Zeile:
//! ohne sie zoege `cargo test --workspace --all-targets --locked` dieses Ziel
//! auf dem Wirt mit und faende dort weder `FileSystemSyncAccessHandle` noch
//! einen Testlaeufer. `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg`
//! durchlaeuft nur `src/` und faengt das NICHT — eine fehlende Kopfzeile faellt
//! erst im `pnpm verify:quick`, an der spaetesten und teuersten Stelle.
//!
//! # Warum die Faelle ASYNCHRON sind
//!
//! `OpfsBlobStore::open` ist der asynchrone Vorlauf, der die Zugriffshandles
//! oeffnet; erst danach ist der Speicher synchron. Ein synchroner Testfall
//! koennte ihn nicht abwarten — genau die Naht, die
//! `crates/ea-reader-wasm/src/opfs_worker.rs` beschreibt. `put`, `get`,
//! `delete` und `keys` stehen in den ersten beiden Faellen bewusst OHNE
//! `await` da: dass sie es nicht brauchen, IST die Zusage dieses Zeugen.
//!
//! # Die zwei Faelle ueber die ECHTEN Ausfuhren
//!
//! `a_second_request_on_the_same_key_waits_instead_of_being_refused` und
//! `overlapping_writes_on_distinct_keys_both_succeed` greifen NICHT zu
//! `OpfsBlobStore`, sondern zu
//! `ea_reader_wasm::bridge::{blob_put, blob_get}` — den Funktionen, die
//! `wasm_bindgen` nach JavaScript ausfuehrt —, und sie treiben sie ueber
//! `wasm_bindgen_futures::future_to_promise`. Das ist keine Nachbildung,
//! sondern der Weg selbst: das Attributmakro uebersetzt eine `async fn` GENAU
//! ueber `future_to_promise` in ein JS-`Promise`. Was hier laeuft, ist damit
//! der Aufbau, den `apps/web/src/bridge/opfs-worker.ts` erzeugt.

use ea_reader::{InMemoryReaderBlobStore, ReaderBlobKey, ReaderBlobStore};
use ea_reader_wasm::bridge::{blob_get, blob_put};
use ea_reader_wasm::opfs_worker::{OpfsBlobStore, blob_key_queue_is_open};
use js_sys::Promise;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::DedicatedWorkerGlobalScope;

// IM DEDIZIERTEN WORKER und nirgends sonst: `FileSystemSyncAccessHandle`
// existiert auf dem Hauptthread nicht. Eine Implementierung dort bestuende jeden
// Wirtstest und fiele erst im Browser.
wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Der Namensraum der Zeugen — ein Verzeichnis unter der OPFS-Wurzel und nicht
/// die Wurzel selbst, damit kein Lauf Fremdes trifft.
const NAMESPACE: &str = "ea-reader-test";

/// Die Bytefolge traegt eine 0, ein 0xff und ASCII: sie faellt an jeder Stelle
/// auf, die Bytes fuer Text haelt oder am Nullbyte abschneidet.
const OPAQUE: &[u8] = b"\x00\xff\x00opaque";

#[wasm_bindgen_test]
async fn opfs_round_trips_the_same_bytes_the_in_memory_double_does() {
    let key = ReaderBlobKey::new("probe/opaque").unwrap();
    let mut opfs = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("OPFS must be reachable");
    // Das Doppel laeuft Schritt fuer Schritt MIT: der Zeuge vergleicht nicht
    // gegen erwartete Werte, die jemand aufgeschrieben hat, sondern gegen den
    // Port selbst, wie ihn `cargo test -p ea-reader` ohne Browser sieht.
    let mut double = InMemoryReaderBlobStore::new();

    assert_eq!(opfs.get(&key).unwrap(), double.get(&key).unwrap());

    opfs.put(&key, OPAQUE).unwrap();
    double.put(&key, OPAQUE).unwrap();
    assert_eq!(opfs.get(&key).unwrap().as_deref(), Some(OPAQUE));
    assert_eq!(opfs.get(&key).unwrap(), double.get(&key).unwrap());
    assert_eq!(opfs.keys().unwrap(), double.keys().unwrap());

    opfs.delete(&key).unwrap();
    double.delete(&key).unwrap();
    assert_eq!(opfs.get(&key).unwrap(), None);
    assert_eq!(opfs.get(&key).unwrap(), double.get(&key).unwrap());
    assert_eq!(opfs.keys().unwrap(), double.keys().unwrap());
}

/// Der Zeuge gegen den stillen Rueckfall in den Arbeitsspeicher.
///
/// Ein Speicher, der die Bytes in einer `BTreeMap` neben sich haelt, bestuende
/// den Rundlauf oben vollstaendig. Er faellt HIER: der erste Speicher wird
/// GESCHLOSSEN — `drop` gibt die Zugriffshandles zurueck —, und der zweite
/// oeffnet dieselbe Datei neu. Was der zweite liest, kann nur von der Platte
/// kommen.
#[wasm_bindgen_test]
async fn bytes_survive_a_store_that_is_dropped_and_opened_again() {
    let key = ReaderBlobKey::new("probe/persisted").unwrap();

    let mut first = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("OPFS must be reachable");
    first.put(&key, OPAQUE).unwrap();
    drop(first);

    let mut second = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("the namespace must reopen after the first store closed its handles");
    assert_eq!(second.get(&key).unwrap().as_deref(), Some(OPAQUE));

    // Und die Loeschung ueberlebt genauso: sonst kaeme der Blob nach einem
    // Neustart des Workers zurueck.
    second.delete(&key).unwrap();
    drop(second);

    let third = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("the namespace must reopen a third time");
    assert_eq!(third.get(&key).unwrap(), None);
}

/// Wartet EINE Makrotask ab.
///
/// `setTimeout(…, 0)` und kein `Promise.resolve()`: eine Mikrotask liefe noch
/// im selben Tick, waehrend die gemessene Form des Befundes GENAU ZWEI
/// `message`-Ereignisse war — und ein `message`-Ereignis ist eine Makrotask.
/// Der Zeuge stellt also die Verschraenkung nach, die im Browser wirklich
/// entsteht, und nicht die schaerfste denkbare.
async fn one_macrotask() {
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("the witness runs in a dedicated worker");
    let timeout = Promise::new(&mut |resolve, _reject| {
        scope
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 0)
            .expect("setTimeout must be available in a dedicated worker");
    });
    JsFuture::from(timeout)
        .await
        .expect("a setTimeout promise resolves");
}

/// Der Zeuge gegen zwei ueberlappende Anfragen auf DEMSELBEN Schluessel.
///
/// Die Form ist die GEMESSENE: zwei Anfragen ueber die echten Ausfuhren, die
/// zweite eine MAKROTASK spaeter. Genau diese Verschraenkung erzeugt
/// `apps/web/src/bridge/opfs-worker.ts`, seit sein Nachrichtenhandler `async`
/// ist — jedes `message`-Ereignis haengt ein eigenes `ready.then(...)` an,
/// ohne Kette zum vorigen.
///
/// Ohne die Warteschlange in `crates/ea-reader-wasm/src/opfs_worker.rs`
/// SETZEN beide Futures ihr `createSyncAccessHandle()` ab, bevor eines der
/// zwei Promises erfuellt ist, und der Verlierer wird abgewiesen. GEMESSEN
/// gegen den unkorrigierten Stand, woertlich:
/// `get outcome: Err(JsValue("EA-READER-BLOB-HOST"))`.
///
/// Geprueft wird MEHR als die Abwesenheit des Fehlers: das `get` muss die
/// Bytes des `put` sehen. Eine Warteschlange, die zwar niemanden abweist,
/// aber die Ordnung aufgibt, faellt an dieser Zeile.
#[wasm_bindgen_test]
async fn a_second_request_on_the_same_key_waits_instead_of_being_refused() {
    const KEY: &str = "probe/overlapping";

    let put = future_to_promise(async {
        blob_put(KEY.to_owned(), OPAQUE.to_vec())
            .await
            .map(|()| JsValue::from_str("put:ok"))
    });
    one_macrotask().await;
    let get = future_to_promise(async {
        blob_get(KEY.to_owned()).await.map(|found| {
            JsValue::from_str(match found.as_deref() {
                Some(OPAQUE) => "get:ok",
                Some(_) => "get:other",
                None => "get:none",
            })
        })
    });

    let put = JsFuture::from(put).await;
    let get = JsFuture::from(get).await;
    assert_eq!(
        put.as_ref().ok().and_then(JsValue::as_string).as_deref(),
        Some("put:ok"),
        "put outcome: {put:?}"
    );
    assert_eq!(
        get.as_ref().ok().and_then(JsValue::as_string).as_deref(),
        Some("get:ok"),
        "get outcome: {get:?}"
    );
}

/// Die Gegenprobe, die die SCHWAECHERE Sperre traegt.
///
/// Derselbe ueberlappende Aufbau auf ZWEI verschiedenen Schluesseln lief schon
/// OHNE jede Warteschlange gruen. GEMESSEN im selben Lauf, in dem der Fall
/// darueber gegen den unkorrigierten Stand rot wurde, woertlich:
/// `test overlapping_writes_on_distinct_keys_both_succeed ... ok`. Ein
/// `FileSystemSyncAccessHandle` sperrt PRO DATEI, also darf die Sperre je
/// Schluessel gelten und nicht global.
///
/// Was dieser Fall festhaelt, ist deshalb NICHT „eine globale Sperre faellt
/// hier rot" — sie faellt es nicht, sie serialisierte nur unnoetig. Er haelt
/// fest, dass die Warteschlange je Schluessel zwei verschiedene Schluessel
/// weder ueberkreuz blockiert noch verklemmt, und er bewahrt die Messung, mit
/// der die schwaechere Sperre gewaehlt wurde.
#[wasm_bindgen_test]
async fn overlapping_writes_on_distinct_keys_both_succeed() {
    let first = future_to_promise(async {
        blob_put("probe/distinct-a".to_owned(), OPAQUE.to_vec())
            .await
            .map(|()| JsValue::from_str("put:ok"))
    });
    one_macrotask().await;
    let second = future_to_promise(async {
        blob_put("probe/distinct-b".to_owned(), OPAQUE.to_vec())
            .await
            .map(|()| JsValue::from_str("put:ok"))
    });

    let first = JsFuture::from(first).await;
    let second = JsFuture::from(second).await;
    assert!(first.is_ok(), "first outcome: {first:?}");
    assert!(second.is_ok(), "second outcome: {second:?}");
}

/// Der Zeuge gegen das LECK in der Warteschlangenablage.
///
/// Die Ablage traegt einen Eintrag je Schluessel, der gerade jemanden warten
/// laesst. Wuerde der Eintrag nach dem letzten Halter stehenbleiben, waechse
/// sie in einem lange laufenden Worker mit jedem jemals beruehrten Schluessel
/// mit — und JEDER Zeuge oben bliebe davon gruen. Deshalb dieser hier: der
/// Eintrag entsteht mit dem Speicher und faellt mit ihm.
///
/// Gefragt wird nach EINEM Schluessel und nicht nach der Groesse der Ablage,
/// weil `wasm-bindgen-test` seine Faelle nebenlaeufig faehrt; der Schluessel
/// dieses Falls kommt in keinem anderen vor.
#[wasm_bindgen_test]
async fn a_closed_store_leaves_no_queue_entry_behind() {
    let key = ReaderBlobKey::new("probe/no-leak").unwrap();
    assert!(
        !blob_key_queue_is_open(&key),
        "no store holds this key before the case starts"
    );

    let store = OpfsBlobStore::open(NAMESPACE, std::slice::from_ref(&key))
        .await
        .expect("OPFS must be reachable");
    assert!(
        blob_key_queue_is_open(&key),
        "an open store must hold its turn"
    );

    drop(store);
    assert!(
        !blob_key_queue_is_open(&key),
        "a closed store must leave no queue entry behind"
    );
}
