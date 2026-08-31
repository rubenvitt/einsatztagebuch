//! `ReaderBlobStore` ueber OPFS — IM DEDIZIERTEN WORKER und nirgends sonst.
//!
//! # Warum dieses Modul nicht auf dem Hauptthread stehen darf
//!
//! `FileSystemSyncAccessHandle` — der einzige OPFS-Zugang, dessen Lesen,
//! Schreiben, Kuerzen und Schliessen SYNCHRON ist — existiert ausschliesslich
//! in einem dedizierten Worker. Auf dem Hauptthread gibt es ihn nicht.
//!
//! Das ist die Aussage dieses Moduls, und sie ist eine Warnung: eine
//! Hauptthread-Fassung bestuende JEDEN Wirtstest. Kein `cargo test`, kein
//! `cargo clippy`, kein `cargo check --target wasm32-unknown-unknown` faende
//! daran etwas — sie alle uebersetzen nur, und die Typen von `web-sys` gibt es
//! auf beiden Faeden. Der Fehlschlag kaeme erst im Browser, im Lauf, an der
//! spaetesten und teuersten Stelle. Deshalb steht der Zugriff HIER, in einer
//! Datei, die `crates/ea-reader-wasm/tests/opfs_browser.rs` mit
//! `wasm_bindgen_test_configure!(run_in_dedicated_worker)` und nur so faehrt.
//!
//! # Warum das Modul als Ganzes hinter `cfg(target_arch = "wasm32")` steht
//!
//! Das Tor sitzt an der `mod`-Zeile in `src/lib.rs` und nicht an jedem Item.
//! Das ist hier zulaessig und in `src/bridge.rs` nicht: der Zeuge
//! `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg` liest Text und folgt
//! keinem `mod`, seine Regel gilt aber ausschliesslich fuer
//! `wasm_bindgen`-AUSFUHREN. Dieses Modul hat keine — es ist gewoehnliches
//! Rust ueber `web-sys`-Typen, und die Ausfuhren, die es bedient, stehen in
//! `src/bridge.rs`. Das Attribut steht hier ohne seine Klammern, weil der
//! Zeuge Text liest und eine Erwaehnung nicht von einer Ausfuhr unterscheidet.
//!
//! # SYNCHRONER Port, ASYNCHRONE Flaeche — und wie die Naht geschlossen ist
//!
//! `ea_reader::ReaderBlobStore` ist SYNCHRON: `put`, `get`, `delete` und
//! `keys` geben ein `Result` und keinen Future zurueck. Die OPFS-Flaeche ist es
//! an jedem EINSTIEG nicht — GEMESSEN an `web-sys 0.3.103`:
//! `StorageManager::get_directory`, `FileSystemDirectoryHandle::
//! get_directory_handle_with_options`, `get_file_handle_with_options` und
//! `FileSystemFileHandle::create_sync_access_handle` liefern alle vier ein
//! `js_sys::Promise`. Blockierend warten geht nicht: `Atomics.wait` haelt genau
//! den Faden an, dessen Ereignisschleife das Promise erfuellen muesste — der
//! Worker liefe in seinen eigenen Stillstand.
//!
//! Die Aufloesung ist die von SQLites `opfs-sahpool`: EIN asynchroner Vorlauf
//! ([`OpfsBlobStore::open`]) oeffnet die Zugriffshandles, danach bedient der
//! Speicher synchron. Ein einmal geoeffnetes `FileSystemSyncAccessHandle` kann
//! `read`, `write`, `truncate`, `getSize` und `flush` vollstaendig ohne
//! Promise; ab da liegt kein asynchroner Aufruf mehr im Weg.
//!
//! # Die Einschraenkung, die daraus folgt — ausgeschrieben statt versteckt
//!
//! Der Vorlauf braucht die Schluessel, BEVOR er laeuft. `OpfsBlobStore::open`
//! nimmt sie deshalb als Argument, und die vier Traitmethoden bedienen
//! ausschliesslich diese Menge; ein Zugriff auf einen nicht vorgelaufenen
//! Schluessel faellt mit `EA-READER-BLOB-HOST` statt still etwas anderes zu
//! tun. Die volle `opfs-sahpool`-Form — ein Vorrat anonymer, vorab geoeffneter
//! Slots samt Schluesselzuordnung im Dateikopf — braucht diese Stufe nicht:
//! „Dieser Task legt das Fundament und keine Reader-Funktion." Der Aufrufer,
//! der heute existiert, ist `src/bridge.rs`, und der kennt seinen Schluessel je
//! Nachricht. Wer spaeter ueber einen unbekannten Schluessel schreiben will,
//! hebt hier auf den Slotvorrat — die Traitmethoden bleiben davon unberuehrt,
//! weil sie schon heute nur auf offenen Handles rechnen.
//!
//! # Warum ein zweiter Zugriff auf DENSELBEN Schluessel WARTET
//!
//! Dass `createSyncAccessHandle()` seine Datei EXKLUSIV sperrt, steht unten
//! schon zweimal — an [`OpfsBlobStore::open`] und an seinem [`Drop`] —, dort
//! aber nur fuer den NACHEINANDER laufenden Fall. Der Fall, den dieser
//! Abschnitt loest, ist der UEBERLAPPENDE: `crates/ea-reader-wasm/src/bridge.rs`
//! oeffnet je Aufruf von `blobPut`/`blobGet` einen eigenen Speicher, und der
//! Worker-Einstieg `apps/web/src/bridge/opfs-worker.ts` haengt je
//! `message`-Ereignis ein eigenes `ready.then(...)` an, ohne Kette zum vorigen.
//! Zwei Nachrichten auf denselben Schluessel SETZEN dann beide ihr
//! `createSyncAccessHandle()` ab, bevor eines der zwei Promises erfuellt ist.
//! Niemand haelt dabei einen lebenden Speicher ueber ein `await` — es genuegt,
//! dass die zwei Anfragen abgesetzt sind —, und der Verlierer bekam
//! `EA-READER-BLOB-HOST`: eine GUELTIGE Anfrage, mit einem Wirtsfehler
//! beantwortet. GEMESSEN in Headless-Chromium, zwei Anfragen auf einen
//! Schluessel, die zweite eine Makrotask spaeter:
//! `get outcome: Err(JsValue("EA-READER-BLOB-HOST"))`.
//!
//! [`OpfsBlobStore::open`] nimmt deshalb je Schluessel einen PLATZ IN EINER
//! WARTESCHLANGE, bevor es irgendein Handle oeffnet, und gibt ihn erst frei,
//! wenn `Drop` die Handles geschlossen hat. Der Verlierer WARTET damit, statt
//! abgewiesen zu werden.
//!
//! Drei Entscheidungen daran sind gemessen und keine Geschmacksfragen:
//!
//! 1. **Die Regel steht in Rust und nicht im TypeScript-Worker.** Der Plan
//!    sagt ueber `opfs-worker.ts` woertlich: „er enthaelt keine Entscheidung,
//!    nur Zustellung", und die Global Constraints lassen TypeScript „no
//!    security decision" ausfuehren. Eine Serialisierungsregel IST eine
//!    Entscheidung. Sie steht hier ausserdem dort, wo ein Zeuge dieser Stufe
//!    sie ERREICHT: `crates/ea-reader-wasm/tests/opfs_browser.rs` faehrt sie
//!    im Browser. Eine Kette im Worker faenge kein Zeuge dieser Stufe — genau
//!    die Luecke, in der der Fehler entstanden ist.
//! 2. **Je Schluessel und NICHT global.** Ein `FileSystemSyncAccessHandle`
//!    sperrt PRO DATEI. GEMESSEN: derselbe ueberlappende Aufbau auf ZWEI
//!    verschiedenen Schluesseln lief schon OHNE jede Warteschlange gruen
//!    durch. Eine globale Sperre serialisierte also Zugriffe, die der Wirt
//!    nebeneinander erlaubt; die schwaechere Sperre traegt.
//! 3. **Eine asynchrone Warteschlange und KEIN `std::sync::Mutex`.** Der
//!    Worker ist einfaedig, und die Futures laufen auf EINER Ereignisschleife.
//!    Ein blockierendes Schloss hielte genau den Faden an, dessen
//!    Ereignisschleife das Promise des Vorgaengers erfuellen muss — derselbe
//!    Stillstand, den dieser Modulkopf oben fuer `Atomics.wait` beschreibt.
//!
//! Ein Rueckfall in den Arbeitsspeicher ist AUSGESCHLOSSEN, und zwar an jeder
//! einzelnen Stelle: es gibt in diesem Modul keine Bytefolge, die einen
//! Aufruf ueberlebt. Was nicht durch ein `FileSystemSyncAccessHandle` geht,
//! geht gar nicht — ein Speicher, der heimlich im Arbeitsspeicher landet, sieht
//! in jedem Test gruen aus und verliert im Browser Daten.

use std::cell::RefCell;
use std::collections::{BTreeMap, btree_map::Entry};

use ea_reader::{ReaderBlobError, ReaderBlobKey, ReaderBlobStore};
use js_sys::{Function, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    DedicatedWorkerGlobalScope, FileSystemDirectoryHandle, FileSystemFileHandle,
    FileSystemGetDirectoryOptions, FileSystemGetFileOptions, FileSystemReadWriteOptions,
    FileSystemSyncAccessHandle,
};

/// Das erste Byte jeder BELEGTEN Blobdatei.
///
/// Die Anwesenheit eines Blobs steht damit AUF DER PLATTE und nicht in einer
/// Nebenbuchhaltung im Arbeitsspeicher. Ohne dieses Byte waere die Groesse 0
/// zweideutig — ein geloeschter Blob und ein abgelegter LEERER Blob saehen
/// gleich aus —, und `get` muesste raten. Mit ihm gilt: Groesse 0 heisst
/// abwesend, Groesse >= 1 heisst vorhanden mit `len - 1` Nutzbyte.
const PRESENT_MARKER: u8 = 0x01;

/// Baut einen Wirtsfehler mit einem Text, der KEINEN Schluessel nennt.
///
/// Ein Ablagepfad im Fehlertext waere ein Leck ueber die Bruecke hinaus;
/// `ReaderBlobError::code` liefert nach aussen ohnehin nur
/// `EA-READER-BLOB-HOST`.
fn host(reason: &str) -> ReaderBlobError {
    ReaderBlobError::Host(reason.to_owned())
}

/// Liest den Namen einer DOMException, ohne ihren Text zu uebernehmen.
///
/// Der Name („NotFoundError", „NoModificationAllowedError", …) sagt, WAS der
/// Wirt abgewiesen hat, und traegt anders als `message` keinen Pfad.
fn error_name(error: &JsValue) -> Option<String> {
    Reflect::get(error, &JsValue::from_str("name"))
        .ok()
        .and_then(|name| name.as_string())
}

/// Uebersetzt einen JS-Fehlschlag in einen Speicherfehler.
fn from_js(error: &JsValue) -> ReaderBlobError {
    match error_name(error) {
        Some(name) => ReaderBlobError::Host(name),
        None => host("the host storage rejected the access without naming a reason"),
    }
}

/// Wartet ein OPFS-Promise ab — der EINE Ort, an dem dieses Modul asynchron ist.
///
/// `JsFuture` kommt aus `wasm-bindgen-futures`, der Crate der in ADR 0005
/// ratifizierten Browser-Laufzeitklasse. Die Kante kostet nichts Zusaetzliches:
/// `crates/ea-reader-wasm/Cargo.toml` muss sie ohnehin fuehren, weil das
/// Attributmakro `wasm_bindgen` die asynchronen Ausfuhren in `src/bridge.rs`
/// ueber `wasm_bindgen_futures::future_to_promise` uebersetzt. Der Makroname
/// steht hier OHNE seine Attributklammern, aus demselben Grund wie oben: der
/// Zeuge `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg` liest Text und
/// unterscheidet eine Erwaehnung nicht von einer Ausfuhr — GEMESSEN, die
/// ausgeschriebene Form faerbte ihn an genau dieser Zeile rot.
async fn settle(promise: Promise) -> Result<JsValue, ReaderBlobError> {
    JsFuture::from(promise)
        .await
        .map_err(|error| from_js(&error))
}

/// Ein Kindverzeichnis, angelegt oder geoeffnet.
///
/// Immer mit `create`: der Vorlauf legt den Namensraum an, wenn es ihn noch
/// nicht gibt. Ein leeres Verzeichnis ist beobachtbar dasselbe wie keines —
/// `get` antwortet in beiden Faellen `Ok(None)`, weil die Anwesenheit am
/// Marker und nicht am Verzeichniseintrag haengt.
async fn directory_child(
    parent: &FileSystemDirectoryHandle,
    name: &str,
) -> Result<FileSystemDirectoryHandle, ReaderBlobError> {
    let options = FileSystemGetDirectoryOptions::new();
    options.set_create(true);
    settle(parent.get_directory_handle_with_options(name, &options))
        .await?
        .dyn_into::<FileSystemDirectoryHandle>()
        .map_err(|_| host("getDirectoryHandle() did not yield a directory handle"))
}

/// Oeffnet den SYNCHRONEN Zugriff auf die Datei EINES Schluessels.
///
/// Die Segmente eines Schluessels sind Verzeichnisse: OPFS-Dateinamen duerfen
/// kein `/` tragen, und `ea_reader::ReaderBlobKey` laesst genau diesen einen
/// Trenner zu.
async fn open_handle(
    namespace: &FileSystemDirectoryHandle,
    key: &ReaderBlobKey,
) -> Result<FileSystemSyncAccessHandle, ReaderBlobError> {
    let mut segments: Vec<&str> = key.as_str().split('/').collect();
    let file = segments
        .pop()
        .ok_or_else(|| host("a blob key must end in a file segment"))?;
    let mut current = namespace.clone();
    for segment in segments {
        current = directory_child(&current, segment).await?;
    }
    let options = FileSystemGetFileOptions::new();
    options.set_create(true);
    let file_handle = settle(current.get_file_handle_with_options(file, &options))
        .await?
        .dyn_into::<FileSystemFileHandle>()
        .map_err(|_| host("getFileHandle() did not yield a file handle"))?;
    settle(file_handle.create_sync_access_handle())
        .await?
        .dyn_into::<FileSystemSyncAccessHandle>()
        .map_err(|_| host("createSyncAccessHandle() did not yield a sync access handle"))
}

/// Ein Lese-/Schreiboffset als `FileSystemReadWriteOptions`.
///
/// Der Offset steht AUSGESCHRIEBEN an jedem Zugriff und wird nicht dem
/// Dateizeiger ueberlassen: `FileSystemSyncAccessHandle` fuehrt einen solchen
/// Zeiger, und `write` ohne `at` schriebe dorthin, wo der letzte Zugriff
/// aufgehoert hat. Ein Speicher, dessen Ablageort vom vorigen Aufruf abhaengt,
/// ist nicht pruefbar.
fn at(offset: f64) -> FileSystemReadWriteOptions {
    // `f64` und nicht `u64`: `set_at` nimmt genau das, was JS kennt, und ein
    // Cast an dieser Stelle waere eine Umrechnung ohne Gegenwert.
    let options = FileSystemReadWriteOptions::new();
    options.set_at(offset);
    options
}

/// Uebersetzt eine JS-Zahl in eine Laenge.
///
/// `getSize`, `read` und `write` geben `f64` zurueck, weil JS keine andere Zahl
/// kennt. Die Schranke steht hier und nicht als blosses `as usize`: ein
/// negativer oder gebrochener Wert waere ein Fehlschlag des Wirts, und ein
/// stiller Cast machte daraus eine falsche Laenge.
fn length(value: f64) -> Result<usize, ReaderBlobError> {
    // Die Obergrenze steht als Literal und nicht als `usize::MAX as f64`: auf
    // `wasm32-unknown-unknown` ist `usize` 32 Bit, und ein Cast der Schranke
    // waere eine zweite, ziel-abhaengige Zahl an derselben Stelle.
    const MAX_LENGTH: f64 = u32::MAX as f64;
    // `contains` und nicht zwei Vergleiche: `cargo clippy --target
    // wasm32-unknown-unknown -p ea-reader-wasm --all-targets -- -D warnings`
    // faellt sonst mit `clippy::manual_range_contains` — GEMESSEN, und die
    // wasm32-Zeile ist die einzige, die diese Datei ueberhaupt sieht.
    if !(0.0..=MAX_LENGTH).contains(&value) || value.fract() != 0.0 {
        return Err(host(
            "the sync access handle reported an implausible length",
        ));
    }
    // Nach den drei Schranken ist der Wert eine ganze Zahl in [0, u32::MAX];
    // der Cast kann weder abschneiden noch das Vorzeichen verlieren.
    Ok(value as usize)
}

// ---------------------------------------------------------------------------
// Die Warteschlange je Schluessel. Begruendet im Modulkopf, Abschnitt
// „Warum ein zweiter Zugriff auf DENSELBEN Schluessel WARTET".
// ---------------------------------------------------------------------------

/// Das Ende der Warteschlange EINES Schluessels.
#[derive(Debug)]
struct KeyQueue {
    /// Das Promise, auf das der NAECHSTE Ankoemmling wartet.
    ///
    /// Es wird erfuellt, sobald der aktuelle Halter seinen [`KeyTurn`] fallen
    /// laesst. Ein `js_sys::Promise` und kein Rust-Kanal: die Crate haelt keine
    /// Kanalkante, und der Warteschritt ist ohnehin ein `JsFuture` — die
    /// Ereignisschleife, die ihn weckt, ist dieselbe, die auch die
    /// OPFS-Promises erfuellt.
    tail: Promise,
    /// Wie viele Aufrufer zwischen Einreihung und Freigabe stehen.
    ///
    /// Der Zaehler ist die AUFRAEUMBEDINGUNG und keine Statistik: bei 0 faellt
    /// der Eintrag. Ohne ihn bliebe je jemals beruehrtem Schluessel ein
    /// Promise in der Ablage stehen — ein Leck, das in jedem Test gruen
    /// aussieht und in einem lange laufenden Worker mitwaechst.
    waiting: usize,
}

thread_local! {
    /// Die Warteschlangen, EINE je Schluessel.
    ///
    /// `thread_local!` und kein `static` hinter einem Schloss: der Worker ist
    /// einfaedig, `Promise` ist nicht `Send`, und zwischen zwei Futures
    /// DERSELBEN Ereignisschleife gibt es nichts zu synchronisieren — nur zu
    /// ordnen.
    ///
    /// Der Schluessel ist eine `String`-Kopie und kein `ReaderBlobKey`: die
    /// Ablage ueberlebt jeden einzelnen Speicher, und ein geliehener
    /// Schluessel koennte das nicht.
    ///
    /// Der `const`-Block ist keine Zierde: `cargo clippy --target
    /// wasm32-unknown-unknown --locked -p ea-reader-wasm --all-targets --
    /// -D warnings` faellt ohne ihn mit
    /// `clippy::missing_const_for_thread_local` — GEMESSEN.
    static BLOB_KEY_QUEUES: RefCell<BTreeMap<String, KeyQueue>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Der Platz EINES Halters in der Warteschlange EINES Schluessels.
///
/// Der Typ ist nur ueber [`Drop`] zu verlassen: solange er lebt, wartet jeder
/// weitere Aufrufer desselben Schluessels.
#[derive(Debug)]
struct KeyTurn {
    /// Der Schluessel, dessen Warteschlange dieser Platz gehoert.
    key: String,
    /// Die `resolve`-Funktion des Promises, auf das der Nachfolger wartet.
    release: Function,
}

impl Drop for KeyTurn {
    /// Raeumt den Platz ab und weckt den Nachfolger.
    fn drop(&mut self) {
        // `take` und nicht `clone`: der Platz ist am Ende, sein Schluessel wird
        // danach nicht mehr gelesen, und `entry` will ihn besitzen.
        let key = std::mem::take(&mut self.key);
        BLOB_KEY_QUEUES.with_borrow_mut(|queues| {
            if let Entry::Occupied(mut occupied) = queues.entry(key) {
                let queue = occupied.get_mut();
                // Kein Unterlauf moeglich: ein `KeyTurn` entsteht
                // ausschliesslich in `enqueue`, wo derselbe Zaehler um genau
                // eins waechst, und faellt genau einmal.
                queue.waiting -= 1;
                if queue.waiting == 0 {
                    occupied.remove();
                }
            }
        });
        // NACH dem Abraeumen und ausserhalb der Ausleihe: `call0` geht nach
        // JavaScript, und eine offene `RefCell`-Ausleihe ueber einen
        // JS-Aufruf hinweg waere die Sorte Panik, die erst im Browser faellt.
        // Der Rueckgabewert ist gleichgueltig — `resolve` gibt `undefined`.
        let _ = self.release.call0(&JsValue::NULL);
    }
}

/// Reiht den Aufrufer in die Warteschlange EINES Schluessels ein.
///
/// Platz und Vorgaenger kommen GETRENNT zurueck, weil der Platz VOR dem Warten
/// entstehen muss: faellt der wartende Future weg, gibt sein `Drop` den
/// Nachfolger frei, statt die Warteschlange fuer immer anzuhalten.
fn enqueue(key: &ReaderBlobKey) -> (KeyTurn, Option<Promise>) {
    let mut release = None;
    // Der Executor von `new Promise` laeuft SYNCHRON (ECMA-262 27.2.3.1);
    // `release` ist unmittelbar nach dem Aufruf besetzt.
    let successor = Promise::new(&mut |resolve, _reject| release = Some(resolve));
    let release = release.expect("the promise executor runs synchronously");
    let predecessor = BLOB_KEY_QUEUES.with_borrow_mut(|queues| {
        match queues.entry(key.as_str().to_owned()) {
            Entry::Occupied(mut occupied) => {
                let queue = occupied.get_mut();
                queue.waiting += 1;
                // Der neue Schwanz ist das Promise DIESES Platzes; abgewartet
                // wird der bisherige.
                Some(std::mem::replace(&mut queue.tail, successor))
            }
            Entry::Vacant(vacant) => {
                vacant.insert(KeyQueue {
                    tail: successor,
                    waiting: 1,
                });
                None
            }
        }
    });
    (
        KeyTurn {
            key: key.as_str().to_owned(),
            release,
        },
        predecessor,
    )
}

/// Ob dieser Schluessel GERADE eine Warteschlange in der Ablage hat.
///
/// Der einzige Zweck ist der Zeuge gegen das LECK: ein Eintrag je Schluessel,
/// der nie entfernt wird, waechst in einem lange laufenden Worker mit und
/// sieht dabei in jedem Test gruen aus. Ohne diesen Blick waere die
/// Aufraeumregel von [`KeyTurn::drop`] eine Behauptung; mit ihm faehrt
/// `a_closed_store_leaves_no_queue_entry_behind` in
/// `crates/ea-reader-wasm/tests/opfs_browser.rs` sie im Browser.
///
/// Die Frage geht ueber EINEN Schluessel und nicht ueber die Groesse der
/// Ablage, und das ist keine Umstaendlichkeit: `wasm-bindgen-test` faehrt
/// seine Faelle NEBENLAEUFIG — GEMESSEN an der Ergebnisreihenfolge, die von
/// der Deklarationsreihenfolge abweicht —, und eine Gesamtzahl saehe die
/// Plaetze der gleichzeitig laufenden Faelle mit.
#[must_use]
pub fn blob_key_queue_is_open(key: &ReaderBlobKey) -> bool {
    BLOB_KEY_QUEUES.with_borrow(|queues| queues.contains_key(key.as_str()))
}

/// Wartet, bis der Schluessel frei ist, und liefert den Platz.
async fn take_turn(key: &ReaderBlobKey) -> KeyTurn {
    let (turn, predecessor) = enqueue(key);
    if let Some(predecessor) = predecessor {
        // Der AUSGANG des Vorgaengers ist gleichgueltig: die Warteschlange
        // ordnet Zugriffe, sie reicht keinen Fehlschlag weiter. Das Promise
        // wird ohnehin nur erfuellt und nie abgewiesen.
        let _ = JsFuture::from(predecessor).await;
    }
    turn
}

/// Der Speicher des Readers auf OPFS.
///
/// Er haelt je Schluessel des Vorlaufs ein OFFENES `FileSystemSyncAccessHandle`
/// — das ist der ganze Zustand. Die Bytes selbst liegen in keiner Sammlung
/// dieses Typs, sondern ausschliesslich in den Dateien dahinter.
///
/// Die Ablage ist eine `BTreeMap` und keine `HashMap`: [`ReaderBlobStore::keys`]
/// sagt die Schluesselordnung zu, und eine Streuordnung faellt in Unit-Tests
/// nicht auf und kippt spaeter den Wiederaufbau des Index sporadisch —
/// dieselbe Begruendung, die `crates/ea-reader/src/blob_store.rs` fuer das
/// Doppel ausschreibt.
#[derive(Debug)]
pub struct OpfsBlobStore {
    handles: BTreeMap<ReaderBlobKey, FileSystemSyncAccessHandle>,
    /// Die Plaetze in den Warteschlangen der Schluessel DIESES Speichers.
    ///
    /// Das Feld steht NACH `handles`, und die Reihenfolge ist tragend: `Drop`
    /// schliesst im Rumpf die Handles, danach fallen die Felder in
    /// DEKLARATIONSREIHENFOLGE. Der Nachfolger wird also erst geweckt, wenn die
    /// Dateien schon freigegeben sind — anders herum faende er sie noch
    /// gesperrt und bekaeme genau den `EA-READER-BLOB-HOST`, den die
    /// Warteschlange verhindern soll.
    turns: Vec<KeyTurn>,
}

impl OpfsBlobStore {
    /// Der ASYNCHRONE Vorlauf: Namensraum oeffnen, Zugriffshandles oeffnen.
    ///
    /// Danach ist der Speicher synchron. `directory` ist ein Verzeichnis
    /// unterhalb der OPFS-Wurzel und nicht die Wurzel selbst: der Reader teilt
    /// OPFS mit allem anderen, was dieselbe Herkunft ablegt, und ein Zeuge, der
    /// die Wurzel leerraeumte, traefe Fremdes.
    ///
    /// `keys` ist die VOLLSTAENDIGE Menge, die der entstehende Speicher
    /// bedienen kann; ein doppelt genannter Schluessel wird einmal geoeffnet,
    /// weil ein zweites `createSyncAccessHandle` auf dieselbe Datei mit
    /// `NoModificationAllowedError` faellt. Eine noch nicht vorhandene Datei
    /// wird LEER angelegt und liest sich als abwesend (Groesse 0) — nach aussen
    /// ist das kein Unterschied.
    ///
    /// # Der Aufruf WARTET, statt an einem fremden Speicher zu scheitern
    ///
    /// Lebt zu einem der Schluessel noch ein anderer `OpfsBlobStore` — auch
    /// einer, der erst in einem anderen, gleichzeitig laufenden Future
    /// entsteht —, haelt dieser Aufruf an, bis jener geschlossen ist. Die
    /// Begruendung samt Messung steht im Modulkopf. Die Kehrseite ist
    /// benannt und nicht versteckt: wer im SELBEN Ablauf einen zweiten
    /// Speicher ueber einen Schluessel oeffnet, den er noch haelt, wartet auf
    /// sich selbst. Vorher bekam er dafuer `EA-READER-BLOB-HOST`; beides ist
    /// ein Programmierfehler, und der einzige Aufrufer, den es gibt
    /// (`crates/ea-reader-wasm/src/bridge.rs`), oeffnet und schliesst je
    /// Nachricht genau einen Speicher.
    ///
    /// # Errors
    /// `EA-READER-BLOB-HOST`, wenn der Aufruf nicht in einem dedizierten
    /// Worker steht oder der Wirtspeicher nicht antwortet.
    pub async fn open(directory: &str, keys: &[ReaderBlobKey]) -> Result<Self, ReaderBlobError> {
        // SORTIERT und ohne Doppel, und beides ist tragend. Die Sortierung
        // gibt allen Aufrufern EINE globale Ordnung, in der sie ihre Plaetze
        // nehmen: zwei Speicher ueber {a, b} und ueber {b, a} warteten sonst
        // ueberkreuz aufeinander, und der Worker stuende still. Das Entdoppeln
        // ersetzt den frueheren `contains_key`-Sprung in der Oeffnungsschleife
        // und verhindert zusaetzlich, dass ein doppelt genannter Schluessel
        // sich selbst in der Warteschlange blockiert.
        let mut ordered = keys.to_vec();
        ordered.sort_unstable();
        ordered.dedup();

        // Der Speicher entsteht VOR dem ersten Warten und waechst in sich:
        // bricht etwas ab, gibt sein `Drop` die schon genommenen Plaetze
        // zurueck. Eine Zwischensammlung liesse den Nachfolger haengen.
        let mut store = Self {
            handles: BTreeMap::new(),
            turns: Vec::with_capacity(ordered.len()),
        };
        // Die Plaetze VOR jeder OPFS-Beruehrung: ab hier liegt der ganze
        // Zugriff dieses Speichers innerhalb seiner Warteschlangenplaetze.
        for key in &ordered {
            store.turns.push(take_turn(key).await);
        }

        let scope = js_sys::global()
            .dyn_into::<DedicatedWorkerGlobalScope>()
            .map_err(|_| {
                host(
                    "OPFS sync access handles exist only in a dedicated worker; \
                     this call did not run in one",
                )
            })?;
        let root = settle(scope.navigator().storage().get_directory())
            .await?
            .dyn_into::<FileSystemDirectoryHandle>()
            .map_err(|_| host("navigator.storage.getDirectory() did not yield a directory"))?;
        let namespace = directory_child(&root, directory).await?;
        // Die Handles wachsen IN den Speicher und nicht in eine freie
        // Sammlung, die erst am Ende hineinwandert: faellt das dritte
        // `open_handle`, schliesst das `?` ueber `Drop` die zwei bereits
        // offenen Handles UND gibt die Warteschlangenplaetze zurueck. Eine
        // Zwischensammlung liesse die Handles als Dateisperren zurueck, und der
        // naechste Versuch faende `NoModificationAllowedError` vor.
        for key in &ordered {
            let handle = open_handle(&namespace, key).await?;
            store.handles.insert(key.clone(), handle);
        }
        Ok(store)
    }

    /// Das offene Handle eines Schluessels — oder der benannte Fehlschlag.
    fn handle(&self, key: &ReaderBlobKey) -> Result<&FileSystemSyncAccessHandle, ReaderBlobError> {
        self.handles.get(key).ok_or_else(|| {
            host(
                "this key was not part of the asynchronous open(); a synchronous store \
                 cannot open a sync access handle after the fact",
            )
        })
    }
}

impl Drop for OpfsBlobStore {
    /// Schliesst JEDES Handle.
    ///
    /// Ein offenes `FileSystemSyncAccessHandle` sperrt seine Datei fuer jeden
    /// weiteren Zugriff derselben Herkunft — auch fuer den naechsten
    /// `OpfsBlobStore::open` im selben Worker. Ohne dieses `Drop` bestuende der
    /// erste Zeuge und der zweite faende `NoModificationAllowedError`.
    ///
    /// Die Warteschlangenplaetze gibt der Rumpf NICHT zurueck, und das ist
    /// Absicht: `turns` faellt als Feld unmittelbar danach, also GARANTIERT
    /// nach diesen `close()`-Aufrufen. Ein Freigeben im Rumpf brauchte
    /// dieselbe Ordnung von Hand und verloere sie beim naechsten Umbau.
    fn drop(&mut self) {
        for handle in self.handles.values() {
            handle.close();
        }
    }
}

impl ReaderBlobStore for OpfsBlobStore {
    fn put(&mut self, key: &ReaderBlobKey, bytes: &[u8]) -> Result<(), ReaderBlobError> {
        let handle = self.handle(key)?;
        let mut framed = Vec::with_capacity(bytes.len() + 1);
        framed.push(PRESENT_MARKER);
        framed.extend_from_slice(bytes);
        // Kuerzen VOR dem Schreiben: `write` ueberschreibt ab dem gegebenen
        // Offset, laesst einen laengeren Vorgaengerinhalt aber stehen, und der
        // Rest waere danach fremdes Chiffrat am Ende desselben Blobs.
        handle
            .truncate_with_u32(0)
            .map_err(|error| from_js(&error))?;
        let written = handle
            .write_with_u8_array_and_options(&framed, &at(0.0))
            .map_err(|error| from_js(&error))?;
        if length(written)? != framed.len() {
            return Err(host(
                "the sync access handle accepted only part of the blob",
            ));
        }
        // `flush` und nicht „irgendwann": erst danach steht der Blob so auf der
        // Platte, dass ihn ein neu geoeffnetes Handle liest.
        handle.flush().map_err(|error| from_js(&error))
    }

    fn get(&self, key: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError> {
        let handle = self.handle(key)?;
        let size = length(handle.get_size().map_err(|error| from_js(&error))?)?;
        if size == 0 {
            return Ok(None);
        }
        let mut framed = vec![0_u8; size];
        let read = handle
            .read_with_u8_array_and_options(&mut framed, &at(0.0))
            .map_err(|error| from_js(&error))?;
        if length(read)? != size {
            return Err(host("the sync access handle returned a short read"));
        }
        match framed.split_first() {
            Some((&PRESENT_MARKER, payload)) => Ok(Some(payload.to_vec())),
            _ => Err(host("the blob file did not carry the presence marker")),
        }
    }

    fn delete(&mut self, key: &ReaderBlobKey) -> Result<(), ReaderBlobError> {
        let handle = self.handle(key)?;
        // Kuerzen auf 0 und NICHT `removeEntry`: das Entfernen des
        // Verzeichniseintrags ist wieder ein Promise, und der Port ist synchron.
        // Die Loeschung ist darum trotzdem echt und ueberlebt einen Neustart —
        // die Datei traegt danach kein Byte, und ohne Marker ist sie abwesend.
        // Was zurueckbleibt, ist ein LEERER Verzeichniseintrag; ihn abzuraeumen
        // gehoert dem Task, der einen asynchronen Aufraeumlauf besitzt.
        handle
            .truncate_with_u32(0)
            .map_err(|error| from_js(&error))?;
        handle.flush().map_err(|error| from_js(&error))
    }

    fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError> {
        // Der Umfang ist die Menge des Vorlaufs — und die Anwesenheit wird je
        // Schluessel AUF DER PLATTE nachgesehen. Ein Verzeichnisdurchlauf waere
        // die vollstaendigere Antwort, ist aber ausgeschlossen: `entries()`
        // liefert einen ASYNCHRONEN Iterator, dessen `next()` ein Promise ist.
        let mut found = Vec::new();
        for (key, handle) in &self.handles {
            if length(handle.get_size().map_err(|error| from_js(&error))?)? > 0 {
                found.push(key.clone());
            }
        }
        // `BTreeMap` laeuft bereits in Schluesselordnung; die Zusage von
        // `keys()` haengt damit an der Sammlung und nicht an einem Sortierruf.
        Ok(found)
    }
}
