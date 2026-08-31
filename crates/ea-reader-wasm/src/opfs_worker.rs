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
//! Ein Rueckfall in den Arbeitsspeicher ist AUSGESCHLOSSEN, und zwar an jeder
//! einzelnen Stelle: es gibt in diesem Modul keine Bytefolge, die einen
//! Aufruf ueberlebt. Was nicht durch ein `FileSystemSyncAccessHandle` geht,
//! geht gar nicht — ein Speicher, der heimlich im Arbeitsspeicher landet, sieht
//! in jedem Test gruen aus und verliert im Browser Daten.

use std::collections::BTreeMap;

use ea_reader::{ReaderBlobError, ReaderBlobKey, ReaderBlobStore};
use js_sys::{Promise, Reflect};
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
    /// # Errors
    /// `EA-READER-BLOB-HOST`, wenn der Aufruf nicht in einem dedizierten
    /// Worker steht oder der Wirtspeicher nicht antwortet.
    pub async fn open(directory: &str, keys: &[ReaderBlobKey]) -> Result<Self, ReaderBlobError> {
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
        // Der Speicher waechst IN SICH und nicht in einer freien Sammlung, die
        // erst am Ende hineinwandert: faellt das dritte `open_handle`, schliesst
        // das `?` ueber `Drop` die zwei bereits offenen Handles. Eine
        // Zwischensammlung liesse sie als Dateisperren zurueck, und der
        // naechste Versuch faende `NoModificationAllowedError` vor.
        let mut store = Self {
            handles: BTreeMap::new(),
        };
        for key in keys {
            if store.handles.contains_key(key) {
                continue;
            }
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
