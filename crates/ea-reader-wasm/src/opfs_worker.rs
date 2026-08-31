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
//! # Die offene Naht: SYNCHRONER Port, ASYNCHRONE Flaeche
//!
//! [`settle`] traegt die Begruendung. Kurz: `getDirectory()`,
//! `getFileHandle()` und `createSyncAccessHandle()` liefern alle drei ein
//! Promise, waehrend `ea_reader::ReaderBlobStore` synchron ist. Ein dedizierter
//! Worker kann darauf nicht blockierend warten.

use ea_reader::{ReaderBlobError, ReaderBlobKey, ReaderBlobStore};
use js_sys::{Array, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{
    DedicatedWorkerGlobalScope, FileSystemDirectoryHandle, FileSystemFileHandle,
    FileSystemGetDirectoryOptions, FileSystemGetFileOptions, FileSystemSyncAccessHandle,
};

/// Der DOMException-Name, den OPFS fuer einen fehlenden Eintrag benutzt.
///
/// Er wird gelesen und nicht der ganze Fehler verworfen: ein fehlender Blob ist
/// `Ok(None)`, eine verweigerte Berechtigung oder eine volle Platte ist ein
/// Fehlschlag. Wer beides zusammenwirft, meldet einen leeren Speicher, wo der
/// Speicher nur nicht antwortet.
const NOT_FOUND_ERROR: &str = "NotFoundError";

/// Baut einen Wirtsfehler mit einem Text, der KEINEN Schluessel nennt.
///
/// Ein Ablagepfad im Fehlertext waere ein Leck ueber die Bruecke hinaus;
/// `ReaderBlobError::code` liefert nach aussen ohnehin nur
/// `EA-READER-BLOB-HOST`.
fn host(reason: &str) -> ReaderBlobError {
    ReaderBlobError::Host(reason.to_owned())
}

/// Wartet auf ein Promise — und kann es nicht.
///
/// # Hier gehen Port und Flaeche auseinander, und das steht offen statt versteckt
///
/// `ea_reader::ReaderBlobStore` ist SYNCHRON: `put`, `get`, `delete` und `keys`
/// geben ein `Result` und keinen Future zurueck. Die OPFS-Flaeche ist es an
/// jedem Einstieg NICHT — GEMESSEN an `web-sys 0.3.103`:
/// `StorageManager::get_directory`, `FileSystemDirectoryHandle::get_file_handle`
/// und `FileSystemFileHandle::create_sync_access_handle` liefern alle drei
/// `js_sys::Promise`. Synchron ist erst, was das fertige
/// `FileSystemSyncAccessHandle` kann.
///
/// Blockierend warten geht nicht: `Atomics.wait` haelt genau den Faden an,
/// dessen Ereignisschleife das Promise erfuellen muesste — der Worker liefe in
/// seinen eigenen Stillstand.
///
/// Die bekannte Aufloesung ist die von SQLites `opfs-sahpool`: EIN
/// asynchroner Vorlauf oeffnet die Zugriffshandles, danach bedient der Speicher
/// synchron. Sie verlangt ein `async fn open`, und die gehoert dem Task, der
/// den Browserlauf besitzt — dieser hier baut die Flaeche und faehrt sie nicht.
/// Bis dahin schlaegt der Zugriff FEHL statt still etwas anderes zu tun: ein
/// Speicher, der heimlich im Arbeitsspeicher landet, sieht in jedem Test gruen
/// aus und verliert im Browser Daten.
fn settle(promise: &Promise) -> Result<JsValue, ReaderBlobError> {
    let _ = promise;
    Err(host(
        "the synchronous ReaderBlobStore cannot await an OPFS promise; \
         an asynchronous open() must pre-open the sync access handles first",
    ))
}

/// Liest den Namen einer DOMException, ohne ihren Text zu uebernehmen.
fn error_name(error: &JsValue) -> Option<String> {
    Reflect::get(error, &JsValue::from_str("name"))
        .ok()
        .and_then(|name| name.as_string())
}

/// Der Speicher des Readers auf OPFS.
///
/// Er haelt das Wurzelverzeichnis seines Namensraums. Alles Weitere wird je
/// Zugriff aufgeloest: ein Schluessel ist ein Pfad, und seine Segmente sind
/// Verzeichnisse — OPFS-Dateinamen duerfen kein `/` tragen.
#[derive(Debug)]
pub struct OpfsBlobStore {
    directory: FileSystemDirectoryHandle,
}

impl OpfsBlobStore {
    /// Oeffnet — bzw. legt an — den Namensraum `directory` unterhalb der
    /// OPFS-Wurzel.
    ///
    /// Der Namensraum ist ein Verzeichnis und nicht die Wurzel selbst: der
    /// Reader teilt OPFS mit allem anderen, was dieselbe Herkunft ablegt, und
    /// ein Zeuge, der die Wurzel leerraeumte, traefe Fremdes.
    ///
    /// # Errors
    /// `EA-READER-BLOB-HOST`, wenn der Aufruf nicht in einem dedizierten
    /// Worker steht oder der Wirtspeicher nicht antwortet.
    pub fn open(directory: &str) -> Result<Self, ReaderBlobError> {
        let scope = js_sys::global()
            .dyn_into::<DedicatedWorkerGlobalScope>()
            .map_err(|_| {
                host(
                    "OPFS sync access handles exist only in a dedicated worker; \
                     this call did not run in one",
                )
            })?;
        let root = settle(&scope.navigator().storage().get_directory())?
            .dyn_into::<FileSystemDirectoryHandle>()
            .map_err(|_| host("navigator.storage.getDirectory() did not yield a directory"))?;
        let directory = directory_child(&root, directory, true)?
            .ok_or_else(|| host("the reader namespace directory was not created"))?;
        Ok(Self { directory })
    }

    /// Loest die Verzeichnissegmente eines Schluessels auf und gibt zusaetzlich
    /// den Dateinamen zurueck.
    fn resolve(
        &self,
        key: &ReaderBlobKey,
        create: bool,
    ) -> Result<Option<(FileSystemDirectoryHandle, String)>, ReaderBlobError> {
        let mut segments: Vec<&str> = key.as_str().split('/').collect();
        let file = segments
            .pop()
            .ok_or_else(|| host("a blob key must end in a file segment"))?
            .to_owned();
        let mut current = self.directory.clone();
        for segment in segments {
            match directory_child(&current, segment, create)? {
                Some(child) => current = child,
                None => return Ok(None),
            }
        }
        Ok(Some((current, file)))
    }

    /// Oeffnet den SYNCHRONEN Zugriff auf eine Datei des Namensraums.
    fn access(
        &self,
        key: &ReaderBlobKey,
        create: bool,
    ) -> Result<Option<FileSystemSyncAccessHandle>, ReaderBlobError> {
        let Some((directory, name)) = self.resolve(key, create)? else {
            return Ok(None);
        };
        let options = FileSystemGetFileOptions::new();
        options.set_create(create);
        let handle = match settle(&directory.get_file_handle_with_options(&name, &options)) {
            Ok(value) => value,
            Err(error) => return absent_or(error, create),
        };
        let handle = handle
            .dyn_into::<FileSystemFileHandle>()
            .map_err(|_| host("getFileHandle() did not yield a file handle"))?;
        settle(&handle.create_sync_access_handle())?
            .dyn_into::<FileSystemSyncAccessHandle>()
            .map(Some)
            .map_err(|_| host("createSyncAccessHandle() did not yield a sync access handle"))
    }
}

/// Ein Kindverzeichnis, angelegt oder gesucht.
///
/// `Ok(None)` heisst „gibt es nicht" und ist nur ohne `create` moeglich.
fn directory_child(
    parent: &FileSystemDirectoryHandle,
    name: &str,
    create: bool,
) -> Result<Option<FileSystemDirectoryHandle>, ReaderBlobError> {
    let options = FileSystemGetDirectoryOptions::new();
    options.set_create(create);
    let child = match settle(&parent.get_directory_handle_with_options(name, &options)) {
        Ok(value) => value,
        Err(error) => return absent_or(error, create),
    };
    child
        .dyn_into::<FileSystemDirectoryHandle>()
        .map(Some)
        .map_err(|_| host("getDirectoryHandle() did not yield a directory handle"))
}

/// Uebersetzt einen Fehlschlag in „nicht vorhanden", WENN er das sagt.
///
/// Mit `create` kann ein fehlender Eintrag nicht die Ursache sein; dann bleibt
/// jeder Fehlschlag ein Fehlschlag.
fn absent_or<T>(error: ReaderBlobError, create: bool) -> Result<Option<T>, ReaderBlobError> {
    let absent = !create
        && match &error {
            ReaderBlobError::Host(reason) => reason == NOT_FOUND_ERROR,
            ReaderBlobError::Key => false,
        };
    if absent { Ok(None) } else { Err(error) }
}

/// Uebersetzt einen JS-Fehlschlag in einen Speicherfehler und behaelt den
/// DOMException-Namen — er ist das einzige, was [`absent_or`] auswerten kann.
fn from_js(error: &JsValue) -> ReaderBlobError {
    match error_name(error) {
        Some(name) => ReaderBlobError::Host(name),
        None => host("the host storage rejected the access without naming a reason"),
    }
}

impl ReaderBlobStore for OpfsBlobStore {
    fn put(&mut self, key: &ReaderBlobKey, bytes: &[u8]) -> Result<(), ReaderBlobError> {
        let handle = self
            .access(key, true)?
            .ok_or_else(|| host("the blob file was not created"))?;
        // Kuerzen VOR dem Schreiben: `write` ueberschreibt ab Offset 0, laesst
        // einen laengeren Vorgaengerinhalt aber stehen, und der Rest waere
        // danach fremdes Chiffrat am Ende desselben Blobs.
        let outcome = handle
            .truncate_with_u32(0)
            .map_err(|error| from_js(&error))
            .and_then(|()| {
                handle
                    .write_with_u8_array(bytes)
                    .map_err(|error| from_js(&error))
            })
            .and_then(|_| handle.flush().map_err(|error| from_js(&error)));
        // `close()` in JEDEM Fall: ein offener Zugriffshandle sperrt die Datei
        // fuer jeden weiteren Zugriff derselben Herkunft.
        handle.close();
        outcome
    }

    fn get(&self, key: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError> {
        let Some(handle) = self.access(key, false)? else {
            return Ok(None);
        };
        let outcome = handle
            .get_size()
            .map_err(|error| from_js(&error))
            .and_then(|size| {
                let mut bytes = vec![0_u8; size as usize];
                handle
                    .read_with_u8_array(&mut bytes)
                    .map_err(|error| from_js(&error))?;
                Ok(bytes)
            });
        handle.close();
        outcome.map(Some)
    }

    fn delete(&mut self, key: &ReaderBlobKey) -> Result<(), ReaderBlobError> {
        let Some((directory, name)) = self.resolve(key, false)? else {
            return Ok(());
        };
        match settle(&directory.remove_entry(&name)) {
            Ok(_) => Ok(()),
            Err(error) => absent_or::<()>(error, false).map(|_| ()),
        }
    }

    fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError> {
        let mut found = Vec::new();
        collect_keys(&self.directory, "", &mut found)?;
        found.sort();
        Ok(found)
    }
}

/// Laeuft den Verzeichnisbaum ab und sammelt die Schluessel der Dateien.
///
/// Rekursiv, weil ein Schluessel Segmente tragen darf; `prefix` traegt den
/// bisher gelaufenen Pfad, damit der zurueckgegebene Schluessel derselbe ist,
/// mit dem abgelegt wurde.
fn collect_keys(
    directory: &FileSystemDirectoryHandle,
    prefix: &str,
    into: &mut Vec<ReaderBlobKey>,
) -> Result<(), ReaderBlobError> {
    let iterator = directory.entries();
    loop {
        let step = settle(&iterator.next().map_err(|error| from_js(&error))?)?;
        let done = Reflect::get(&step, &JsValue::from_str("done"))
            .map_err(|error| from_js(&error))?
            .as_bool()
            .unwrap_or(true);
        if done {
            return Ok(());
        }
        let entry = Array::from(
            &Reflect::get(&step, &JsValue::from_str("value")).map_err(|error| from_js(&error))?,
        );
        let name = entry
            .get(0)
            .as_string()
            .ok_or_else(|| host("a directory entry carried no name"))?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let handle = entry.get(1);
        match handle.dyn_into::<FileSystemDirectoryHandle>() {
            Ok(child) => collect_keys(&child, &path, into)?,
            Err(_) => into.push(ReaderBlobKey::new(&path)?),
        }
    }
}
