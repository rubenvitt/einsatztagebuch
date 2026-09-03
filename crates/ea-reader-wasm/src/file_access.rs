//! Die Bruecke des Datei-Modus: SECHS Ausfuhren, und keine von ihnen rechnet.
//!
//! # Was hinein- und was herausgeht
//!
//! Hinein gehen BYTES und Pfadhinweise, hinaus gehen ein Sitzungsgriff und das
//! GENERIERTE Status-DTO als JSON. Nie ein Bericht als freier Text, nie
//! Schluesselmaterial, nie ein entschluesselter Wert
//! (`web-reader-design.md` §9). Der Fehlerweg ist der der Nachbarausfuhren:
//! der stabile Code und sonst nichts.
//!
//! # Die Bruecke ENTSCHEIDET nicht
//!
//! Sie zaehlt keine Blobs, vergleicht keine Deckel und klassifiziert kein
//! Objekt. Die Blobzahl und die Bytesumme fuehrt
//! `ea_reader::DirectoryHandleSource`, die Klassifikation faehrt
//! `ea_reader::ReaderFileMode` ueber `ReaderVerifier::classify`, und der
//! Wortlaut der Server-Bestaetigung kommt aus `ServerConfirmationV1::label`.
//! Was hier ueberhaupt gerechnet wird, ist das Falten der Objektergebnisse zu
//! EINER archivweiten Spalte — und das steht als reine Funktion daneben, mit
//! zwei Wirtszeugen darunter, weil es die einzige Stelle dieses Moduls ist,
//! die falsch sein koennte.
//!
//! # Warum die Ausfuhren im WORKER laufen
//!
//! `ReaderFileMode` verlangt einen `&UnlockedVault`, und die entsperrten
//! Sitzungen liegen in einem `thread_local!` in [`crate::vault_bridge`] — alle
//! Aufrufe muessen denselben Faden sehen. Die Verzeichnistabelle unten liegt
//! aus demselben Grund daneben und in derselben Bauform.
//!
//! # Und warum es KEINE Uhr gibt
//!
//! Der wirksame Zeitwert kommt als Argument herein, genau wie bei
//! `readerTrustAge` in [`crate::bridge`]. Eine Uhr in diesem Modul waere die
//! zweite Stelle, an der der Reader entscheidet, welcher Augenblick gilt;
//! `ea_reader::ReaderVerifier` reicht den Wert wortwoertlich an
//! `VerifyOptions::new` durch, und Gate `recipient-grant` misst die
//! Nutzungsfrist des eigenen Grants gegen ihn.

use ea_reader::{ObjectResultV1, OpenedArchiveV1, ServerConfirmationV1};

use crate::bridge::Json;

// Jede Einfuhr, die nur der Browserpfad braucht, traegt ihr eigenes cfg: auf
// einem Wirtsziel waere sie unbenutzt, und das Clippy-Gate faellt an einer
// unbenutzten Einfuhr genauso wie an einem echten Fehler.
#[cfg(target_arch = "wasm32")]
use core::cell::{Cell, RefCell};
#[cfg(target_arch = "wasm32")]
use std::collections::BTreeMap;

#[cfg(target_arch = "wasm32")]
use ea_reader::{BUNDLE_FILE_EXTENSION_V1, DirectoryHandleSource, ReaderFileMode, UnixMillis};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::vault_bridge::with_unlocked_vault;

/// Der Code fuer eine Bruecken-Eingabe, die keine Aussage ueber einen Bestand
/// ist.
///
/// Eine unbekannte Sitzungs- oder Ordnerkennung ist ein Fehler des Aufrufers
/// und kein Befund ueber ein Archiv; sie bekommt deshalb einen eigenen Code und
/// nicht einen der Archivcodes, die eine Aussage BEDEUTEN. Dieselbe Trennung
/// und dieselbe Begruendung wie `EA-READER-VAULT-BRIDGE-ARGUMENT` in
/// [`crate::vault_bridge`].
#[cfg(target_arch = "wasm32")]
const BRIDGE_ARGUMENT_CODE: &str = "EA-READER-FILE-MODE-BRIDGE-ARGUMENT";

#[cfg(target_arch = "wasm32")]
thread_local! {
    /// Die angefangenen Verzeichnisquellen dieses Workers.
    ///
    /// Eine Ordnerkennung ist ein `u32` ohne Bedeutung ausserhalb dieses
    /// Moduls. Gaebe die Bruecke stattdessen die Quelle als exportierten Typ
    /// heraus, laege der halbe Bestand im JavaScript-Heap — und der Sinn des
    /// Push-Weges ist gerade, dass die Buchhaltung ueber ihn in Rust bleibt.
    static DIRECTORY_SOURCES: RefCell<BTreeMap<u32, DirectoryHandleSource>> =
        const { RefCell::new(BTreeMap::new()) };
    /// Der Zaehler dieser Tabelle. Monoton und nie wiederverwendet.
    static NEXT_DIRECTORY_HANDLE: Cell<u32> = const { Cell::new(1) };
}

/// Die naechste Ordnerkennung.
#[cfg(target_arch = "wasm32")]
fn next_directory_handle() -> u32 {
    NEXT_DIRECTORY_HANDLE.with(|counter| {
        let handle = counter.get();
        counter.set(handle.wrapping_add(1));
        handle
    })
}

/// Fuehrt eine Rechnung auf einer angefangenen Verzeichnisquelle aus.
///
/// Die Ausleihe wird NIE ueber einen JS-Aufruf hinweg gehalten — dieselbe
/// Regel wie bei den Tresorsitzungen: eine `RefCell`, die waehrend eines
/// Promise offen steht, faellt beim naechsten Ereignis mit einer
/// Doppelausleihe um.
#[cfg(target_arch = "wasm32")]
fn with_directory_source<R>(
    handle: u32,
    use_it: impl FnOnce(&mut DirectoryHandleSource) -> R,
) -> Option<R> {
    DIRECTORY_SOURCES.with(|table| table.borrow_mut().get_mut(&handle).map(use_it))
}

/// Die zwei Bestaetigungsspalten und der EINE archivweite Wert darueber.
///
/// Er steht als eigener Typ und nicht als drei lose Ausdruecke im DTO-Bauer,
/// damit die Faltungsregel unten einen Zeugen bekommen kann. Sie ist die
/// einzige Rechnung dieses Moduls.
struct ConfirmationTally {
    server_confirmed: usize,
    not_server_confirmed: usize,
    archive_wide: ServerConfirmationV1,
}

impl ConfirmationTally {
    /// Faltet die Objektergebnisse zu EINER Spalte.
    ///
    /// Archivweit `ServerConfirmed` NUR, wenn es mindestens ein Ergebnis gibt
    /// UND jedes einzelne den Wert traegt. Der leere Bestand ist deshalb
    /// ausdruecklich NICHT bestaetigt, und das ist eine Entscheidung mit einem
    /// Grund: ein Lauf, der fail-closed an Gate `trust` aussteigt, liefert
    /// einen Bericht mit LEEREN `object_results` — ein blosses `all(..)`
    /// darueber waere wahr, und ausgerechnet der Bestand, ueber den nichts
    /// ausgesagt werden konnte, behauptete die staerkste Spalte.
    ///
    /// Ueber MAENGEL sagt diese Faltung nichts. `notServerConfirmed` ist eine
    /// eigene Dimension neben dem Verifikationsbegriff (`design.md` §17.4) und
    /// senkt `is_fully_verified()` nicht; im Datei-Modus ist es der Regelfall.
    fn over(confirmations: impl Iterator<Item = ServerConfirmationV1>) -> Self {
        let mut server_confirmed = 0_usize;
        let mut not_server_confirmed = 0_usize;
        for confirmation in confirmations {
            match confirmation {
                ServerConfirmationV1::ServerConfirmed => server_confirmed += 1,
                ServerConfirmationV1::NotServerConfirmed => not_server_confirmed += 1,
            }
        }
        let archive_wide = if server_confirmed > 0 && not_server_confirmed == 0 {
            ServerConfirmationV1::ServerConfirmed
        } else {
            ServerConfirmationV1::NotServerConfirmed
        };
        Self {
            server_confirmed,
            not_server_confirmed,
            archive_wide,
        }
    }
}

/// Das Ergebnis EINES Oeffnens als `FileModeArchiveView`.
///
/// Die REINE Haelfte der zwei oeffnenden Ausfuhren: sie uebersetzt auf jedem
/// Ziel und liegt damit neben `bundle_activation_json` in [`crate::bridge`],
/// dessen Bauform sie erbt — derselbe `Json`-Bauer, dieselbe Regel, dass die
/// Bruecke ein DTO formt und nichts entscheidet.
///
/// Jedes der sieben Felder wird GELESEN und keines nachgerechnet:
/// `archiveObjectCount`, `entryPackageCount`, `fullyVerified` und `gapCount`
/// kommen unveraendert aus dem Bericht der neun Gates, die drei
/// Bestaetigungsfelder aus [`ConfirmationTally`], und der Wortlaut aus
/// `ServerConfirmationV1::label` — er hat GENAU EINE Quelle, und die liegt in
/// `ea-verify`.
///
/// `pub` aus demselben Grund wie `bundle_activation_json`: die reine Haelfte
/// bleibt aus einem gewoehnlichen Wirtstest erreichbar, waehrend die zwei
/// Ausfuhren darueber hinter ihrem cfg stehen.
#[must_use]
pub fn file_mode_archive_json(opened: &OpenedArchiveV1) -> String {
    let report = opened.report();
    let tally = ConfirmationTally::over(
        report
            .object_results()
            .map(ObjectResultV1::server_confirmation),
    );

    let mut json = Json::object();
    json.raw(
        "archiveObjectCount",
        &report.archive_object_count().to_string(),
    );
    json.raw(
        "entryPackageCount",
        &report.entry_package_count().to_string(),
    );
    json.bool("fullyVerified", report.is_fully_verified());
    json.raw("gapCount", &report.gaps().len().to_string());
    json.raw("serverConfirmedCount", &tally.server_confirmed.to_string());
    json.raw(
        "notServerConfirmedCount",
        &tally.not_server_confirmed.to_string(),
    );
    json.string("serverConfirmation", tally.archive_wide.label());
    json.finish()
}

// ---------------------------------------------------------------------------
// Die sechs Ausfuhren. JEDE traegt ihr eigenes `cfg(target_arch = "wasm32")`
// unmittelbar ueber ihrem Attribut — `every_wasm_bindgen_export_sits_behind_the
// _wasm32_cfg` liest das als Text und folgt keinem `mod`.
// ---------------------------------------------------------------------------

/// Die Dateiendung, auf die der gewoehnliche Dateidialog filtert.
///
/// Sie kommt aus `ea_archive::BUNDLE_FILE_EXTENSION_V1`, damit `eabundle`
/// nirgends in TypeScript steht. Sie ist ein HINWEIS und keine Entscheidung:
/// klassifiziert wird am 9-Byte-Exact-Object-Praefix beziehungsweise an
/// `BUNDLE_MAGIC_V1`, und eine umbenannte Datei faellt dort und nicht am Namen.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "fileModeBundleExtension")]
#[must_use]
pub fn file_mode_bundle_extension() -> String {
    BUNDLE_FILE_EXTENSION_V1.to_owned()
}

/// Oeffnet die EINE exportierte Datei — der universelle Weg.
///
/// Die Bytes sind BESITZEND und keine Referenz: `ArchiveBundleSource` uebernimmt
/// den Container, und eine zweite Kopie waere an der Obergrenze ein zweites
/// Gibibyte.
///
/// # Errors
/// `EA-READER-FILE-MODE-BRIDGE-ARGUMENT` fuer eine Sitzungskennung, die kein
/// entsperrter Tresor ist, und sonst der stabile Code des Befunds:
/// `EA-BUNDLE-MALFORMED` fuer eine abgeschnittene oder umbenannte Datei, die
/// Codes von `ea-archive` fuer einen Bestand, der sich nicht durchlaufen
/// laesst, und die des Klassifizierers.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "fileModeOpenBundle")]
pub fn file_mode_open_bundle(
    session: u32,
    bytes: Vec<u8>,
    effective_now_ms: i64,
) -> Result<String, JsValue> {
    let opened = with_unlocked_vault(session, move |vault| {
        ReaderFileMode::open_bundle(bytes, vault, UnixMillis::new(effective_now_ms))
    })
    .ok_or_else(|| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?
    .map_err(|error| JsValue::from_str(error.code()))?;
    Ok(file_mode_archive_json(&opened))
}

/// Legt eine leere Verzeichnisquelle an und gibt ihre Kennung zurueck.
///
/// Der Anfang des Komfortweges. Sie traegt die ECHTEN Deckel — welche Zahlen
/// das sind, weiss `ea_reader::DirectoryHandleSource::new` und niemand hier.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "fileModeBeginDirectory")]
#[must_use]
pub fn file_mode_begin_directory() -> u32 {
    let handle = next_directory_handle();
    DIRECTORY_SOURCES.with(|table| {
        table
            .borrow_mut()
            .insert(handle, DirectoryHandleSource::new());
    });
    handle
}

/// Reicht EINE Bytefolge samt ihrem Pfadhinweis ein.
///
/// Einzeln und nicht als Sammlung, weil `DirectoryHandle.ts` den Handle
/// rekursiv ablaeuft und eine Datei nach der anderen liest; ein Sammelaufruf
/// haette den ganzen Bestand ein zweites Mal im JavaScript-Heap gehalten.
///
/// # Errors
/// `EA-READER-FILE-MODE-BRIDGE-ARGUMENT` fuer eine unbekannte Ordnerkennung,
/// und sonst der Deckelcode aus `ea-archive` — `EA-ARCHIVE-BLOB-LIMIT` oder
/// `EA-ARCHIVE-TOTAL-BYTE-LIMIT`, unveraendert durchgereicht. Die Grenzzahlen
/// stehen NICHT hier: `push_blob` setzt sie durch und gibt den Code heraus.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "fileModePushBlob")]
pub fn file_mode_push_blob(handle: u32, path_hint: &str, bytes: &[u8]) -> Result<(), JsValue> {
    with_directory_source(handle, |source| source.push_blob(path_hint, bytes))
        .ok_or_else(|| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?
        .map_err(|error| JsValue::from_str(error.code()))
}

/// Merkt an, dass dem Ordner die Berechtigung entzogen wurde.
///
/// `DirectoryHandle.ts` ruft sie, sobald `queryPermission` beziehungsweise
/// `requestPermission` nicht mehr die Erlaubnis meldet. Der Vermerk wird NICHT
/// zurueckgenommen: ein Ordner, der mitten im Durchlauf aufgehoert hat zu
/// liefern, hat einen unvollstaendigen Bestand hinterlassen, und aus Teilbytes
/// ein Urteil zu bilden ist der Fehler, den `ArchiveError::Unavailable`
/// verhindert.
///
/// # Errors
/// `EA-READER-FILE-MODE-BRIDGE-ARGUMENT` fuer eine unbekannte Ordnerkennung.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "fileModeDirectoryUnavailable")]
pub fn file_mode_directory_unavailable(handle: u32) -> Result<(), JsValue> {
    with_directory_source(handle, DirectoryHandleSource::mark_unavailable)
        .ok_or_else(|| JsValue::from_str(BRIDGE_ARGUMENT_CODE))
}

/// Oeffnet den eingereichten Ordner — der Chromium-Komfortweg.
///
/// Die Quelle wird der Tabelle ENTNOMMEN und nicht geliehen, denn
/// `ReaderFileMode::open_directory` uebernimmt sie. Sie faellt damit auch dann,
/// wenn die Sitzungskennung unbekannt ist, und das ist Absicht: ein Bestand,
/// der schon einmal an einem Tresor vorbeigelaufen ist, den es nicht gibt,
/// wird nicht aufgehoben, sondern neu eingereicht.
///
/// # Errors
/// Wie [`file_mode_open_bundle`], ohne dessen Containercodes: eine unbekannte
/// Sitzungs- oder Ordnerkennung ist
/// `EA-READER-FILE-MODE-BRIDGE-ARGUMENT`, ein Ordner ohne Berechtigung ist
/// `EA-ARCHIVE-UNAVAILABLE`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "fileModeOpenDirectory")]
pub fn file_mode_open_directory(
    session: u32,
    handle: u32,
    effective_now_ms: i64,
) -> Result<String, JsValue> {
    let source = DIRECTORY_SOURCES
        .with(|table| table.borrow_mut().remove(&handle))
        .ok_or_else(|| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?;
    let opened = with_unlocked_vault(session, move |vault| {
        ReaderFileMode::open_directory(source, vault, UnixMillis::new(effective_now_ms))
    })
    .ok_or_else(|| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?
    .map_err(|error| JsValue::from_str(error.code()))?;
    Ok(file_mode_archive_json(&opened))
}

#[cfg(test)]
mod tests {
    use ea_reader::ServerConfirmationV1;

    use super::ConfirmationTally;

    /// Die Faltung ist FAIL-CLOSED, und das ist der Zeuge dafuer.
    ///
    /// Ein Lauf, der an Gate `trust` aussteigt, traegt LEERE `object_results`.
    /// Waere die Regel ein blosses `all(..)`, stuende ausgerechnet ueber diesem
    /// Bestand die staerkste Spalte — obwohl er ueber keinen Eintrag etwas
    /// aussagt.
    #[test]
    fn an_archive_without_a_single_object_result_is_never_server_confirmed() {
        let tally = ConfirmationTally::over(core::iter::empty());
        assert_eq!(tally.server_confirmed, 0);
        assert_eq!(tally.not_server_confirmed, 0);
        assert_eq!(tally.archive_wide, ServerConfirmationV1::NotServerConfirmed);
    }

    /// Ein EINZIGES Objekt ohne Quittung entscheidet die archivweite Spalte.
    ///
    /// Die Gegenkontrolle steht daneben und ist der Grund, aus dem dieser
    /// Zeuge etwas misst: derselbe Bestand ohne das eine Objekt IST
    /// bestaetigt, die Spalte kann also beide Werte annehmen.
    #[test]
    fn one_object_without_a_receipt_decides_the_archive_wide_value() {
        let confirmed = ConfirmationTally::over(
            [
                ServerConfirmationV1::ServerConfirmed,
                ServerConfirmationV1::ServerConfirmed,
            ]
            .into_iter(),
        );
        assert_eq!(confirmed.server_confirmed, 2);
        assert_eq!(
            confirmed.archive_wide,
            ServerConfirmationV1::ServerConfirmed
        );

        let mixed = ConfirmationTally::over(
            [
                ServerConfirmationV1::ServerConfirmed,
                ServerConfirmationV1::NotServerConfirmed,
            ]
            .into_iter(),
        );
        assert_eq!(mixed.server_confirmed, 1);
        assert_eq!(mixed.not_server_confirmed, 1);
        assert_eq!(mixed.archive_wide, ServerConfirmationV1::NotServerConfirmed);
    }
}
