//! Die Bruecke der Sitzungssperre: VIER Ausfuhren, und keine entscheidet.
//!
//! `apps/web` haengt `visibilitychange`, `pointerdown` und `keydown` an diese
//! Ausfuhren und reicht dabei die Uhr der Seite als Wert herein; die vierte,
//! `readerSessionLock`, sperrt eine Sitzung SOFORT — der Weg, auf dem der
//! Hauptthread eine Kennung schliesst, die er nicht mehr haelt, statt sie mit
//! ihrem Schluesselmaterial im Worker liegen zu lassen. Ob eine
//! Frist erreicht ist, rechnet `ea_reader::ReaderSession::state_at` — bei
//! JEDEM Aufruf, ohne Timer. Ein `setTimeout` im Wirt darf zusaetzlich
//! sperren; die Zusage steht in Rust, weil Hintergrundtabs gedrosselt und auf
//! Mobilgeraeten angehalten werden und ein Timer dort nie feuert.
//!
//! # Warum die Ausfuhren im WORKER laufen
//!
//! Die Sitzungen liegen in einem `thread_local!` in [`crate::vault_bridge`];
//! jeder Aufruf, der eine Sitzung nennt, muss denselben Faden sehen wie der,
//! der sie eroeffnet hat. Der Hauptthread beobachtet die Ereignisse und
//! schickt sie als Nachrichten — er ENTSCHEIDET nichts, und er haelt auch
//! keine eigene Uhr der Sitzung: `nowMs` ist `Date.now()` der Seite zum
//! Zeitpunkt des Ereignisses.
//!
//! # Was hinausgeht
//!
//! Das GENERIERTE `ReaderSessionView` als JSON: ob die Sitzung gesperrt ist
//! und die Eintragshashes der offenen Datensaetze, hexadezimal. Nie ein
//! Klartext, nie ein Schluessel, nie der Tresor.

use ea_reader::EntryHash;

use crate::bridge::Json;

#[cfg(target_arch = "wasm32")]
use ea_reader::{ReaderSessionState, TabVisibility, UnixMillis};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::vault_bridge::{SESSION_UNKNOWN_CODE, with_session};

/// Das `ReaderSessionView` als JSON — die REINE Haelfte, auf jedem Ziel
/// uebersetzbar und auf dem Wirt bezeugt.
#[must_use]
pub fn session_view_json(locked: bool, open_entry_hashes: &[EntryHash]) -> String {
    let hashes = open_entry_hashes
        .iter()
        .map(|hash| format!("\"{}\"", hex::encode(hash.as_bytes())))
        .collect::<Vec<String>>()
        .join(",");
    let mut json = Json::object();
    json.bool("locked", locked)
        .raw("openEntryHashes", &format!("[{hashes}]"));
    json.finish()
}

/// Meldet der Sitzung die Sichtbarkeit des Tabs.
///
/// `hidden` ist `document.visibilityState === 'hidden'`, `now_ms` die Uhr
/// der Seite. Der Wechsel in den Hintergrund startet die verkuerzte Frist;
/// eine zu `now_ms` bereits faellige Sperre faellt in demselben Aufruf.
///
/// # Errors
/// `EA-READER-SESSION-UNKNOWN` fuer eine Kennung, die es nicht gibt.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerNoteVisibility")]
pub fn reader_note_visibility(session: u32, hidden: bool, now_ms: f64) -> Result<(), JsValue> {
    let visibility = if hidden {
        TabVisibility::Hidden
    } else {
        TabVisibility::Visible
    };
    with_session(session, |session| {
        session.note_visibility(visibility, UnixMillis::new(now_ms as i64));
    })
    .ok_or_else(|| JsValue::from_str(SESSION_UNKNOWN_CODE))
}

/// Meldet der Sitzung eine Eingabe — `pointerdown` oder `keydown`.
///
/// Eine Eingabe verlaengert NUR eine Sitzung, die zu `now_ms` noch offen ist.
///
/// # Errors
/// `EA-READER-SESSION-UNKNOWN` fuer eine Kennung, die es nicht gibt.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerNoteActivity")]
pub fn reader_note_activity(session: u32, now_ms: f64) -> Result<(), JsValue> {
    with_session(session, |session| {
        session.note_activity(UnixMillis::new(now_ms as i64));
    })
    .ok_or_else(|| JsValue::from_str(SESSION_UNKNOWN_CODE))
}

/// Der Zustand der Sitzung zu `now_ms`, als `ReaderSessionView`.
///
/// Der Aufruf ist die Sperrentscheidung: `state_at` rechnet die Frist nach
/// und sperrt, wenn sie erreicht ist. Die Flaeche liest danach `locked` und
/// die offenen Eintragshashes — nach einer Sperre ist die Liste leer, weil die
/// Datensaetze mit dem Tresor gefallen sind.
///
/// # Errors
/// `EA-READER-SESSION-UNKNOWN` fuer eine Kennung, die es nicht gibt.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerSessionStateAt")]
pub fn reader_session_state_at(session: u32, now_ms: f64) -> Result<String, JsValue> {
    with_session(session, |session| {
        let locked = session.state_at(UnixMillis::new(now_ms as i64)) == ReaderSessionState::Locked;
        let hashes: Vec<EntryHash> = session
            .open_records()
            .iter()
            .map(ea_reader::VerifiedDecryptedRecord::entry_hash)
            .collect();
        session_view_json(locked, &hashes)
    })
    .ok_or_else(|| JsValue::from_str(SESSION_UNKNOWN_CODE))
}

/// Sperrt eine Sitzung SOFORT: Tresor und offene Datensaetze fallen.
///
/// Fuer den Hauptthread, wenn er eine Kennung aufgibt — etwa weil eine
/// frische Bestaetigung eine neue eroeffnet hat. Eine Sitzung, an die
/// niemand mehr Sichtbarkeit und Eingaben meldet, liefe sonst in die volle
/// Fuenfminutenfrist statt in die verkuerzte des Hintergrundtabs. Ein
/// zweiter Aufruf auf eine gesperrte Sitzung ist wirkungslos und kein Fehler.
///
/// # Errors
/// `EA-READER-SESSION-UNKNOWN` fuer eine Kennung, die es nicht gibt.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerSessionLock")]
pub fn reader_session_lock(session: u32) -> Result<(), JsValue> {
    with_session(session, ea_reader::ReaderSession::lock)
        .ok_or_else(|| JsValue::from_str(SESSION_UNKNOWN_CODE))
}
