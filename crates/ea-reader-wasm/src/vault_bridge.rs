//! Die Tresorbruecke: GENAU ZWEI Ausfuhren, und keine gibt Schluesselmaterial
//! heraus.
//!
//! # Die Richtung ist die Zusage
//!
//! Die PRF-Ausgabe geht HINEIN, weil ihre Erzeugung eine Browser-API ist und
//! nirgends sonst stattfinden kann: WebAuthn mit der `prf`-Erweiterung liefert
//! sie an JavaScript, und geteiltes Rust hat keinen Weg, sie selbst zu holen.
//! Sie geht deshalb als BESITZENDER `Vec<u8>` ueber die Grenze und wird
//! unmittelbar nach der Ableitung geloescht — ein `&[u8]` liesse sich nicht
//! loeschen, weil der Puffer dann dem Aufrufer gehoerte. Geloescht werden BEIDE
//! Klartextkopien: der `Vec<u8>` von der Grenze UND das `[u8; 32]`, ueber das
//! `SecretBytes::new` gebaut wird. Das zweite ist keine Peinlichkeitsvermeidung:
//! `SecretBytes::new` nimmt sein Array BY VALUE, und `[u8; 32]` ist `Copy` —
//! ohne das ausdrueckliche Loeschen bliebe die PRF-Ausgabe im Rahmen stehen,
//! waehrend `ZeroizeOnDrop` nur die Kopie IM Traeger raeumt.
//!
//! Zurueck gehen eine Sitzungskennung und der versiegelte Tresor. Der
//! Tresorschluessel, der X25519-Rohschluessel und der Ed25519-Rohschluessel
//! gehen NIE zurueck: TypeScript erhaelt Sitzungskennung, Fingerabdruecke und
//! Statuswerte, nie Schluesselmaterial
//! (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §9).
//! Der Rohschluessel liegt waehrend einer entsperrten Sitzung im WASM-Speicher,
//! und das ist die in §6.5 benannte, bewusst getragene Folge der
//! HPKE-Entkapselung im Modul; die Gegenmassnahmen dazu baut die Aufgabe
//! „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und
//! signiertes lokales Audit".
//!
//! # Warum es eine prozessinterne Tabelle gibt und keinen Zeiger
//!
//! Eine Sitzungskennung ist ein `u32` ohne Bedeutung ausserhalb dieses Moduls.
//! Gaebe die Bruecke stattdessen ein `UnlockedVault` als exportierten Typ
//! heraus, laege ein Objekt mit privaten Schluesseln im JavaScript-Heap, und
//! jede Erweiterung, jedes Debugging-Werkzeug und jeder Crash-Dump saehe es.
//! Die Tabelle ist ein `thread_local!` mit `RefCell<BTreeMap<..>>` und kein
//! `std::sync::Mutex`: der Worker ist einfaedig, und JS-Typen sind nicht `Send`
//! — dieselbe Bauform und dieselbe Begruendung wie `BLOB_KEY_QUEUES` in
//! `crate::opfs_worker`. Der `const`-Initialisierer ist Pflicht, sonst faellt
//! `clippy::missing_const_for_thread_local` unter `-D warnings`.
//!
//! # Der Tresorinhalt entsteht NICHT hier
//!
//! `register_vault_contents` ist der Rust-seitige Einstieg, den die Aufgabe
//! „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht
//! überspringbare Fingerprint-Gate" benutzt: sie zieht die Schluessel, pinnt
//! den Anker und legt den fertigen `VaultContentsV1` hier ab. Er ist
//! ausdruecklich KEINE Ausfuhr nach JavaScript — Schluesselmaterial soll die
//! Grenze auch nicht in dieser Richtung ueberqueren.

// Jede Einfuhr traegt ihr eigenes cfg. Auf einem Wirtsziel waere sie unbenutzt,
// und `cargo clippy --workspace --all-targets --all-features --locked --
// -D warnings` faellt an einer unbenutzten Einfuhr genauso wie an einem echten
// Fehler — dieselbe Lage wie im Kopf von `crate::bridge`.
#[cfg(target_arch = "wasm32")]
use core::cell::{Cell, RefCell};
#[cfg(target_arch = "wasm32")]
use std::collections::BTreeMap;

#[cfg(target_arch = "wasm32")]
use ea_crypto::SecretBytes;
#[cfg(target_arch = "wasm32")]
use ea_reader::{
    AuthenticatorPrfV1, ReaderAuthenticatorConfirmation, ReaderConfirmationPurpose, ReaderSession,
    ReaderSessionState, ReaderVault, SealedVaultV1, UnixMillis, UnlockedVault, VaultContentsV1,
};
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Uint8Array};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use zeroize::Zeroize;

/// Die Laenge einer PRF-Ausgabe in Byte.
///
/// Die WebAuthn-`prf`-Erweiterung liefert 32 Byte je Ausgabe. Eine andere
/// Laenge ist kein Grenzfall, den man dehnen koennte, sondern eine Aussage
/// darueber, dass der Aufrufer etwas anderes geschickt hat als eine
/// PRF-Ausgabe.
#[cfg(target_arch = "wasm32")]
const PRF_OUTPUT_SIZE: usize = 32;

/// Der Code fuer eine Bruecken-Eingabe, die keine Aussage des Tresors ist.
///
/// Eine falsche Argumentform ist ein Fehler des Aufrufers und kein Befund ueber
/// den Tresor; sie bekommt deshalb einen eigenen Code und nicht einen der
/// Tresorcodes, die eine Weigerung BEDEUTEN.
#[cfg(target_arch = "wasm32")]
const BRIDGE_ARGUMENT_CODE: &str = "EA-READER-VAULT-BRIDGE-ARGUMENT";

/// Der Code fuer eine Sitzungskennung, die diese Tabelle nicht kennt.
///
/// Seit der Aufgabe „Sitzungssperre, Zeroize, authenticator-bestätigter
/// Einzelexport und signiertes lokales Audit" ist „unbekannt" von „gesperrt"
/// unterscheidbar, und beide sind Aussagen ueber die SITZUNG, nicht ueber das
/// Argument: die Kennung war einmal gueltig, oder sie war es nie.
pub const SESSION_UNKNOWN_CODE: &str = "EA-READER-SESSION-UNKNOWN";

#[cfg(target_arch = "wasm32")]
thread_local! {
    /// Die Sitzungen dieses Workers — entsperrt oder gesperrt.
    ///
    /// Seit der Sitzungssperre liegt hier eine [`ReaderSession`] und kein
    /// nackter [`UnlockedVault`]: JEDER Zugriff auf den Tresor laeuft ueber
    /// `ReaderSession::vault(now)`, das die Frist nachrechnet und sperrt,
    /// bevor es etwas herausgibt. Eine gesperrte Sitzung bleibt in der
    /// Tabelle — mit ihrer Kennung, ohne Tresor —, damit `reopen` sie mit
    /// einer frischen Bestaetigung wieder eroeffnen kann.
    static VAULT_SESSIONS: RefCell<BTreeMap<u32, ReaderSession>> =
        const { RefCell::new(BTreeMap::new()) };
    /// Die noch nicht versiegelten Tresorinhalte des Enrollments.
    static PENDING_CONTENTS: RefCell<BTreeMap<u32, VaultContentsV1>> =
        const { RefCell::new(BTreeMap::new()) };
    /// Der Zaehler beider Tabellen. EINER, damit eine Sitzungskennung nie mit
    /// einer Inhaltskennung verwechselt werden kann.
    static NEXT_HANDLE: Cell<u32> = const { Cell::new(1) };
}

/// Die naechste Kennung, monoton und nie wiederverwendet.
#[cfg(target_arch = "wasm32")]
fn next_handle() -> u32 {
    NEXT_HANDLE.with(|counter| {
        let handle = counter.get();
        counter.set(handle.wrapping_add(1));
        handle
    })
}

/// Legt einen fertigen Tresorinhalt ab und gibt seine Kennung zurueck.
///
/// Der Einstieg des Enrollments und KEINE Ausfuhr nach JavaScript: der Inhalt
/// traegt zwei private Schluessel, und die entstehen in geteiltem Rust.
#[cfg(target_arch = "wasm32")]
pub fn register_vault_contents(contents: VaultContentsV1) -> u32 {
    let handle = next_handle();
    PENDING_CONTENTS.with(|pending| {
        pending.borrow_mut().insert(handle, contents);
    });
    handle
}

/// Ob eine Sitzungskennung zu `now` ENTSPERRT ist.
///
/// Das Beobachtungsfenster fuer den Zeugen der Aufgabe „Sitzungssperre,
/// Zeroize, authenticator-bestätigter Einzelexport und signiertes lokales
/// Audit": eine Sperrung soll BELEGBAR sein und nicht behauptet. Der Aufruf
/// rechnet die Frist nach — eine faellige Sperre faellt HIER.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn vault_session_is_open(session: u32, now: UnixMillis) -> bool {
    with_session(session, |session| {
        session.state_at(now) == ReaderSessionState::Unlocked
    })
    .unwrap_or(false)
}

/// Fuehrt eine Rechnung auf einer Sitzung aus — gesperrt oder nicht.
///
/// Die Ausleihe wird NIE ueber einen JS-Aufruf hinweg gehalten — dieselbe Regel
/// wie bei den Warteschlangen in `crate::opfs_worker`: eine `RefCell`, die
/// waehrend eines Promise offen steht, faellt beim naechsten Ereignis mit einer
/// Doppelausleihe um. `None` heisst: diese Kennung gibt es nicht.
#[cfg(target_arch = "wasm32")]
pub fn with_session<R>(session: u32, use_it: impl FnOnce(&mut ReaderSession) -> R) -> Option<R> {
    VAULT_SESSIONS.with(|sessions| sessions.borrow_mut().get_mut(&session).map(use_it))
}

/// Fuehrt eine Rechnung auf dem Tresor einer zu `now` ENTSPERRTEN Sitzung aus.
///
/// Der Tresor kommt ueber `ReaderSession::vault(now)` und nie direkt: die
/// Frist wird bei JEDEM Zugriff nachgerechnet, und eine faellige Sperre
/// faellt, bevor die Rechnung den Tresor sieht. Zwei Weigerungen, zwei Codes:
/// [`SESSION_UNKNOWN_CODE`] fuer eine Kennung, die es nicht gibt, und
/// `EA-READER-SESSION-LOCKED` fuer eine, deren Tresor gefallen ist.
///
/// # Errors
/// Die zwei genannten Codes als JS-Zeichenkette.
#[cfg(target_arch = "wasm32")]
pub fn with_unlocked_vault<R>(
    session: u32,
    now: UnixMillis,
    use_it: impl FnOnce(&UnlockedVault) -> R,
) -> Result<R, JsValue> {
    with_session(session, |session| {
        session
            .vault(now)
            .map(use_it)
            .ok_or_else(|| JsValue::from_str(ea_reader::ReaderSessionError::Locked.code()))
    })
    .ok_or_else(|| JsValue::from_str(SESSION_UNKNOWN_CODE))?
}

/// Liest eine Bytefolge aus einem JS-Array-Platz.
#[cfg(target_arch = "wasm32")]
fn bytes_at(values: &Array, index: u32) -> Result<Vec<u8>, JsValue> {
    let value = values.get(index);
    if !value.is_instance_of::<Uint8Array>() {
        return Err(JsValue::from_str(BRIDGE_ARGUMENT_CODE));
    }
    Ok(Uint8Array::unchecked_from_js(value).to_vec())
}

/// Baut die Authenticator-Liste und LOESCHT jede PRF-Kopie danach.
#[cfg(target_arch = "wasm32")]
fn take_authenticators(
    credential_ids: &Array,
    prf_outputs: &Array,
) -> Result<Vec<AuthenticatorPrfV1>, JsValue> {
    if credential_ids.length() != prf_outputs.length() || credential_ids.length() == 0 {
        return Err(JsValue::from_str(BRIDGE_ARGUMENT_CODE));
    }
    let mut authenticators = Vec::with_capacity(credential_ids.length() as usize);
    for index in 0..credential_ids.length() {
        let credential_id = bytes_at(credential_ids, index)?;
        let mut prf_output = bytes_at(prf_outputs, index)?;
        let mut prf: [u8; PRF_OUTPUT_SIZE] = prf_output
            .as_slice()
            .try_into()
            .map_err(|_| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?;
        prf_output.zeroize();
        authenticators.push(AuthenticatorPrfV1::new(
            credential_id,
            SecretBytes::new(prf),
        ));
        // In JEDER Runde, nicht einmal am Ende: `SecretBytes::new` nimmt sein
        // Array BY VALUE, und `[u8; 32]` ist `Copy` — die Uebernahme laesst
        // die Kopie hier stehen. Dasselbe Muster wie `derive_key` in
        // `ea_reader`s `envelope.rs`.
        prf.zeroize();
    }
    Ok(authenticators)
}

// ---------------------------------------------------------------------------
// Die zwei Ausfuhren. JEDE traegt ihr eigenes `cfg(target_arch = "wasm32")`
// unmittelbar ueber dem Attribut — `every_wasm_bindgen_export_sits_behind_the
// _wasm32_cfg` liest das als Text und folgt keinem `mod`.
// ---------------------------------------------------------------------------

/// Versiegelt einen zuvor abgelegten Tresorinhalt.
///
/// Der Inhalt wird der Tabelle ENTNOMMEN und nicht geliehen: `SecretBytes`
/// traegt kein `Clone`, und `HpkeRecipientPrivateKey::from_bytes` konsumiert
/// sein Geheimnis — ein zweites Versiegeln desselben Inhalts gibt es nicht.
///
/// Zurueck geht der versiegelte Tresor als deterministisches CBOR. Er enthaelt
/// Chiffrat, die `credentialId`s und die Nonces; ein Klartextschluessel steht
/// nicht darin, und deshalb darf JavaScript ihn in OPFS schreiben.
///
/// # Errors
/// `EA-READER-VAULT-BRIDGE-ARGUMENT` fuer eine Argumentform, die keine
/// Authenticator-Liste ist, und die stabilen Codes des Tresors — insbesondere
/// `EA-READER-VAULT-NO-AUTHENTICATOR` fuer die leere Liste.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerVaultSeal")]
pub fn reader_vault_seal(
    contents_handle: u32,
    credential_ids: Array,
    prf_outputs: Array,
) -> Result<Vec<u8>, JsValue> {
    let authenticators = take_authenticators(&credential_ids, &prf_outputs)?;
    let contents = PENDING_CONTENTS
        .with(|pending| pending.borrow_mut().remove(&contents_handle))
        .ok_or_else(|| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?;
    let sealed = ReaderVault::seal(contents, &authenticators)
        .map_err(|error| JsValue::from_str(error.code()))?;
    Ok(sealed.to_deterministic_cbor())
}

/// Entsperrt einen Tresor und gibt die Sitzungskennung zurueck.
///
/// Die Argumente sind BESITZEND, und das ist der Zeroize-Vertrag: die
/// PRF-Ausgabe wird in einen `SecretBytes` gehoben, ihre BEIDEN Kopien im
/// linearen Speicher — der `Vec<u8>` und das Stackarray — werden sofort
/// geloescht, und der `SecretBytes` selbst faellt am Ende
/// dieser Funktion unter `ZeroizeOnDrop` — die Ableitung des Wrapping-
/// Schluessels ist da laengst geschehen. Mit einem geliehenen `&[u8]` gehoerte
/// der Puffer dem Aufrufer, und die Zusage waere nicht einloesbar.
///
/// # Die Zeit tritt als WERT ein
///
/// `now_ms` ist die Uhr der Seite, als `f64`, weil JavaScript Zahlen so
/// traegt. Sie eroeffnet die Sitzung, stellt die Entsperrbestaetigung aus und
/// setzt die monotone Untergrenze; von hier an rechnet
/// `ReaderSession::state_at` gegen sie. Die Bruecke liest KEINE eigene Uhr —
/// dieselbe Regel wie bei `readerTrustAge` und den Datei-Modus-Ausfuhren.
///
/// # Errors
/// `EA-READER-VAULT-BRIDGE-ARGUMENT` fuer eine PRF-Ausgabe falscher Laenge und
/// die stabilen Codes des Tresors: `EA-READER-VAULT-NO-ENVELOPE` fuer einen
/// geloeschten Passkey, `EA-CRYPTO-AEAD-OPEN` fuer einen verfaelschten Tresor,
/// `EA-TRUST-ANCHOR-HASH` fuer einen untergeschobenen Anker.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerVaultUnlock")]
pub fn reader_vault_unlock(
    sealed: Vec<u8>,
    credential_id: Vec<u8>,
    mut prf_output: Vec<u8>,
    now_ms: f64,
) -> Result<u32, JsValue> {
    let mut prf: [u8; PRF_OUTPUT_SIZE] = prf_output
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str(BRIDGE_ARGUMENT_CODE))?;
    prf_output.zeroize();
    let authenticator = AuthenticatorPrfV1::new(credential_id, SecretBytes::new(prf));
    prf.zeroize();
    let now = UnixMillis::new(now_ms as i64);
    let sealed = SealedVaultV1::from_deterministic_cbor(&sealed)
        .map_err(|error| JsValue::from_str(error.code()))?;
    // Die Bestaetigung ZUERST: sie belegt den Authenticator gegen das Envelope
    // und ist die Voraussetzung der Sitzung, nicht ihre Folge.
    let confirmation = ReaderAuthenticatorConfirmation::prove(
        &sealed,
        &authenticator,
        ReaderConfirmationPurpose::Unlock,
        now,
    )
    .map_err(|error| JsValue::from_str(error.code()))?;
    let unlocked = ReaderVault::unlock(&sealed, &authenticator)
        .map_err(|error| JsValue::from_str(error.code()))?;
    let opened = ReaderSession::unlock(unlocked, confirmation, now)
        .map_err(|error| JsValue::from_str(error.code()))?;
    let session = next_handle();
    VAULT_SESSIONS.with(|sessions| {
        sessions.borrow_mut().insert(session, opened);
    });
    Ok(session)
}
