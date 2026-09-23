//! Die Escrow-Zeremonien des Readers im Worker (Escrow-Profil §5–§7,
//! Scheibe e): GENAU FÜNF Ausfuhren, und keine gibt Schlüsselmaterial heraus.
//!
//! - `readerRegistrationRequest` (Fähigkeit `Enrollment`): der
//!   Registrierungsantrag aus dem entsperrten Tresor.
//! - `readerKeyEscrowSealPackage` (`ReaderKeyEscrow`): Zeremonie A, das Paket
//!   hinter dem KEM-Gleichheitsgate.
//! - `readerKeyEscrowTransportBegin`, `…Open`, `…Abort` (`ReaderKeyEscrow`):
//!   Zeremonie B mit dem flüchtigen Transport-Schlüssel.
//!
//! # Was hier NICHT entschieden wird
//!
//! Ziel, Gate, Versiegeln, Bindungsprüfung und Öffnen stehen vollständig in
//! `ea_reader` (`reader_key_escrow`, `reader_key_escrow_restore`). Dieses
//! Modul hält Zustand, übersetzt Argumente und gibt Status-DTOs heraus —
//! Hex, Zahlen, feste Codes und öffentliche Dateibytes (Paket,
//! Transportanfrage, Registrierungsantrag). JavaScript trifft keine
//! Entscheidung (`web-reader-design.md` §9).
//!
//! # Der Transport-Schlüssel verlässt diese Tabelle nie
//!
//! `ESCROW_CEREMONIES` hält je Kennung den lebenden Transport, den
//! wiederhergestellten KEM oder — nach `enrollmentBeginRestored` — die
//! Kennung des Enrollments, in das der KEM gewandert ist; im Worker und
//! einfädig wie [`crate::vault_bridge`]. Keine Ausfuhr öffnet OPFS; erst
//! `enrollmentFinishRestored` in [`crate::webauthn`] schreibt den NEUEN,
//! versiegelten Tresor. `readerKeyEscrowTransportOpen` ENTNIMMT den Transport,
//! bevor irgendetwas geprüft wird — in jedem Ausgang ist er danach fort. Ein
//! Neuladen beendet den Worker und mit ihm die Tabelle.
//!
//! # Sperrung in Zeremonie B
//!
//! Zeremonie B hat keine `ReaderSession`. „Bei Sperrung genullt“ (Profil §7)
//! heißt hier (Controller-Ruling Fixrunde 3): Verbrauch durch `open`,
//! Abbruch, `pagehide` und Neuladen — und jede dieser Stellen nullt auch den
//! bereits wiederhergestellten KEM, egal unter welcher Kennung er liegt. Der
//! Abbruch unter der Escrow-Kennung ([`transport_abort`]) folgt deshalb der
//! Verknüpfung ins Enrollment. Die Tabellenhälften stehen auf jedem Ziel und
//! sind auf dem Wirt bezeugt (`tests/escrow_restore_abort.rs`).

use core::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use ea_reader::{
    ArchiveSource, ReaderKeyEscrowTransportV1, RestoredReaderKemV1, SubjectId, TrustAnchorV1,
    UnixMillis,
};
#[cfg(target_arch = "wasm32")]
use ea_reader::{decode_trust_anchor, reader_registration_request, seal_reader_key_escrow_package};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::bridge::Json;

#[cfg(target_arch = "wasm32")]
use crate::file_access::take_directory_source;
#[cfg(target_arch = "wasm32")]
use crate::vault_bridge::with_unlocked_vault;

/// Der Code für eine Brücken-Eingabe, die keine Aussage einer Zeremonie ist:
/// eine unbekannte oder verbrauchte Kennung, eine falsche Länge.
pub const ESCROW_BRIDGE_ARGUMENT_CODE: &str = "EA-READER-ESCROW-BRIDGE-ARGUMENT";

/// Ein Eintrag der Zeremonientabelle.
enum EscrowCeremony {
    /// Der lebende Transport-Schlüssel, wartend auf den Umschlag.
    Awaiting(ReaderKeyEscrowTransportV1),
    /// Der wiederhergestellte KEM, wartend auf `enrollmentBeginRestored`.
    Restored(RestoredReaderKemV1),
    /// Der KEM ist in das Enrollment unter DIESER Kennung gewandert
    /// ([`crate::webauthn`]). Die Verknüpfung bleibt stehen, damit der
    /// Abbruch unter der Escrow-Kennung ihn dort erreicht (review-e F1).
    Enrolling(u32),
}

thread_local! {
    static ESCROW_CEREMONIES: RefCell<BTreeMap<u32, EscrowCeremony>> =
        const { RefCell::new(BTreeMap::new()) };
    static NEXT_HANDLE: Cell<u32> = const { Cell::new(1) };
}

fn next_handle() -> u32 {
    NEXT_HANDLE.with(|counter| {
        let handle = counter.get();
        counter.set(handle.wrapping_add(1));
        handle
    })
}

#[cfg(target_arch = "wasm32")]
fn bridge_argument() -> JsValue {
    JsValue::from_str(ESCROW_BRIDGE_ARGUMENT_CODE)
}

/// Entnimmt den wiederhergestellten KEM — für `enrollmentBeginRestored`.
/// Ein Eintrag in einem anderen Zustand bleibt liegen.
pub(crate) fn take_restored(handle: u32) -> Option<RestoredReaderKemV1> {
    ESCROW_CEREMONIES.with(|table| {
        let mut table = table.borrow_mut();
        match table.remove(&handle)? {
            EscrowCeremony::Restored(restored) => Some(restored),
            other @ (EscrowCeremony::Awaiting(_) | EscrowCeremony::Enrolling(_)) => {
                table.insert(handle, other);
                None
            }
        }
    })
}

/// Hält fest, dass der KEM unter `handle` in das Enrollment `enrollment`
/// gewandert ist. Gerufen von [`crate::webauthn::begin_restored_status`]
/// unmittelbar nach der Ablage — ohne `await` dazwischen.
pub(crate) fn link_enrollment(handle: u32, enrollment: u32) {
    ESCROW_CEREMONIES.with(|table| {
        table
            .borrow_mut()
            .insert(handle, EscrowCeremony::Enrolling(enrollment));
    });
}

/// Ob unter `handle` ein wiederhergestellter KEM liegt.
#[cfg(target_arch = "wasm32")]
pub(crate) fn holds_restored(handle: u32) -> bool {
    ESCROW_CEREMONIES.with(|table| {
        matches!(
            table.borrow().get(&handle),
            Some(EscrowCeremony::Restored(_))
        )
    })
}

// ---------------------------------------------------------------------------
// Die reinen DTO-Hälften — auf jedem Ziel übersetzbar, auf dem Wirt bezeugt
// (`tests/escrow_dto.rs`).
// ---------------------------------------------------------------------------

/// `{fileName, bytesHex, kemFingerprint, signingFingerprint}`.
#[must_use]
pub fn registration_request_json(
    file_name: &str,
    exact_bytes: &[u8],
    kem_fingerprint: &[u8],
    signing_fingerprint: &[u8],
) -> String {
    let mut json = Json::object();
    json.string("fileName", file_name)
        .string("bytesHex", &hex::encode(exact_bytes))
        .string("kemFingerprint", &hex::encode(kem_fingerprint))
        .string("signingFingerprint", &hex::encode(signing_fingerprint));
    json.finish()
}

/// `{fileName, bytesHex, escrowCoreHash, readerCertificate,
/// recoveryCertificate, kemFingerprint}`.
#[must_use]
pub fn escrow_package_json(
    file_name: &str,
    exact_bytes: &[u8],
    escrow_core_hash: &[u8],
    reader_certificate: &[u8],
    recovery_certificate: &[u8],
    kem_fingerprint: &[u8],
) -> String {
    let mut json = Json::object();
    json.string("fileName", file_name)
        .string("bytesHex", &hex::encode(exact_bytes))
        .string("escrowCoreHash", &hex::encode(escrow_core_hash))
        .string("readerCertificate", &hex::encode(reader_certificate))
        .string("recoveryCertificate", &hex::encode(recovery_certificate))
        .string("kemFingerprint", &hex::encode(kem_fingerprint));
    json.finish()
}

/// `{handle, transportFingerprint, escrowObjectHash, readerCertificate,
/// fileName, bytesHex}`.
#[must_use]
pub fn transport_begin_json(
    handle: u32,
    transport_fingerprint: &[u8],
    escrow_object_hash: &[u8],
    reader_certificate: &[u8],
    file_name: &str,
    exact_bytes: &[u8],
) -> String {
    let mut json = Json::object();
    json.raw("handle", &handle.to_string())
        .string("transportFingerprint", &hex::encode(transport_fingerprint))
        .string("escrowObjectHash", &hex::encode(escrow_object_hash))
        .string("readerCertificate", &hex::encode(reader_certificate))
        .string("fileName", file_name)
        .string("bytesHex", &hex::encode(exact_bytes));
    json.finish()
}

/// `{restored: true, kemFingerprint, authorizationObjectHash}`.
#[must_use]
pub fn transport_open_json(kem_fingerprint: &[u8], authorization_object_hash: &[u8]) -> String {
    let mut json = Json::object();
    json.bool("restored", true)
        .string("kemFingerprint", &hex::encode(kem_fingerprint))
        .string(
            "authorizationObjectHash",
            &hex::encode(authorization_object_hash),
        );
    json.finish()
}

// ---------------------------------------------------------------------------
// Die fünf Ausfuhren. JEDE trägt ihr eigenes `cfg(target_arch = "wasm32")`
// unmittelbar über dem Attribut.
// ---------------------------------------------------------------------------

/// Der Registrierungsantrag aus dem Tresor einer entsperrten Sitzung.
///
/// # Errors
/// `EA-READER-SESSION-LOCKED` und die Codes von
/// `ea_reader::reader_registration_request`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerRegistrationRequest")]
pub fn reader_registration_request_js(session: u32, now_ms: f64) -> Result<String, JsValue> {
    let file = with_unlocked_vault(session, UnixMillis::new(now_ms as i64), |vault| {
        reader_registration_request(vault)
    })?
    .map_err(|error| JsValue::from_str(error.code()))?;
    Ok(registration_request_json(
        file.file_name(),
        file.exact_bytes(),
        file.kem_key_thumbprint().as_bytes(),
        file.signing_key_thumbprint().as_bytes(),
    ))
}

/// Zeremonie A: das Paket aus dem entsperrten Tresor und einem
/// Datei-Modus-Ordner. Der Ordner wird ENTNOMMEN.
///
/// # Errors
/// `EA-READER-ESCROW-BRIDGE-ARGUMENT` für eine Subject-ID falscher Länge oder
/// einen unbekannten Ordner, `EA-READER-SESSION-LOCKED`, und die Codes von
/// `ea_reader::seal_reader_key_escrow_package` — darunter
/// `EA-READER-ESCROW-KEM-MISMATCH`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerKeyEscrowSealPackage")]
pub fn reader_key_escrow_seal_package(
    session: u32,
    source: u32,
    subject_id: Vec<u8>,
    now_ms: f64,
) -> Result<String, JsValue> {
    let subject = SubjectId::try_from(&subject_id[..]).map_err(|_| bridge_argument())?;
    let source = take_directory_source(source).map_err(|_| bridge_argument())?;
    let now = UnixMillis::new(now_ms as i64);
    let file = with_unlocked_vault(session, now, |vault| {
        seal_reader_key_escrow_package(vault, &source, subject, now)
    })?
    .map_err(|error| JsValue::from_str(error.code()))?;
    Ok(escrow_package_json(
        file.file_name(),
        file.exact_bytes(),
        file.escrow_core_hash().as_bytes(),
        file.reader_certificate_object_hash().as_bytes(),
        file.recovery_certificate_object_hash().as_bytes(),
        file.kem_key_thumbprint().as_bytes(),
    ))
}

/// Zeremonie B, Beginn — die Tabellenhälfte von
/// `readerKeyEscrowTransportBegin`, auf jedem Ziel übersetzt und auf dem Wirt
/// bezeugt (`tests/escrow_restore_abort.rs`): gültiges Escrow zur Subject-ID
/// prüfen, flüchtigen Transport-Schlüssel ziehen, unter einer neuen Kennung
/// ablegen und das DTO aus [`transport_begin_json`] herausgeben.
///
/// # Errors
/// Die Codes von `ReaderKeyEscrowTransportV1::begin` und
/// `…::transport_request` — darunter `EA-READER-ESCROW-NOT-FOUND`.
pub fn transport_begin_status(
    anchor: &TrustAnchorV1,
    source: &dyn ArchiveSource,
    subject: SubjectId,
    now: UnixMillis,
) -> Result<String, &'static str> {
    let transport =
        ReaderKeyEscrowTransportV1::begin(anchor, source, subject, now).map_err(|e| e.code())?;
    let file = transport.transport_request().map_err(|e| e.code())?;
    let rendered_fingerprint = transport.fingerprint();
    let escrow_object_hash = transport.escrow_object_hash();
    let reader_certificate = transport.reader_certificate_object_hash();
    let handle = next_handle();
    ESCROW_CEREMONIES.with(|table| {
        table
            .borrow_mut()
            .insert(handle, EscrowCeremony::Awaiting(transport));
    });
    Ok(transport_begin_json(
        handle,
        rendered_fingerprint.as_bytes(),
        escrow_object_hash.as_bytes(),
        reader_certificate.as_bytes(),
        file.file_name(),
        file.exact_bytes(),
    ))
}

/// Zeremonie B, Import — die Tabellenhälfte von
/// `readerKeyEscrowTransportOpen`: öffnet den Umschlag GENAU EINMAL. Der
/// Transport wird entnommen, bevor geprüft wird; nach Erfolg liegt unter
/// derselben Kennung der wiederhergestellte KEM, nach einem Fehler nichts.
///
/// # Errors
/// `EA-READER-ESCROW-BRIDGE-ARGUMENT` für eine unbekannte oder verbrauchte
/// Kennung und die Codes von `ReaderKeyEscrowTransportV1::open`.
pub fn transport_open_status(handle: u32, envelope: &[u8]) -> Result<String, &'static str> {
    let transport = ESCROW_CEREMONIES.with(|table| {
        let mut table = table.borrow_mut();
        match table.remove(&handle)? {
            EscrowCeremony::Awaiting(transport) => Some(transport),
            other @ (EscrowCeremony::Restored(_) | EscrowCeremony::Enrolling(_)) => {
                table.insert(handle, other);
                None
            }
        }
    });
    let restored = transport
        .ok_or(ESCROW_BRIDGE_ARGUMENT_CODE)?
        .open(envelope)
        .map_err(|error| error.code())?;
    let rendered = transport_open_json(
        restored.kem_key_thumbprint().as_bytes(),
        restored.authorization_object_hash().as_bytes(),
    );
    ESCROW_CEREMONIES.with(|table| {
        table
            .borrow_mut()
            .insert(handle, EscrowCeremony::Restored(restored));
    });
    Ok(rendered)
}

/// Zeremonie B, Abbruch — die Tabellenhälfte von
/// `readerKeyEscrowTransportAbort`: nullt Transport oder wiederhergestellten
/// KEM, und zwar unter JEDER Kennung, unter der er liegt — auch im
/// Enrollment, in das `enrollmentBeginRestored` ihn gelegt hat
/// (Controller-Ruling Fixrunde 3: Sperrung in Zeremonie B = Verbrauch durch
/// `open`, Abbruch, `pagehide`, Neuladen). Idempotent.
pub fn transport_abort(handle: u32) {
    let removed = ESCROW_CEREMONIES.with(|table| table.borrow_mut().remove(&handle));
    if let Some(EscrowCeremony::Enrolling(enrollment)) = removed {
        crate::webauthn::discard_enrollment(enrollment);
    }
}

/// Zeremonie B, Beginn: gültiges Escrow zur Subject-ID prüfen, flüchtigen
/// Transport-Schlüssel ziehen, Transportdatei herausgeben.
///
/// # Errors
/// `EA-READER-ESCROW-BRIDGE-ARGUMENT`, die Codes von `ea-trust` für einen
/// Anker, der nicht dekodiert, und die von [`transport_begin_status`].
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerKeyEscrowTransportBegin")]
pub fn reader_key_escrow_transport_begin(
    pinned_anchor: Vec<u8>,
    subject_id: Vec<u8>,
    source: u32,
    now_ms: f64,
) -> Result<String, JsValue> {
    let subject = SubjectId::try_from(&subject_id[..]).map_err(|_| bridge_argument())?;
    let anchor =
        decode_trust_anchor(&pinned_anchor).map_err(|error| JsValue::from_str(error.code()))?;
    let source = take_directory_source(source).map_err(|_| bridge_argument())?;
    transport_begin_status(&anchor, &source, subject, UnixMillis::new(now_ms as i64))
        .map_err(JsValue::from_str)
}

/// Zeremonie B, Import: siehe [`transport_open_status`].
///
/// # Errors
/// Die von [`transport_open_status`].
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerKeyEscrowTransportOpen")]
pub fn reader_key_escrow_transport_open(handle: u32, envelope: Vec<u8>) -> Result<String, JsValue> {
    transport_open_status(handle, &envelope).map_err(JsValue::from_str)
}

/// Bricht ab: siehe [`transport_abort`]. Die Oberfläche ruft es beim
/// Verlassen der Seite und auf `pagehide`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "readerKeyEscrowTransportAbort")]
pub fn reader_key_escrow_transport_abort(handle: u32) {
    transport_abort(handle);
}
