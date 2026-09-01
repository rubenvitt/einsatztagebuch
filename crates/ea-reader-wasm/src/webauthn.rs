//! Das Browser-Enrollment: GENAU FUENF Ausfuhren, und keine gibt
//! Schluesselmaterial heraus.
//!
//! # Was hier NICHT entschieden wird
//!
//! Die Kardinalitaet (zwei Pflicht-Authenticators), das Fingerprint-Gate, der
//! Bau und die Signatur der drei Anfragen und die Reihenfolge, in der sie
//! laufen, stehen VOLLSTAENDIG in `ea_reader::ReaderEnrollment`. Dieses Modul
//! haelt den Zustand, uebersetzt Argumente und traegt Bytes — dieselbe
//! Rollenteilung wie in [`crate::vault_bridge`], und dieselbe, die
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §9
//! verlangt: Kryptographie und Sicherheitsentscheidungen ausschliesslich in
//! geteiltem Rust, TypeScript traegt Bytes.
//!
//! # Warum alle fuenf Ausfuhren IM DEDIZIERTEN WORKER laufen
//!
//! Drei Gruende, die zusammen keinen zweiten Ort zulassen. Erstens liegt der
//! Enrollment-Zustand in einem `thread_local!`, also muessen alle fuenf
//! Aufrufe denselben Faden sehen. Zweitens schreibt `finish` am Ende ueber
//! [`crate::opfs_worker::OpfsBlobStore`], und ein synchrones OPFS-Handle gibt
//! es nur im Worker. Drittens ist die einzige SYNCHRONE Transportflaeche, die
//! ein Browser ueberhaupt anbietet, ein synchrones `XMLHttpRequest` — und auch
//! die gibt es ausschliesslich in einem dedizierten Worker.
//!
//! `navigator.credentials` gibt es umgekehrt NUR auf dem Hauptthread. Die
//! Zeremonien laufen deshalb in `apps/web/src/vault/webauthn-prf.ts` und
//! schicken ihre Ergebnisse als Bytes ueber die Nachrichtenform von
//! `apps/web/src/bridge/opfs-worker.ts` hierher; entschieden wird hier, weil
//! hier Rust liegt.
//!
//! Wer die fuenf Ausfuhren stattdessen auf dem Hauptthread riefe, bekaeme eine
//! Fassung, die JEDEN Wirtstest besteht und erst im Browser an OPFS und am
//! synchronen `XMLHttpRequest` scheitert — dieselbe Warnung, die der Kopf von
//! [`crate::opfs_worker`] fuer seinen eigenen Fall schon ausschreibt.
//!
//! # Warum der Endpunktport hier steht und nicht in `ea-reader`
//!
//! `ea_reader::EnrollmentEndpoints` ist ein PORT ueber fertige Anfragen: Rust
//! baut und signiert, der Aufrufer fuehrt aus. Der Wirtstest fuehrt ueber
//! `ea_reader::InMemoryEnrollmentEndpoints` aus, der Browser ueber
//! [`XhrEnrollmentEndpoints`] weiter unten. `ea-reader` selbst traegt keine
//! Wirtsabhaengigkeit, weil es auf der wasm32-Positivliste in
//! `tools/xtask/src/main.rs` steht.
//!
//! # Die eine benannte Luecke dieses Laufs: Bundle-Origin gegen `@authority`
//!
//! [`XhrEnrollmentEndpoints`] schickt an den PFAD aus
//! `EnrollmentRequestV1::target_uri`, also SAME-ORIGIN gegen das Bundle.
//! `apps/web/index.html` traegt `connect-src 'self'`, und Chromium setzt die
//! Richtlinie im Renderer durch, BEVOR die Anfrage den Prozess verlaesst; eine
//! fremde Herkunft kaeme in diesem Stand gar nicht erst hinaus. Die SIGNIERTE
//! `@authority` bleibt davon unberuehrt — sie kommt aus
//! `EnrollmentRequestContextV1` und nennt den Sync-Server, abrufbar ueber
//! `EnrollmentRequestV1::authority`. Dass beide in diesem Stand auseinander
//! fallen, ist die benannte Luecke; sie schliesst der Bundle-Task, wenn
//! `connect-src` die Herkunft des Sync-Servers aufnimmt. Bis dahin ist der
//! Pfad die richtige Adresse, und ein hier gebauter absoluter URL waere eine
//! Anfrage, die der Renderer verwuerfe.

// Jede Einfuhr traegt ihr eigenes cfg. Auf einem Wirtsziel waere sie unbenutzt,
// und `cargo clippy --workspace --all-targets --all-features --locked --
// -D warnings` faellt an einer unbenutzten Einfuhr genauso wie an einem echten
// Fehler — dieselbe Lage wie im Kopf von [`crate::vault_bridge`].
#[cfg(target_arch = "wasm32")]
use core::cell::{Cell, RefCell};
#[cfg(target_arch = "wasm32")]
use std::collections::BTreeMap;

#[cfg(target_arch = "wasm32")]
use ea_crypto::SecretBytes;
// `CanonicalPublicCoseKey` steht auch dem Wirtstest dieser Datei offen: die
// Umschrift der WebAuthn-Karte in die kanonische Form ist genau das, was dort
// bezeugt wird.
#[cfg(any(target_arch = "wasm32", test))]
use ea_crypto::CanonicalPublicCoseKey;
// Die Transportklassifikation und der CBOR-Gang stehen auch dem Wirtstest
// dieser Datei offen; die Einfuhr traegt deshalb dasselbe erweiterte cfg wie
// die Funktionen, die sie benutzen.
#[cfg(any(target_arch = "wasm32", test))]
use ea_reader::AuthenticatorTransportProfileV1;
// `decode_trust_anchor`, `Hash32`, `OrganizationId` und `SubjectId` kommen
// ueber `ea_reader` und NICHT ueber eine eigene Kante nach `ea-trust` oder
// `ea-types`: sie stehen in der Signatur von `ReaderEnrollment::begin`, und
// `crates/ea-reader/src/lib.rs` re-exportiert sie genau deshalb — dieselbe
// Anordnung, die es fuer `GATE_ORDER_V1` schon haelt.
#[cfg(target_arch = "wasm32")]
use ea_reader::{
    AttestedAuthenticatorV1, EnrollmentEndpointError, EnrollmentEndpoints,
    EnrollmentRequestContextV1, EnrollmentRequestV1, FingerprintConfirmationV1, Hash32,
    MIN_ENROLLED_AUTHENTICATORS_V1, OrganizationId, READER_VAULT_BLOB_KEY_V1, ReaderBlobError,
    ReaderBlobKey, ReaderEnrollment, SubjectId, VAULT_PRF_SALT_V1, decode_trust_anchor,
};
#[cfg(target_arch = "wasm32")]
use js_sys::Uint8Array;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::{XmlHttpRequest, XmlHttpRequestResponseType};
#[cfg(target_arch = "wasm32")]
use zeroize::Zeroize;

#[cfg(target_arch = "wasm32")]
use crate::opfs_worker::OpfsBlobStore;

/// Das OPFS-Verzeichnis, unter dem der versiegelte Tresor liegt.
///
/// Zeichengleich zu `BRIDGE_BLOB_DIRECTORY` in [`crate::bridge`], und die
/// Wiederholung ist BENANNT statt still: die Konstante dort ist privat, und
/// `crates/ea-reader-wasm/src/bridge.rs` gehoert nicht in den Umfang des
/// Browser-Enrollments — sie dort aufzuweiten hiesse, eine fremde Datei fuer
/// eine Bequemlichkeit anzufassen. Eine Abweichung faellt nicht still: der
/// Vorlauf von `enrollmentFinish` schreibt hierhin, `blobGet` liest aus dem
/// Verzeichnis von [`crate::bridge`], und `apps/web/tests/e2e/enrollment.spec.ts`
/// oeffnet in seiner lebenden Paritaetsprobe genau diesen Tresor — zwei
/// verschiedene Namen enden dort in „Unter dem Tresorschluessel liegt lokal
/// nichts."
#[cfg(target_arch = "wasm32")]
const ENROLLMENT_BLOB_DIRECTORY: &str = "ea-reader";

/// Die Laenge einer PRF-Ausgabe in Byte.
///
/// Die WebAuthn-`prf`-Erweiterung liefert 32 Byte je Ausgabe. Eine andere
/// Laenge ist kein Grenzfall, den man dehnen koennte, sondern eine Aussage
/// darueber, dass der Aufrufer etwas anderes geschickt hat als eine
/// PRF-Ausgabe — dieselbe Lesart wie in [`crate::vault_bridge`].
#[cfg(target_arch = "wasm32")]
const PRF_OUTPUT_SIZE: usize = 32;

/// Der Code fuer eine Bruecken-Eingabe, die keine Aussage des Enrollments ist.
///
/// Eine falsche Argumentform ist ein Fehler des Aufrufers und kein Befund ueber
/// das Enrollment; sie bekommt deshalb einen eigenen Code und nicht einen der
/// Enrollment-Codes, die eine Weigerung BEDEUTEN.
#[cfg(target_arch = "wasm32")]
const BRIDGE_ARGUMENT_CODE: &str = "EA-READER-ENROLLMENT-BRIDGE-ARGUMENT";

/// Der Code fuer ein `attestationObject`, das die WebAuthn-Form nicht haelt.
///
/// Getrennt vom Argumentcode, weil die zwei Faelle verschiedene Adressaten
/// haben: der eine sagt „der Aufrufer hat falsch gerufen", dieser sagt „was der
/// Browser geliefert hat, ist keine attestierte Credentialdatenstruktur".
#[cfg(target_arch = "wasm32")]
const BRIDGE_ATTESTATION_CODE: &str = "EA-READER-ENROLLMENT-BRIDGE-ATTESTATION";

/// Die COSE-Algorithmuskennung, die `enrollmentBegin` als einzige anbietet.
///
/// `-8` ist EdDSA (RFC 9053 §2.2). Die Auswahl ist NICHT frei:
/// `WebauthnCredentialRegistrationV1::new` weist jeden oeffentlichen Schluessel
/// ab, den `CanonicalPublicCoseKey::from_deterministic_cbor` nicht als
/// `Ed25519`-Arm zurueckgibt, und diese Pruefung ist auf Stufe 3 eingefroren.
/// Ein stiller Rueckfall auf ES256 im Browser liefe deshalb erst spaeter und an
/// einer Stelle auf, an der niemand die Ursache sucht.
///
/// Dasselbe cfg wie [`canonical_credential_public_key`]: die Umschrift prueft
/// den Wert gegen die Karte des Browsers, und der Wirtstest bezeugt sie.
#[cfg(any(target_arch = "wasm32", test))]
const CREDENTIAL_PUBLIC_KEY_ALGORITHM_V1: i32 = -8;

/// Die groesste Verschachtelungstiefe, die der CBOR-Gang mitgeht.
///
/// Das `attestationObject` kommt aus dem Browser und damit aus einer Quelle,
/// die dieses Modul nicht kontrolliert; eine unbegrenzt rekursive Struktur
/// waere ein Stapelueberlauf statt einer Weigerung. Die attestierte
/// Credentialdatenstruktur ist zwei Ebenen tief, sechzehn sind also
/// grosszuegig.
#[cfg(any(target_arch = "wasm32", test))]
const MAX_CBOR_NESTING_V1: u8 = 16;

#[cfg(target_arch = "wasm32")]
thread_local! {
    /// Die laufenden Enrollments dieses Workers.
    ///
    /// `ReaderEnrollment` traegt WEDER Lebenszeit- NOCH Typparameter — genau
    /// deshalb ist diese Tabelle moeglich. Bytespeicher und Endpunktport
    /// werden erst an `finish` uebergeben und nie festgehalten.
    static ENROLLMENTS: RefCell<BTreeMap<u32, ReaderEnrollment>> =
        const { RefCell::new(BTreeMap::new()) };
    /// Die bestaetigten Fingerprint-Vergleiche, je Enrollment hoechstens einer.
    ///
    /// `FingerprintConfirmationV1` kann die Grenze nach JavaScript NICHT
    /// ueberqueren, und das ist der ganze Punkt des Gates: der Typ ist
    /// ausschliesslich in `confirm_fingerprints` konstruierbar. Er bleibt
    /// deshalb hier liegen, bis `finish` ihn abholt.
    static CONFIRMATIONS: RefCell<BTreeMap<u32, FingerprintConfirmationV1>> =
        const { RefCell::new(BTreeMap::new()) };
    /// Der Zaehler BEIDER Tabellen dieses Moduls. EINER, damit eine
    /// Enrollment-Kennung nie mit einer Bestaetigungskennung verwechselt werden
    /// kann — dieselbe Anordnung, die [`crate::vault_bridge`] fuer seine zwei
    /// Tabellen schon haelt. Ein eigener Zaehler und nicht der von dort: die
    /// beiden Kennungsraeume sind getrennt, sie reisen ueber verschiedene
    /// Nachrichtenarten, und `crates/ea-reader-wasm/src/vault_bridge.rs` steht
    /// nicht im Umfang dieser Aufgabe.
    static NEXT_HANDLE: Cell<u32> = const { Cell::new(1) };
}

/// Die naechste Enrollment-Kennung, monoton und nie wiederverwendet.
#[cfg(target_arch = "wasm32")]
fn next_handle() -> u32 {
    NEXT_HANDLE.with(|counter| {
        let handle = counter.get();
        counter.set(handle.wrapping_add(1));
        handle
    })
}

// ---------------------------------------------------------------------------
// Der CBOR-Gang durch das `attestationObject`.
//
// Warum von Hand und nicht mit `minicbor`: diese Crate traegt keine
// CBOR-Kante, und der Files-Block der Aufgabe legt auch keine an. Gebraucht
// werden zwei Dinge und sonst nichts — der Wert zu `authData` im aeusseren
// Rahmen und das ENDE der COSE-Karte in den attestierten Credentialdaten. Das
// zweite ist der eigentliche Grund: `CanonicalPublicCoseKey::
// from_deterministic_cbor` verlangt EXAKTE Bytes (`decoder.position() !=
// bytes.len()` ist dort eine Weigerung), und hinter der Karte koennen
// Erweiterungsausgaben stehen. Ein Rest-des-Puffers-Schnitt waere also still
// falsch, sobald der Authenticator das ED-Flag setzt.
//
// Die Funktionen stehen unter `cfg(any(target_arch = "wasm32", test))` und
// nicht unter `cfg(target_arch = "wasm32")`: auf einem Wirtsziel waeren sie
// sonst tot, unter `-D warnings` also ein Fehler — und ohne Wirtsziel gaebe es
// fuer sie ueberhaupt keinen Zeugen, weil `tests/opfs_browser.rs` einen
// Browser voraussetzt.
// ---------------------------------------------------------------------------

/// Liest EINEN CBOR-Kopf und gibt Haupttyp, Argument und die Position dahinter.
///
/// Unbestimmte Laengen (`additional == 31`) und die reservierten Werte 28..=30
/// sind eine Weigerung: deterministisches CBOR kennt sie nicht, und der
/// CTAP2-Rahmen eines `attestationObject` ebenso wenig.
#[cfg(any(target_arch = "wasm32", test))]
fn cbor_head(bytes: &[u8], at: usize) -> Option<(u8, u64, usize)> {
    let initial = *bytes.get(at)?;
    let major = initial >> 5;
    let (argument, next) = match initial & 0x1f {
        additional @ 0..=23 => (u64::from(additional), at.checked_add(1)?),
        24 => (
            u64::from(*bytes.get(at.checked_add(1)?)?),
            at.checked_add(2)?,
        ),
        25 => (
            u64::from(u16::from_be_bytes(
                bytes
                    .get(at.checked_add(1)?..at.checked_add(3)?)?
                    .try_into()
                    .ok()?,
            )),
            at.checked_add(3)?,
        ),
        26 => (
            u64::from(u32::from_be_bytes(
                bytes
                    .get(at.checked_add(1)?..at.checked_add(5)?)?
                    .try_into()
                    .ok()?,
            )),
            at.checked_add(5)?,
        ),
        27 => (
            u64::from_be_bytes(
                bytes
                    .get(at.checked_add(1)?..at.checked_add(9)?)?
                    .try_into()
                    .ok()?,
            ),
            at.checked_add(9)?,
        ),
        _ => return None,
    };
    Some((major, argument, next))
}

/// Ueberspringt GENAU EINEN CBOR-Wert und gibt die Position dahinter.
///
/// Der Rueckgabewert ist die eigentliche Leistung dieser Funktion: er ist das
/// exakte Ende des Wertes, und nur damit laesst sich die COSE-Karte
/// bytegenau ausschneiden.
#[cfg(any(target_arch = "wasm32", test))]
fn cbor_skip(bytes: &[u8], at: usize, depth: u8) -> Option<usize> {
    if depth > MAX_CBOR_NESTING_V1 {
        return None;
    }
    let (major, argument, next) = cbor_head(bytes, at)?;
    let length = usize::try_from(argument).ok()?;
    match major {
        // Ganzzahlen und die einfachen Werte tragen ihren Inhalt im Kopf.
        0 | 1 | 7 => Some(next),
        // Byte- und Textketten: der Kopf nennt die Laenge.
        2 | 3 => {
            let end = next.checked_add(length)?;
            (end <= bytes.len()).then_some(end)
        }
        // Ein Feld: `length` Elemente.
        4 => (0..length).try_fold(next, |position, _| cbor_skip(bytes, position, depth + 1)),
        // Eine Karte: `length` PAARE, also doppelt so viele Elemente.
        5 => (0..length.checked_mul(2)?)
            .try_fold(next, |position, _| cbor_skip(bytes, position, depth + 1)),
        // Eine Marke steht vor genau einem Wert.
        6 => cbor_skip(bytes, next, depth + 1),
        _ => None,
    }
}

/// Hebt `credentialId` und die COSE-Schluesselbytes aus einem
/// `attestationObject`.
///
/// Der Weg ist der aus dem WebAuthn-Level-3-Text: der aeussere Rahmen ist eine
/// CBOR-Karte mit dem Eintrag `authData`, und `authData` ist
/// `rpIdHash` (32) ‖ `flags` (1) ‖ `signCount` (4) ‖ attestierte
/// Credentialdaten ‖ optionale Erweiterungsausgaben. Die attestierten
/// Credentialdaten sind `aaguid` (16) ‖ `credentialIdLength` (2, big-endian) ‖
/// `credentialId` ‖ `credentialPublicKey`, und der oeffentliche Schluessel ist
/// eine CBOR-Karte OHNE vorangestellte Laenge — deshalb der CBOR-Gang.
///
/// Ein fehlendes AT-Flag ist eine Weigerung und keine leere Ausgabe: ohne das
/// Flag gibt es die attestierten Credentialdaten schlicht nicht, und ein
/// Rueckfall auf eine geratene Position waere genau die stille Uebernahme, die
/// hier nicht stattfinden darf.
#[cfg(any(target_arch = "wasm32", test))]
fn attested_credential(attestation_object: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    /// Bit 6 von `flags`: attestierte Credentialdaten liegen vor.
    const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
    /// `rpIdHash` (32) ‖ `flags` (1) ‖ `signCount` (4).
    const ATTESTED_DATA_START: usize = 37;
    /// … plus `aaguid` (16).
    const CREDENTIAL_ID_LENGTH_AT: usize = ATTESTED_DATA_START + 16;
    /// … plus `credentialIdLength` (2).
    const CREDENTIAL_ID_AT: usize = CREDENTIAL_ID_LENGTH_AT + 2;

    let (major, entries, mut at) = cbor_head(attestation_object, 0)?;
    if major != 5 {
        return None;
    }
    let mut auth_data: Option<&[u8]> = None;
    for _ in 0..entries {
        let (key_major, key_length, key_start) = cbor_head(attestation_object, at)?;
        if key_major != 3 {
            return None;
        }
        let key_end = key_start.checked_add(usize::try_from(key_length).ok()?)?;
        let key = attestation_object.get(key_start..key_end)?;
        if key == b"authData" {
            let (value_major, value_length, value_start) = cbor_head(attestation_object, key_end)?;
            if value_major != 2 {
                return None;
            }
            let value_end = value_start.checked_add(usize::try_from(value_length).ok()?)?;
            auth_data = Some(attestation_object.get(value_start..value_end)?);
            at = value_end;
        } else {
            at = cbor_skip(attestation_object, key_end, 0)?;
        }
    }

    let auth_data = auth_data?;
    if *auth_data.get(32)? & FLAG_ATTESTED_CREDENTIAL_DATA == 0 {
        return None;
    }
    let credential_id_length = usize::from(u16::from_be_bytes(
        auth_data
            .get(CREDENTIAL_ID_LENGTH_AT..CREDENTIAL_ID_AT)?
            .try_into()
            .ok()?,
    ));
    let credential_id_end = CREDENTIAL_ID_AT.checked_add(credential_id_length)?;
    let credential_id = auth_data.get(CREDENTIAL_ID_AT..credential_id_end)?.to_vec();
    let public_key_end = cbor_skip(auth_data, credential_id_end, 0)?;
    let public_key = auth_data.get(credential_id_end..public_key_end)?.to_vec();
    Some((credential_id, public_key))
}

/// Schreibt den `credentialPublicKey` aus WebAuthn in die KANONISCHE Form um.
///
/// # Warum das ueberhaupt noetig ist — GEMESSEN und nicht vermutet
///
/// Die beiden Formen sind NICHT dieselbe Karte, und der Unterschied ist genau
/// ein Eintrag. WebAuthn schreibt fuer `credentialPublicKey` eine COSE_Key-Karte
/// vor, die den Algorithmus MITFUEHRT — `{1: 1, 3: -8, -1: 6, -2: h'…'}`, vier
/// Eintraege. `CanonicalPublicCoseKey::to_deterministic_cbor` in
/// `crates/ea-crypto/src/thumbprint.rs` schreibt dagegen DREI Eintraege ohne
/// `alg` (`{1: 1, -1: 6, -2: h'…'}`), und `from_deterministic_cbor` weist alles
/// ab, was nicht `map(3)` ist.
///
/// Ohne diese Umschrift kann DEINE Bruecke keinen einzigen echten Authenticator
/// aufnehmen: `ReaderEnrollment::register_authenticator` faellt fuer JEDES
/// Browser-Credential mit `EA-CRYPTO-UNSUPPORTED-SUITE`. Gemessen an Chromiums
/// virtuellem CTAP2-Authenticator, der unter `pubKeyCredParams: [{alg: -8}]`
/// die Karte `a4 0101 0327 2006 215820 …` liefert — also einen ECHTEN
/// Ed25519-Schluessel in der WebAuthn-Form. Der Befund ist damit KEINE
/// Aussage ueber die eingefrorene Stufe-3-Flaeche: der Algorithmus stimmt, die
/// Kartenform nicht.
///
/// # Warum die Probe STRENG ist und keine Karte durchwinkt
///
/// Erwartet wird genau die eine Form, die WebAuthn Level 3 fuer ein
/// Ed25519-Credential vorschreibt, in genau ihrer Reihenfolge: `credentialPublic
/// Key` MUSS in CTAP2-kanonischem CBOR kodiert sein, und dort stehen die
/// unsigned Label vor den negativen — also `1`, `3`, `-1`, `-2`. Alles andere
/// ist `None` und wird LAUT abgewiesen; ein Rueckfall auf „irgendein Feld
/// heraussuchen" waere die stille Uebernahme, die hier nicht stattfinden darf.
/// Die Rueckgabe entsteht ueber `CanonicalPublicCoseKey::ed25519`, also ueber
/// eine echte Punktpruefung, und nicht durch Umsortieren von Bytes.
#[cfg(any(target_arch = "wasm32", test))]
fn canonical_credential_public_key(webauthn_cose_key: &[u8]) -> Option<Vec<u8>> {
    /// COSE `kty` = `OKP` (RFC 9053 §7.1).
    const KEY_TYPE_OKP: u64 = 1;
    /// COSE `crv` = `Ed25519` (RFC 9053 §7.1).
    const CURVE_ED25519: u64 = 6;

    /// Liest einen Kopf und verlangt genau diesen Haupttyp und dieses Argument.
    fn expect(bytes: &[u8], at: usize, major: u8, argument: u64) -> Option<usize> {
        let (found_major, found_argument, next) = cbor_head(bytes, at)?;
        (found_major == major && found_argument == argument).then_some(next)
    }

    // Ein negatives CBOR-Label `-n` traegt `n - 1` im Kopf: `-1` ist `0x20`,
    // `-2` ist `0x21`, und `alg` = -8 ist `0x27`.
    let negative = |value: i32| -> u64 { u64::try_from(-value - 1).expect("value < 0") };

    let at = expect(webauthn_cose_key, 0, 5, 4)?;
    let at = expect(webauthn_cose_key, at, 0, 1)?;
    let at = expect(webauthn_cose_key, at, 0, KEY_TYPE_OKP)?;
    let at = expect(webauthn_cose_key, at, 0, 3)?;
    let at = expect(
        webauthn_cose_key,
        at,
        1,
        negative(CREDENTIAL_PUBLIC_KEY_ALGORITHM_V1),
    )?;
    let at = expect(webauthn_cose_key, at, 1, negative(-1))?;
    let at = expect(webauthn_cose_key, at, 0, CURVE_ED25519)?;
    let at = expect(webauthn_cose_key, at, 1, negative(-2))?;
    let public_key_at = expect(webauthn_cose_key, at, 2, 32)?;
    let end = public_key_at.checked_add(32)?;
    if end != webauthn_cose_key.len() {
        return None;
    }
    let public: [u8; 32] = webauthn_cose_key.get(public_key_at..end)?.try_into().ok()?;
    Some(
        CanonicalPublicCoseKey::ed25519(public)
            .ok()?
            .to_deterministic_cbor(),
    )
}

/// Ordnet einen WebAuthn-Transportnamen dem Zwei-Werte-Profil zu.
///
/// `hybrid` und sein alter Name `cable` sind der QR-Flow; alles andere ist ein
/// Authenticator an diesem Geraet. Ein UNBEKANNTER Name ist bewusst KEINER von
/// beiden: ihn auf `ClientDevice` abzubilden hiesse, einen Entsperrpfad
/// zuzulassen, ueber den niemand entschieden hat. Die harte Abweisung des
/// QR-Flows selbst steht in `ea_reader::ReaderEnrollment::
/// register_authenticator` und nicht hier.
#[cfg(any(target_arch = "wasm32", test))]
fn transport_profile(transport: &str) -> Option<AuthenticatorTransportProfileV1> {
    match transport {
        "internal" | "usb" | "nfc" | "ble" | "smart-card" => {
            Some(AuthenticatorTransportProfileV1::ClientDevice)
        }
        "hybrid" | "cable" => Some(AuthenticatorTransportProfileV1::CrossDevice),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Der Endpunktport im Browser.
// ---------------------------------------------------------------------------

/// `EnrollmentEndpoints` ueber ein SYNCHRONES `XMLHttpRequest`.
///
/// Der Port ist synchron, weil `ea_reader::ReaderEnrollment::finish` synchron
/// ist, und `finish` ist synchron, weil `ea-reader` keine Wirtsabhaengigkeit
/// tragen darf. Die einzige synchrone Transportflaeche eines Browsers ist ein
/// synchrones `XMLHttpRequest`, und die gibt es AUSSCHLIESSLICH in einem
/// dedizierten Worker: auf dem Hauptthread wirft schon das Setzen von
/// `responseType` auf einer synchronen Anfrage. `fetch` scheidet aus — es gibt
/// ein Promise, und blockierend darauf zu warten hielte genau den Faden an,
/// dessen Ereignisschleife es erfuellen muesste.
///
/// Der Typ traegt KEINEN Zustand: Herkunft und Zeit stehen in
/// `EnrollmentRequestContextV1`, die Kopfzeilen in der Anfrage selbst, und ein
/// Feld hier waere eine zweite Stelle, an der ueber die Adresse entschieden
/// wird.
#[cfg(target_arch = "wasm32")]
struct XhrEnrollmentEndpoints;

#[cfg(target_arch = "wasm32")]
impl XhrEnrollmentEndpoints {
    /// Uebersetzt einen JS-Fehlschlag in `Host`, ohne den Koerper zu nennen.
    fn host(error: &JsValue) -> EnrollmentEndpointError {
        EnrollmentEndpointError::Host(
            error
                .as_string()
                .unwrap_or_else(|| String::from("XMLHttpRequest")),
        )
    }
}

#[cfg(target_arch = "wasm32")]
impl EnrollmentEndpoints for XhrEnrollmentEndpoints {
    /// # Errors
    /// `Host` fuer jeden Fehlschlag des Wirts, `Status` fuer jede Antwort
    /// ausserhalb von 2xx.
    fn send(&mut self, request: &EnrollmentRequestV1) -> Result<Vec<u8>, EnrollmentEndpointError> {
        let xhr = XmlHttpRequest::new().map_err(|error| Self::host(&error))?;
        // Das dritte Argument ist `async`, und es ist FALSCH. Genau daran
        // haengt die ganze Bauform dieses Moduls.
        xhr.open_with_async(request.method().as_str(), request.target_uri(), false)
            .map_err(|error| Self::host(&error))?;
        // Ohne diese Zeile gaebe `response()` eine Zeichenkette, und ein
        // CBOR-Koerper ueberlebte den Weg nicht. In einem Worker ist sie auch
        // auf einer synchronen Anfrage zulaessig.
        xhr.set_response_type(XmlHttpRequestResponseType::Arraybuffer);
        for (name, value) in request.headers() {
            xhr.set_request_header(name, value)
                .map_err(|error| Self::host(&error))?;
        }
        xhr.send_with_opt_u8_array(Some(request.body()))
            .map_err(|error| Self::host(&error))?;

        let status = xhr.status().map_err(|error| Self::host(&error))?;
        if !(200..300).contains(&status) {
            return Err(EnrollmentEndpointError::Status(status));
        }
        let response = xhr.response().map_err(|error| Self::host(&error))?;
        if response.is_null() || response.is_undefined() {
            return Ok(Vec::new());
        }
        Ok(Uint8Array::new(&response).to_vec())
    }
}

// ---------------------------------------------------------------------------
// Kleine Uebersetzer zwischen den Argumenten der Grenze und den Typen des
// Kerns. Sie geben JS-Werte zurueck, die NUR einen stabilen Code tragen: der
// Text einer Wirtsmeldung kann eine Kennung nennen, ein Code nie.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
fn bridge_argument() -> JsValue {
    JsValue::from_str(BRIDGE_ARGUMENT_CODE)
}

#[cfg(target_arch = "wasm32")]
fn blob_failure(error: &ReaderBlobError) -> JsValue {
    JsValue::from_str(error.code())
}

/// Fuehrt eine Rechnung auf einem laufenden Enrollment aus.
///
/// Die Ausleihe wird NIE ueber einen JS-Aufruf hinweg gehalten — dieselbe
/// Regel wie bei [`crate::vault_bridge::with_unlocked_vault`]: eine `RefCell`,
/// die waehrend eines Promise offen steht, faellt beim naechsten Ereignis mit
/// einer Doppelausleihe um.
#[cfg(target_arch = "wasm32")]
fn with_enrollment<R>(
    handle: u32,
    use_it: impl FnOnce(&mut ReaderEnrollment) -> R,
) -> Result<R, JsValue> {
    ENROLLMENTS.with(|enrollments| {
        enrollments
            .borrow_mut()
            .get_mut(&handle)
            .map(use_it)
            .ok_or_else(bridge_argument)
    })
}

/// Die bisher aufgenommenen `credentialId`s als JSON-Feld von Hexzeichenketten.
///
/// Sie reisen ueber ZWEI der fuenf Ausfuhren mit — `enrollmentBegin` und
/// `enrollmentRegisterAuthenticator` —, weil beide den aktuellen Satz kennen
/// und keine sechste Ausfuhr dafuer entstehen darf. Der Empfaenger setzt sie
/// unveraendert als `excludeCredentials` in die naechste
/// `navigator.credentials.create`-Zeremonie; die Begruendung, warum diese Liste
/// aus RUST kommen muss und nicht in der Oberflaeche gefuehrt werden darf,
/// steht vollstaendig bei `ReaderEnrollment::registered_credential_ids`.
///
/// Hexadezimal und ein Feld von Zeichenketten, weil das die Schreibweise
/// dieser Bruecke ist: `prfSalt` reist genauso, und der Hauptthread hat mit
/// `bytesFromHex` die Umrechnung ohnehin schon.
#[cfg(target_arch = "wasm32")]
fn registered_credential_ids_json(enrollment: &ReaderEnrollment) -> String {
    let ids: Vec<String> = enrollment
        .registered_credential_ids()
        .iter()
        .map(|id| format!("\"{}\"", hex::encode(id)))
        .collect();
    format!("[{}]", ids.join(","))
}

// ---------------------------------------------------------------------------
// Die fuenf Ausfuhren und keine sechste. JEDE traegt ihr eigenes
// `cfg(target_arch = "wasm32")` unmittelbar ueber dem Attribut —
// `every_wasm_bindgen_export_sits_behind_the_wasm32_cfg` liest das als Text
// und folgt keinem `mod`.
//
// Jede gibt ihren Status als JSON-Zeichenkette heraus, wie die Ausfuhren in
// `crate::bridge`: TypeScript bekommt Ansichts- und Status-DTOs und nie ein
// Rechenobjekt. Eingesetzt werden ausschliesslich Zahlen, Hexzeichenketten und
// feste Codes — es gibt in diesen Zeichenketten nichts zu maskieren.
// ---------------------------------------------------------------------------

/// Legt ein Enrollment an und gibt seine Kennung heraus.
///
/// `organization_id` und `subject_id` sind je 16 Byte, `bundle_fingerprint`
/// 32. `pinned_anchor` sind die EXAKTEN Bytes des gepinnten Root-Ankers: er
/// kommt als Argument und niemals aus einer Serverantwort, und er gilt nicht,
/// weil er irgendwo lag, sondern weil `decode_trust_anchor` seinen
/// Bootstrap-Hash beim Dekodieren NEU rechnet.
///
/// Zurueck geht
/// `{"handle":…,"prfSalt":"<hex>","publicKeyAlgorithms":[-8],"registeredCredentialIds":[]}`.
/// Das Salz ist `VAULT_PRF_SALT_V1` aus geteiltem Rust — es steht deshalb in
/// KEINER Datei von `apps/web`, und `webauthn-prf.ts` schreibt keine einzige
/// kryptografische Konstante hin. Hexadezimal, weil das die Schreibweise
/// dieser Bruecke ist; der Worker macht daraus ein `Uint8Array`.
///
/// `registeredCredentialIds` ist an dieser Stelle IMMER leer — ein eben
/// angelegtes Enrollment hat keinen Authenticator. Es steht trotzdem hier und
/// wird GERECHNET statt als `[]` hingeschrieben, weil die erste Zeremonie
/// ihren Ausschlusssatz von derselben Stelle bekommen soll wie jede spaetere:
/// eine zweite Quelle derselben Wahrheit waere genau die Stelle, an der ein
/// spaeterer Umbau die leere Liste stehen liesse.
///
/// # Warum auch DIESE Ausfuhr asynchron ist
///
/// `ReaderEnrollment::begin` liest den lokalen Bytespeicher und WEIGERT sich
/// auf einem Geraet, das schon einen versiegelten Tresor traegt. Genau das ist
/// der Grund, aus dem der eben genannte leere Ausschlusssatz nicht gefaehrlich
/// ist: ein zweiter Besuch auf `/enrollment` bekommt gar kein Enrollment mehr,
/// statt eines mit leerem Satz. Der Speicher kommt wie in
/// [`enrollment_finish`] ueber EINEN asynchronen Vorlauf auf
/// `READER_VAULT_BLOB_KEY_V1`; ein `FileSystemSyncAccessHandle` liest synchron,
/// sein OEFFNEN tut es nicht. Die drei mittleren Ausfuhren beruehren keinen
/// Wirtsspeicher und bleiben synchron.
///
/// # Errors
/// `EA-READER-ENROLLMENT-BRIDGE-ARGUMENT` fuer eine Kennung oder einen
/// Fingerprint falscher Laenge, `EA-READER-BLOB-KEY`/`EA-READER-BLOB-HOST` aus
/// dem Vorlauf, `EA-READER-ENROLLMENT-VAULT-PRESENT` auf einem Geraet mit
/// bereits versiegeltem Tresor, die stabilen Codes von `ea-trust` fuer einen
/// Anker, der nicht dekodiert, und die des Enrollments fuer alles Weitere.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "enrollmentBegin")]
pub async fn enrollment_begin(
    organization_id: Vec<u8>,
    subject_id: Vec<u8>,
    pinned_anchor: Vec<u8>,
    bundle_fingerprint: Vec<u8>,
) -> Result<String, JsValue> {
    let organization_id =
        OrganizationId::try_from(&organization_id[..]).map_err(|_| bridge_argument())?;
    let subject_id = SubjectId::try_from(&subject_id[..]).map_err(|_| bridge_argument())?;
    let bundle_fingerprint =
        Hash32::try_from(&bundle_fingerprint[..]).map_err(|_| bridge_argument())?;
    let anchor =
        decode_trust_anchor(&pinned_anchor).map_err(|error| JsValue::from_str(error.code()))?;
    let key = ReaderBlobKey::new(READER_VAULT_BLOB_KEY_V1).map_err(|error| blob_failure(&error))?;
    let store = OpfsBlobStore::open(ENROLLMENT_BLOB_DIRECTORY, std::slice::from_ref(&key))
        .await
        .map_err(|error| blob_failure(&error))?;
    let enrollment = ReaderEnrollment::begin(
        &store,
        organization_id,
        subject_id,
        anchor,
        bundle_fingerprint,
    )
    .map_err(|error| JsValue::from_str(error.code()))?;

    let registered_credential_ids = registered_credential_ids_json(&enrollment);
    let handle = next_handle();
    ENROLLMENTS.with(|enrollments| {
        enrollments.borrow_mut().insert(handle, enrollment);
    });
    let salt = hex::encode(VAULT_PRF_SALT_V1);
    Ok(format!(
        "{{\"handle\":{handle},\"prfSalt\":\"{salt}\",\"publicKeyAlgorithms\":[{CREDENTIAL_PUBLIC_KEY_ALGORITHM_V1}],\"registeredCredentialIds\":{registered_credential_ids}}}"
    ))
}

/// Nimmt einen Authenticator auf und gibt den Stand der Kardinalitaet heraus.
///
/// `attestation_object` sind die ROHEN Bytes aus
/// `PublicKeyCredential.response.attestationObject`; `credentialId` und die
/// COSE-Schluesselbytes werden HIER gehoben und nicht in TypeScript. Eine
/// nicht-kanonische Karte scheitert anschliessend in
/// `CanonicalPublicCoseKey::from_deterministic_cbor` an der Rueckprobe gegen
/// die eigenen Bytes und wird LAUT abgewiesen statt still uebernommen. Eine
/// Attestation-AUSSAGE wird NICHT geprueft — §6.6 verlangt sie nicht, und sie
/// hier zu behaupten waere eine Ueberzusage.
///
/// Die PRF-Ausgabe kommt als BESITZENDER `Vec<u8>` ueber die Grenze und wird
/// nach der Uebernahme in `SecretBytes<32>` in BEIDEN Klartextkopien geloescht
/// — dem `Vec<u8>` von der Grenze UND dem `[u8; 32]`, ueber das
/// `SecretBytes::new` gebaut wird. Das zweite ist keine
/// Peinlichkeitsvermeidung: `SecretBytes::new` nimmt sein Array BY VALUE, und
/// `[u8; 32]` ist `Copy`.
///
/// Zurueck geht
/// `{"registered":…,"required":2,"registeredCredentialIds":["<hex>",…]}`.
///
/// Das dritte Feld ist der Satz, den die NAECHSTE Zeremonie ausschliessen muss.
/// Er reist hier mit und nicht ueber eine sechste Ausfuhr, weil dieser Aufruf
/// den Satz ohnehin gerade veraendert hat: er ist die einzige Stelle, an der er
/// waechst, also ist er auch die richtige, an der er herausgeht. Warum die
/// Liste in Rust gefuehrt werden MUSS, steht bei
/// `ReaderEnrollment::registered_credential_ids`.
///
/// # Errors
/// `EA-READER-ENROLLMENT-BRIDGE-ARGUMENT` fuer eine unbekannte Kennung, einen
/// unbekannten Transportnamen oder eine PRF-Ausgabe falscher Laenge,
/// `EA-READER-ENROLLMENT-BRIDGE-ATTESTATION` fuer ein `attestationObject`, das
/// die WebAuthn-Form nicht haelt, und die stabilen Codes des Enrollments:
/// `EA-READER-ENROLLMENT-CREDENTIAL-ID-LENGTH`,
/// `EA-READER-ENROLLMENT-TRANSPORT-REFUSED`,
/// `EA-READER-ENROLLMENT-DUPLICATE-AUTHENTICATOR` und
/// `EA-CRYPTO-UNSUPPORTED-SUITE`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "enrollmentRegisterAuthenticator")]
pub fn enrollment_register_authenticator(
    handle: u32,
    attestation_object: Vec<u8>,
    transport: String,
    mut prf_output: Vec<u8>,
) -> Result<String, JsValue> {
    let profile = transport_profile(&transport).ok_or_else(bridge_argument)?;
    let (credential_id, webauthn_cose_key) = attested_credential(&attestation_object)
        .ok_or_else(|| JsValue::from_str(BRIDGE_ATTESTATION_CODE))?;
    // Die Umschrift steht HIER und nicht in `ea-reader`: die WebAuthn-Form ist
    // eine Aussage des BROWSERS, und diese Datei ist die Naht zu ihm.
    let credential_public_cose_key = canonical_credential_public_key(&webauthn_cose_key)
        .ok_or_else(|| JsValue::from_str(BRIDGE_ATTESTATION_CODE))?;
    let mut prf: [u8; PRF_OUTPUT_SIZE] = prf_output
        .as_slice()
        .try_into()
        .map_err(|_| bridge_argument())?;
    prf_output.zeroize();
    let attested = AttestedAuthenticatorV1::new(
        credential_id,
        credential_public_cose_key,
        profile,
        SecretBytes::new(prf),
    );
    prf.zeroize();

    let (registered, registered_credential_ids) =
        with_enrollment(handle, |enrollment| -> Result<(usize, String), JsValue> {
            // Zwei Anweisungen und kein `map`: `register_authenticator` gibt eine
            // AUSLEIHE auf das Enrollment zurueck, und `registered_authenticator_
            // count` braucht daneben eine zweite. Erst das Semikolon beendet die
            // erste (`E0502`, gemessen). Aus demselben Grund steht auch
            // `registered_credential_ids_json` hinter dem Semikolon.
            enrollment
                .register_authenticator(attested)
                .map_err(|error| JsValue::from_str(error.code()))?;
            Ok((
                enrollment.registered_authenticator_count(),
                registered_credential_ids_json(enrollment),
            ))
        })??;
    Ok(format!(
        "{{\"registered\":{registered},\"required\":{MIN_ENROLLED_AUTHENTICATORS_V1},\"registeredCredentialIds\":{registered_credential_ids}}}"
    ))
}

/// Gibt die ANGEZEIGTEN Fingerprints heraus.
///
/// Beide sind 64 Hexzeichen und UNGRUPPIERT. Die Gruppierung waere keine
/// Kosmetik: `hex::decode` auf der Gegenseite weist jedes Leer- und
/// Bindezeichen ab, ein gruppierter Wert liefe also in
/// `EA-READER-ENROLLMENT-FINGERPRINT-ENCODING` statt in eine Uebereinstimmung.
///
/// Zurueck geht `{"keyFingerprint":"<hex>","bundleFingerprint":"<hex>"}`.
///
/// # Errors
/// `EA-READER-ENROLLMENT-BRIDGE-ARGUMENT` fuer eine unbekannte Kennung.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "enrollmentFingerprints")]
pub fn enrollment_fingerprints(handle: u32) -> Result<String, JsValue> {
    let (key, bundle) = with_enrollment(handle, |enrollment| {
        let shown = enrollment.fingerprints();
        (shown.key_fingerprint_hex(), shown.bundle_fingerprint_hex())
    })?;
    Ok(format!(
        "{{\"keyFingerprint\":\"{key}\",\"bundleFingerprint\":\"{bundle}\"}}"
    ))
}

/// Vergleicht die abgetippte Referenz mit den angezeigten Werten.
///
/// Der Vergleich selbst laeuft in `ea_reader` und konstantzeitig; hier steht
/// keine Zeichenkettenprobe. Eine ABWEICHUNG ist KEIN Ausnahmefall, sondern
/// ein Ergebnis: sie kommt als `{"confirmed":false,"code":…}` zurueck, damit
/// die Oberflaeche sie anzeigen kann, ohne einen Fehlerpfad zu bauen. Nur eine
/// unbekannte Kennung ist ein Fehler des Aufrufers und wirft.
///
/// Bei Uebereinstimmung bleibt die `FingerprintConfirmationV1` HIER liegen —
/// sie kann die Grenze nach JavaScript nicht ueberqueren, und genau das macht
/// das Gate nach §4.3 unueberspringbar: `finish` nimmt diesen Typ, und der ist
/// ausschliesslich in `confirm_fingerprints` konstruierbar.
///
/// Zurueck geht `{"confirmed":true}` oder
/// `{"confirmed":false,"code":"EA-READER-ENROLLMENT-FINGERPRINT-…"}`.
///
/// # Errors
/// `EA-READER-ENROLLMENT-BRIDGE-ARGUMENT` fuer eine unbekannte Kennung.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "enrollmentConfirmFingerprints")]
pub fn enrollment_confirm_fingerprints(
    handle: u32,
    expected_key_fingerprint: String,
    expected_bundle_fingerprint: String,
) -> Result<String, JsValue> {
    let confirmed = with_enrollment(handle, |enrollment| {
        enrollment.confirm_fingerprints(&expected_key_fingerprint, &expected_bundle_fingerprint)
    })?;
    match confirmed {
        Ok(confirmation) => {
            CONFIRMATIONS.with(|confirmations| {
                confirmations.borrow_mut().insert(handle, confirmation);
            });
            Ok(String::from("{\"confirmed\":true}"))
        }
        Err(error) => {
            // Eine verworfene Bestaetigung darf keine aeltere stehen lassen:
            // sonst oeffnete ein zweiter, falscher Versuch das Enrollment
            // trotzdem, weil der erste noch in der Tabelle liegt.
            CONFIRMATIONS.with(|confirmations| {
                confirmations.borrow_mut().remove(&handle);
            });
            let code = error.code();
            Ok(format!("{{\"confirmed\":false,\"code\":\"{code}\"}}"))
        }
    }
}

/// Schliesst das Enrollment ab: drei Endpunktaufrufe, dann der lokale Tresor.
///
/// # Warum diese Ausfuhr ASYNCHRON ist
///
/// `finish` schreibt am Ende ueber den SYNCHRONEN `ReaderBlobStore`, und
/// `OpfsBlobStore::open` verlangt die Schluessel VOR dem Vorlauf — ein Zugriff
/// auf einen nicht vorgelaufenen Schluessel faellt mit `EA-READER-BLOB-HOST`.
/// Die Ausfuhr macht deshalb, was `blobPut` und `blobGet` schon machen: EIN
/// asynchroner Vorlauf oeffnet `READER_VAULT_BLOB_KEY_V1`, danach laeuft
/// `finish` vollstaendig synchron durch, Endpunkte eingeschlossen. Sie ist
/// nicht die einzige: [`enrollment_begin`] traegt denselben Vorlauf, seit sein
/// Tor den Geraetezustand liest. Die drei mittleren Ausfuhren beruehren keinen
/// Wirtsspeicher und bleiben synchron.
///
/// # Uhr und Herkunft treten als WERTE ein
///
/// `created_unix_seconds` kommt herein, weil `wasm32-unknown-unknown` keinen
/// Wirt fuer `SystemTime::now()` hat — das ist eine Unmoeglichkeit. Auf der
/// JS-Seite ist der Parameter ein `BigInt`, weil `wasm_bindgen` `i64` so
/// abbildet. `authority` kommt herein, weil `ea-reader` keine Konfiguration
/// liest; sie ist der einzige Wert dieser Flaeche, den die Bruecke BESTIMMT
/// statt zu TRAGEN, und sie bindet die RFC-9421-Signatur an eine Herkunft.
///
/// # Das Enrollment ist danach VERBRAUCHT, auch im Fehlerfall
///
/// `ReaderEnrollment::finish` nimmt `self` besitzend; ein gefallener Aufruf
/// laesst sich deshalb nicht wiederholen, und die Kennung ist danach
/// unbekannt. Das ist keine Bequemlichkeit, sondern die Folge der Signatur —
/// wer erneut anfaengt, faengt mit frischen Schluesseln an, und ein zweiter
/// Versuch ueber dieselben Schluessel gaebe es nicht.
///
/// Zurueck geht `{"finished":true}`.
///
/// # Errors
/// `EA-READER-ENROLLMENT-BRIDGE-ARGUMENT` fuer eine unbekannte Kennung oder
/// ein Enrollment ohne bestaetigten Fingerprint-Vergleich,
/// `EA-READER-BLOB-KEY`/`EA-READER-BLOB-HOST` aus dem Vorlauf und die stabilen
/// Codes des Enrollments — insbesondere
/// `EA-READER-ENROLLMENT-SINGLE-AUTHENTICATOR` und
/// `EA-READER-ENROLLMENT-ENDPOINT-STATUS`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "enrollmentFinish")]
pub async fn enrollment_finish(
    handle: u32,
    authority: String,
    created_unix_seconds: i64,
) -> Result<String, JsValue> {
    // Erst pruefen, dann den Vorlauf fahren: ein Handle, das es nicht gibt,
    // soll kein OPFS-Handle oeffnen. Die Ausleihe endet VOR dem `await`.
    let known = ENROLLMENTS.with(|enrollments| enrollments.borrow().contains_key(&handle));
    if !known {
        return Err(bridge_argument());
    }
    let key = ReaderBlobKey::new(READER_VAULT_BLOB_KEY_V1).map_err(|error| blob_failure(&error))?;
    let mut store = OpfsBlobStore::open(ENROLLMENT_BLOB_DIRECTORY, std::slice::from_ref(&key))
        .await
        .map_err(|error| blob_failure(&error))?;

    // Beides wird ENTNOMMEN und nicht geliehen: `finish` nimmt `self` und die
    // Bestaetigung besitzend.
    let enrollment = ENROLLMENTS
        .with(|enrollments| enrollments.borrow_mut().remove(&handle))
        .ok_or_else(bridge_argument)?;
    let confirmation = CONFIRMATIONS
        .with(|confirmations| confirmations.borrow_mut().remove(&handle))
        .ok_or_else(bridge_argument)?;

    let context = EnrollmentRequestContextV1::new(authority, created_unix_seconds);
    let mut endpoints = XhrEnrollmentEndpoints;
    enrollment
        .finish(confirmation, context, &mut endpoints, &mut store)
        .map_err(|error| JsValue::from_str(error.code()))?;
    Ok(String::from("{\"finished\":true}"))
}

#[cfg(test)]
mod tests {
    use super::{
        attested_credential, canonical_credential_public_key, cbor_head, cbor_skip,
        transport_profile,
    };
    use ea_crypto::CanonicalPublicCoseKey;
    use ea_reader::AuthenticatorTransportProfileV1;

    /// Ein ECHTER Ed25519-Punkt und keine Fuellung.
    ///
    /// Abgelesen aus dem `attestationObject`, das Chromiums virtueller
    /// CTAP2-Authenticator unter `pubKeyCredParams: [{alg: -8}]` geliefert hat.
    /// Er muss ein gueltiger Punkt sein, weil `CanonicalPublicCoseKey::ed25519`
    /// ihn dekomprimiert; eine Bytefuellung wie `[0x11; 32]` bezeugte hier nur
    /// die Ablehnung.
    const CREDENTIAL_PUBLIC_KEY: [u8; 32] = [
        0x8e, 0xba, 0x47, 0xc5, 0x43, 0xc7, 0x0e, 0x0a, 0x80, 0x39, 0x09, 0xdf, 0x75, 0xef, 0xec,
        0x2d, 0x28, 0xb7, 0x0c, 0xad, 0xfc, 0x24, 0x41, 0x40, 0xe1, 0x2c, 0xb5, 0xf3, 0xd2, 0xa0,
        0xaa, 0x3a,
    ];

    /// Die COSE-Karte, wie WEBAUTHN sie liefert: `{1: 1, 3: -8, -1: 6, -2: h'…'}`.
    ///
    /// VIER Eintraege, und der vierte ist der Punkt: `alg` steht mit drin. Diese
    /// Datei baute hier frueher die DREI-Eintraege-Form von
    /// `CanonicalPublicCoseKey::to_deterministic_cbor` — eine Karte, die kein
    /// Browser je liefert. Damit war der Zeuge gruen, waehrend
    /// `register_authenticator` im echten Lauf JEDES Credential mit
    /// `EA-CRYPTO-UNSUPPORTED-SUITE` abwies. Die Vorlage ist deshalb jetzt die
    /// gemessene: 43 Byte, und ihr Ende ist die Zahl, die `attested_credential`
    /// treffen muss.
    fn webauthn_cose_key() -> Vec<u8> {
        let mut key = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        key.extend_from_slice(&CREDENTIAL_PUBLIC_KEY);
        key
    }

    /// Baut ein `attestationObject` mit `fmt`, `attStmt` und `authData`.
    ///
    /// `trailing` steht HINTER der COSE-Karte und ist der eigentliche Zweck des
    /// Zeugen: ein Schnitt „bis zum Ende des Puffers" waere ohne ihn gruen.
    fn attestation_object(credential_id: &[u8], trailing: &[u8]) -> Vec<u8> {
        let mut auth_data = vec![0x22; 32];
        // UP | UV | AT | ED, damit die Erweiterungsausgaben erlaubt sind.
        auth_data.push(0xc5);
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        auth_data.extend_from_slice(&[0x33; 16]);
        auth_data.extend_from_slice(&u16::try_from(credential_id.len()).unwrap().to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(&webauthn_cose_key());
        auth_data.extend_from_slice(trailing);

        let mut object = vec![0xa3];
        object.extend_from_slice(b"\x63fmt");
        object.extend_from_slice(b"\x64none");
        object.extend_from_slice(b"\x67attStmt");
        object.push(0xa0);
        object.extend_from_slice(b"\x68authData");
        object.push(0x59);
        object.extend_from_slice(&u16::try_from(auth_data.len()).unwrap().to_be_bytes());
        object.extend_from_slice(&auth_data);
        object
    }

    #[test]
    fn the_cose_key_ends_where_cbor_says_and_not_where_the_buffer_does() {
        let credential_id = b"ea-reader-passkey-1";
        // Eine leere Erweiterungskarte HINTER dem Schluessel.
        let object = attestation_object(credential_id, &[0xa0]);
        let (found_id, found_key) = attested_credential(&object).expect("wohlgeformt");
        assert_eq!(found_id, credential_id);
        assert_eq!(found_key, webauthn_cose_key());
    }

    #[test]
    fn the_webauthn_cose_key_is_rewritten_into_the_canonical_three_entry_map() {
        let rewritten = canonical_credential_public_key(&webauthn_cose_key())
            .expect("die gemessene WebAuthn-Karte ist ein Ed25519-Credential");
        assert_eq!(
            rewritten,
            CanonicalPublicCoseKey::ed25519(CREDENTIAL_PUBLIC_KEY)
                .expect("ein gemessener Ed25519-Punkt ist ein gueltiger Punkt")
                .to_deterministic_cbor()
        );
        // Die eigentliche Zusage: was hier herauskommt, kommt drueben durch.
        assert!(matches!(
            CanonicalPublicCoseKey::from_deterministic_cbor(&rewritten),
            Ok(CanonicalPublicCoseKey::Ed25519(_))
        ));
    }

    #[test]
    fn a_credential_key_that_is_not_ed25519_in_the_webauthn_form_is_refused() {
        // Schon KANONISCH, also drei Eintraege: dieselbe Karte, die diese Datei
        // frueher als Vorlage benutzte. Sie ist hier eine Weigerung, weil kein
        // Browser sie liefert und ein Durchwinken die Herkunft verschliffe.
        let mut canonical = vec![0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20];
        canonical.extend_from_slice(&CREDENTIAL_PUBLIC_KEY);
        assert!(canonical_credential_public_key(&canonical).is_none());
        // ES256: `{1: 2, 3: -7, …}` — der Fall, den die Stufe-3-Flaeche nicht
        // kennt. Er faellt HIER und nicht erst an einer Protokollform.
        let mut es256 = vec![0xa4, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        es256.extend_from_slice(&CREDENTIAL_PUBLIC_KEY);
        assert!(canonical_credential_public_key(&es256).is_none());
        // Die richtige Karte mit einem angehaengten Byte: ein Schnitt „bis zum
        // Ende des Puffers" waere hier gruen.
        let mut trailing = webauthn_cose_key();
        trailing.push(0x00);
        assert!(canonical_credential_public_key(&trailing).is_none());
    }

    #[test]
    fn an_attestation_object_without_attested_credential_data_is_refused() {
        let mut object = attestation_object(b"ea-reader-passkey-1", &[]);
        // Das AT-Flag loeschen. Es steht im 32. Byte von `authData`, und
        // `authData` beginnt hinter dem 3-Byte-Kopf seiner Bytekette.
        let flags_at = object
            .windows(9)
            .position(|window| window == b"\x68authData")
            .expect("die Testvorlage traegt authData")
            + 9
            + 3
            + 32;
        object[flags_at] &= !0x40;
        assert!(attested_credential(&object).is_none());
    }

    #[test]
    fn an_indefinite_length_head_is_refused() {
        // 0x5f ist eine Bytekette unbestimmter Laenge — deterministisches CBOR
        // kennt sie nicht.
        assert!(cbor_head(&[0x5f], 0).is_none());
        assert!(cbor_skip(&[0x5f], 0, 0).is_none());
    }

    #[test]
    fn a_truncated_value_is_refused_instead_of_read_past_its_end() {
        // Eine Bytekette, die 4 Byte ankuendigt und 2 traegt.
        assert!(cbor_skip(&[0x44, 0x01, 0x02], 0, 0).is_none());
        assert!(attested_credential(&[0xa3, 0x63]).is_none());
    }

    #[test]
    fn the_cross_device_transports_are_the_only_refused_ones_and_unknown_is_neither() {
        assert_eq!(
            transport_profile("internal"),
            Some(AuthenticatorTransportProfileV1::ClientDevice)
        );
        assert_eq!(
            transport_profile("hybrid"),
            Some(AuthenticatorTransportProfileV1::CrossDevice)
        );
        assert_eq!(
            transport_profile("cable"),
            Some(AuthenticatorTransportProfileV1::CrossDevice)
        );
        assert!(transport_profile("").is_none());
        assert!(transport_profile("bluetooth").is_none());
    }
}
