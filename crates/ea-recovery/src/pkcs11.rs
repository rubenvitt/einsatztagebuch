//! Die explizite PKCS#11-Referenz — und die benannte Grenze dahinter.
//!
//! # DREI PFLICHTANGABEN, KEINE VOREINSTELLUNG
//!
//! Modulpfad, Token-Label und Schluessel-ID sind saemtlich Pflicht. Es gibt
//! kein „erstes Token", keinen Standardmodulpfad und keine Suche ueber alle
//! Slots: die Global Constraint des Stage-5-Plans verbietet, einen
//! Root-/Recovery-/HGA-/Approver-Schluessel durch Absuchen eines Mediums zu
//! finden, und ein Modul, das nicht genannt ist, wird auch nicht geladen. Die
//! PIN kommt aus einer benannten Datei mit restriktiven Rechten
//! ([`crate::read_secret_file`]), nie aus argv und nie aus der Umgebung.
//!
//! # WARUM ES KEINE `cryptoki`-KANTE GIBT
//!
//! `cryptoki` bindet ein PKCS#11-Modul ueber `cryptoki-sys` und `libloading`
//! zur Laufzeit als native Bibliothek. Das zieht genau die Varianz der
//! nativen Toolchain in den Graphen, derentwegen
//! `docs/adr/0001-toolchain-and-cryptography-dependencies.md` unter „Rejected
//! alternatives" OpenSSL und `ring` als suite-weite Abstraktionen abgelehnt
//! hat (`ring` selbst liegt ueber `rustls` weiterhin im Lockfile, siehe
//! `deny.toml`) — und es gibt in dieser
//! Stufe nichts, wogegen die Bindung gemessen werden koennte: kein Modul im
//! Baum, keines auf dem Host, kein SoftHSM im Browser-Container. Eine Bindung
//! ohne Zeugen waere eine Zusage, die kein Test traegt.
//!
//! Die Referenz wird deshalb VOLLSTAENDIG geprueft und die PIN-Datei
//! VOLLSTAENDIG gelesen; danach endet der Lauf mit
//! [`crate::RecoveryError::Pkcs11Unbound`] (Exitcode 21) und benennt die
//! Grenze. Das ist dasselbe Muster wie `--report-signing-key` in ADR 0001,
//! Abschnitt „Blocked": angenommen, verweigert, benannt.
//!
//! # WAS EIN SPAETERER TASK ERGAENZEN MUSS
//!
//! 1. Eine ADR-Zeile fuer `cryptoki` (samt `cryptoki-sys` und `libloading`)
//!    mit Primaerquellen- und RustSec-Pruefung; `libloading` traegt ISC, also
//!    eine NAMENTLICHE Ausnahme in `deny.toml`, falls die Lizenzpruefung sie
//!    verlangt.
//! 2. Ein SoftHSM-Modul im Browser-Container als Zeuge, gegen das Login,
//!    Objektsuche ueber `CKA_LABEL`/`CKA_ID` und Entkapselung beziehungsweise
//!    Signatur gemessen werden.
//! 3. Den Austausch von [`PKCS11_UNBOUND_CODE`] gegen die Bindung — an genau
//!    einer Stelle, in [`crate::key_source`].

use std::path::{Path, PathBuf};

use crate::key_source::{KeySourceKind, KeySourceSpecError};

/// Der Code, mit dem die unverbundene Modulbindung benannt wird.
///
/// DIE BENANNTE GRENZE DIESER STUFE. Ein Aufruf mit einer `pkcs11:`-Quelle
/// endet — nach vollstaendig geprueffter Referenz und gelesener PIN-Datei —
/// mit [`crate::RecoveryError::Pkcs11Unbound`], dessen `code()` genau diese
/// Zeichenkette ist, und mit [`crate::ExitCode::Unsupported`] (21): „nicht
/// unterstuetzte Providerfaehigkeit". Die Begruendung steht im Modulkopf.
pub const PKCS11_UNBOUND_CODE: &str = "EA-RECOVERY-PKCS11-UNBOUND";

/// Die Obergrenze einer `CKA_ID` in Bytes.
///
/// PKCS#11 legt keine harte Grenze fest; 255 Bytes ist die Grenze, die diese
/// Grammatik zieht, damit eine ID nie ein Blob wird. Jeder reale Token liegt
/// weit darunter.
pub const PKCS11_KEY_ID_MAX_BYTES: usize = 255;

/// Eine vollstaendig benannte PKCS#11-Referenz: Modul, Token, Schluessel-ID.
///
/// # Kein `Debug`
///
/// Der Modulpfad ist ein Hostpfad und das Token-Label benennt ein
/// Recovery-Medium; beides darf nach der Global Constraint in keine Ausgabe
/// gelangen. Die Zugriffe geben die Werte einzeln heraus, damit ein Aufrufer
/// bewusst entscheidet, was er damit tut.
#[derive(Clone, Eq, PartialEq)]
pub struct Pkcs11KeyReference {
    module: PathBuf,
    token_label: String,
    key_id: Vec<u8>,
}

impl Pkcs11KeyReference {
    /// Baut die Referenz aus den drei Pflichtangaben.
    ///
    /// `key_id_hex` ist die `CKA_ID` in Hexschreibung, beide
    /// Schreibweisen, gerade Laenge.
    ///
    /// # Errors
    ///
    /// [`KeySourceSpecError::EmptyValue`] fuer ein leeres Label oder eine
    /// leere ID, [`KeySourceSpecError::NotHex`] fuer eine ID, die kein Hex
    /// ist (auch bei ungerader Laenge), [`KeySourceSpecError::ValueTooLong`]
    /// fuer eine ID jenseits von [`PKCS11_KEY_ID_MAX_BYTES`].
    pub fn new(
        module: PathBuf,
        token_label: String,
        key_id_hex: &str,
    ) -> Result<Self, KeySourceSpecError> {
        if token_label.is_empty() {
            return Err(KeySourceSpecError::EmptyValue {
                source: KeySourceKind::Pkcs11,
                field: "token=",
            });
        }
        if key_id_hex.is_empty() {
            return Err(KeySourceSpecError::EmptyValue {
                source: KeySourceKind::Pkcs11,
                field: "id=",
            });
        }
        // Die Laenge ZUERST und in Hexzeichen gerechnet: eine ueberlange ID
        // wird abgewiesen, ohne dass ihre Bytes je entstehen.
        if key_id_hex.len() > 2 * PKCS11_KEY_ID_MAX_BYTES {
            return Err(KeySourceSpecError::ValueTooLong {
                source: KeySourceKind::Pkcs11,
                field: "id=",
            });
        }
        let key_id = decode_hex(key_id_hex).ok_or(KeySourceSpecError::NotHex {
            source: KeySourceKind::Pkcs11,
            field: "id=",
        })?;
        Ok(Self {
            module,
            token_label,
            key_id,
        })
    }

    /// Der Pfad der PKCS#11-Modulbibliothek.
    #[must_use]
    pub fn module(&self) -> &Path {
        &self.module
    }

    /// Das Label des Tokens, in dem der Schluessel liegt.
    #[must_use]
    pub fn token_label(&self) -> &str {
        &self.token_label
    }

    /// Die `CKA_ID` des Schluesselobjekts.
    #[must_use]
    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }
}

/// Dekodiert Hex beider Schreibweisen; `None` bei ungerader Laenge oder einer
/// Ziffer ausser der Reihe.
///
/// Von Hand und nicht ueber `hex`: die Kiste ist eine DEV-Dependency dieser
/// Crate — dieselbe Entscheidung wie in [`crate::decrypt`].
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}

/// Der Wert einer Hexziffer.
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
