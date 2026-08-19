//! Die macOS-Ernte des OS-Kontos.
//!
//! Was Stufe 1 verlangt und dieses Modul deshalb ERNTET: die Wertliste
//! `dsAttrTypeStandard:GeneratedUID` des Open-Directory-Datensatzes, die
//! Wertliste `dsAttrTypeStandard:UniqueID` und die UID, die `getuid()`
//! TATSAECHLICH meldet. Stufe 1 dekodiert die GUID daraus zu ihren sechzehn
//! Oktetten in Netzwerkreihenfolge und prueft die beiden Wertlisten gegen die
//! numerische UID; deshalb reisen sie hier unveraendert und nicht als bereits
//! ausgewertete Werte. Der Bedienerinstanzschluessel liegt in der Keychain und
//! in der Secure Enclave, soweit fuer den Algorithmus verfuegbar, und die
//! Praesenz wird ueber LocalAuthentication verlangt.
//!
//! Was hier ausdruecklich NICHT geerntet wird: der Kurzname, der vollstaendige
//! Name, das Heimatverzeichnis oder ein Kennwort. Auch keine „bereinigte" UID:
//! die geforderte Angabe ist die TATSAECHLICHE, damit ein Prozess, der unter
//! einer anderen UID laeuft, als anderes Konto erkannt wird.
//!
//! Was hier NICHT liegt: der Aufruf selbst. Open Directory und
//! LocalAuthentication sind Systemframeworks, und Stufe 2 nimmt keine native
//! API-Familie in `[workspace.dependencies]` auf
//! (`docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-153`).
//!
//! Die FOLGE, damit sie niemand erst im Betrieb entdeckt: diese Crate liefert
//! auf dieser Zeile KEINE Implementierung von [`crate::OsAccountProvider`] und
//! keine von [`crate::OperatorAuthenticator::prove_presence_and_sign`]. Beide
//! Haken sind Ports; wer eine Sitzung produktiv aufbauen will, braucht den
//! Task, der Keychain, Secure Enclave und LocalAuthentication samt ADR
//! einfuehrt. Bis dahin gibt es genau zwei Erfueller: die Attrappen der Tests.
//! Nichts an dieser Grenze behauptet, eine Praesenz sei geprueft worden.

use crate::account::OsAccountInputs;

/// Bindet die geernteten Open-Directory-Werte an die numerische UID.
///
/// Reine Uebergabe. Die beiden Wertlisten behalten ihre Reihenfolge und ihren
/// Wortlaut; eine Normalisierung — Kleinschreibung, entfernte Bindestriche, eine
/// aufgefuellte UID — waere nach `design.md:233` unzulaessig und wird von Stufe 1
/// mit `EA-IDENTITY-INVALID-OS-ACCOUNT` abgewiesen statt zurechtgebogen.
#[must_use]
pub fn account_inputs(
    guid_values: Vec<String>,
    unique_id_values: Vec<String>,
    actual_uid: u32,
) -> OsAccountInputs {
    OsAccountInputs::MacOs {
        guid_values,
        unique_id_values,
        actual_uid,
    }
}
