//! Die Ubuntu-Ernte des OS-Kontos.
//!
//! Was Stufe 1 verlangt und dieses Modul deshalb ERNTET: den vollstaendigen
//! Inhalt von `/etc/machine-id` samt Zeilenende und die UID, die `getuid()`
//! TATSAECHLICH meldet. Stufe 1 dekodiert die Maschinenkennung daraus zu ihren
//! sechzehn Oktetten; deshalb reisen hier die Dateibytes und nicht ein bereits
//! geparster Wert. Der Bedienerinstanzschluessel liegt in einer per PAM
//! entsperrten Secret-Service-Collection mit eigener zufaelliger Kontoinstanz,
//! und die Praesenz wird ueber PAM beziehungsweise Polkit verlangt.
//!
//! Was hier ausdruecklich NICHT geerntet wird: der Anmeldename, ein
//! `/etc/passwd`-Eintrag, der Hostname oder ein Kennwort. Auch kein
//! zurechtgeschnittener Dateiinhalt: die Bytes reisen wie gelesen, damit eine
//! abweichende Datei als abweichendes Geraet erkannt wird und nicht durch eine
//! eigene Bereinigung angeglichen wird.
//!
//! Was hier NICHT liegt: der Aufruf selbst. `getuid` und der Secret Service
//! liegen hinter libc beziehungsweise D-Bus, und Stufe 2 nimmt keine native
//! API-Familie in `[workspace.dependencies]` auf
//! (`docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-153`).
//!
//! Die FOLGE, damit sie niemand erst im Betrieb entdeckt: diese Crate liefert
//! auf dieser Zeile KEINE Implementierung von [`crate::OsAccountProvider`] und
//! keine von [`crate::OperatorAuthenticator::prove_presence_and_sign`]. Beide
//! Haken sind Ports; wer eine Sitzung produktiv aufbauen will, braucht den
//! Task, der den Secret Service und PAM beziehungsweise Polkit samt ADR
//! einfuehrt. Bis dahin gibt es genau zwei Erfueller: die Attrappen der Tests.
//! Nichts an dieser Grenze behauptet, eine Praesenz sei geprueft worden.

use crate::account::OsAccountInputs;

/// Bindet die geernteten `machine-id`-Bytes an die numerische UID.
///
/// Reine Uebergabe: beide Angaben gehen unveraendert nach Stufe 1.
#[must_use]
pub fn account_inputs(machine_id_file: Vec<u8>, uid: u32) -> OsAccountInputs {
    OsAccountInputs::Linux {
        machine_id_file,
        uid,
    }
}
