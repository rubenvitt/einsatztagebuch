//! Die Windows-Ernte des OS-Kontos.
//!
//! Was Stufe 1 verlangt und dieses Modul deshalb ERNTET: die validierte binaere
//! `TokenUser`-SID, ihre sechs Oktette `IdentifierAuthority` in
//! Netzwerkreihenfolge und ihre Subauthorities in Deklarationsreihenfolge —
//! `GetTokenInformation(TokenUser)` liefert genau das. Der Bedienerinstanz-
//! schluessel liegt unter CNG/DPAPI, und die Praesenz wird ueber Windows Hello
//! beziehungsweise die Credential-UI verlangt
//! (`OperatorAuthenticator::prove_presence_and_sign`).
//!
//! Was hier ausdruecklich NICHT geerntet wird: der Anmeldename, der Anzeigename,
//! die Domaene, ein Kennwort oder eine textuelle Fassung der SID.
//! `design.md:233` laesst nur die kanonische Angabe zu, und die
//! Stufe-1-Signatur nimmt gar nichts anderes an. Ein Kennwort wird nirgends
//! gespeichert, und Kontoidentitaet wird nie aus der Oberflaeche uebernommen.
//!
//! Was hier NICHT liegt: der Aufruf selbst. `GetTokenInformation` ist eine
//! Win32-Funktion, und Stufe 2 nimmt keine native API-Familie in
//! `[workspace.dependencies]` auf
//! (`docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-153`) — jede
//! Dependency-Aenderung ist ADR-pflichtig, und dieser Task fuehrt keinen ADR.
//! Was hier liegt, ist die vollstaendig pruefbare Haelfte: die typisierte
//! Uebergabe der Rohangaben an Stufe 1, ohne Umformung.
//!
//! Die FOLGE, damit sie niemand erst im Betrieb entdeckt: diese Crate liefert
//! auf dieser Zeile KEINE Implementierung von [`crate::OsAccountProvider`] und
//! keine von [`crate::OperatorAuthenticator::prove_presence_and_sign`]. Beide
//! Haken sind Ports; wer eine Sitzung produktiv aufbauen will, braucht den
//! Task, der CNG/DPAPI und Windows Hello beziehungsweise die Credential UI
//! samt ADR einfuehrt. Bis dahin gibt es genau zwei Erfueller: die Attrappen
//! der Tests. Nichts an dieser Grenze behauptet, eine Praesenz sei geprueft
//! worden.

use crate::account::OsAccountInputs;

/// Bindet die geerntete Windows-SID an ihre Bestandteile.
///
/// Reine Uebergabe: die drei Angaben gehen unveraendert in
/// [`OsAccountInputs::binding_hash`] und damit in
/// `ea_crypto::windows_os_account_binding_hash`, die sie gegeneinander prueft.
#[must_use]
pub fn account_inputs(
    sid: Vec<u8>,
    identifier_authority: [u8; 6],
    subauthorities: Vec<u32>,
) -> OsAccountInputs {
    OsAccountInputs::Windows {
        sid,
        identifier_authority,
        subauthorities,
    }
}
