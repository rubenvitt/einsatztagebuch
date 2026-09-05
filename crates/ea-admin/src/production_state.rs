//! Schritt 12 und der einzige Weg in den Produktivzustand.
//!
//! Die Spezifikation sagt an dieser Stelle genau einen Satz, und er ist binaer:
//! „Ohne erfolgreichen Schritt 12 darf die Organisation nicht in den
//! Produktivzustand wechseln"
//! (`docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md:1349`).
//! Schritt 12 selbst lautet: „Testeintrag finalisieren, auf einem frischen
//! Rechner mit explizitem finalem Trust Anchor offline verifizieren und per
//! Recovery entschluesseln" (`:1347`).
//!
//! # Woher die beiden NAMEN kommen
//!
//! Ausdruecklich nicht aus der Spezifikation. Sie kennt keinen Zustandsnamen,
//! sondern nur die eine Regel oben. `BlockedRecoveryTest` und `Ready` stammen
//! aus dem Umsetzungsplan
//! (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md`,
//! Task 2). Dieses Modul uebersetzt also die EINE spezifizierte Regel in zwei
//! benannte Zustaende; es behauptet keine spezifizierte Zustandsmaschine.
//!
//! # Was einen Recovery-Test zaehlen laesst
//!
//! `:1897` ist unmissverstaendlich: „Ein fehlendes Medium, falscher Key,
//! abweichender Anchor, nicht lesbarer Testeintrag oder unvollstaendiges
//! Sample macht den Gesamttest fehlgeschlagen; Teilerfolg darf nicht als
//! erfolgreicher Recovery-Test erscheinen." Genau das setzt
//! [`verify_fresh_machine_recovery_test`] durch — und weil die Folge in allen
//! fuenf Faellen dieselbe ist, tragen sie EINEN Code.
//!
//! # Es gibt keinen Schalter nach `Ready`
//!
//! [`ProductionState::Ready`] entsteht ausschliesslich dadurch, dass ein
//! [`FreshMachineRecoveryProof`] VERBRAUCHT wird. Der Typ hat private Felder,
//! kein `Default`, kein `Clone` und in seinem inhaerenten `impl`-Block
//! ausschliesslich LESER — keine assoziierte Funktion, die ihn baut; die eine
//! Konstruktionsstelle ist eine freie Funktion mit einer Pruefung davor. Das
//! ist dieselbe Bauart wie [`crate::MediaConfirmation`] und
//! [`ea_trust::VerifiedAdminAuthorization`]. Ein Aufrufer kann sich die
//! Produktionsfreigabe damit nicht selbst ausstellen:
//!
//! ```compile_fail
//! use ea_admin::FreshMachineRecoveryProof;
//!
//! fn forge() -> FreshMachineRecoveryProof {
//!     FreshMachineRecoveryProof::default()
//! }
//! ```
//!
//! Auch nicht ueber die Felder:
//!
//! ```compile_fail
//! use ea_admin::FreshMachineRecoveryProof;
//! use ea_types::Hash32;
//!
//! fn forge(machine: Hash32) -> FreshMachineRecoveryProof {
//!     FreshMachineRecoveryProof { machine_fingerprint: machine }
//! }
//! ```
//!
//! Und es gibt keinen `set_ready`, kein `force`, kein Merkmal und keine
//! `#[cfg(test)]`-Hintertuer — diese Datei enthaelt kein einziges `cfg`.
//!
//! Der positive Gegenzeuge, damit die beiden obigen an ihrem Gegenstand
//! scheitern und nicht an ihren Importen:
//!
//! ```
//! use ea_admin::ProductionState;
//! use ea_types::Hash32;
//!
//! assert_eq!(format!("{:?}", ProductionState::BlockedRecoveryTest), "BlockedRecoveryTest");
//! assert_ne!(ProductionState::BlockedRecoveryTest, ProductionState::Ready);
//! // `ea_types::Hash32` ist hier erreichbar — die beiden `compile_fail`-Zeugen
//! // oben scheitern also an ihrem Gegenstand und nicht an ihren Importen.
//! let _ = Hash32::try_from(&[0_u8; 32][..]).unwrap();
//! ```

use core::fmt;

use ea_crypto::object_hash;
use ea_types::{Hash32, KeyThumbprint};

use crate::AdminError;

/// Die Domaene des Rechnerabdrucks.
///
/// Er steht als erstes Element IN den gehashten Bytes und trennt ihn damit von
/// jedem anderen Digest dieses Produkts — dieselbe Bauart wie die zwei
/// Domaenen in [`crate::bootstrap`].
const MACHINE_DOMAIN: &[u8] = b"EINSATZARCHIV-CEREMONY-MACHINE-v1";

/// Der Abdruck EINES Rechners aus dem, was der Wirt ueber ihn weiss.
///
/// # Warum diese Funktion existiert
///
/// Schritt 12 vergleicht zwei Rechner: den, auf dem die Zeremonie lief, und
/// den, auf dem der Recovery-Test lief (`:1347`). Ein Vergleich zweier Werte
/// ist nur dann eine Aussage, wenn beide auf DIESELBE Weise entstanden sind —
/// zwei Bildungsvorschriften waeren zwei Wahrheiten darueber, was „derselbe
/// Rechner" heisst, und der Vergleich faende dann nie eine Gleichheit.
///
/// WAS der Wirt hineingibt, entscheidet er: unter Linux ueblicherweise der
/// Inhalt von `/etc/machine-id`, unter macOS die Hardware-UUID. Diese Crate
/// liest kein Betriebssystem — genau wie `ea_operator::linux::account_inputs`
/// die geernteten Bytes entgegennimmt und nicht selbst erntet
/// (`crates/ea-operator/src/linux.rs:32-40`).
///
/// Der Wert ist ein Bindungshash und kein Geheimnis; er steht so auch im
/// persistierten Zeremoniezustand.
#[must_use]
pub fn machine_fingerprint(host_machine_identity: &[u8]) -> Hash32 {
    let mut bytes = Vec::with_capacity(MACHINE_DOMAIN.len() + host_machine_identity.len());
    bytes.extend_from_slice(MACHINE_DOMAIN);
    bytes.extend_from_slice(host_machine_identity);
    // Ein `ObjectHash` IST 32 Byte; der zweite Zweig ist unerreichbar. Er
    // traegt trotzdem keinen `expect`: ein Abdruck, der die Zeremonie
    // begleitet, soll den Prozess unter keinen Umstaenden beenden, und
    // [`Hash32::ZERO`] ist der konservative Wert — er gleicht keinem Rechner,
    // den ein Wirt je meldet, und laesst Schritt 12 damit fail-closed.
    Hash32::try_from(object_hash(&bytes).as_bytes().as_slice()).unwrap_or(Hash32::ZERO)
}

/// Der Freigabezustand einer Organisation.
///
/// `Copy`, weil er zwei Werte hat und ueberall gelesen wird; `Eq`, weil ein
/// Zeuge ihn vergleicht.
///
/// # Warum ein HANDGESCHRIEBENES `Debug`
///
/// [`AdminError`] druckt seinen Code und nicht seine Variante, weil ein
/// Fehlercode das stabile Aussenverhalten IST. Hier ist es umgekehrt: ein
/// Produktionszustand hat keinen Code, sein stabiles Aussenverhalten ist der
/// Variantenname. Beide Typen drucken damit dasselbe Prinzip — das, wonach
/// man sie draussen benennt — und genau deshalb sieht die Umsetzung
/// unterschiedlich aus. Das Ergebnis ist identisch zu einem abgeleiteten
/// `Debug`; es steht hier von Hand, damit die Entscheidung an der Stelle
/// nachlesbar ist, an der sie getroffen wurde.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProductionState {
    /// Der Regelzustand nach der Zeremonie: Schritt 12 steht aus.
    ///
    /// Kein Feldbetrieb, keine echten Einsaetze. Der Zustand ist die
    /// Uebersetzung von `:1349` und nicht seine Abschwaechung.
    BlockedRecoveryTest,
    /// Erreichbar ausschliesslich ueber
    /// [`FreshMachineRecoveryProof`].
    Ready,
}

impl fmt::Debug for ProductionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BlockedRecoveryTest => "BlockedRecoveryTest",
            Self::Ready => "Ready",
        })
    }
}

/// Was ein Frischrechner-Recovery-Test BEOBACHTET hat.
///
/// Reine Beobachtung und kein Urteil: die Felder sind das, was der Wirt beim
/// Durchlauf gesehen hat, das Urteil faellt
/// [`verify_fresh_machine_recovery_test`]. Der Bericht selbst — Test-ID,
/// Zeiten, Versionen, pseudonyme Medien-IDs — gehoert nach `:1897` in die
/// Berichtsschicht und nicht hierher; hier stehen genau die fuenf Groessen,
/// an denen der Test scheitern kann, plus der Rechner, auf dem er lief.
///
/// Kein privater Schluessel und kein entschluesselter Payload steht darin —
/// `:1897` verbietet beides ausdruecklich auch fuer den Bericht.
pub struct RecoveryTestObservation {
    /// Der Rechner, auf dem der Test lief. Ein Bindungshash, kein Geheimnis.
    pub machine_fingerprint: Hash32,
    /// Wie viele Recovery-Medien der Test erwartet hat.
    pub media_expected: usize,
    /// Wie viele davon tatsaechlich da waren („ein fehlendes Medium").
    pub media_present: usize,
    /// Der Hash des finalen Trust Anchors, gegen den geprueft werden sollte.
    pub expected_trust_anchor_hash: Hash32,
    /// Der Hash des Ankers, den der Test tatsaechlich vorgelegt bekam
    /// („abweichender Anchor").
    pub observed_trust_anchor_hash: Hash32,
    /// Der erwartete RFC-9679-Abdruck des geprueften Schluessels (`:1893`).
    pub expected_key_thumbprint: KeyThumbprint,
    /// Der beobachtete Abdruck („falscher Key").
    pub observed_key_thumbprint: KeyThumbprint,
    /// Ob der Testeintrag lesbar war („nicht lesbarer Testeintrag").
    pub test_entry_readable: bool,
    /// Wie viele Eintraege das Sample umfassen sollte.
    pub sample_entries_expected: usize,
    /// Wie viele davon per Recovery entschluesselt wurden
    /// („unvollstaendiges Sample").
    pub sample_entries_decrypted: usize,
}

/// Der Nachweis, dass Schritt 12 auf einem FRISCHEN Rechner vollstaendig
/// gelungen ist.
///
/// Konstruierbar ausschliesslich in [`verify_fresh_machine_recovery_test`].
/// Kein `Default`, kein `Clone`, kein `Debug`, und im inhaerenten
/// `impl`-Block nur Leser — siehe die Moduldokumentation.
///
/// Er wird von
/// [`BootstrapCoordinator::record_fresh_machine_recovery_test`] VERBRAUCHT und
/// nicht geliehen: ein Nachweis deckt genau einen Uebergang nach
/// [`ProductionState::Ready`].
///
/// [`BootstrapCoordinator::record_fresh_machine_recovery_test`]: crate::BootstrapCoordinator::record_fresh_machine_recovery_test
pub struct FreshMachineRecoveryProof {
    machine_fingerprint: Hash32,
    expected_trust_anchor_hash: Hash32,
    media_expected: usize,
}

/// Faellt das Urteil ueber einen Recovery-Testlauf.
///
/// Zwei getrennte Befunde, und sie sind bewusst nicht derselbe:
///
/// 1. **Der Rechner.** `:1347` verlangt „einen frischen Rechner". Lief der
///    Test auf der Zeremonienmaschine, hat er die Frage gar nicht gestellt,
///    auf die es ankommt — ob der Bestand OHNE die lokal vorhandenen
///    Nebenwirkungen der Einrichtung wiederherstellbar ist. Das ist kein
///    Teilerfolg, sondern ein anderer Test.
/// 2. **Die Vollstaendigkeit.** `:1897` zaehlt fuenf Ausgaenge auf, die den
///    GESAMTEN Test fehlschlagen lassen, und verbietet, dass ein Teilerfolg
///    als erfolgreicher Recovery-Test erscheint. Alle fuenf tragen deshalb
///    denselben Code: welcher davon zutraf, aendert an der Folge nichts, und
///    zwei Codes fuer dieselbe Folge waeren eine zweite Wahrheit. Die
///    Diagnose, welcher Ausgang es war, gehoert in den Bericht nach `:1897`.
///
/// Der Vergleich der Abdruecke laeuft nicht in konstanter Zeit: ein
/// RFC-9679-Abdruck ist ein oeffentlicher Wert.
///
/// # Errors
/// [`AdminError::RecoveryTestSameMachine`] mit
/// `EA-CEREMONY-RECOVERY-TEST-SAME-MACHINE`, wenn der Test auf der
/// Zeremonienmaschine lief; [`AdminError::RecoveryTestFailed`] mit
/// `EA-CEREMONY-RECOVERY-TEST-FAILED` fuer jeden der fuenf Ausgaenge aus
/// `:1897`.
pub fn verify_fresh_machine_recovery_test(
    ceremony_machine_fingerprint: Hash32,
    observation: &RecoveryTestObservation,
) -> Result<FreshMachineRecoveryProof, AdminError> {
    if observation.machine_fingerprint == ceremony_machine_fingerprint {
        return Err(AdminError::RecoveryTestSameMachine);
    }
    // Ein Test ohne erwartete Medien oder ohne erwartetes Sample hat nichts
    // geprueft; fail-closed zaehlt er nicht als bestanden.
    if observation.media_expected == 0 || observation.sample_entries_expected == 0 {
        return Err(AdminError::RecoveryTestFailed);
    }
    if observation.media_present < observation.media_expected
        || observation.observed_trust_anchor_hash != observation.expected_trust_anchor_hash
        || observation.observed_key_thumbprint != observation.expected_key_thumbprint
        || !observation.test_entry_readable
        || observation.sample_entries_decrypted < observation.sample_entries_expected
    {
        return Err(AdminError::RecoveryTestFailed);
    }
    Ok(FreshMachineRecoveryProof {
        machine_fingerprint: observation.machine_fingerprint,
        expected_trust_anchor_hash: observation.expected_trust_anchor_hash,
        media_expected: observation.media_expected,
    })
}

impl FreshMachineRecoveryProof {
    /// Der Rechner, der den Test bestanden hat.
    ///
    /// Ein Leser und kein Konstruktor: der Koordinator schreibt den Wert in
    /// den persistierten Zeremoniezustand, damit spaeter nachlesbar ist, WO
    /// Schritt 12 lief.
    #[must_use]
    pub const fn machine_fingerprint(&self) -> Hash32 {
        self.machine_fingerprint
    }

    /// Der Anker, gegen den der Test geprueft hat.
    ///
    /// `:1347` verlangt den Test „mit explizitem finalem Trust Anchor". WELCHER
    /// Anker das war, entscheidet, ob dieser Nachweis ueberhaupt von der
    /// Zeremonie handelt, die ihn verbraucht: ein in sich vollkommen
    /// stimmiger Lauf gegen den Anker einer FREMDEN Organisation ist ein
    /// bestandener Test — nur nicht dieser. Der Wert wandert deshalb aus der
    /// Beobachtung in den Nachweis und wird von
    /// [`BootstrapCoordinator::record_fresh_machine_recovery_test`] gegen die
    /// Ankerbytes gehalten, die Schritt 11 angenommen hat.
    ///
    /// [`BootstrapCoordinator::record_fresh_machine_recovery_test`]: crate::BootstrapCoordinator::record_fresh_machine_recovery_test
    #[must_use]
    pub const fn expected_trust_anchor_hash(&self) -> Hash32 {
        self.expected_trust_anchor_hash
    }

    /// Wie viele Recovery-Medien der Test erwartet hat.
    ///
    /// Ein Lauf, der weniger Medien erwartet hat, als Schritt 4 versiegelt
    /// hat, hat den Bestand nicht vollstaendig geprueft — `:1897` nennt „ein
    /// fehlendes Medium" als Grund fuer den Fehlschlag des GESAMTEN Tests, und
    /// ein Medium, nach dem gar nicht gefragt wurde, fehlt genauso.
    #[must_use]
    pub const fn media_expected(&self) -> usize {
        self.media_expected
    }
}
