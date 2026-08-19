//! Der macOS-Rand des Schluesselports.
//!
//! `design.md`:1484 nennt fuer macOS Keychain und Secure Enclave, „soweit fuer
//! den Algorithmus verfuegbar". Die Einschraenkung ist keine Erlaubnis zum
//! stillen Ausweichen: `design.md`:1489 laesst `hardwareNonExportable` nur mit
//! einem ausdruecklich unterstuetzten Provider zu, und diese Zeile beansprucht
//! deshalb ausschliesslich [`KeyProtectionProfileV1::OsWrapped`]
//! ([`SupportMatrixRow::reachable_protection_profile`]).
//!
//! Was hier NICHT liegt: ein `KeyProvider`. Der Zugriff auf die Keychain ist ein
//! C-API-Aufruf, und Stufe 2 nimmt keine native API-Familie in
//! `[workspace.dependencies]` auf — `docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-153`
//! macht jede Dependency-Aenderung ADR-pflichtig, und dieser Task fuehrt keinen
//! ADR. Was hier liegt, ist alles, was OHNE diese Familie vollstaendig und
//! pruefbar ist: die Uebersetzung der einen Eintragspolitik in die Kennzeichen
//! der Keychain und der Haltungsadapter dieser Zeile.
//!
//! Die FOLGE dieser Grenze, damit sie niemand erst im Betrieb entdeckt: es gibt
//! auf dieser Zeile keinen `KeyProvider`, der Keychain oder Secure Enclave ruft,
//! keine LocalAuthentication-Praesenzpruefung und keinen Leser des
//! FileVault-Status. `MacOsDevicePosture` meldet vier `Unknown`, also ist
//! `DevicePostureReport::is_production_ready` auf beiden macOS-Zeilen immer
//! `false` und eine Sitzung in produktiver Rolle entsteht hier nicht.
//! Fail-closed und richtig gerichtet — aber eine SPERRE, die erst der Task
//! loest, der die nativen API-Familien samt ADR einfuehrt.
//!
//! [`KeyProtectionProfileV1::OsWrapped`]: ea_format::KeyProtectionProfileV1::OsWrapped

use crate::{
    contract::{KeyEntryPolicy, KeyError},
    posture::{DevicePostureProvider, DevicePostureReport, SupportMatrixRow},
};

/// Die Zeile der Support-Matrix, fuer die dieses Modul spricht — beide macOS-
/// Architekturen teilen Keychain und LocalAuthentication.
pub const SUPPORT_MATRIX_ROWS: [SupportMatrixRow; 2] =
    [SupportMatrixRow::MacOsArm64, SupportMatrixRow::MacOsX86_64];

/// Die Keychain-Kennzeichen eines Eintrags dieses Produkts.
///
/// Benannt nach den Attributen, die `SecItemAdd` entgegennimmt, damit die
/// Uebersetzung nachlesbar bleibt, sobald der Aufruf gelegt wird.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsKeychainAttributes {
    /// `kSecAttrSynchronizable` — iCloud-Schluesselbund.
    pub synchronizable: bool,
    /// `kSecAttrAccessible` in der Fassung
    /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
    pub accessible_when_unlocked_this_device_only: bool,
}

/// Uebersetzt die eine Eintragspolitik in Keychain-Attribute.
///
/// Die Politik wird GELESEN und nicht behauptet: `KeyEntryPolicy::DEVICE_LOCAL`
/// ist die einzige konstruierbare Politik, aber diese Funktion leitet ihre drei
/// Kennzeichen aus ihren Lesern ab und nicht aus dieser Kenntnis. `…ThisDeviceOnly`
/// traegt zwei der drei Zusagen zugleich: der Eintrag wandert nicht in den
/// iCloud-Schluesselbund und nicht in ein Geraetebackup.
#[must_use]
pub const fn keychain_attributes(policy: KeyEntryPolicy) -> MacOsKeychainAttributes {
    MacOsKeychainAttributes {
        synchronizable: policy.is_cloud_synchronised() || policy.is_roaming(),
        accessible_when_unlocked_this_device_only: !policy.is_included_in_ordinary_backup(),
    }
}

/// Der Haltungsadapter dieser Zeile.
///
/// Die vier Signale, die macOS dafuer dokumentiert bereitstellt, sind
/// Datentraegerverschluesselung ueber den FileVault-Status, das Konto ueber
/// Open Directory, die Bildschirmsperre ueber die `askForPassword`-Einstellung
/// und der Patchstand ueber die Systemversion. Alle vier liegen hinter
/// Systemframeworks beziehungsweise Systemwerkzeugen; Stufe 2 traegt keine
/// native API-Familie, um sie zu lesen, und dieser Adapter meldet deshalb vier
/// `Unknown` mit ihren Beweiscodes.
///
/// Das ist der vom Produkt VERLANGTE Ausgang und keine Luecke: ein `Unknown`
/// sperrt die Sitzung in produktiver Rolle und erzeugt eine Pflichtzeile im
/// Go-live-Bericht. Ein Adapter, der Systemwerkzeuge ausliest und ihre Ausgabe
/// interpretiert, waere hier zugleich der Ort, an dem Benutzernamen und
/// Softwareinventare mitgelesen wuerden — genau das, was dieser Task verbietet.
pub struct MacOsDevicePosture;

impl DevicePostureProvider for MacOsDevicePosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        Ok(DevicePostureReport::unresolved())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_only_entry_policy_forbids_icloud_and_backup() {
        assert_eq!(
            keychain_attributes(KeyEntryPolicy::DEVICE_LOCAL),
            MacOsKeychainAttributes {
                synchronizable: false,
                accessible_when_unlocked_this_device_only: true,
            }
        );
    }

    #[test]
    fn both_macos_rows_reach_only_the_os_wrapped_floor() {
        for row in SUPPORT_MATRIX_ROWS {
            assert_eq!(
                row.reachable_protection_profile(),
                ea_format::KeyProtectionProfileV1::OsWrapped
            );
        }
    }
}
