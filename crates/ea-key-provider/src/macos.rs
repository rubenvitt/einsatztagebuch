//! macOS-Rand: Gerätemessungen und lokale Schlüsselpolitik.
//!
//! Der native Schlüsselhost liegt in `ea-admin` (ADR-0006). Dieser Adapter
//! liest FileVault-Status des Systemvolumes.
//! Unbelegbare Voraussetzungen bleiben Unknown; Rohdaten verlassen den Adapter nicht.
//! Die Messgrenzen stehen in `docs/device-posture.md`.

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

/// Liest die belegbaren macOS-Signale über feste, begrenzte Systemaufrufe.
/// Andere Plattformen und nicht belegbare Voraussetzungen bleiben Unknown.
pub struct MacOsDevicePosture;

impl DevicePostureProvider for MacOsDevicePosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        Ok(crate::native_posture::macos_report())
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
