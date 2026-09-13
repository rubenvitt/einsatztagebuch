//! Ubuntu-Rand: Gerätemessungen und lokale Schlüsselpolitik.
//!
//! Der native Schlüsselhost liegt in `ea-admin` (ADR-0006). Dieser Adapter
//! liest Verschlüsselung der eindeutigen Blockgeräte-Abstammung des Root-Dateisystems.
//! Unbelegbare Voraussetzungen bleiben Unknown; Rohdaten verlassen den Adapter nicht.
//! Die Messgrenzen stehen in `docs/device-posture.md`.

use crate::{
    contract::{KeyEntryPolicy, KeyError},
    posture::{DevicePostureProvider, DevicePostureReport, SupportMatrixRow},
};

/// Die Zeile der Support-Matrix, fuer die dieses Modul spricht.
pub const SUPPORT_MATRIX_ROW: SupportMatrixRow = SupportMatrixRow::Ubuntu2404X86_64;

/// Die Kennzeichen der Secret-Service-Collection dieses Produkts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UbuntuSecretServiceAttributes {
    /// Die Collection wird durch PAM entsperrt und nicht durch Dateirechte
    /// geschuetzt (`design.md`:235). Nie `false`: eine Datei mit
    /// UID-Dateirechten ist fuer diesen Zweck ausdruecklich unzulaessig.
    pub pam_unlocked_collection: bool,
    /// Die Collection wird nicht auf ein zweites Geraet uebertragen.
    pub roaming: bool,
    /// Aufnahme in die gewoehnliche Anwendungs- und Systemsicherung.
    pub included_in_ordinary_backup: bool,
}

/// Uebersetzt die eine Eintragspolitik in Collection-Kennzeichen.
///
/// `pam_unlocked_collection` ist nicht aus der Politik abgeleitet, sondern eine
/// Zusage dieser Plattform: `design.md`:235 schliesst die Dateivariante aus, und
/// die Eintragspolitik kennt dafuer kein Feld. Die beiden uebrigen Kennzeichen
/// werden aus den Lesern der Politik GELESEN.
#[must_use]
pub const fn secret_service_attributes(policy: KeyEntryPolicy) -> UbuntuSecretServiceAttributes {
    UbuntuSecretServiceAttributes {
        pam_unlocked_collection: true,
        roaming: policy.is_roaming() || policy.is_cloud_synchronised(),
        included_in_ordinary_backup: policy.is_included_in_ordinary_backup(),
    }
}

/// Liest die belegbaren Ubuntu-Signale über feste, begrenzte Systemaufrufe.
/// Andere Plattformen und nicht belegbare Voraussetzungen bleiben Unknown.
pub struct UbuntuDevicePosture;

impl DevicePostureProvider for UbuntuDevicePosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        Ok(crate::native_posture::ubuntu_report())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_only_entry_policy_stays_in_a_pam_unlocked_collection() {
        assert_eq!(
            secret_service_attributes(KeyEntryPolicy::DEVICE_LOCAL),
            UbuntuSecretServiceAttributes {
                pam_unlocked_collection: true,
                roaming: false,
                included_in_ordinary_backup: false,
            }
        );
    }

    #[test]
    fn the_ubuntu_row_reaches_only_the_os_wrapped_floor() {
        assert_eq!(
            SUPPORT_MATRIX_ROW.reachable_protection_profile(),
            ea_format::KeyProtectionProfileV1::OsWrapped
        );
    }
}
