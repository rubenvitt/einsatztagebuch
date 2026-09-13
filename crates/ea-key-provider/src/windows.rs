//! Windows-Rand: Gerätemessungen und lokale Schlüsselpolitik.
//!
//! Der native Schlüsselhost liegt in `ea-admin` (ADR-0006). Dieser Adapter
//! liest BitLocker-Schutz der festen Volumes und explizite Inaktivitätssperre.
//! Unbelegbare Voraussetzungen bleiben Unknown; Rohdaten verlassen den Adapter nicht.
//! Die Messgrenzen stehen in `docs/device-posture.md`.

use crate::{
    contract::{KeyEntryPolicy, KeyError},
    posture::{DevicePostureProvider, DevicePostureReport, SupportMatrixRow},
};

/// Die Zeile der Support-Matrix, fuer die dieses Modul spricht.
pub const SUPPORT_MATRIX_ROW: SupportMatrixRow = SupportMatrixRow::Windows11X86_64;

/// Die DPAPI-Kennzeichen eines Eintrags dieses Produkts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsDpapiFlags {
    /// Roamendes Benutzerprofil und damit `CRYPTPROTECT_*`-Entschluesselbarkeit
    /// auf einem zweiten Geraet derselben Domaene.
    pub roaming_profile: bool,
    /// Aufnahme in die gewoehnliche Anwendungs- und Systemsicherung.
    pub included_in_ordinary_backup: bool,
}

/// Uebersetzt die eine Eintragspolitik in DPAPI-Kennzeichen.
///
/// Die Politik wird GELESEN und nicht behauptet: die beiden Kennzeichen
/// entstehen aus ihren Lesern (`crates/ea-key-provider/src/contract.rs`), damit
/// eine spaetere Politik mit anderen Werten hier nicht stillschweigend dieselben
/// Kennzeichen erhaelt.
#[must_use]
pub const fn dpapi_flags(policy: KeyEntryPolicy) -> WindowsDpapiFlags {
    WindowsDpapiFlags {
        roaming_profile: policy.is_roaming() || policy.is_cloud_synchronised(),
        included_in_ordinary_backup: policy.is_included_in_ordinary_backup(),
    }
}

/// Liest die belegbaren Windows-Signale über feste, begrenzte Systemaufrufe.
/// Andere Plattformen und nicht belegbare Voraussetzungen bleiben Unknown.
pub struct WindowsDevicePosture;

impl DevicePostureProvider for WindowsDevicePosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        Ok(crate::native_posture::windows_host_report())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_only_entry_policy_forbids_roaming_and_backup() {
        assert_eq!(
            dpapi_flags(KeyEntryPolicy::DEVICE_LOCAL),
            WindowsDpapiFlags {
                roaming_profile: false,
                included_in_ordinary_backup: false,
            }
        );
    }

    #[test]
    fn the_windows_row_reaches_only_the_os_wrapped_floor() {
        assert_eq!(
            SUPPORT_MATRIX_ROW.reachable_protection_profile(),
            ea_format::KeyProtectionProfileV1::OsWrapped
        );
    }
}
