//! Der Windows-Rand des Schluesselports.
//!
//! `design.md`:1483 nennt fuer Windows CNG/DPAPI und hardwaregestuetzte
//! Provider, „soweit verfuegbar". Wie unter macOS ist das keine Erlaubnis zum
//! stillen Ausweichen: diese Zeile beansprucht ausschliesslich
//! [`KeyProtectionProfileV1::OsWrapped`]
//! ([`SupportMatrixRow::reachable_protection_profile`]).
//!
//! Was hier NICHT liegt: ein `KeyProvider`. CNG und DPAPI sind Win32-Aufrufe,
//! und Stufe 2 nimmt keine native API-Familie in `[workspace.dependencies]` auf
//! (`docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-153`). Was
//! hier liegt, ist die vollstaendig pruefbare Haelfte: die Uebersetzung der einen
//! Eintragspolitik in die DPAPI-Kennzeichen und der Haltungsadapter dieser
//! Zeile.
//!
//! [`KeyProtectionProfileV1::OsWrapped`]: ea_format::KeyProtectionProfileV1::OsWrapped

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

/// Der Haltungsadapter dieser Zeile.
///
/// Die vier Signale, die Windows 11 dafuer dokumentiert bereitstellt, sind der
/// BitLocker-Schutzstatus des Systemvolumes, die Kontoart samt
/// Mehrfachanmeldung, die Richtlinie fuer die Bildschirmsperre und der
/// Buildstand des Betriebssystems. Alle vier liegen hinter Win32-, WMI- oder
/// Richtlinien-APIs; Stufe 2 traegt keine native API-Familie, um sie zu lesen,
/// und dieser Adapter meldet deshalb vier `Unknown` mit ihren Beweiscodes.
///
/// Ein `Unknown` sperrt die Sitzung in produktiver Rolle und erzeugt eine
/// Pflichtzeile im Go-live-Bericht — der vom Produkt verlangte Ausgang, kein
/// automatischer Pass.
pub struct WindowsDevicePosture;

impl DevicePostureProvider for WindowsDevicePosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        Ok(DevicePostureReport::unresolved())
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
