//! Der Ubuntu-Rand des Schluesselports.
//!
//! `design.md`:1485 nennt fuer Ubuntu Secret Service plus einen geschuetzten
//! lokalen Schluesselcontainer, und `design.md`:235 verlangt ausdruecklich eine
//! durch PAM entsperrte Secret-Service-Collection mit eigener zufaelliger
//! Kontoinstanz — NICHT eine Datei, die allein durch UID-Dateirechte geschuetzt
//! ist. Diese Zeile beansprucht ausschliesslich
//! [`KeyProtectionProfileV1::OsWrapped`]
//! ([`SupportMatrixRow::reachable_protection_profile`]).
//!
//! Was hier NICHT liegt: ein `KeyProvider`. Der Secret Service ist ein
//! D-Bus-Dienst, und Stufe 2 nimmt keine native API-Familie in
//! `[workspace.dependencies]` auf
//! (`docs/adr/0001-toolchain-and-cryptography-dependencies.md:152-153`). Was hier
//! liegt, ist die vollstaendig pruefbare Haelfte: die Uebersetzung der einen
//! Eintragspolitik in die Kennzeichen der Collection und der Haltungsadapter
//! dieser Zeile.
//!
//! [`KeyProtectionProfileV1::OsWrapped`]: ea_format::KeyProtectionProfileV1::OsWrapped

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

/// Der Haltungsadapter dieser Zeile.
///
/// Die vier Signale, die Ubuntu 24.04 LTS dafuer dokumentiert bereitstellt, sind
/// der LUKS-Status des Wurzelgeraets, die Kontoart samt aktiver Sitzungen des
/// Sitzungsmanagers, die Sperrbildschirm-Einstellung der Sitzung und der
/// Paketstand der unterstuetzten Veroeffentlichung. Alle vier liegen hinter
/// D-Bus-Diensten beziehungsweise Systemwerkzeugen; Stufe 2 traegt keine native
/// API-Familie, um sie zu lesen, und dieser Adapter meldet deshalb vier
/// `Unknown` mit ihren Beweiscodes.
///
/// Ein `Unknown` sperrt die Sitzung in produktiver Rolle und erzeugt eine
/// Pflichtzeile im Go-live-Bericht — der vom Produkt verlangte Ausgang, kein
/// automatischer Pass.
pub struct UbuntuDevicePosture;

impl DevicePostureProvider for UbuntuDevicePosture {
    fn report(&self) -> Result<DevicePostureReport, KeyError> {
        Ok(DevicePostureReport::unresolved())
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
