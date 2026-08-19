//! Die Rollentrennung des Writers, uebersetzt statt beschrieben.

use ea_crypto::CertificateCapability;
use ea_format::KeyProtectionProfileV1;

use crate::contract::{KeyError, KeyPurpose, KeystoreProvider, SecretPurpose};

/// Die Faehigkeiten, die ein Writer-Geraetezertifikat tragen darf.
///
/// Abgeleitet aus den Konstruktoren von `ea_crypto::VerificationContext`:
/// `record` verlangt `SignerRole::Writer` OHNE Faehigkeit, `initial_grant`
/// verlangt `SignerRole::Writer` MIT `initialGrant`. Kein weiterer
/// Verifikationskontext paart die Writer-Rolle mit einer Faehigkeit.
const WRITER_CAPABILITIES: &[CertificateCapability] = &[CertificateCapability::InitialGrant];

/// Das Schluesselprofil eines Writer-Geraets.
///
/// Ein reiner Namensraum; er hat keinen Zustand und wird nie als Wert gefuehrt.
pub struct WriterKeyProfile;

impl WriterKeyProfile {
    /// Die NEGATIVE Haelfte der Zusage: kein privater Reader-, Recovery-,
    /// Historical-Grant-Authority- oder Key-Approver-Schluessel auf einem
    /// Writer.
    ///
    /// Diese Funktion kann nur ablehnen, und das ist ihr Zweck: [`KeyPurpose`]
    /// benennt ausschliesslich fremdes Material, das auf einem Writer nie
    /// privat vorliegt. Eine leere Liste ist nichts zu Beanstandendes und
    /// deshalb kein Fehler.
    pub fn validate(purposes: &[KeyPurpose]) -> Result<(), KeyError> {
        if purposes.is_empty() {
            Ok(())
        } else {
            Err(KeyError::ForbiddenPurpose)
        }
    }

    /// Die POSITIVE Haelfte: genau die vier lokalen Zwecke.
    pub fn validate_local(purposes: &[SecretPurpose]) -> Result<(), KeyError> {
        for purpose in purposes {
            // Erschoepfend und ohne Platzhalter. Eine fuenfte Variante bricht
            // hier die Uebersetzung und erzwingt eine Entscheidung, statt
            // stillschweigend zugelassen zu werden.
            match purpose {
                SecretPurpose::WriterSigningKey
                | SecretPurpose::OperatorInstanceKey
                | SecretPurpose::DraftDek
                | SecretPurpose::LocalDatabaseKey => {}
            }
        }
        Ok(())
    }

    /// Prueft die Faehigkeiten, die ein Geraetezertifikat BEANSPRUCHT.
    ///
    /// Entschieden wird gegen die GEPARSTEN Faehigkeiten der Stufe-1-Allowlist
    /// (`ea_crypto::CertificateCapability`) und nie gegen die rohen
    /// Zeichenketten, die ein Zertifikat traegt. Diese Crate fuehrt keine
    /// zweite Allowlist.
    ///
    /// Fail-closed in beide Richtungen: ein unbekanntes Literal ist ein Befund,
    /// und ein bekanntes Literal ausserhalb der Writer-Menge ebenfalls.
    pub fn validate_capabilities(
        claimed: &[String],
    ) -> Result<Vec<CertificateCapability>, KeyError> {
        let mut parsed = Vec::with_capacity(claimed.len());
        for literal in claimed {
            let capability = CertificateCapability::try_from(literal.as_str())
                .map_err(|_| KeyError::UnknownCapability)?;
            if !WRITER_CAPABILITIES.contains(&capability) {
                return Err(KeyError::ForbiddenCapability);
            }
            parsed.push(capability);
        }
        Ok(parsed)
    }
}

/// Die Provider, denen `HardwareNonExportable` ueberhaupt zugestanden wird.
///
/// HEUTE LEER, und das ist die Aussage: Stufe 2 kennt keinen Provider, der
/// nicht-exportierbares Hardwarematerial erreicht, also besteht kein solcher
/// Anspruch. Fail-closed als Ausgangslage — ein Provider, der es kann, wird
/// hier namentlich eingetragen, statt dass ein Anspruch stillschweigend
/// durchginge, weil niemand widerspricht.
const HARDWARE_CAPABLE_PROVIDERS: &[KeystoreProvider] = &[];

/// Prueft das ERREICHTE Schutzprofil gegen das im Geraetezertifikat
/// BEANSPRUCHTE.
///
/// Drei Klauseln, alle fail-closed:
///
/// 1. Ein Profil ausserhalb der Teilmenge, die Stufe 2 produktiv erreicht,
///    bricht ab.
/// 2. Nur Gleichheit besteht — es gibt keinen stillen Rueckfall auf
///    ungeschuetzte Schluesseldateien (`design.md`:1489).
/// 3. `HardwareNonExportable` besteht nur bei einem ausdruecklich
///    unterstuetzten Provider aus [`HARDWARE_CAPABLE_PROVIDERS`].
///
/// Die Reihenfolge ist bedeutsam. Klausel 2 laeuft VOR Klausel 3, damit ein
/// Geraetezertifikat, das Hardware beansprucht, waehrend der Provider Software
/// erreicht hat, als ABWEICHUNG gemeldet wird und nicht als fehlende
/// Providerfaehigkeit: der Betreiber unterscheidet daran ein falsch
/// ausgestelltes Zertifikat von einem Geraet, dem die Faehigkeit fehlt.
///
/// Klausel 3 ist eine GEMEINSAME Sperre und ausdruecklich nicht dasselbe wie
/// die Weigerung eines einzelnen Providers, ein Profil zu erreichen. Ein
/// Provider, der seine eigene Faehigkeit falsch meldet, kaeme an einer reinen
/// Provider-Selbstauskunft vorbei; an dieser Liste nicht.
pub fn require_claimed_protection_profile(
    provider: KeystoreProvider,
    reached: KeyProtectionProfileV1,
    claimed: KeyProtectionProfileV1,
) -> Result<(), KeyError> {
    require_stage_two_protection_profile(reached)?;
    require_stage_two_protection_profile(claimed)?;
    if reached != claimed {
        return Err(KeyError::ProtectionProfileMismatch);
    }
    if claimed == KeyProtectionProfileV1::HardwareNonExportable
        && !HARDWARE_CAPABLE_PROVIDERS.contains(&provider)
    {
        return Err(KeyError::UnreachableProtectionProfile);
    }
    Ok(())
}

/// Grenzt die Teilmenge der Schutzprofile ab, die Stufe 2 produktiv erreicht.
///
/// Erschoepfend und ohne Platzhalter, damit eine sechste Variante des
/// Wire-Formats hier die Uebersetzung bricht statt stillschweigend durch die
/// eine oder andere Seite zu fallen.
pub(crate) const fn require_stage_two_protection_profile(
    profile: KeyProtectionProfileV1,
) -> Result<(), KeyError> {
    match profile {
        KeyProtectionProfileV1::OsWrapped | KeyProtectionProfileV1::HardwareNonExportable => Ok(()),
        KeyProtectionProfileV1::OfflineEncryptedContainer
        | KeyProtectionProfileV1::Pkcs11
        | KeyProtectionProfileV1::ServerSecretStoreOrHsm => {
            Err(KeyError::UnsupportedProtectionProfile)
        }
    }
}
