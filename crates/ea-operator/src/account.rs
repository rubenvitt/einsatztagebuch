//! Das gebundene Konto und die Rohangaben, aus denen sein Bindungshash entsteht.

use ea_crypto::{
    CanonicalPublicCoseKey, CryptoError, linux_os_account_binding_hash,
    macos_os_account_binding_hash, windows_os_account_binding_hash,
};
use ea_trust::SelectedRegistryHead;
use ea_types::{DeviceId, Hash32, KeyThumbprint, ObjectHash, OrganizationId, UnixMillis};

/// Ein Fehlschlag an der Bedienergrenze.
///
/// Wie ueberall in diesem Bauwerk assertieren Tests gegen [`OperatorError::code`]
/// und nie gegen eine Formatierung.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OperatorError {
    /// Der gewaehlte Registry-Head fuehrt diese Bedienerbindung nicht als aktiv.
    BindingNotActive,
    /// Das Writer-Zertifikat, das die Bindung nennt, ist nicht aktiv.
    DeviceCertificateNotActive,
    /// Das OS-Konto dieses Prozesses ist nicht das gebundene Konto.
    AccountMismatch,
    /// Auf diesem Konto liegt kein Bedienerinstanzschluessel.
    ///
    /// Neuinstallation, Wiederherstellung auf ein anderes Geraet oder Verlust
    /// des Schluessels. Scharf getrennt von [`Self::InstanceKeyMismatch`]: dort
    /// liegt EIN Schluessel, aber nicht der gebundene.
    InstanceKeyMissing,
    /// Der vorliegende Instanzschluessel ist nicht der gebundene.
    InstanceKeyMismatch,
    /// Die Praesenzsignatur haelt der Pruefung gegen den gebundenen Schluessel
    /// nicht stand.
    PresenceProofInvalid,
    /// Die lokale Zufallsquelle hat keine Challenge-Nonce geliefert.
    LocalRng,
    /// Der Gueltigkeitszeitraum eines Nachweises laesst sich nicht bilden.
    ///
    /// Nur bei einem Ueberlauf der Millisekundenachse erreichbar; ein Abbruch
    /// statt einer stillen Saettigung, die einen unbegrenzt gueltigen Nachweis
    /// ausstellen wuerde.
    ValidityWindowUnrepresentable,
    /// Ein Vorgang der Kryptografieschicht ist gescheitert.
    Crypto(CryptoError),
}

impl OperatorError {
    /// Der stabile Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BindingNotActive => "EA-OPERATOR-BINDING-NOT-ACTIVE",
            Self::DeviceCertificateNotActive => "EA-OPERATOR-DEVICE-CERTIFICATE-NOT-ACTIVE",
            Self::AccountMismatch => "EA-OPERATOR-ACCOUNT-MISMATCH",
            Self::InstanceKeyMissing => "EA-OPERATOR-INSTANCE-KEY-MISSING",
            Self::InstanceKeyMismatch => "EA-OPERATOR-INSTANCE-KEY-MISMATCH",
            Self::PresenceProofInvalid => "EA-OPERATOR-PRESENCE-PROOF-INVALID",
            Self::LocalRng => "EA-OPERATOR-LOCAL-RNG",
            Self::ValidityWindowUnrepresentable => "EA-OPERATOR-VALIDITY-WINDOW-UNREPRESENTABLE",
            Self::Crypto(error) => error.code(),
        }
    }
}

impl From<CryptoError> for OperatorError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

/// Die ROHANGABEN eines OS-Kontos, genau in der Gestalt, die Stufe 1 verlangt.
///
/// Geschlossen und ohne Zwischenschritt: jede Variante traegt buchstaeblich die
/// Argumente einer der drei Stufe-1-Funktionen
/// (`crates/ea-crypto/src/os_account.rs:207`, `:223`, `:239`). Diese Crate
/// normalisiert nichts, sortiert nichts um und setzt keine eigenen Trennzeichen
/// — `design.md:233` verbietet genau das, und die Stufe-1-Signaturen erzwingen
/// es.
///
/// Es gibt hier keine Variante fuer Plattformnamen, Benutzernamen oder textuelle
/// UIDs ausserhalb der von Stufe 1 anerkannten Wertlisten. Eine unzulaessige
/// Angabe wird von [`Self::binding_hash`] abgelehnt und nicht zurechtgebogen.
///
/// Der Typ traegt KEINE Formatierung, keinen Vergleich und keine Kopie. Stufe 1
/// haelt dieselben Angaben in einem `Zeroize`-Traeger und verweigert ihre
/// Herausgabe (`crates/ea-crypto/src/os_account.rs:195-206`); eine SID oder eine
/// Maschinenkennung, die ueber `{:?}` in eine Protokollzeile rutscht, waere
/// derselbe Austritt durch eine bequemere Tuer.
pub enum OsAccountInputs {
    /// Windows: die validierte binaere `TokenUser`-SID samt der Bestandteile,
    /// gegen die Stufe 1 sie prueft.
    Windows {
        /// Die binaere SID, wie `GetTokenInformation(TokenUser)` sie liefert.
        sid: Vec<u8>,
        /// `IdentifierAuthority`, sechs Oktette in Netzwerkreihenfolge.
        identifier_authority: [u8; 6],
        /// Die Subauthorities in Deklarationsreihenfolge.
        subauthorities: Vec<u32>,
    },
    /// macOS: die Wertlisten des Open-Directory-Datensatzes und die numerische
    /// UID.
    MacOs {
        /// `dsAttrTypeStandard:GeneratedUID`, unveraendert.
        guid_values: Vec<String>,
        /// `dsAttrTypeStandard:UniqueID`, unveraendert.
        unique_id_values: Vec<String>,
        /// Die UID, die `getuid()` TATSAECHLICH meldet.
        actual_uid: u32,
    },
    /// Ubuntu: die Bytes der `machine-id`-Datei und die numerische UID.
    Linux {
        /// Der vollstaendige Inhalt von `/etc/machine-id`, mit Zeilenende.
        machine_id_file: Vec<u8>,
        /// Die UID, die `getuid()` TATSAECHLICH meldet.
        uid: u32,
    },
}

impl OsAccountInputs {
    /// Rechnet den Bindungshash — ausschliesslich durch Stufe 1.
    ///
    /// Diese Funktion ist eine Weitergabe und bewusst nichts weiter: es gibt
    /// keinen Zweig, in dem eine Angabe vorher berichtigt wird.
    pub fn binding_hash(
        &self,
        organization_id: OrganizationId,
        device_id: DeviceId,
    ) -> Result<Hash32, OperatorError> {
        let hash = match self {
            Self::Windows {
                sid,
                identifier_authority,
                subauthorities,
            } => windows_os_account_binding_hash(
                organization_id,
                device_id,
                sid,
                *identifier_authority,
                subauthorities,
            )?,
            Self::MacOs {
                guid_values,
                unique_id_values,
                actual_uid,
            } => {
                let guid: Vec<&str> = guid_values.iter().map(String::as_str).collect();
                let unique_id: Vec<&str> = unique_id_values.iter().map(String::as_str).collect();
                macos_os_account_binding_hash(
                    organization_id,
                    device_id,
                    &guid,
                    &unique_id,
                    *actual_uid,
                )?
            }
            Self::Linux {
                machine_id_file,
                uid,
            } => linux_os_account_binding_hash(organization_id, device_id, machine_id_file, *uid)?,
        };
        Ok(hash)
    }
}

/// Der synchrone Port zum OS-Konto und zum Bedienerinstanzschluessel.
///
/// Beide Methoden LESEN; keine schreibt, legt an oder aendert. Der Port nimmt
/// ausdruecklich KEINE Kontoidentitaet aus der Oberflaeche an: die Werte
/// entstehen im Betriebssystem, und ein OS-Kennwort geht ihn nichts an.
pub trait OsAccountProvider {
    /// Der Bindungshash des Kontos, unter dem dieser Prozess laeuft.
    fn os_account_binding_hash(
        &self,
        organization_id: OrganizationId,
        device_id: DeviceId,
    ) -> Result<Hash32, OperatorError>;

    /// Der oeffentliche Bedienerinstanzschluessel dieser Installation.
    ///
    /// `None` heisst: auf diesem Konto liegt kein Instanzschluessel. Der PRIVATE
    /// Teil verlaesst den Schluesselspeicher nie und erscheint in dieser
    /// Signatur nicht.
    fn operator_instance_public_key(&self)
    -> Result<Option<CanonicalPublicCoseKey>, OperatorError>;
}

/// Eine Bedienerbindung, die der GEWAEHLTE Registry-Head als aktiv fuehrt.
///
/// Nicht frei konstruierbar: der einzige Weg ist [`Self::resolve`] mit einem
/// [`SelectedRegistryHead`]. Eine selbst gebaute Bindung wuerde die Aktivitaets-
/// und Widerrufspruefung der Stufe 1 umgehen, und mit ihr die Zeit, gegen die
/// jeder Nachweis bewertet wird.
pub struct BoundOperator {
    organization_id: OrganizationId,
    device_id: DeviceId,
    binding_object_hash: ObjectHash,
    os_account_binding_hash: Hash32,
    operator_instance_key_thumbprint: KeyThumbprint,
    effective_now: UnixMillis,
}

impl BoundOperator {
    /// Loest die Bindung aus dem gewaehlten Head auf.
    ///
    /// Das Geraet kommt NICHT aus einem Parameter, sondern aus dem
    /// Writer-Zertifikat, das die Bindung nennt — sonst koennte ein Aufrufer
    /// eine Bindung gegen ein fremdes Geraet pruefen lassen.
    pub fn resolve(
        head: &SelectedRegistryHead,
        binding_object_hash: ObjectHash,
    ) -> Result<Self, OperatorError> {
        let binding = head
            .active_operator_binding_fields(binding_object_hash)
            .ok_or(OperatorError::BindingNotActive)?;
        let certificate = head
            .active_certificate_fields(binding.device_certificate_hash)
            .ok_or(OperatorError::DeviceCertificateNotActive)?;
        Ok(Self {
            organization_id: binding.organization_id,
            device_id: certificate.device_id,
            binding_object_hash,
            os_account_binding_hash: binding.os_account_binding_hash,
            operator_instance_key_thumbprint: binding.operator_instance_key_thumbprint,
            effective_now: head.preexisting_effective_now().value(),
        })
    }

    pub(crate) const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    pub(crate) const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub(crate) const fn binding_object_hash(&self) -> ObjectHash {
        self.binding_object_hash
    }

    pub(crate) const fn os_account_binding_hash(&self) -> Hash32 {
        self.os_account_binding_hash
    }

    pub(crate) const fn operator_instance_key_thumbprint(&self) -> KeyThumbprint {
        self.operator_instance_key_thumbprint
    }

    /// Die Zeit des Head, zu der diese Bindung aufgeloest wurde.
    ///
    /// Ein Nachweis wird zu genau dieser Zeit ausgestellt. Es gibt keinen Weg,
    /// stattdessen eine andere Zeit einzusetzen: `PreexistingEffectiveNow` ist
    /// in Stufe 1 nicht frei baubar, und diese Crate nimmt keine Zeit als
    /// Parameter.
    pub(crate) const fn effective_now(&self) -> UnixMillis {
        self.effective_now
    }
}
