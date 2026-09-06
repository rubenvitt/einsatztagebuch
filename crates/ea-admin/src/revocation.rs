//! Der Widerruf ueber Aenderung 1 — und was er ausdruecklich NICHT tut.
//!
//! # Warum dieses Modul duenn ist
//!
//! Der Bindungswiderruf hat seinen Dienst bereits:
//! [`crate::OperatorBindingService::revoke`]
//! (`crates/ea-admin/src/operator.rs:531`) mit seinem dauerhaften Zielvorsatz
//! in `operator_revocation.rs`. Der Widerruf eines
//! Administrationszertifikats ist Aktion 5 Effekt 1 und gehoert zum
//! Zertifikatslebenszyklus. Uebrig bleibt genau das, was keiner von beiden
//! leistet: die ZUORDNUNG eines benannten Objekts zu seiner Zielart und die
//! ausdrueckliche Aussage darueber, was ein Widerruf nicht zurueckholt. Beides
//! einmal, nicht zweimal.

use core::fmt;

use ea_format::{CertificateKindV1, RegistryEventFieldsV1};
use ea_trust::SelectedRegistryHead;
use ea_types::{CertificateHash, ChainSequence, ObjectHash};

use crate::{
    RegistryWindow,
    registry::{RegistryActionV1, RegistryEventFactory, RegistryWorkflowError},
};

/// Die Zielart einer Aenderung 1 als BENANNTE Art statt als roher `u8`.
///
/// Die drei Arten sind die des Draht-Dekodierers
/// (`crates/ea-format/src/etb.rs:1678-1688`, `target_kind > 2` ist ein
/// Formfehler) und die des Kerns
/// (`crates/ea-trust/src/registry.rs:1194-1240`).
///
/// Der Typ ist ein reines Wort fuer die Anzeige. Was ein Widerruf tatsaechlich
/// benennen darf, traegt [`ClassifiedRevocationTarget`] — dort steht die Art
/// UNTRENNBAR neben ihrem Objekt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationTargetClass {
    /// Zielart 0: Writer, Reader, Key Approver, Recovery-Empfaenger,
    /// Historical Grant Authority.
    NonAdminDevice,
    /// Zielart 1: eine Bedienerbindung.
    OperatorBinding,
    /// Zielart 2: Serverquittungs- und Loeschattestierungskomponenten.
    Component,
}

impl RevocationTargetClass {
    /// Die Zahl, die auf den Draht geht.
    #[must_use]
    pub const fn target_kind(self) -> u8 {
        match self {
            Self::NonAdminDevice => 0,
            Self::OperatorBinding => 1,
            Self::Component => 2,
        }
    }
}

/// Ein Widerrufsziel, dessen Art aus dem BESTAND hergeleitet wurde — und das
/// deshalb kein Administrationszertifikat sein kann.
///
/// # Warum Art und Objekt EIN Typ sind
///
/// Die Global Constraints sagen „Change 1 never revokes Admins". Diese Zusage
/// traegt der Typ und nicht die Sorgfalt des Aufrufers: Der Wert hat keine
/// oeffentlichen Felder und keinen oeffentlichen Konstruktor, er entsteht
/// ausschliesslich in [`classify_revocation_target`], und dort ist ein
/// Administrationszertifikat der Fehlerarm
/// `EA-WORKFLOW-ADMIN-CERTIFICATE-LIFECYCLE`. Dieselbe Bauart wie
/// [`crate::device::ConfirmedDeviceFingerprint`] und
/// [`ea_trust::VerifiedClockRelease`]: ein Zustand, den nur die Pruefung
/// erreicht.
///
/// Waeren Art und Objekt ZWEI Felder einer Aktionsvariante, brauchte die
/// Umgehung keinen neuen Typ: man liesse ein Lesegeraet einordnen und haengte
/// die gewonnene Art an den Hash eines Administrationszertifikats. Dass beide
/// zusammen entstehen und zusammen bleiben, ist die eigentliche Zusage.
///
/// ```compile_fail
/// use ea_admin::revocation::{ClassifiedRevocationTarget, RevocationTargetClass};
/// use ea_types::{Hash32, ObjectHash};
///
/// fn forge(admin_certificate: ObjectHash) -> ClassifiedRevocationTarget {
///     ClassifiedRevocationTarget {
///         class: RevocationTargetClass::NonAdminDevice,
///         object_hash: admin_certificate,
///     }
/// }
/// ```
///
/// Der positive Gegenzeuge, damit der obige an seinem Gegenstand scheitert und
/// nicht an seinen Importen:
///
/// ```
/// use ea_admin::revocation::RevocationTargetClass;
///
/// assert_eq!(RevocationTargetClass::NonAdminDevice.target_kind(), 0);
/// let _: fn(&ea_trust::SelectedRegistryHead, ea_types::ObjectHash) -> _ =
///     ea_admin::revocation::classify_revocation_target;
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ClassifiedRevocationTarget {
    class: RevocationTargetClass,
    object_hash: ObjectHash,
}

/// Zeigt die ART, nicht das Objekt.
///
/// [`ObjectHash`] traegt im ganzen Baum bewusst kein `Debug`; ein abgeleitetes
/// `Debug` haette den Hash durch diese Huelle hindurch doch in jede Ausgabe
/// getragen. Was ein Leser hier braucht, ist die Einordnung — welches Objekt
/// gemeint war, steht ohnehin in der Handlung, die den Wert erzeugt hat.
impl fmt::Debug for ClassifiedRevocationTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ClassifiedRevocationTarget({:?})", self.class)
    }
}

impl ClassifiedRevocationTarget {
    /// Die hergeleitete Art.
    #[must_use]
    pub const fn class(&self) -> RevocationTargetClass {
        self.class
    }

    /// Das Objekt, fuer das die Art hergeleitet wurde.
    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }
}

/// Was ein Widerruf bewirkt — und was er ausdruecklich nicht bewirkt.
///
/// # Warum das ein TYP ist und kein Absatz in der Bedienfuehrung
///
/// „Widerruf holt nichts zurueck" ist eine Produktinvariante der Global
/// Constraints („no cryptographic recall of already decrypted data"). Als
/// blosser Text stuende sie in der Oberflaeche und koennte dort still
/// verschwinden; als abfragbarer Zustand kann ein Zeuge sie belegen und eine
/// Anzeige sie nicht versehentlich anders behaupten.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationEffect {
    effective_from_sequence: ChainSequence,
    class: RevocationTargetClass,
}

impl RevocationEffect {
    /// Ab dieser Sequenz bleiben NEUE Freigaben aus.
    ///
    /// Davor erteilte bleiben unberuehrt: der gewaehlte Kopf wertet seinen
    /// aktiven Bestand an der `proposed_sequence` aus
    /// (`SelectedRegistryHead::active_certificates`), und ein frueherer Kopf
    /// bleibt ein frueherer Kopf.
    #[must_use]
    pub const fn stops_new_grants_from(&self) -> ChainSequence {
        self.effective_from_sequence
    }

    /// Immer `false`. Ein Widerruf holt bereits erteilte Zugriffsfreigaben
    /// nicht zurueck; die Schluesselumschlaege liegen im Archiv und in
    /// Repliken, die diese Handlung nicht erreicht.
    #[must_use]
    pub const fn recalls_issued_grants(&self) -> bool {
        false
    }

    /// Immer `false`. Bereits entschluesselter Klartext ist ausserhalb der
    /// Reichweite jeder Registrierungsaenderung — die Non-Goals nennen den
    /// „cryptographic recall of already decrypted data" ausdruecklich als
    /// Nichtziel.
    #[must_use]
    pub const fn recalls_decrypted_plaintext(&self) -> bool {
        false
    }

    /// Die Zielart, ueber die dieser Widerruf laeuft.
    #[must_use]
    pub const fn target_class(&self) -> RevocationTargetClass {
        self.class
    }
}

/// Bestimmt die Zielart eines Widerrufs aus dem Bestand des gewaehlten Kopfes.
///
/// Das Ergebnis ist der EINZIGE Weg zu einem [`ClassifiedRevocationTarget`] und
/// damit zu [`crate::registry::RegistryActionV1::DeviceRevoke`].
///
/// # Errors
///
/// `EA-WORKFLOW-ADMIN-CERTIFICATE-LIFECYCLE`, wenn das Objekt ein
/// Administrationszertifikat ist — Aenderung 1 widerruft NIE Administratoren,
/// dafuer gibt es Aktion 5 Effekt 1. `EA-WORKFLOW-TARGET-NOT-ACTIVE`, wenn am
/// gewaehlten Kopf weder ein Zertifikat noch eine Bindung dieses Namens aktiv
/// ist.
pub fn classify_revocation_target(
    head: &SelectedRegistryHead,
    object_hash: ObjectHash,
) -> Result<ClassifiedRevocationTarget, RegistryWorkflowError> {
    let class = classify(head, object_hash)?;
    Ok(ClassifiedRevocationTarget { class, object_hash })
}

fn classify(
    head: &SelectedRegistryHead,
    object_hash: ObjectHash,
) -> Result<RevocationTargetClass, RegistryWorkflowError> {
    if let Some(fields) = head.active_certificate_fields(CertificateHash::from(object_hash)) {
        return match fields.certificate_kind {
            CertificateKindV1::Writer
            | CertificateKindV1::Reader
            | CertificateKindV1::KeyApprover
            | CertificateKindV1::RecoveryRecipient
            | CertificateKindV1::HistoricalGrantAuthority => {
                Ok(RevocationTargetClass::NonAdminDevice)
            }
            CertificateKindV1::ServerReceipt | CertificateKindV1::DeletionAttest => {
                Ok(RevocationTargetClass::Component)
            }
            CertificateKindV1::OrganizationAdmin => {
                Err(RegistryWorkflowError::AdminCertificateLifecycle)
            }
        };
    }
    if head.active_operator_binding_fields(object_hash).is_some() {
        return Ok(RevocationTargetClass::OperatorBinding);
    }
    Err(RegistryWorkflowError::TargetNotActive)
}

/// Plant eine Aenderung 1 fuer ein am gewaehlten Kopf aktives Ziel.
///
/// Gibt neben dem Ereignis den [`RevocationEffect`] heraus, damit die
/// Bedienfuehrung die Reichweite des Widerrufs nicht selbst behaupten muss.
///
/// # Errors
///
/// Wie [`classify_revocation_target`], zusaetzlich `EA-OPERATOR-REGISTRY-WINDOW`
/// aus der Ereignisfabrik.
pub fn plan_revocation(
    events: &RegistryEventFactory<'_>,
    window: RegistryWindow,
    object_hash: ObjectHash,
) -> Result<(RegistryEventFieldsV1, RevocationEffect), RegistryWorkflowError> {
    let target = classify_revocation_target(events.head(), object_hash)?;
    let event = events.plan(window, &RegistryActionV1::DeviceRevoke(target))?;
    let effect = RevocationEffect {
        effective_from_sequence: event.effective_from_sequence,
        class: target.class(),
    };
    Ok((event, effect))
}
