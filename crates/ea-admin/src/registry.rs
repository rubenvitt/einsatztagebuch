//! Die Fassade der Registrierungsablaeufe ueber dem Auswahlkern von `ea-trust`.
//!
//! # Was hier NICHT passiert
//!
//! Der Dreischritt [`ea_trust::verify_registry_candidate`] →
//! [`ea_trust::prepare_local_time`] → [`ea_trust::select_registry_head`] wird
//! nicht nachgebaut, sondern angeordnet. Insbesondere rechnet dieses Modul
//! KEINE Millisekunden: Skew, Ablauf, Alterung und Lease kommen aus `ea-trust`
//! und `ea-time`. Der Plan sagt dazu „no duplicate grace period or clock
//! calculation is allowed" — eine zweite Uhr waere eine zweite Wahrheit, und
//! die falsche waere nicht die, die man beim Bauen im Blick hat.
//!
//! Auch das Registrierungsereignis entsteht nicht hier: die Fensterpruefung und
//! die Versionsfortschreibung liegen in
//! [`crate::OperatorBindingService::registry_event`], und
//! [`RegistryEventFactory`] reicht genau dorthin durch.

use core::fmt;

use ea_audit::LocalAuditService;
use ea_format::{FormatError, RegistryChangeV1, RegistryEventFieldsV1};
use ea_trust::{
    PendingFutureSuccessor, RegistryError, RegistrySelectionOutcome, SelectedRegistryHead,
    TrustError, TrustStateStore, VerifiedClockRelease, VerifiedSignedTime, VerifiedTrust,
    prepare_local_time, select_registry_head, verify_current_head_fallback,
    verify_registry_candidate,
};
use ea_types::{ChainSequence, ObjectHash, UnixMillis};

use crate::{
    OperatorBindingService, OperatorLifecycleError, RegistryWindow, VerifiedLocalDeviceIdentity,
    revocation::ClassifiedRevocationTarget,
};

/// Ein Fehlschlag an der Grenze der Registrierungsablaeufe.
///
/// # Warum das Praefix `EA-WORKFLOW-` heisst
///
/// Zwei naheliegende Namen sind vergeben, und zwar beide an etwas anderes:
///
/// `EA-ADMIN-` ist der AKTIONSCODE-Namensraum der Serverzeilen des technischen
/// Verwaltungsaudits (`apps/server/src/admin_audit.rs`); die Begruendung steht
/// ausfuehrlich an [`crate::AdminError`] (`crates/ea-admin/src/error.rs:12-52`).
/// Ein Fehlercode desselben Praefixes machte fuer den Leser einer Zeile
/// ununterscheidbar, ob `EA-ADMIN-…` eine vollzogene Handlung oder ihr
/// Scheitern meldet.
///
/// `EA-REGISTRY-` ist entgegen der Planannahme NICHT frei: `ea-writer` fuehrt
/// dort bereits `EA-REGISTRY-STALE-BLOCKED` und
/// `EA-REGISTRY-STALE-ACK-{REQUIRED,REPLAY,PREVIEW-MISMATCH}`
/// (`crates/ea-writer/src/error.rs:119,137-139`). Dazu kaeme die Verwechslung
/// mit der bestehenden Familie `EA-TRUST-REGISTRY-{GAP,FORK,ROLLBACK,…}`
/// (`crates/ea-trust/src/error.rs:136-140`), die Aussagen ueber die TOPOLOGIE
/// einer Linie macht — dieses Modul macht Aussagen ueber einen ABLAUF.
///
/// `EA-WORKFLOW-` benennt genau diesen Gegenstand und ist im Baum sonst
/// nirgends vergeben (`grep -rhoE '"EA-[A-Z0-9-]+"' crates apps` kennt 46
/// Familien, diese nicht).
///
/// Die durchgereichten Arme behalten den Code ihrer Herkunft. Ein erschoepftes
/// Lease bleibt `EA-TRUST-SEQUENCE-LEASE`; es unter neuem Namen zu melden
/// hiesse, denselben Befund zweimal zu benennen.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum RegistryWorkflowError {
    /// Der ueber den zweiten Kanal zurueckgemeldete Fingerprint ist nicht der
    /// des beantragten Zertifikats.
    FingerprintMismatch,
    /// Das benannte Objekt ist ein Administrationszertifikat.
    ///
    /// Weder Aenderung 0 noch Aenderung 1 fassen es an: seine Ausstellung ist
    /// Aktion 5 Effekt 0, sein Widerruf Aktion 5 Effekt 1. Der Kern sieht
    /// dasselbe (`crates/ea-trust/src/registry.rs:1071-1077` fuer Aenderung 0,
    /// `:1199-1229` fuer Aenderung 1); dieser Arm sagt nur frueher und
    /// deutlicher, WOHIN die Handlung stattdessen gehoert.
    AdminCertificateLifecycle,
    /// Die initiale Policy laesst eine der Dimensionen offen, die sie
    /// ausdruecklich festlegen muss.
    PolicyIncomplete,
    /// Das benannte Objekt ist nicht das, was diese Handlung braucht.
    ///
    /// Zwei Faelle teilen sich diesen Arm, weil sie derselbe Befund sind —
    /// „hier steht nicht der Gegenstand, ueber den gehandelt werden soll":
    /// ein Widerrufsziel, das am gewaehlten Kopf weder als Zertifikat noch als
    /// Bindung aktiv ist, und ein Geraeteantrag, dessen Bytes kein
    /// Geraetezertifikat tragen. Ein zweiter Code daneben unterschiede zwei
    /// Lesarten desselben Satzes.
    TargetNotActive,
    Registry(RegistryError),
    Trust(TrustError),
    Lifecycle(OperatorLifecycleError),
    Format(FormatError),
}

impl RegistryWorkflowError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FingerprintMismatch => "EA-WORKFLOW-FINGERPRINT-MISMATCH",
            Self::AdminCertificateLifecycle => "EA-WORKFLOW-ADMIN-CERTIFICATE-LIFECYCLE",
            Self::PolicyIncomplete => "EA-WORKFLOW-POLICY-INCOMPLETE",
            Self::TargetNotActive => "EA-WORKFLOW-TARGET-NOT-ACTIVE",
            Self::Registry(error) => error.code(),
            Self::Trust(error) => error.code(),
            Self::Lifecycle(error) => error.code(),
            Self::Format(error) => error.code(),
        }
    }
}

impl fmt::Debug for RegistryWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for RegistryWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RegistryWorkflowError {}

impl From<RegistryError> for RegistryWorkflowError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<TrustError> for RegistryWorkflowError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<OperatorLifecycleError> for RegistryWorkflowError {
    fn from(error: OperatorLifecycleError) -> Self {
        Self::Lifecycle(error)
    }
}

impl From<FormatError> for RegistryWorkflowError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

/// Der Auswahlablauf: Kandidat pruefen, lokale Zeit binden, Kopf waehlen.
///
/// Der Dienst haelt den persistenten Zustandsspeicher, weil
/// [`ea_trust::prepare_local_time`] ihn bis zur Auswahl AUSSCHLIESSLICH
/// borgt — Zeitblock und Auswahl gehoeren zu einem einzigen Speicherzugriff,
/// und ein Aufrufer, der beide Schritte selbst anordnete, koennte dazwischen
/// schreiben.
pub struct RegistryWorkflowService<'store> {
    store: &'store mut dyn TrustStateStore,
}

impl<'store> RegistryWorkflowService<'store> {
    pub fn new(store: &'store mut dyn TrustStateStore) -> Self {
        Self { store }
    }

    /// Waehlt den hoechsten anwendbaren Kopf fuer `proposed_sequence`.
    ///
    /// `release` wird ALS WERT verbraucht: [`VerifiedClockRelease`] ist nicht
    /// `Clone`, und `select_registry_head` bucht Nonce-Wiedereinspielung, Kopf
    /// und Zeitboden atomar. Ein zweiter Versuch nach einem Fehlschlag braucht
    /// deshalb eine neue Freigabe — genau das soll er.
    ///
    /// # Errors
    ///
    /// Reicht den Befund des Kerns durch: Rueckrollen, Gabelung, Luecke,
    /// falscher Vorgaenger, erschoepftes Lease, veralteter Kopf, nur
    /// zukuenftiger Nachfolger, Zeitversatz.
    pub fn select(
        &mut self,
        trust: &VerifiedTrust,
        proposed_sequence: ChainSequence,
        os_wall_clock: UnixMillis,
        sources: &[VerifiedSignedTime],
        release: Option<VerifiedClockRelease>,
    ) -> Result<RegistrySelectionOutcome, RegistryWorkflowError> {
        let candidate = verify_registry_candidate(trust, proposed_sequence)?;
        let local_time = prepare_local_time(&mut *self.store, &candidate, os_wall_clock, sources)?;
        Ok(select_registry_head(candidate, local_time, release)?)
    }

    /// Faellt nach einem nur zukuenftigen Nachfolger auf den GEBUNDENEN Kopf
    /// zurueck.
    ///
    /// Der Rueckfall ist kein Freibrief: steht der Nachfolger inzwischen
    /// bereit, sperrt der Kern ihn mit `EA-TRUST-SUCCESSOR-READY`. Das ist der
    /// Fall „ein neuerer anwendbarer Kopf ist bekannt".
    ///
    /// # Errors
    ///
    /// Wie [`Self::select`], zusaetzlich der bereitstehende Nachfolger.
    pub fn select_after_future_successor(
        &mut self,
        trust: &VerifiedTrust,
        pending: PendingFutureSuccessor,
        os_wall_clock: UnixMillis,
        sources: &[VerifiedSignedTime],
        release: Option<VerifiedClockRelease>,
    ) -> Result<RegistrySelectionOutcome, RegistryWorkflowError> {
        let candidate = verify_current_head_fallback(trust, pending)?;
        let local_time = prepare_local_time(&mut *self.store, &candidate, os_wall_clock, sources)?;
        Ok(select_registry_head(candidate, local_time, release)?)
    }
}

/// Eine Administrationshandlung mit ihrem eingefrorenen Aktionscode.
///
/// # Warum die Stelligkeit AM TYP haengt
///
/// Die Aktionscodes 0..6 sind auf dem Draht ein rohes `pub action_code: u8`
/// (`crates/ea-format/src/etb.rs:151`), und die Zuordnung von Code zu
/// Stelligkeit lebt sonst allein im Dekodierer `decode_registry_change`
/// (`crates/ea-format/src/etb.rs:1670-1710`). Ein Erzeuger, der sie aus
/// getrennten Feldern zusammensetzt, kann sie verfehlen — Aktion 1
/// `deviceRevoke` hat KEIN direktes Ziel, Aktion 5 hat eines nur im Effekt 0.
/// Hier folgen Code, Stelligkeit und Aenderung aus DERSELBEN Variante, also
/// koennen sie nicht auseinanderlaufen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RegistryActionV1 {
    /// 0 `deviceApprove`: ein direktes Nicht-Administrationszertifikat,
    /// gepaart mit Aenderung 0.
    DeviceApprove { certificate_object_hash: ObjectHash },
    /// 1 `deviceRevoke`: KEIN direktes Ziel, ausschliesslich Aenderung 1 auf
    /// ein bereits aktives Geraet, eine Bindung oder eine Komponente.
    ///
    /// Die Variante nimmt KEIN rohes Paar aus Art und Hash entgegen, sondern
    /// ein [`ClassifiedRevocationTarget`]: nur so laesst sich die Zusage der
    /// Global Constraints („Change 1 never revokes Admins") am Typ und nicht
    /// erst am naechsten Kopfuebergang halten.
    DeviceRevoke(ClassifiedRevocationTarget),
    /// 2 `policyChange`: die Policy, gepaart mit Aenderung 2. Kopf 1 traegt
    /// hierueber die initiale Policy.
    PolicyChange { policy_object_hash: ObjectHash },
    /// 3 `writerTransition`: der Uebergang, gepaart mit Aenderung 3.
    WriterTransition { transition_object_hash: ObjectHash },
    /// 4 `operatorBinding`: die Bindung, gepaart mit Aenderung 4.
    OperatorBinding { binding_object_hash: ObjectHash },
    /// 5 `adminKeyChange`, Effekt 0: ein direktes NEUES
    /// Administrationszertifikat.
    AdminKeyIssue { certificate_object_hash: ObjectHash },
    /// 5 `adminKeyChange`, Effekt 1: KEIN direktes Ziel; widerrufen wird ein
    /// bereits aktives Administrationszertifikat.
    AdminKeyRevoke { certificate_object_hash: ObjectHash },
    /// 6 `rootRotation`: die Wurzelurkunde, gepaart mit Aenderung 6.
    RootRotation { certificate_object_hash: ObjectHash },
}

impl RegistryActionV1 {
    /// Der eingefrorene Aktionscode 0..6 der Global Constraints.
    #[must_use]
    pub const fn action_code(&self) -> u8 {
        match self {
            Self::DeviceApprove { .. } => 0,
            Self::DeviceRevoke(_) => 1,
            Self::PolicyChange { .. } => 2,
            Self::WriterTransition { .. } => 3,
            Self::OperatorBinding { .. } => 4,
            Self::AdminKeyIssue { .. } | Self::AdminKeyRevoke { .. } => 5,
            Self::RootRotation { .. } => 6,
        }
    }

    /// Das GENAU EINE direkte Ziel dieser Autorisierung — oder keines.
    ///
    /// `None` heisst nicht „unbekannt", sondern „diese Handlung bereitet kein
    /// neues Objekt vor": ein Widerruf benennt einen Bestand, den es schon
    /// gibt.
    #[must_use]
    pub const fn direct_target_object_hash(&self) -> Option<ObjectHash> {
        match self {
            Self::DeviceApprove {
                certificate_object_hash,
            }
            | Self::AdminKeyIssue {
                certificate_object_hash,
            }
            | Self::RootRotation {
                certificate_object_hash,
            } => Some(*certificate_object_hash),
            Self::PolicyChange { policy_object_hash } => Some(*policy_object_hash),
            Self::WriterTransition {
                transition_object_hash,
            } => Some(*transition_object_hash),
            Self::OperatorBinding {
                binding_object_hash,
            } => Some(*binding_object_hash),
            Self::DeviceRevoke(_) | Self::AdminKeyRevoke { .. } => None,
        }
    }

    /// Die GENAU EINE Registrierungsaenderung, die zu dieser Handlung passt.
    #[must_use]
    pub const fn change(&self) -> RegistryChangeV1 {
        match self {
            Self::DeviceApprove {
                certificate_object_hash,
            } => RegistryChangeV1::Certificate {
                object_hash: *certificate_object_hash,
            },
            Self::DeviceRevoke(target) => RegistryChangeV1::Target {
                target_kind: target.class().target_kind(),
                object_hash: target.object_hash(),
            },
            Self::PolicyChange { policy_object_hash } => RegistryChangeV1::Policy {
                object_hash: *policy_object_hash,
            },
            Self::WriterTransition {
                transition_object_hash,
            } => RegistryChangeV1::WriterTransition {
                object_hash: *transition_object_hash,
            },
            Self::OperatorBinding {
                binding_object_hash,
            } => RegistryChangeV1::OperatorBinding {
                object_hash: *binding_object_hash,
            },
            Self::AdminKeyIssue {
                certificate_object_hash,
            } => RegistryChangeV1::AdminCertificate {
                object_hash: *certificate_object_hash,
                effect: 0,
            },
            Self::AdminKeyRevoke {
                certificate_object_hash,
            } => RegistryChangeV1::AdminCertificate {
                object_hash: *certificate_object_hash,
                effect: 1,
            },
            Self::RootRotation {
                certificate_object_hash,
            } => RegistryChangeV1::RootCertificate {
                object_hash: *certificate_object_hash,
            },
        }
    }
}

/// Die Ereignisfabrik der Administrationsablaeufe.
///
/// Sie baut nichts selbst: [`crate::OperatorBindingService::registry_event`]
/// haelt die Fensterpruefung, die Versionsfortschreibung (`+1` auf die
/// GEPRUEFTE Vorgaengerversion), die Bindung an den geprueften Vorgaengerkopf
/// und die Uebernahme des Policy-Hashes. Ein zweiter Erzeuger daneben waere
/// die zweite Uhr, die der Plan ausdruecklich verbietet.
///
/// Auditzeilen bucht die Fabrik KEINE. Sie bereitet vor; gebucht wird beim
/// Signieren — die Zeremonie schreibt ihre `adminRootCeremony`-Zeile, der
/// Bindungswiderruf seine `revocation`-Zeile. Eine dritte Zeile ueber dieselbe
/// Handlung waere doppelte Buchfuehrung.
pub struct RegistryEventFactory<'a> {
    head: &'a SelectedRegistryHead,
    service: OperatorBindingService<'a>,
}

impl<'a> RegistryEventFactory<'a> {
    #[must_use]
    pub const fn new(
        head: &'a SelectedRegistryHead,
        audit: &'a dyn LocalAuditService,
        local_device: VerifiedLocalDeviceIdentity,
    ) -> Self {
        Self {
            head,
            service: OperatorBindingService::new(head, audit, local_device),
        }
    }

    /// Der Kopf, gegen den diese Fabrik plant.
    #[must_use]
    pub const fn head(&self) -> &SelectedRegistryHead {
        self.head
    }

    /// Das Aktivierungsereignis fuer GENAU EINE Handlung.
    ///
    /// # Errors
    ///
    /// `EA-OPERATOR-REGISTRY-WINDOW`, wenn das Fenster ausserhalb des Lease
    /// des gewaehlten Kopfes liegt oder die Registrierungsalterung der
    /// gebundenen Policy ueberschreitet.
    pub fn plan(
        &self,
        window: RegistryWindow,
        action: &RegistryActionV1,
    ) -> Result<RegistryEventFieldsV1, RegistryWorkflowError> {
        Ok(self.service.registry_event(window, action.change())?)
    }
}
