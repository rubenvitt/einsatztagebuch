//! Die getrennten Schritte einer Trust-Zeremonie als GESCHLOSSENE Aufzaehlung.
//!
//! # Warum eine Aufzaehlung und kein Ablaufdiagramm in der Oberflaeche
//!
//! Der Plan der Stufe 5 verlangt, dass ausstehende Anfrage, Fingerprint-
//! Vergleich, Admin-Autorisierung, Offline-Root-Export, Offline-Root-Import
//! und Registry-Veroeffentlichung GETRENNTE Schritte bleiben, die der Wirt
//! einzeln und in Reihenfolge geht. Stuende die Folge nur in der Schale,
//! koennte ein Knopf zwei Schritte auf einmal tun — und genau das soll
//! strukturell unmoeglich sein. Hier steht sie deshalb als Wert: [`next_step`]
//! kennt fuer jede Art den einen Nachfolger, und es gibt keine zweite Funktion,
//! die einen anderen kennte.
//!
//! Dieses Modul rechnet nichts und schreibt nichts. Die Dienste, die einen
//! Schritt AUSFUEHREN, liegen daneben: [`crate::device`] fuer Anfrage und
//! Fingerprint, [`crate::RootCeremonyService`] fuer die Autorisierung,
//! [`crate::operator_exchange`] fuer Export und Import,
//! [`crate::registry::RegistryWorkflowService`] fuer die Veroeffentlichung.
//!
//! # Warum nur `FingerprintConfirmed` entfaellt
//!
//! Der Fingerprint ist der Objekthash der EXAKTEN Zertifikatsbytes eines
//! beantragenden Geraets (`device.rs`). Ein Widerruf, eine Policy-Aenderung
//! und ein Writer-Uebergang benennen kein solches Geraet — es gibt nichts, was
//! ueber den zweiten Kanal zu vergleichen waere. Alle anderen Schritte
//! brauchen alle vier Arten gleich: jede ist eine Root-Zeremonie mit
//! Administrationsautorisierung, Offline-Signatur und Registry-Wirkung.

use ea_operator::ReauthPurpose;

/// Die vier Arten einer Trust-Zeremonie, die die Verwaltungsflaeche fuehrt.
///
/// Die Reihenfolge ist die der Registry-Aktionen 0 bis 3 (`deviceApprove`,
/// `deviceRevoke`, `policyChange`, `writerTransition`); Aktion 4 bis 6
/// (Bedienerbindung, Admin-Schluesselwechsel, Root-Rotation) haben in dieser
/// Stufe keine Oberflaeche und stehen deshalb nicht hier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustCeremonyKind {
    /// Aktion 0: ein beantragendes Nicht-Admin-Geraet wird freigegeben.
    DeviceApprove,
    /// Aktion 1: ein Zertifikat, eine Bindung oder eine Komponente wird
    /// widerrufen.
    DeviceRevoke,
    /// Aktion 2: eine neue Policy tritt in Kraft.
    PolicyChange,
    /// Aktion 3: der einzige aktive Writer wechselt.
    WriterTransition,
}

impl TrustCeremonyKind {
    /// Alle vier Arten, in Deklarationsreihenfolge.
    pub const ALL: [Self; 4] = [
        Self::DeviceApprove,
        Self::DeviceRevoke,
        Self::PolicyChange,
        Self::WriterTransition,
    ];
}

/// Die sechs Schritte einer Trust-Zeremonie, in der Reihenfolge, in der sie
/// gegangen werden.
///
/// Jeder Schritt ist ein ZUSTAND, den die Zeremonie dauerhaft erreicht hat,
/// und kein Knopf. `RegistryPublished` ist der letzte; er hat fuer keine Art
/// einen Nachfolger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustCeremonyStep {
    /// Die Anfrage liegt vor und ist noch nicht angesehen.
    PendingRequest,
    /// Der vollstaendige Fingerprint wurde ueber den zweiten Kanal bestaetigt
    /// (nur [`TrustCeremonyKind::DeviceApprove`]).
    FingerprintConfirmed,
    /// Die Administrationsautorisierung ist erteilt — verlangt einen FRISCHEN
    /// Bedienernachweis.
    AdminAuthorized,
    /// Die Root-Anfrage ist als Offline-Austauschdatei exportiert.
    RootRequestExported,
    /// Die Root-Antwort ist aus der Offline-Austauschdatei importiert.
    RootReplyImported,
    /// Das Registry-Ereignis ist veroeffentlicht — verlangt einen FRISCHEN
    /// Bedienernachweis.
    RegistryPublished,
    /// The signed target is published; its separate Registry activation is pending.
    TargetPublished,
}

impl TrustCeremonyStep {
    /// Every step, including the distinct terminal step of an issuance round.
    pub const ALL: [Self; 7] = [
        Self::PendingRequest,
        Self::FingerprintConfirmed,
        Self::AdminAuthorized,
        Self::RootRequestExported,
        Self::RootReplyImported,
        Self::RegistryPublished,
        Self::TargetPublished,
    ];
}

/// Der EINE Nachfolger eines Schritts fuer eine Art — `None` nach dem letzten.
///
/// [`TrustCeremonyKind::DeviceApprove`] geht alle sechs Schritte; die drei
/// anderen Arten gehen von `PendingRequest` direkt zu `AdminAuthorized`, weil
/// kein Geraetefingerprint zu vergleichen ist. Es gibt keinen weiteren Sprung.
/// Wer bei einer fingerprintlosen Art dennoch `FingerprintConfirmed` vorlegt,
/// bekommt denselben Nachfolger wie die Geraetefreigabe — der Schritt ist
/// dann ueberfluessig, aber kein Ausbruch aus der Folge.
#[must_use]
pub const fn next_step(
    kind: TrustCeremonyKind,
    step: TrustCeremonyStep,
) -> Option<TrustCeremonyStep> {
    match step {
        TrustCeremonyStep::PendingRequest => match kind {
            TrustCeremonyKind::DeviceApprove => Some(TrustCeremonyStep::FingerprintConfirmed),
            TrustCeremonyKind::DeviceRevoke
            | TrustCeremonyKind::PolicyChange
            | TrustCeremonyKind::WriterTransition => Some(TrustCeremonyStep::AdminAuthorized),
        },
        TrustCeremonyStep::FingerprintConfirmed => Some(TrustCeremonyStep::AdminAuthorized),
        TrustCeremonyStep::AdminAuthorized => Some(TrustCeremonyStep::RootRequestExported),
        TrustCeremonyStep::RootRequestExported => Some(TrustCeremonyStep::RootReplyImported),
        TrustCeremonyStep::RootReplyImported => Some(TrustCeremonyStep::RegistryPublished),
        TrustCeremonyStep::RegistryPublished | TrustCeremonyStep::TargetPublished => None,
    }
}

/// Chooses the successor within one explicitly identified ceremony round.
#[must_use]
pub const fn next_step_for_round(
    kind: TrustCeremonyKind,
    round: crate::administration_runtime::TrustCeremonyRoundV1,
    step: TrustCeremonyStep,
) -> Option<TrustCeremonyStep> {
    match (round, step) {
        (
            crate::administration_runtime::TrustCeremonyRoundV1::IssueTarget,
            TrustCeremonyStep::RootReplyImported,
        ) => Some(TrustCeremonyStep::TargetPublished),
        _ => next_step(kind, step),
    }
}

/// Ob das ERREICHEN dieses Schritts einen frischen Bedienernachweis verlangt.
///
/// `true` genau fuer [`TrustCeremonyStep::AdminAuthorized`] und
/// [`TrustCeremonyStep::RegistryPublished`]: das sind die zwei Schritte, an
/// denen eine Root-signierte Wirkung entsteht. Export und Import bewegen nur
/// Austauschdateien, der Fingerprint-Vergleich bewegt nichts.
#[must_use]
pub const fn requires_fresh_reauth(step: TrustCeremonyStep) -> bool {
    match step {
        TrustCeremonyStep::AdminAuthorized
        | TrustCeremonyStep::RegistryPublished
        | TrustCeremonyStep::TargetPublished => true,
        TrustCeremonyStep::PendingRequest
        | TrustCeremonyStep::FingerprintConfirmed
        | TrustCeremonyStep::RootRequestExported
        | TrustCeremonyStep::RootReplyImported => false,
    }
}

/// Der Zweck des Bedienernachweises fuer eine Art.
///
/// Alle vier Arten sind administrative Root-Zeremonien; der Zweck ist
/// deshalb fuer alle [`ReauthPurpose::AdminRootCeremony`]. Die Funktion steht
/// trotzdem hier und nicht als Konstante beim Aufrufer: kommt eine fuenfte
/// Art mit anderem Zweck hinzu, entscheidet der `match` ohne Sammelarm, dass
/// jemand ihn hier eintraegt.
#[must_use]
pub const fn reauth_purpose(kind: TrustCeremonyKind) -> ReauthPurpose {
    match kind {
        TrustCeremonyKind::DeviceApprove
        | TrustCeremonyKind::DeviceRevoke
        | TrustCeremonyKind::PolicyChange
        | TrustCeremonyKind::WriterTransition => ReauthPurpose::AdminRootCeremony,
    }
}

#[cfg(test)]
mod round_tests {
    use super::*;
    use crate::administration_runtime::TrustCeremonyRoundV1;
    #[test]
    fn target_publication_never_claims_registry_activation() {
        let published = next_step_for_round(
            TrustCeremonyKind::DeviceApprove,
            TrustCeremonyRoundV1::IssueTarget,
            TrustCeremonyStep::RootReplyImported,
        )
        .unwrap();
        assert_eq!(format!("{published:?}"), "TargetPublished");
        assert!(requires_fresh_reauth(published));
        assert!(
            next_step_for_round(
                TrustCeremonyKind::DeviceApprove,
                TrustCeremonyRoundV1::IssueTarget,
                published
            )
            .is_none()
        );
        assert_eq!(
            next_step_for_round(
                TrustCeremonyKind::DeviceRevoke,
                TrustCeremonyRoundV1::ActivateRegistry,
                TrustCeremonyStep::RootReplyImported
            ),
            Some(TrustCeremonyStep::RegistryPublished)
        );
    }
}
