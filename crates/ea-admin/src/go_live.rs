//! Das Go-live-Aggregat: sechzehn Anforderungen, drei Zustände, und
//! Rohe Messungen und signiert dokumentierte Voraussetzungen bleiben getrennt.
//!
//! # Was hier zusammenkommt
//!
//! `design.md` §17.3, §18.4 und §21 verlangen vor dem Produktivbetrieb:
//! mindestens zwei aktive Administratoren, verifizierte Sicherungen der vier
//! Schluesselklassen auf je zwei Medien, einen frischen Registry-Kopf mit
//! reichendem Lease, eine Policy und eine Evidence-Richtlinie, einen
//! Frischrechner-Recovery-Test innerhalb seines Intervalls, keinen halb
//! vollendeten Writer-Übergang, eine belegte Gerätehaltung und eine
//! dokumentierte datenschutzrechtliche Freigabe oder Deaktivierung des
//! `.eds`-Restnachweises (§16.3, AK 44). Der Baum
//! hat fuer keine dieser Aussagen ein gemeinsames Aggregat —
//! [`crate::operator_runtime::OperatorGoLiveReport`] ist ein Betriebsbericht
//! ueber Bindungen und nicht diese Liste. Hier entsteht sie.
//!
//! # Die eine Regel
//!
//! Jede Anforderung hat GENAU einen von drei Zustaenden
//! ([`GoLiveRequirementStatus`]), und [`GoLiveChecklist::production_ready`]
//! ist `true` NUR, wenn jede `Confirmed` ist. `NotAutomaticallyVerifiable` ist
//! kein Ja und kein „wahrscheinlich": es ist die Aussage, dass diese Maschine
//! den Beleg nicht hat. Eine Oberflaeche, die daraus ein Gruen machte, wuerde
//! den Bericht nach §17.3 in sein Gegenteil verkehren. Auch eine signiert
//! dokumentierte Voraussetzung bleibt deshalb `NotAutomaticallyVerifiable`:
//! die separat verifizierte, bei der Auswertung erneut gepruefte
//! Runtime-Admission setzt nur den Belegcode `EA-GOLIVE-POSTURE-DOCUMENTED`
//! und bestaetigt nichts. Sie darf eine Sitzung oeffnen, macht den Go-live aber
//! nie gruen. Deshalb wird `production_ready` HIER gerechnet und nicht in
//! TypeScript.
//!
//! # Was dieses Modul NICHT tut
//!
//! Es liest keinen Bestand. Jeder Beleg kommt als Wert in
//! [`GoLiveEvidence`], und jedes Feld ist `Option`: `None` heisst „nicht
//! automatisch pruefbar" mit dem Belegcode `EA-GOLIVE-EVIDENCE-UNAVAILABLE`.
//! Wer den Bestand hat — der Wirt —, fuellt die Felder; wer ihn nicht hat,
//! laesst sie leer und bekommt eine ehrliche Liste. Ein Aggregat, das selbst
//! in Kopf, Zeremoniezustand und Haltungsanbieter griffe, truege fuenf
//! Lebensdauern und waere ohne Wirt nicht messbar.
//!
//! # Die Ausgabe
//!
//! [`GoLiveChecklist::unresolved_report_json`] ist die deterministische
//! Go-live-Evidenzliste `ea.go-live-checklist/v1`: nur Codes, kein
//! Zeitstempel, kein Pfad, keine Zahl. Zwei Aufrufe liefern dieselben Bytes;
//! die Reihenfolge ist die der Anforderungen und nie die einer `HashMap`.

#[cfg(feature = "test-support")]
use crate::production_state::ProductionState;
use ea_format::RetentionPolicyFieldsV1;
use ea_key_provider::{DevicePostureReport, PostureCheck, PostureRequirement};
use ea_types::{ChainSequence, UnixMillis};
use serde::Serialize;

use crate::{
    bootstrap::{BackedUpKeyClass, KeyBackupRecordV1},
    writer_transition::WriterTransitionPhase,
};

/// Der Zustand EINER Go-live-Anforderung.
///
/// Drei Arme und kein `bool`: ein `bool` haette `NotAutomaticallyVerifiable`
/// in ein `false` oder — schlimmer — in ein `true` gedrueckt. Die deutsche
/// Kopie (`bestaetigt`, `nicht erfuellt`, `nicht automatisch pruefbar`)
/// entsteht in der Schale; die Variantennamen sind die emittierten Literale.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum GoLiveRequirementStatus {
    /// Der Beleg liegt vor und erfuellt die Anforderung.
    Confirmed,
    /// Der Beleg liegt vor und erfuellt die Anforderung NICHT.
    NotMet,
    /// Diese Maschine hat keinen Beleg; die Anforderung ist ausserhalb der
    /// Anwendung zu pruefen und im Go-live-Bericht zu dokumentieren.
    NotAutomaticallyVerifiable,
}

impl GoLiveRequirementStatus {
    /// Alle drei Zustaende, in Deklarationsreihenfolge.
    pub const ALL: [Self; 3] = [
        Self::Confirmed,
        Self::NotMet,
        Self::NotAutomaticallyVerifiable,
    ];
}

/// Der Belegcode, wenn kein Beleg vorliegt.
pub const EVIDENCE_UNAVAILABLE: &str = "EA-GOLIVE-EVIDENCE-UNAVAILABLE";

/// Die sechzehn Anforderungscodes in der FESTEN Reihenfolge der Liste.
///
/// Elf Go-live-Codes, die vier Haltungscodes, die
/// `apps/desktop/src-tauri/src/commands/writer.rs` schon heute fuer
/// [`PostureRequirement`] fuehrt — dieselben Zeichenketten, damit die
/// Haltungszeile der Verwaltungsflaeche und die des Writers denselben Code
/// tragen —, und am Ende die `.eds`-Restnachweis-Entscheidung (AK 44), additiv
/// angehängt, damit kein bestehender Index wandert.
pub const GO_LIVE_REQUIREMENT_CODES: [&str; 16] = [
    TWO_ADMINS,
    KEY_BACKUP_ROOT,
    KEY_BACKUP_ADMIN,
    KEY_BACKUP_RECOVERY_KEM,
    KEY_BACKUP_HGA,
    REGISTRY_AGE,
    REGISTRY_LEASE,
    POLICY,
    EVIDENCE_POLICY,
    RECOVERY_TEST,
    WRITER_TRANSITION,
    posture_requirement_code(PostureRequirement::FullDiskEncryption),
    posture_requirement_code(PostureRequirement::LockedNonSharedAccount),
    posture_requirement_code(PostureRequirement::AutomaticScreenLock),
    posture_requirement_code(PostureRequirement::SupportedOsPatchLevel),
    EDS_PRIVACY_DECISION,
];

const TWO_ADMINS: &str = "EA-GOLIVE-TWO-ADMINS";
const KEY_BACKUP_ROOT: &str = "EA-GOLIVE-KEY-BACKUP-ROOT";
const KEY_BACKUP_ADMIN: &str = "EA-GOLIVE-KEY-BACKUP-ADMIN";
const KEY_BACKUP_RECOVERY_KEM: &str = "EA-GOLIVE-KEY-BACKUP-RECOVERY-KEM";
const KEY_BACKUP_HGA: &str = "EA-GOLIVE-KEY-BACKUP-HGA";
const REGISTRY_AGE: &str = "EA-GOLIVE-REGISTRY-AGE";
const REGISTRY_LEASE: &str = "EA-GOLIVE-REGISTRY-LEASE";
const POLICY: &str = "EA-GOLIVE-POLICY";
const EVIDENCE_POLICY: &str = "EA-GOLIVE-EVIDENCE-POLICY";
const RECOVERY_TEST: &str = "EA-GOLIVE-RECOVERY-TEST";
const WRITER_TRANSITION: &str = "EA-GOLIVE-WRITER-TRANSITION";
const EDS_PRIVACY_DECISION: &str = "EA-GOLIVE-EDS-PRIVACY-DECISION";

/// Einstufung „Restnachweis freigegeben": Vernichtung aktiviert und der Hash
/// der datenschutzrechtlichen Freigabe signiert im Kopf.
const EDS_RESIDUAL_RELEASED: &str = "EA-GOLIVE-EVIDENCE-EDS-RESIDUAL-RELEASED";
/// Einstufung „Vernichtung deaktiviert": die signierte Policy selbst ist die
/// dokumentierte Deaktivierung.
const EDS_DESTRUCTION_DISABLED: &str = "EA-GOLIVE-EVIDENCE-EDS-DESTRUCTION-DISABLED";
/// Vernichtung aktiviert OHNE dokumentierte Freigabe — der Fall, den das
/// Vernichtungs-Gate mit `EA-DESTRUCTION-PRIVACY-GATE` abweist.
const EDS_PRIVACY_DECISION_MISSING: &str = "EA-GOLIVE-EVIDENCE-EDS-PRIVACY-DECISION-MISSING";

/// Die Mindestzahl aktiver Administratoren (`design.md` Global Constraints:
/// „At least two active Admin keys … exist before production").
const MINIMUM_ACTIVE_ADMINS: usize = 2;

/// Die Mindestzahl getrennter Medien je Schluesselsicherung (`:1342`).
const MINIMUM_BACKUP_MEDIA: usize = 2;

/// Der stabile Code EINER Haltungsanforderung — dieselben vier Zeichenketten
/// wie `apps/desktop/src-tauri/src/commands/writer.rs::requirement_code`.
///
/// Ein `match` ohne Sammelarm: eine fuenfte Anforderung in `ea-key-provider`
/// bricht die Uebersetzung, statt still zu verschwinden.
const fn posture_requirement_code(requirement: PostureRequirement) -> &'static str {
    match requirement {
        PostureRequirement::FullDiskEncryption => "EA-POSTURE-FULL-DISK-ENCRYPTION",
        PostureRequirement::LockedNonSharedAccount => "EA-POSTURE-ACCOUNT-EXCLUSIVE",
        PostureRequirement::AutomaticScreenLock => "EA-POSTURE-SCREEN-LOCK",
        PostureRequirement::SupportedOsPatchLevel => "EA-POSTURE-OS-PATCH-LEVEL",
    }
}

/// EINE Anforderung mit ihrem Zustand und dem Code des Belegs.
///
/// Keine oeffentlichen Felder: ein Wert entsteht ausschliesslich in
/// [`evaluate_go_live`], und niemand setzt eine Zeile von aussen auf
/// `Confirmed`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoLiveRequirement {
    code: &'static str,
    status: GoLiveRequirementStatus,
    evidence_code: String,
    decision_document_hash: Option<[u8; 32]>,
}

impl GoLiveRequirement {
    /// Der stabile Anforderungscode aus [`GO_LIVE_REQUIREMENT_CODES`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Der Zustand.
    #[must_use]
    pub const fn status(&self) -> GoLiveRequirementStatus {
        self.status
    }

    /// Der Code des Belegs — [`EVIDENCE_UNAVAILABLE`], wenn keiner vorliegt.
    #[must_use]
    pub fn evidence_code(&self) -> &str {
        &self.evidence_code
    }

    /// Der Hash des Dokuments zur `.eds`-Restnachweis-Entscheidung, wie ihn
    /// der gewählte Kopf signiert führt — `None` für jede andere Zeile.
    ///
    /// Er ist Beleg, nicht Einstufung: die Einstufung steht im
    /// [`Self::evidence_code`]. Die Software bewertet das Dokument nicht
    /// (`design.md` §16.3); sie weist nur nach, dass und welches signiert
    /// vorliegt.
    #[must_use]
    pub const fn decision_document_hash(&self) -> Option<&[u8; 32]> {
        self.decision_document_hash.as_ref()
    }

    fn unavailable(code: &'static str) -> Self {
        Self {
            code,
            status: GoLiveRequirementStatus::NotAutomaticallyVerifiable,
            evidence_code: EVIDENCE_UNAVAILABLE.to_owned(),
            decision_document_hash: None,
        }
    }

    /// Ein gelesener Beleg: `met` entscheidet zwischen den ZWEI belegten
    /// Zustaenden; der dritte ist von hier aus unerreichbar.
    fn decided(
        code: &'static str,
        met: bool,
        confirmed_evidence: &'static str,
        not_met_evidence: &'static str,
    ) -> Self {
        Self {
            code,
            status: if met {
                GoLiveRequirementStatus::Confirmed
            } else {
                GoLiveRequirementStatus::NotMet
            },
            evidence_code: if met {
                confirmed_evidence.to_owned()
            } else {
                not_met_evidence.to_owned()
            },
            decision_document_hash: None,
        }
    }

    /// Ein Beleg, der fehlen darf: `None` ist der dritte Zustand.
    fn from_option(
        code: &'static str,
        met: Option<bool>,
        confirmed_evidence: &'static str,
        not_met_evidence: &'static str,
    ) -> Self {
        match met {
            None => Self::unavailable(code),
            Some(met) => Self::decided(code, met, confirmed_evidence, not_met_evidence),
        }
    }
}

/// Frische und Lease des gewaehlten Registry-Kopfes, wie der Wirt sie liest.
///
/// Zwei Anforderungen entstehen daraus: das ALTER gegen die Policyfrist und
/// das LEASE gegen die naechste Sequenz und `notAfter`. Beide kommen aus
/// demselben Kopf und stehen deshalb in einem Wert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryFreshness {
    /// Alter des Kopfes in Millisekunden.
    pub age_ms: u64,
    /// Zulaessiges Hoechstalter aus der Policy (`maxRegistryAgeMs`).
    pub max_age_ms: u64,
    /// Die letzte Sequenz, die das Lease deckt.
    pub lease_valid_through: ChainSequence,
    /// Die Sequenz, die der Writer als naechste schreiben wuerde.
    pub next_sequence: ChainSequence,
    /// Die Zeitgrenze des Kopfes.
    pub not_after: UnixMillis,
    /// Der Zeitpunkt, gegen den `not_after` gehalten wird.
    pub now: UnixMillis,
}

impl RegistryFreshness {
    const fn age_within_limit(self) -> bool {
        self.age_ms <= self.max_age_ms
    }

    const fn lease_covers_next(self) -> bool {
        self.next_sequence.get() <= self.lease_valid_through.get()
            && self.now.get() <= self.not_after.get()
    }
}

/// Die `.eds`-Restnachweis-Entscheidung des gewählten Registry-Kopfes.
///
/// Entsteht AUSSCHLIESSLICH aus der Root-signierten
/// [`RetentionPolicyFieldsV1`] — denselben zwei Feldern, die das
/// Vernichtungs-Gate (`destruction_runtime::prepare`, `ea-destruction`,
/// `ea-sync-server`) liest. Keine öffentlichen Felder, kein Freitext, kein
/// lokaler Schalter: Go-live-Bericht und Gate können nie auseinanderlaufen.
#[derive(Clone, Copy)]
pub struct EdsPrivacyDecision {
    destruction_enabled: bool,
    document_hash: Option<[u8; 32]>,
}

impl EdsPrivacyDecision {
    /// Liest die Entscheidung aus der Aufbewahrungsrichtlinie des Kopfes
    /// (`head.policy_fields().retention_policy`).
    #[must_use]
    pub fn from_retention_policy(policy: &RetentionPolicyFieldsV1) -> Self {
        Self {
            destruction_enabled: policy.destruction_enabled,
            document_hash: policy
                .eds_privacy_decision_document_hash
                .map(|hash| *hash.as_bytes()),
        }
    }

    /// Die Zeile. Drei belegte Fälle; die Rechtmäßigkeit bewertet die
    /// Software nicht (§16.3):
    ///
    /// - Vernichtung aktiviert mit Dokumenthash: erfüllt, „Restnachweis
    ///   freigegeben".
    /// - Vernichtung deaktiviert: erfüllt, „Vernichtung deaktiviert" — ein
    ///   etwa vorhandener Hash wird als Beleg mitgeführt und ändert nichts.
    /// - Vernichtung aktiviert OHNE Dokumenthash: widersprüchlich, NICHT
    ///   erfüllt.
    fn row(self) -> GoLiveRequirement {
        let (status, evidence) = match (self.destruction_enabled, self.document_hash) {
            (true, Some(_)) => (GoLiveRequirementStatus::Confirmed, EDS_RESIDUAL_RELEASED),
            (false, _) => (GoLiveRequirementStatus::Confirmed, EDS_DESTRUCTION_DISABLED),
            (true, None) => (
                GoLiveRequirementStatus::NotMet,
                EDS_PRIVACY_DECISION_MISSING,
            ),
        };
        GoLiveRequirement {
            code: EDS_PRIVACY_DECISION,
            status,
            evidence_code: evidence.to_owned(),
            decision_document_hash: self.document_hash,
        }
    }
}

/// Der letzte Frischrechner-Recovery-Test, wie der Wirt ihn kennt.
///
/// `production_state` ist der Zustand aus
/// [`crate::production_state`]; `Ready` entsteht dort ausschliesslich ueber
/// einen bestandenen Test. Dazu der Zeitpunkt des Abschlusses und das
/// Intervall der Policy (`restoreTestIntervalMs`): ein bestandener Test, der
/// laenger zurueckliegt, belegt nichts mehr.
/// A production caller cannot manufacture a fresh recovery result from flags.
///
/// ```compile_fail
/// let state = ea_admin::ProductionState::Ready;
/// let _ = ea_admin::RecoveryTestFreshness {
///     production_state: &state,
///     completed_at: ea_types::UnixMillis::new(1),
///     interval_ms: 100,
///     now: ea_types::UnixMillis::new(2),
/// };
/// ```
#[derive(Clone, Copy)]
pub struct RecoveryTestFreshness<'a> {
    evidence: RecoveryFreshnessEvidence<'a>,
}
#[derive(Clone, Copy)]
enum RecoveryFreshnessEvidence<'a> {
    Native {
        runtime: &'a crate::recovery_test_runtime::RecoveryTestRuntime,
        inventory: &'a ea_recovery::KeyInventory,
        report_hash: ea_types::ObjectHash,
    },
    #[cfg(feature = "test-support")]
    Fixture {
        state: &'a ProductionState,
        completed_at: UnixMillis,
        interval_ms: u64,
        now: UnixMillis,
    },
}
impl<'a> RecoveryTestFreshness<'a> {
    pub(crate) fn from_current(
        runtime: &'a crate::recovery_test_runtime::RecoveryTestRuntime,
        inventory: &'a ea_recovery::KeyInventory,
        report_hash: ea_types::ObjectHash,
    ) -> Self {
        Self {
            evidence: RecoveryFreshnessEvidence::Native {
                runtime,
                inventory,
                report_hash,
            },
        }
    }
    /// Pure aggregate fixtures cannot be used in production builds.
    #[cfg(feature = "test-support")]
    pub fn for_testing(
        state: &'a ProductionState,
        completed_at: UnixMillis,
        interval_ms: u64,
        now: UnixMillis,
    ) -> Self {
        Self {
            evidence: RecoveryFreshnessEvidence::Fixture {
                state,
                completed_at,
                interval_ms,
                now,
            },
        }
    }
    pub(crate) fn is_fresh(self) -> bool {
        match self.evidence {
            RecoveryFreshnessEvidence::Native {
                runtime,
                inventory,
                report_hash,
            } => runtime
                .current_completed_report_matches(inventory, report_hash)
                .is_ok(),
            #[cfg(feature = "test-support")]
            RecoveryFreshnessEvidence::Fixture {
                state,
                completed_at,
                interval_ms,
                now,
            } => {
                *state == ProductionState::Ready
                    && now
                        .get()
                        .checked_sub(completed_at.get())
                        .and_then(|n| u64::try_from(n).ok())
                        .is_some_and(|elapsed| elapsed <= interval_ms)
            }
        }
    }
}

/// Die Belege, aus denen die Liste entsteht — jedes Feld `Option`.
///
/// `None` ist ueberall dasselbe: „diese Maschine hat den Beleg nicht", also
/// [`GoLiveRequirementStatus::NotAutomaticallyVerifiable`] mit dem Belegcode
/// [`EVIDENCE_UNAVAILABLE`]. Kein Feld hat einen Vorgabewert.
#[derive(Clone, Copy)]
pub struct GoLiveEvidence<'a> {
    /// Zahl der am gewaehlten Kopf aktiven Administrationszertifikate.
    pub active_admin_count: Option<usize>,
    /// Die verifizierten Schluesselsicherungen aus Schritt 7 der Zeremonie.
    pub key_backups: Option<&'a [KeyBackupRecordV1]>,
    /// Alter und Lease des gewaehlten Kopfes.
    pub registry: Option<RegistryFreshness>,
    /// Ob der Kopf eine Policy fuehrt.
    pub policy_present: Option<bool>,
    /// Ob die Policy eine Evidence-Richtlinie (`evidenceMaxDelayMs`) fuehrt.
    pub evidence_policy_present: Option<bool>,
    /// Der letzte Frischrechner-Recovery-Test.
    pub last_recovery_test: Option<RecoveryTestFreshness<'a>>,
    /// Die Phase des Writer-Uebergangs; `Prepared` ist unvollendet.
    pub writer_transition: Option<WriterTransitionPhase>,
    /// Der Haltungsbericht des Geraets.
    pub device_posture: Option<&'a DevicePostureReport>,
    /// Die `.eds`-Restnachweis-Entscheidung aus der signierten Policy des
    /// gewählten Kopfes.
    pub eds_privacy_decision: Option<EdsPrivacyDecision>,
}

/// Die ausgewertete Liste. Entsteht ausschliesslich in [`evaluate_go_live`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoLiveChecklist {
    requirements: Vec<GoLiveRequirement>,
}

impl GoLiveChecklist {
    /// Alle sechzehn Anforderungen, in der Reihenfolge von
    /// [`GO_LIVE_REQUIREMENT_CODES`].
    #[must_use]
    pub fn requirements(&self) -> &[GoLiveRequirement] {
        &self.requirements
    }

    /// `true` NUR, wenn JEDE Anforderung [`GoLiveRequirementStatus::Confirmed`]
    /// ist. `NotAutomaticallyVerifiable` zaehlt wie `NotMet`.
    #[must_use]
    pub fn production_ready(&self) -> bool {
        !self.requirements.is_empty()
            && self
                .requirements
                .iter()
                .all(|requirement| requirement.status == GoLiveRequirementStatus::Confirmed)
    }

    /// Jede Anforderung, die NICHT bestaetigt ist — nicht erfuellte und nicht
    /// pruefbare gleichermassen.
    pub fn unresolved(&self) -> impl Iterator<Item = &GoLiveRequirement> {
        self.requirements
            .iter()
            .filter(|requirement| requirement.status != GoLiveRequirementStatus::Confirmed)
    }

    /// Die Go-live-Evidenzliste `ea.go-live-checklist/v1` als kompaktes JSON.
    ///
    /// Deterministisch: feste Feldreihenfolge, Reihenfolge der Anforderungen,
    /// kein Zeitstempel, kein Pfad, keine Zahl — nur Codes. Ein leerer Bestand
    /// unaufgeloester Zeilen liefert trotzdem das Schema und eine leere Liste.
    #[must_use]
    pub fn unresolved_report_json(&self) -> String {
        let report = UnresolvedReportV1 {
            schema: "ea.go-live-checklist/v1",
            unresolved: self
                .unresolved()
                .map(|requirement| UnresolvedRowV1 {
                    requirement_code: requirement.code,
                    status: requirement.status,
                    evidence_code: &requirement.evidence_code,
                })
                .collect(),
        };
        // Eine Struktur aus `&str`, Aufzaehlung und `Vec` serialisiert nie
        // fehlschlagend; der Ausweichwert deckt den Vertrag von `serde_json`
        // ab, ohne dass ein Panic in einen Bericht wandert.
        serde_json::to_string(&report).unwrap_or_else(|_| {
            String::from("{\"schema\":\"ea.go-live-checklist/v1\",\"unresolved\":[]}")
        })
    }
}

/// Die Drahtform der Evidenzliste — Felder in DIESER Reihenfolge.
#[derive(Serialize)]
struct UnresolvedReportV1<'a> {
    schema: &'static str,
    unresolved: Vec<UnresolvedRowV1<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnresolvedRowV1<'a> {
    requirement_code: &'static str,
    status: GoLiveRequirementStatus,
    evidence_code: &'a str,
}

/// Wertet die Belege aus — genau sechzehn Zeilen, in fester Reihenfolge.
#[must_use]
pub fn evaluate_go_live(evidence: &GoLiveEvidence<'_>) -> GoLiveChecklist {
    evaluate_go_live_with_posture_admission(evidence, None)
}

/// Revalidates the runtime-bound documentation without changing raw measurements.
/// No document ever confirms an Unknown row: a currently valid document only
/// replaces its evidence code with `EA-GOLIVE-POSTURE-DOCUMENTED`, the row stays
/// `NotAutomaticallyVerifiable` and `production_ready` stays `false`.
#[must_use]
pub fn evaluate_go_live_with_posture_admission(
    evidence: &GoLiveEvidence<'_>,
    admission: Option<&crate::operator_runtime::posture::VerifiedPostureAdmission<'_>>,
) -> GoLiveChecklist {
    let documented = evidence
        .device_posture
        .zip(admission)
        .map_or(0, |(report, admission)| {
            admission.current_documented_mask(report)
        });

    let mut requirements = Vec::with_capacity(GO_LIVE_REQUIREMENT_CODES.len());

    requirements.push(GoLiveRequirement::from_option(
        TWO_ADMINS,
        evidence
            .active_admin_count
            .map(|count| count >= MINIMUM_ACTIVE_ADMINS),
        "EA-GOLIVE-EVIDENCE-ADMIN-COUNT-2",
        "EA-GOLIVE-EVIDENCE-ADMIN-COUNT-BELOW-2",
    ));

    for (class, code, confirmed, not_met) in [
        (
            BackedUpKeyClass::Root,
            KEY_BACKUP_ROOT,
            "EA-GOLIVE-EVIDENCE-KEY-BACKUP-ROOT-TWO-MEDIA",
            "EA-GOLIVE-EVIDENCE-KEY-BACKUP-ROOT-MISSING",
        ),
        (
            BackedUpKeyClass::Admin,
            KEY_BACKUP_ADMIN,
            "EA-GOLIVE-EVIDENCE-KEY-BACKUP-ADMIN-TWO-MEDIA",
            "EA-GOLIVE-EVIDENCE-KEY-BACKUP-ADMIN-MISSING",
        ),
        (
            BackedUpKeyClass::RecoveryKem,
            KEY_BACKUP_RECOVERY_KEM,
            "EA-GOLIVE-EVIDENCE-KEY-BACKUP-RECOVERY-KEM-TWO-MEDIA",
            "EA-GOLIVE-EVIDENCE-KEY-BACKUP-RECOVERY-KEM-MISSING",
        ),
        (
            BackedUpKeyClass::HistoricalGrantAuthority,
            KEY_BACKUP_HGA,
            "EA-GOLIVE-EVIDENCE-KEY-BACKUP-HGA-TWO-MEDIA",
            "EA-GOLIVE-EVIDENCE-KEY-BACKUP-HGA-MISSING",
        ),
    ] {
        requirements.push(GoLiveRequirement::from_option(
            code,
            evidence
                .key_backups
                .map(|records| class_is_backed_up(records, class)),
            confirmed,
            not_met,
        ));
    }

    requirements.push(GoLiveRequirement::from_option(
        REGISTRY_AGE,
        evidence.registry.map(RegistryFreshness::age_within_limit),
        "EA-GOLIVE-EVIDENCE-REGISTRY-AGE-WITHIN-LIMIT",
        "EA-GOLIVE-EVIDENCE-REGISTRY-AGE-EXCEEDED",
    ));
    requirements.push(GoLiveRequirement::from_option(
        REGISTRY_LEASE,
        evidence.registry.map(RegistryFreshness::lease_covers_next),
        "EA-GOLIVE-EVIDENCE-REGISTRY-LEASE-COVERS-NEXT",
        "EA-GOLIVE-EVIDENCE-REGISTRY-LEASE-EXHAUSTED",
    ));
    requirements.push(GoLiveRequirement::from_option(
        POLICY,
        evidence.policy_present,
        "EA-GOLIVE-EVIDENCE-POLICY-PRESENT",
        "EA-GOLIVE-EVIDENCE-POLICY-ABSENT",
    ));
    requirements.push(GoLiveRequirement::from_option(
        EVIDENCE_POLICY,
        evidence.evidence_policy_present,
        "EA-GOLIVE-EVIDENCE-EVIDENCE-POLICY-PRESENT",
        "EA-GOLIVE-EVIDENCE-EVIDENCE-POLICY-ABSENT",
    ));
    requirements.push(GoLiveRequirement::from_option(
        RECOVERY_TEST,
        evidence
            .last_recovery_test
            .map(RecoveryTestFreshness::is_fresh),
        "EA-GOLIVE-EVIDENCE-RECOVERY-TEST-FRESH",
        "EA-GOLIVE-EVIDENCE-RECOVERY-TEST-STALE-OR-BLOCKED",
    ));
    requirements.push(GoLiveRequirement::from_option(
        WRITER_TRANSITION,
        evidence.writer_transition.map(|phase| match phase {
            WriterTransitionPhase::NoTransition | WriterTransitionPhase::Activated => true,
            WriterTransitionPhase::Prepared => false,
        }),
        "EA-GOLIVE-EVIDENCE-WRITER-TRANSITION-SETTLED",
        "EA-GOLIVE-EVIDENCE-WRITER-TRANSITION-PREPARED",
    ));

    for (index, requirement) in PostureRequirement::ALL.into_iter().enumerate() {
        let code = posture_requirement_code(requirement);
        requirements.push(match evidence.device_posture {
            None => GoLiveRequirement::unavailable(code),
            Some(report) => posture_row(
                code,
                report.check(requirement),
                documented & (1 << index) != 0,
            ),
        });
    }

    requirements.push(evidence.eds_privacy_decision.map_or_else(
        || GoLiveRequirement::unavailable(EDS_PRIVACY_DECISION),
        EdsPrivacyDecision::row,
    ));

    GoLiveChecklist { requirements }
}

/// Der Belegcode einer `Unknown`-Haltungszeile, deren Voraussetzung ein
/// gueltiger, bei der Auswertung erneut gepruefter Go-live-Nachweis dokumentiert.
const POSTURE_DOCUMENTED: &str = "EA-GOLIVE-POSTURE-DOCUMENTED";

/// EINE Haltungszeile aus der Rohmessung und der erneut geprueften Dokumentation.
///
/// Der Status folgt AUSSCHLIESSLICH der Rohmessung: `Unknown` bleibt
/// `NotAutomaticallyVerifiable`, auch wenn ein gueltiger Nachweis die
/// Voraussetzung dokumentiert (Ruling 2026-09-13, „`Unknown` nie gruen"). Die
/// Dokumentation ersetzt dann nur den Belegcode als sichtbaren Hinweis.
fn posture_row(code: &'static str, check: PostureCheck, documented: bool) -> GoLiveRequirement {
    let documented_unknown = check.is_unknown() && documented;
    GoLiveRequirement {
        code,
        status: if check.is_unknown() {
            GoLiveRequirementStatus::NotAutomaticallyVerifiable
        } else if check.is_pass() {
            GoLiveRequirementStatus::Confirmed
        } else {
            GoLiveRequirementStatus::NotMet
        },
        evidence_code: if documented_unknown {
            POSTURE_DOCUMENTED.to_owned()
        } else {
            check.evidence_code().to_owned()
        },
        decision_document_hash: None,
    }
}

/// Ob EINE Sicherung dieser Klasse mit mindestens zwei Medien vorliegt.
fn class_is_backed_up(records: &[KeyBackupRecordV1], class: BackedUpKeyClass) -> bool {
    records
        .iter()
        .any(|record| record.class == class && record.media.len() >= MINIMUM_BACKUP_MEDIA)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Elf bestätigte Nicht-Haltungszeilen, die vier gegebenen Haltungszeilen
    /// und eine bestätigte `.eds`-Zeile — sechzehn, wie die echte Liste.
    fn checklist_with_posture(rows: [GoLiveRequirement; 4]) -> GoLiveChecklist {
        let confirmed = |code| GoLiveRequirement {
            code,
            status: GoLiveRequirementStatus::Confirmed,
            evidence_code: "EA-GOLIVE-EVIDENCE-FIXTURE".to_owned(),
            decision_document_hash: None,
        };
        let mut requirements: Vec<GoLiveRequirement> = GO_LIVE_REQUIREMENT_CODES[..11]
            .iter()
            .copied()
            .map(confirmed)
            .collect();
        requirements.extend(rows);
        requirements.push(confirmed(EDS_PRIVACY_DECISION));
        assert_eq!(requirements.len(), GO_LIVE_REQUIREMENT_CODES.len());
        GoLiveChecklist { requirements }
    }

    /// Ruling 2026-09-13 („Plan wörtlich"): `Unknown` ist im Go-live nie gruen —
    /// auch nicht mit gueltigem, erneut geprueftem Go-live-Nachweis. Der Nachweis
    /// bleibt als Belegcode sichtbar und aendert den Status nicht.
    #[test]
    fn a_documented_unknown_posture_row_stays_unresolved_and_blocks_production_ready() {
        for requirement in PostureRequirement::ALL {
            let code = posture_requirement_code(requirement);
            let row = posture_row(code, requirement.unknown(), true);
            assert_eq!(
                row.status(),
                GoLiveRequirementStatus::NotAutomaticallyVerifiable,
                "{code}: dokumentiertes Unknown darf nicht bestaetigt sein"
            );
            assert_eq!(row.evidence_code(), POSTURE_DOCUMENTED, "{code}");

            let rows = PostureRequirement::ALL.map(|other| {
                let other_code = posture_requirement_code(other);
                if other == requirement {
                    posture_row(other_code, other.unknown(), true)
                } else {
                    posture_row(other_code, other.pass(), false)
                }
            });
            let checklist = checklist_with_posture(rows);
            assert!(
                !checklist.production_ready(),
                "{code}: dokumentiertes Unknown macht nie produktionsbereit"
            );
            assert_eq!(
                checklist
                    .unresolved()
                    .map(GoLiveRequirement::code)
                    .collect::<Vec<_>>(),
                vec![code]
            );
        }
    }

    /// Die Dokumentation beruehrt weder Pass noch Fail noch undokumentiertes Unknown.
    #[test]
    fn documentation_never_changes_pass_fail_or_undocumented_unknown_rows() {
        for requirement in PostureRequirement::ALL {
            let code = posture_requirement_code(requirement);
            for documented in [false, true] {
                let pass = posture_row(code, requirement.pass(), documented);
                assert_eq!(pass.status(), GoLiveRequirementStatus::Confirmed);
                assert_eq!(pass.evidence_code(), requirement.pass().evidence_code());

                let fail = posture_row(code, requirement.fail(), documented);
                assert_eq!(fail.status(), GoLiveRequirementStatus::NotMet);
                assert_eq!(fail.evidence_code(), requirement.fail().evidence_code());
            }
            let unknown = posture_row(code, requirement.unknown(), false);
            assert_eq!(
                unknown.status(),
                GoLiveRequirementStatus::NotAutomaticallyVerifiable
            );
            assert_eq!(
                unknown.evidence_code(),
                requirement.unknown().evidence_code()
            );
        }
        let all_pass = checklist_with_posture(
            PostureRequirement::ALL
                .map(|r| posture_row(posture_requirement_code(r), r.pass(), false)),
        );
        assert!(all_pass.production_ready());
    }
}
