#![forbid(unsafe_code)]
//! Die EINE benannte Quelle der DTO-Flaeche des Writers.
//!
//! Die globale Randbedingung „TypeScript erzeugt keinen Grant, keinen Hash,
//! keine Signatur, kein Chiffrat, keine Registry-Entscheidung und kein
//! Archivbyte" haelt nur, wenn die Typen, ueber die die Oberflaeche redet, EINE
//! benannte Quelle haben. Diese Crate ist sie:
//!
//! * Sie fuehrt **keine** kryptographische Operation aus und erzeugt **kein**
//!   Byte. Ihre Abhaengigkeiten sind reine Typkanten.
//! * Sie **re-exportiert** jede Sicherheitsaufzaehlung unveraendert aus der
//!   Crate, in der sie definiert ist, statt sie ein zweites Mal zu erklaeren.
//!   Eine zweite Deklaration waere genau die Drift, die
//!   [`emit_typescript`] und die Driftschranke
//!   `tests/generated_ts_is_current.rs` verhindern sollen.
//! * Sie liegt unter `crates/` und **nicht** als Modul von
//!   `apps/desktop/src-tauri`: ein Emitter dort muesste als
//!   `cargo run -p ea-desktop` laufen und zoege damit den ganzen Tauri-Baustack
//!   — WebView2, Xcode Command Line Tools, webkit2gtk — in das Schreiben einer
//!   einzigen TypeScript-Datei.
//!
//! # Wie die Driftschranke wirklich haelt
//!
//! Zwei Zusagen greifen ineinander, und nur zusammen sind sie dicht:
//!
//! 1. **Rustseite, zur Uebersetzungszeit.** Jede Variantenzuordnung unten ist
//!    ein `match` **ohne Sammelarm**. Kommt in `ea-format`, `ea-crypto`,
//!    `ea-archive` oder `ea-archive-fs` eine Variante hinzu, wird der `match`
//!    unvollstaendig und DIESE Crate uebersetzt nicht mehr. Wer eine Variante
//!    hinzufuegt, MUSS hier vorbeikommen.
//! 2. **Artefaktseite, zur Testzeit.** Die eingecheckten Emitterausdruecke
//!    werden byteweise gegen einen frischen Emitterlauf verglichen. Es sind
//!    ZWEI: [`emit_typescript`] schreibt
//!    `apps/desktop/src/bridge/generated-contracts.ts`,
//!    [`emit_reader_typescript`] schreibt
//!    `apps/web/src/bridge/generated-contracts.ts`, und die zwei Mengen von
//!    Vereinigungen sind DISJUNKT. Aendert sich ein Literal in seiner
//!    definierenden Crate, faellt dieser Vergleich, bis der Emitter erneut
//!    gelaufen und sein Ergebnis committet ist.

mod emit;

pub use emit::{emit_reader_typescript, emit_typescript};

// Die Sicherheitsaufzaehlungen bleiben, wo sie definiert wurden. Hier steht
// ausschliesslich die Weitergabe.
pub use ea_archive::QuarantineReason;
pub use ea_archive_fs::{DetailCause, HealthFinding, SyncStatus};
pub use ea_crypto::SignerRole;
pub use ea_format::{KeyProtectionProfileV1, LocalAuditOutcomeV1, OperatorRoleV1};
pub use ea_reader::BundleRejectionCodeV1;
pub use ea_types::{EntryStatus, EvidenceStatus, VerificationStatus};
pub use ea_verify::ServerConfirmationV1;
pub use ea_writer::{FinalizationPhase, StaleDecision};

use ea_archive::QuarantinedObject;
use ea_archive_fs::ArchiveHealthReport;
use ea_schema::{
    CoordinatesV1, ExternalOrganizationV1, IncidentUniquenessKey, KeywordV1, LocationV1,
    OccurredAtV1, PatientCount, SchemaError, StructuredAddressV1,
};
use ea_types::{ChainSequence, UnixMillis};
use ea_writer::{FinalizationPreview, FinalizeOutcome, RecoveryOutcome};

/// Die Sicherheitsaufzaehlungen der Kontraktflaeche, in Emitterreihenfolge.
///
/// Jedes Paar traegt den emittierten Typnamen und die Literale seiner
/// Varianten in DEKLARATIONSREIHENFOLGE. Die Literale stehen hier nicht als
/// Text: sie entstehen aus den Zuordnungen unten, und jede davon holt sich das
/// Literal entweder aus dem Zugriff der definierenden Crate oder — wo diese
/// keinen fuehrt — aus dem Variantennamen.
pub const SECURITY_ENUMS_V1: &[(&str, &[&str])] = &[
    ("SyncStatus", SYNC_STATUS_LITERALS),
    ("DetailCause", DETAIL_CAUSE_LITERALS),
    ("QuarantineReason", QUARANTINE_REASON_LITERALS),
    ("LocalAuditOutcomeV1", LOCAL_AUDIT_OUTCOME_V1_LITERALS),
    ("KeyProtectionProfileV1", KEY_PROTECTION_PROFILE_V1_LITERALS),
    ("OperatorRoleV1", OPERATOR_ROLE_V1_LITERALS),
    ("SignerRole", SIGNER_ROLE_LITERALS),
];

/// Die geschlossenen Aufzaehlungen der Writer-Ansicht, die keine
/// Sicherheitsaufzaehlung sind — aber genauso emittiert und genauso bewacht
/// werden.
pub const WRITER_ENUMS_V1: &[(&str, &[&str])] = &[
    ("FinalizationPhase", FINALIZATION_PHASE_LITERALS),
    ("StaleDecision", STALE_DECISION_LITERALS),
    ("HealthFinding", HEALTH_FINDING_LITERALS),
    ("PatientCountStatus", PATIENT_COUNT_STATUS_LITERALS),
];

/// Die Statusaufzaehlungen der READER-Flaeche, in Emitterreihenfolge.
///
/// Sie stehen bewusst NICHT in [`SECURITY_ENUMS_V1`]: `emit_typescript`
/// schreibt die Desktop-Datei, und
/// `apps/desktop/src/bridge/no-hand-written-contracts.test.ts` verbannt jedes
/// Literal JEDER dort emittierten Vereinigung aus jeder handgeschriebenen
/// Desktop-Quelle. `ungueltig`, `vorhanden` oder `ausstehend` dort
/// einzutragen verengte die Writer-Flaeche, ohne dass eine
/// Reader-Entscheidung dahinterstuende.
pub const READER_ENUMS_V1: &[(&str, &[&str])] = &[
    ("VerificationStatus", VERIFICATION_STATUS_LITERALS),
    ("EntryStatus", ENTRY_STATUS_LITERALS),
    ("EvidenceStatus", EVIDENCE_STATUS_LITERALS),
    ("ServerConfirmationV1", SERVER_CONFIRMATION_V1_LITERALS),
    ("BundleRejectionCodeV1", BUNDLE_REJECTION_CODE_V1_LITERALS),
];

/// Der Grund, aus dem eine Kandidatenfassung des Web-Bundles NICHT aktiviert
/// wurde.
///
/// Der Arm ist eine Zuordnung OHNE Sammelarm: kommt in `ea-reader` eine
/// Variante hinzu, uebersetzt diese Crate nicht mehr, und niemand kann einen
/// Ablehnungsgrund einfuehren, den die Oberflaeche nicht benennen kann.
const fn bundle_rejection_code_literal(value: BundleRejectionCodeV1) -> &'static str {
    match value {
        BundleRejectionCodeV1::NoPinnedRelease => "NoPinnedRelease",
        BundleRejectionCodeV1::Unsigned => "Unsigned",
        BundleRejectionCodeV1::WrongRoot => "WrongRoot",
        BundleRejectionCodeV1::WrongOrganization => "WrongOrganization",
        BundleRejectionCodeV1::Revoked => "Revoked",
        BundleRejectionCodeV1::NotYetEffective => "NotYetEffective",
        BundleRejectionCodeV1::HashMismatch => "HashMismatch",
    }
}

const BUNDLE_REJECTION_CODE_V1_LITERALS: &[&str] = &[
    bundle_rejection_code_literal(BundleRejectionCodeV1::NoPinnedRelease),
    bundle_rejection_code_literal(BundleRejectionCodeV1::Unsigned),
    bundle_rejection_code_literal(BundleRejectionCodeV1::WrongRoot),
    bundle_rejection_code_literal(BundleRejectionCodeV1::WrongOrganization),
    bundle_rejection_code_literal(BundleRejectionCodeV1::Revoked),
    bundle_rejection_code_literal(BundleRejectionCodeV1::NotYetEffective),
    bundle_rejection_code_literal(BundleRejectionCodeV1::HashMismatch),
];

/// Die woertliche Oberflaechenkopie der vier Sync-Zustaende.
///
/// Der Arm ist eine Oder-Verzweigung ueber ALLE Varianten und ruft dann
/// [`SyncStatus::label`]: das Literal bleibt damit in `ea-archive-fs`, und der
/// fehlende Sammelarm faengt trotzdem jede neue Variante ab.
const fn sync_status_literal(value: SyncStatus) -> &'static str {
    match value {
        SyncStatus::LocallySaved
        | SyncStatus::UploadPending
        | SyncStatus::Synchronized
        | SyncStatus::Failed => value.label(),
    }
}

const SYNC_STATUS_LITERALS: &[&str] = &[
    sync_status_literal(SyncStatus::LocallySaved),
    sync_status_literal(SyncStatus::UploadPending),
    sync_status_literal(SyncStatus::Synchronized),
    sync_status_literal(SyncStatus::Failed),
];

/// Der Text der Detailursache, die NEBEN dem Zustand steht.
const fn detail_cause_literal(value: DetailCause) -> &'static str {
    match value {
        DetailCause::NetworkArchiveWaiting
        | DetailCause::QueueLimitReached
        | DetailCause::ProfileNotAllowed
        | DetailCause::ResumeAttemptsExhausted => value.label(),
    }
}

const DETAIL_CAUSE_LITERALS: &[&str] = &[
    detail_cause_literal(DetailCause::NetworkArchiveWaiting),
    detail_cause_literal(DetailCause::QueueLimitReached),
    detail_cause_literal(DetailCause::ProfileNotAllowed),
    detail_cause_literal(DetailCause::ResumeAttemptsExhausted),
];

/// Das Schemaliteral des Isolationsgrundes.
const fn quarantine_reason_literal(value: QuarantineReason) -> &'static str {
    match value {
        QuarantineReason::Malformed
        | QuarantineReason::Duplicate
        | QuarantineReason::Conflicting
        | QuarantineReason::Unattributable => value.as_str(),
    }
}

const QUARANTINE_REASON_LITERALS: &[&str] = &[
    quarantine_reason_literal(QuarantineReason::Malformed),
    quarantine_reason_literal(QuarantineReason::Duplicate),
    quarantine_reason_literal(QuarantineReason::Conflicting),
    quarantine_reason_literal(QuarantineReason::Unattributable),
];

/// Der Ausgang einer lokalen Auditzeile.
///
/// `ea-format` fuehrt fuer diese Aufzaehlung keinen Zeichenkettenzugriff, also
/// IST der Variantenname das Literal. Er steht hier und nirgends sonst.
const fn local_audit_outcome_literal(value: LocalAuditOutcomeV1) -> &'static str {
    match value {
        LocalAuditOutcomeV1::Failed => "Failed",
        LocalAuditOutcomeV1::Accepted => "Accepted",
        LocalAuditOutcomeV1::Completed => "Completed",
    }
}

const LOCAL_AUDIT_OUTCOME_V1_LITERALS: &[&str] = &[
    local_audit_outcome_literal(LocalAuditOutcomeV1::Failed),
    local_audit_outcome_literal(LocalAuditOutcomeV1::Accepted),
    local_audit_outcome_literal(LocalAuditOutcomeV1::Completed),
];

/// Wie ein Schluessel geschuetzt ist.
const fn key_protection_profile_literal(value: KeyProtectionProfileV1) -> &'static str {
    match value {
        KeyProtectionProfileV1::OsWrapped => "OsWrapped",
        KeyProtectionProfileV1::HardwareNonExportable => "HardwareNonExportable",
        KeyProtectionProfileV1::OfflineEncryptedContainer => "OfflineEncryptedContainer",
        KeyProtectionProfileV1::Pkcs11 => "Pkcs11",
        KeyProtectionProfileV1::ServerSecretStoreOrHsm => "ServerSecretStoreOrHsm",
    }
}

const KEY_PROTECTION_PROFILE_V1_LITERALS: &[&str] = &[
    key_protection_profile_literal(KeyProtectionProfileV1::OsWrapped),
    key_protection_profile_literal(KeyProtectionProfileV1::HardwareNonExportable),
    key_protection_profile_literal(KeyProtectionProfileV1::OfflineEncryptedContainer),
    key_protection_profile_literal(KeyProtectionProfileV1::Pkcs11),
    key_protection_profile_literal(KeyProtectionProfileV1::ServerSecretStoreOrHsm),
];

/// Die Rolle eines Bedieners.
const fn operator_role_literal(value: OperatorRoleV1) -> &'static str {
    match value {
        OperatorRoleV1::Writer => "Writer",
        OperatorRoleV1::Reader => "Reader",
        OperatorRoleV1::OrganizationAdmin => "OrganizationAdmin",
    }
}

const OPERATOR_ROLE_V1_LITERALS: &[&str] = &[
    operator_role_literal(OperatorRoleV1::Writer),
    operator_role_literal(OperatorRoleV1::Reader),
    operator_role_literal(OperatorRoleV1::OrganizationAdmin),
];

/// Die Rolle, unter der ein Zertifikat gebunden wurde.
const fn signer_role_literal(value: SignerRole) -> &'static str {
    match value {
        SignerRole::Writer => "Writer",
        SignerRole::Reader => "Reader",
        SignerRole::OrganizationAdmin => "OrganizationAdmin",
        SignerRole::Root => "Root",
        SignerRole::KeyApprover => "KeyApprover",
        SignerRole::HistoricalGrantAuthority => "HistoricalGrantAuthority",
        SignerRole::ServerReceipt => "ServerReceipt",
        SignerRole::DeletionAttest => "DeletionAttest",
        SignerRole::RecoveryRecipient => "RecoveryRecipient",
    }
}

const SIGNER_ROLE_LITERALS: &[&str] = &[
    signer_role_literal(SignerRole::Writer),
    signer_role_literal(SignerRole::Reader),
    signer_role_literal(SignerRole::OrganizationAdmin),
    signer_role_literal(SignerRole::Root),
    signer_role_literal(SignerRole::KeyApprover),
    signer_role_literal(SignerRole::HistoricalGrantAuthority),
    signer_role_literal(SignerRole::ServerReceipt),
    signer_role_literal(SignerRole::DeletionAttest),
    signer_role_literal(SignerRole::RecoveryRecipient),
];

/// Die dauerhaft erreichte Phase einer Finalisierung.
const fn finalization_phase_literal(value: FinalizationPhase) -> &'static str {
    match value {
        FinalizationPhase::ReversibleDraft => "ReversibleDraft",
        FinalizationPhase::PreparedAndFlushed => "PreparedAndFlushed",
        FinalizationPhase::DraftKeyAbsent => "DraftKeyAbsent",
        FinalizationPhase::GrantsPublished => "GrantsPublished",
        FinalizationPhase::EntryCommitted => "EntryCommitted",
        FinalizationPhase::NetworkArchivePublished => "NetworkArchivePublished",
        FinalizationPhase::Reconciled => "Reconciled",
    }
}

const FINALIZATION_PHASE_LITERALS: &[&str] = &[
    finalization_phase_literal(FinalizationPhase::ReversibleDraft),
    finalization_phase_literal(FinalizationPhase::PreparedAndFlushed),
    finalization_phase_literal(FinalizationPhase::DraftKeyAbsent),
    finalization_phase_literal(FinalizationPhase::GrantsPublished),
    finalization_phase_literal(FinalizationPhase::EntryCommitted),
    finalization_phase_literal(FinalizationPhase::NetworkArchivePublished),
    finalization_phase_literal(FinalizationPhase::Reconciled),
];

/// Der Zeitstatus des gebundenen Vertrauensbestands.
///
/// `ea-writer` fuehrt fuer diese Aufzaehlung keinen Zeichenkettenzugriff, also
/// IST der Variantenname das Literal.
pub const fn stale_decision_literal(value: StaleDecision) -> &'static str {
    match value {
        StaleDecision::Fresh => "Fresh",
        StaleDecision::StaleAcknowledgeable => "StaleAcknowledgeable",
        StaleDecision::HardBlock => "HardBlock",
    }
}

const STALE_DECISION_LITERALS: &[&str] = &[
    stale_decision_literal(StaleDecision::Fresh),
    stale_decision_literal(StaleDecision::StaleAcknowledgeable),
    stale_decision_literal(StaleDecision::HardBlock),
];

/// Der Zeitstatus des gebundenen Head aus seiner DRAHTFORM — fail-closed.
///
/// `None` fuer jedes Wort, das nicht in der emittierten Vereinigung steht.
/// Diese Richtung gibt es, weil die BESTAETIGTE Vorschau ueber den Draht
/// zurueckkommt: der mittlere Arm `StaleAcknowledgeable` verlangt eine
/// ausdrueckliche Bestaetigung, und ein ungeprueftes Wort an dieser Stelle
/// koennte ihn zu `Fresh` machen.
#[must_use]
pub fn stale_decision_from_wire(wire: &str) -> Option<StaleDecision> {
    [
        StaleDecision::Fresh,
        StaleDecision::StaleAcknowledgeable,
        StaleDecision::HardBlock,
    ]
    .into_iter()
    .find(|decision| stale_decision_literal(*decision) == wire)
}

/// Der stabile Code EINES Gesundheitsbefundes.
///
/// Wie bei [`sync_status_literal`] eine Oder-Verzweigung ueber ALLE zehn
/// Varianten mit anschliessendem [`HealthFinding::code`]: das Literal bleibt in
/// `ea-archive-fs`, der fehlende Sammelarm faengt trotzdem jede neue Variante.
const fn health_finding_literal(value: HealthFinding) -> &'static str {
    match value {
        HealthFinding::MissingFile
        | HealthFinding::ModifiedFile
        | HealthFinding::HashSignatureOrChainError
        | HealthFinding::MissingMandatoryGrant
        | HealthFinding::InvalidOrUnauthorizedStub
        | HealthFinding::IncompleteTrustData
        | HealthFinding::OrphanGrantOrTemporaryFile
        | HealthFinding::UnexpectedSequenceForkOrRollback
        | HealthFinding::InsufficientFreeSpace
        | HealthFinding::UnsuitableFilesystemSemantics => value.code(),
    }
}

/// Der Zustand der Patientenzahl — `unknown` und `known`, in WIRE-Reihenfolge.
///
/// `payload-wire-addendum.md`:120 setzt `patientCountStatus = 0` fuer `unknown`
/// und `= 1` fuer `known`. Die Reihenfolge hier ist deshalb die des Drahts und
/// nicht die der Rustdeklaration; das Literal IST der Variantenname, weil
/// `ea-schema` fuer diese Aufzaehlung keinen Zeichenkettenzugriff fuehrt.
const fn patient_count_status_literal(value: &PatientCount) -> &'static str {
    match value {
        PatientCount::Unknown => "Unknown",
        PatientCount::Known(_) => "Known",
    }
}

/// Die zwei Literale des Patientenzahlzustands, in WIRE-Reihenfolge.
///
/// Oeffentlich, damit ein Verbraucher — die Kommandogrenze etwa — den leeren
/// Rumpf nicht mit einem eigenen Literal fuellt.
pub const PATIENT_COUNT_STATUS_LITERALS: &[&str] = &[
    patient_count_status_literal(&PatientCount::Unknown),
    patient_count_status_literal(&PatientCount::Known(0)),
];

const HEALTH_FINDING_LITERALS: &[&str] = &[
    health_finding_literal(HealthFinding::MissingFile),
    health_finding_literal(HealthFinding::ModifiedFile),
    health_finding_literal(HealthFinding::HashSignatureOrChainError),
    health_finding_literal(HealthFinding::MissingMandatoryGrant),
    health_finding_literal(HealthFinding::InvalidOrUnauthorizedStub),
    health_finding_literal(HealthFinding::IncompleteTrustData),
    health_finding_literal(HealthFinding::OrphanGrantOrTemporaryFile),
    health_finding_literal(HealthFinding::UnexpectedSequenceForkOrRollback),
    health_finding_literal(HealthFinding::InsufficientFreeSpace),
    health_finding_literal(HealthFinding::UnsuitableFilesystemSemantics),
];

/// Die woertliche Oberflaechenkopie der sechs Verifikationszustaende.
///
/// Der Arm ist eine Oder-Verzweigung ueber ALLE Varianten und ruft dann
/// [`VerificationStatus::label`]: das Literal bleibt damit in `ea-types`, und
/// der fehlende Sammelarm faengt trotzdem jede neue Variante ab.
const fn verification_status_literal(value: VerificationStatus) -> &'static str {
    match value {
        VerificationStatus::Verified
        | VerificationStatus::Gap
        | VerificationStatus::MissingGrant
        | VerificationStatus::UnknownKey
        | VerificationStatus::UnsupportedSchema
        | VerificationStatus::Invalid => value.label(),
    }
}

const VERIFICATION_STATUS_LITERALS: &[&str] = &[
    verification_status_literal(VerificationStatus::Verified),
    verification_status_literal(VerificationStatus::Gap),
    verification_status_literal(VerificationStatus::MissingGrant),
    verification_status_literal(VerificationStatus::UnknownKey),
    verification_status_literal(VerificationStatus::UnsupportedSchema),
    verification_status_literal(VerificationStatus::Invalid),
];

/// Der Zustand EINES Eintrags — nie mit dem Verifikationsergebnis vermischt.
const fn entry_status_literal(value: EntryStatus) -> &'static str {
    match value {
        EntryStatus::Present | EntryStatus::AuthorizedDestroyed | EntryStatus::UnexplainedGap => {
            value.label()
        }
    }
}

const ENTRY_STATUS_LITERALS: &[&str] = &[
    entry_status_literal(EntryStatus::Present),
    entry_status_literal(EntryStatus::AuthorizedDestroyed),
    entry_status_literal(EntryStatus::UnexplainedGap),
];

/// Der Stand der geforderten Evidence.
const fn evidence_status_literal(value: EvidenceStatus) -> &'static str {
    match value {
        EvidenceStatus::Complete
        | EvidenceStatus::Pending
        | EvidenceStatus::Overdue
        | EvidenceStatus::Invalid => value.label(),
    }
}

const EVIDENCE_STATUS_LITERALS: &[&str] = &[
    evidence_status_literal(EvidenceStatus::Complete),
    evidence_status_literal(EvidenceStatus::Pending),
    evidence_status_literal(EvidenceStatus::Overdue),
    evidence_status_literal(EvidenceStatus::Invalid),
];

/// Die Bestaetigungsdimension — orthogonal zur Verifikation, kein Mangel.
const fn server_confirmation_literal(value: ServerConfirmationV1) -> &'static str {
    match value {
        ServerConfirmationV1::ServerConfirmed | ServerConfirmationV1::NotServerConfirmed => {
            value.label()
        }
    }
}

const SERVER_CONFIRMATION_V1_LITERALS: &[&str] = &[
    server_confirmation_literal(ServerConfirmationV1::ServerConfirmed),
    server_confirmation_literal(ServerConfirmationV1::NotServerConfirmed),
];

/// Das Literal des Patientenzahlzustands aus seiner DRAHTFORM — fail-closed.
///
/// `None` fuer jede Zeichenkette, die nicht in der emittierten Vereinigung
/// steht. Ohne diese Pruefung waere der Zustand ein ungeprueftes Wort aus einer
/// Antwort, und die Unterscheidung „bekannte Null gegen unbekannt" haette an der
/// Grenze keinen Waechter.
#[must_use]
pub fn patient_count_status_from_wire(wire: &str) -> Option<&'static str> {
    PATIENT_COUNT_STATUS_LITERALS
        .iter()
        .copied()
        .find(|literal| *literal == wire)
}

/// Der Patientenzahlzustand SAMT seiner Zahl — EIN Wert.
///
/// Am Draht sind es ZWEI Positionen (`patientCountStatus` und `patientCount`,
/// `payload-wire-addendum.md`:102-118), und genau daran koennen sie
/// auseinanderlaufen: ein Zustand `known` neben einer fehlenden Zahl ist am
/// Draht darstellbar, und wer ihn mit einem Vorgabewert auffuellt, schreibt
/// „bekannt, null" unter eine Anzeige, die „unbekannt" sagt. Diese Aufzaehlung
/// faltet die zwei Positionen an der Grenze zu einem Wert; danach kann sie
/// nichts mehr trennen.
///
/// Sie steht HIER und nicht als Weitergabe von [`PatientCount`], weil jene
/// Stufe-1-Aufzaehlung keine Ableitungen traegt (kein `Clone`, kein `Debug`,
/// kein `Eq`) und die Stufe 1 geschlossen ist. Die zwei Arme sind dieselben,
/// und [`Self::into_schema`] ist die einzige Uebersetzung.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatientCountView {
    /// Die Zahl ist unbekannt — und ausdruecklich nicht null.
    Unknown,
    /// Die Zahl ist bekannt; `0` ist ein gueltiger, bekannter Wert.
    Known(u32),
}

impl PatientCountView {
    /// Der Zustand aus seiner DRAHTFORM — fail-closed in BEIDE Richtungen.
    ///
    /// `None`, wenn das Wort nicht in der emittierten Vereinigung steht, wenn
    /// `known` ohne Zahl kommt und wenn `unknown` mit einer Zahl kommt. Alle
    /// drei sind an dieser Grenze eine Eingabe, die niemand ansehen kann, ohne
    /// zu raten — und ein Vorgabewert waere hier die Zahl selbst.
    #[must_use]
    pub fn from_wire(status: &str, count: Option<u32>) -> Option<Self> {
        match (patient_count_status_from_wire(status)?, count) {
            (literal, Some(count))
                if literal == patient_count_status_literal(&PatientCount::Known(0)) =>
            {
                Some(Self::Known(count))
            }
            (literal, None) if literal == patient_count_status_literal(&PatientCount::Unknown) => {
                Some(Self::Unknown)
            }
            _ => None,
        }
    }

    /// Das Literal der Drahtform dieses Zustands.
    #[must_use]
    pub const fn literal(self) -> &'static str {
        match self {
            Self::Unknown => patient_count_status_literal(&PatientCount::Unknown),
            Self::Known(_) => patient_count_status_literal(&PatientCount::Known(0)),
        }
    }

    /// Die Zahl der Drahtform — `None` fuer `unknown`.
    #[must_use]
    pub const fn count(self) -> Option<u32> {
        match self {
            Self::Unknown => None,
            Self::Known(count) => Some(count),
        }
    }

    /// Derselbe Wert als Stufe-1-Aufzaehlung. KEIN Vorgabewert unterwegs.
    #[must_use]
    pub const fn into_schema(self) -> PatientCount {
        match self {
            Self::Unknown => PatientCount::Unknown,
            Self::Known(count) => PatientCount::Known(count),
        }
    }
}

/// Zweiunddreissig Bytes als Kleinbuchstaben-Hex.
///
/// Sie steht hier, weil ein Hash in der Oberflaeche ein ANZEIGEWERT ist: die
/// Byteform gehoert dem Archiv, und `ea-types` fuehrt bewusst keinen
/// Zeichenkettenzugriff auf sie. Diese Funktion RECHNET nichts — sie
/// formatiert, und die Oberflaeche formatiert deshalb nicht selbst.
fn hex32(bytes: &[u8; 32]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Der Sync-Zustand mit seiner Detailursache DANEBEN.
///
/// Nie ein fuenfter Zustand: verliert ein freigegebenes Netzbackend eine
/// zugesicherte Faehigkeit, bleibt der Zustand `Upload ausstehend` und die
/// Ursache tritt daneben.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncStateView {
    pub status: SyncStatus,
    pub detail_cause: Option<DetailCause>,
}

/// Die Bestaetigungsansicht vor der Finalisierung.
///
/// Sie traegt das ALTER des gebundenen Vertrauensbestands und die Policyfrist
/// als zwei getrennte Zahlen, weil die Ueberschreitung eine WARNUNG ist und die
/// Blockade an `notAfter` haengt — zwei verschiedene Aussagen, die eine
/// Oberflaeche verschieden anzeigen muss.
///
/// [`StaleDecision`] steht UNGEFALTET darin und nicht als abgeleitetes
/// `hardBlock: boolean`. Die Aufzaehlung ist dreiarmig, und der mittlere Arm
/// `StaleAcknowledgeable` verlangt eine nicht uebergehbare sichtbare Warnung
/// und eine ausdrueckliche Bestaetigung; ein Wahrheitswert macht ihn von
/// `Fresh` ununterscheidbar und degradiert damit still, statt fail-closed zu
/// bleiben. `trustRefreshOverdue` deckt das NICHT ab — das ist die
/// Auffrischungsfrist und eine andere Aussage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizationPreviewView {
    pub proposed_sequence: ChainSequence,
    pub binds_predecessor: bool,
    pub effective_now: UnixMillis,
    pub trust_age_ms: u64,
    pub reader_trust_refresh_ms: u64,
    pub trust_refresh_overdue: bool,
    pub stale_decision: StaleDecision,
}

impl From<&FinalizationPreview> for FinalizationPreviewView {
    fn from(preview: &FinalizationPreview) -> Self {
        Self {
            proposed_sequence: preview.proposed_sequence(),
            binds_predecessor: preview.previous_entry_hash().is_some(),
            effective_now: preview.effective_now(),
            trust_age_ms: preview.trust_age_ms(),
            reader_trust_refresh_ms: preview.reader_trust_refresh_ms(),
            trust_refresh_overdue: preview.trust_refresh_overdue(),
            stale_decision: preview.decision(),
        }
    }
}

/// Das Ergebnis eines abgeschlossenen Eintrags — OHNE jede Nutzlast.
///
/// Was die Oberflaeche hier nicht bekommt, ist die Zusage: nach der
/// Finalisierung hat der Writer keinen Zugriff mehr auf den Inhalt.
///
/// Was sie bekommt, sind die zwei HASHES und die Sequenz. Sie stehen als
/// Kleinbuchstaben-Hex darin, weil sie nach dem Commit alles sind, was ueber
/// den Eintrag noch gesagt werden darf: `entryHash` bindet ihn in die Kette,
/// `objectHash` benennt das Archivobjekt, und keiner von beiden gibt einen
/// Inhalt heraus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeOutcomeView {
    pub sequence: ChainSequence,
    pub entry_hash: String,
    pub object_hash: String,
    pub sync: SyncStateView,
}

impl FinalizeOutcomeView {
    /// Die Ursache kommt als eigener Parameter und nicht aus dem Ergebnis: sie
    /// ist eine Aussage der Publikationsschlange und nicht der Finalisierung.
    #[must_use]
    pub fn new(outcome: &FinalizeOutcome, detail_cause: Option<DetailCause>) -> Self {
        Self {
            sequence: outcome.sequence,
            entry_hash: hex32(outcome.entry_hash.as_bytes()),
            object_hash: hex32(outcome.object_hash.as_bytes()),
            sync: SyncStateView {
                status: outcome.sync_status,
                detail_cause,
            },
        }
    }
}

/// Die Zusammenfassung des Archivgesundheitschecks.
///
/// `healthy` ist ausdruecklich UND-verknuepft: ein isoliertes Objekt ist ein
/// ungesunder Bestand, auch wenn kein Gesundheitsbefund daneben steht.
/// `finding_codes` traegt die GESCHLOSSENE Aufzaehlung [`HealthFinding`] und
/// nicht ihre Codes als nackte Zeichenketten: nur so stehen die zehn Codes in
/// der emittierten Vereinigung, und nur dann sieht
/// `no-hand-written-contracts.test.ts` einen spaeteren handgeschriebenen
/// Vergleich gegen einen von ihnen. Die Reihenfolge kommt aus dem
/// `BTreeSet` des Berichts und damit — die Aufzaehlung ist feldlos und leitet
/// `Ord` ab — aus der Deklarationsreihenfolge: deterministisch ohne Zutun.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveHealthSummaryView {
    pub healthy: bool,
    pub finding_codes: Vec<HealthFinding>,
    pub quarantine_reasons: Vec<QuarantineReason>,
}

impl ArchiveHealthSummaryView {
    #[must_use]
    pub fn new(report: &ArchiveHealthReport, quarantined: &[QuarantinedObject]) -> Self {
        Self {
            healthy: report.is_empty() && quarantined.is_empty(),
            finding_codes: report.findings(),
            quarantine_reasons: quarantined.iter().map(QuarantinedObject::reason).collect(),
        }
    }
}

/// EIN Haltungssignal des Geraets.
///
/// `satisfied` ist dreiwertig, und `None` heisst „auf dieser Plattform nicht
/// belegbar" — kein automatisches Ja. Der Typ traegt bewusst KEINE eigene
/// Aufzaehlung: die geschlossene Menge der vier Anforderungen und ihrer drei
/// Ergebnisse lebt in `ea-key-provider`, und diese Crate haengt nicht daran.
/// Eine Kopie hier waere eine zweite Quelle derselben Wahrheit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostureRequirementView {
    pub requirement_code: String,
    pub satisfied: Option<bool>,
    pub evidence_code: String,
}

/// Die Haltung des Geraets ueber alle gemeldeten Anforderungen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevicePostureSummaryView {
    pub requirements: Vec<PostureRequirementView>,
    pub production_ready: bool,
}

impl DevicePostureSummaryView {
    /// `production_ready` wird ABGELEITET und nicht uebergeben: fail-closed,
    /// also nur wenn mindestens eine Anforderung gemeldet ist und JEDE davon
    /// belegt erfuellt ist.
    #[must_use]
    pub fn new(requirements: Vec<PostureRequirementView>) -> Self {
        let production_ready = !requirements.is_empty()
            && requirements
                .iter()
                .all(|requirement| requirement.satisfied == Some(true));
        Self {
            requirements,
            production_ready,
        }
    }
}

/// Die Fortsetzungsansicht einer angetroffenen Finalisierung.
///
/// `irreversible` wird aus der Phase abgeleitet, damit die Oberflaeche die
/// unwiderrufliche Grenze nicht ein zweites Mal beschreiben muss.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingFinalizationResumeView {
    pub phase: FinalizationPhase,
    pub irreversible: bool,
    pub outcome_code: Option<String>,
    pub outcome_sequence: Option<ChainSequence>,
}

impl PendingFinalizationResumeView {
    #[must_use]
    pub fn new(phase: FinalizationPhase, recovery: Option<&RecoveryOutcome>) -> Self {
        Self {
            phase,
            irreversible: phase.is_irreversible(),
            outcome_code: recovery.map(|outcome| outcome.summary().0.to_owned()),
            // Die VARIANTE entscheidet, nicht der Zahlenwert. `summary` benutzt
            // die Null bei `NothingPending` als Sentinel, aber Sequenz 0 ist
            // der GUELTIGE erste Eintrag jeder Kette
            // (`ea-chain/src/chain.rs`: `is_genesis` heisst
            // `chain_sequence.get() == 0`; `ea-writer/src/finalize.rs`
            // schlaegt bei leerer Kette `ChainSequence::new(0)` vor). Ein
            // Filter auf `!= 0` haette die unterbrochene Finalisierung des
            // ERSTEN Eintrags als „committet, Sequenz unbekannt" angezeigt.
            // Der `match` ohne Sammelarm faellt bei einem vierten Ausgang von
            // `RecoveryOutcome` in die Uebersetzung.
            outcome_sequence: match recovery {
                None | Some(RecoveryOutcome::NothingPending) => None,
                Some(RecoveryOutcome::DraftRestored { unused_sequence }) => Some(*unused_sequence),
                Some(RecoveryOutcome::CommittedFromPreparedBytes { sequence }) => Some(*sequence),
            },
        }
    }
}

/// Welchen Vorgang eine Finalisierung abschliesst.
///
/// Die Identitaet kommt aus dem GESCHLOSSENEN
/// [`IncidentUniquenessKey`] der Stufe 1 und wird nicht daneben
/// zusammengesetzt. Die Organisationskennung bleibt draussen: sie ist ein
/// opaker 16-Byte-Wert und keine Anzeigeinformation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentIdentityView {
    pub local_civil_year: i16,
    pub incident_number: String,
}

impl From<&IncidentUniquenessKey> for IncidentIdentityView {
    fn from(key: &IncidentUniquenessKey) -> Self {
        Self {
            local_civil_year: key.local_civil_year(),
            // Die Bytes sind die NFC-Form einer bereits validierten
            // Zeichenkette, also ersetzt die verlustbehaftete Wandlung nie
            // etwas. Sie steht hier, damit ein Anzeigepfad nicht fehlschlagen
            // kann.
            incident_number: String::from_utf8_lossy(key.incident_number_nfc_bytes()).into_owned(),
        }
    }
}

/// Ein Koordinatenpaar als GANZZAHLIGES E7-Paar.
///
/// Kein Gleitkommawert an der Grenze: `payload-wire-addendum.md`:108 fixiert
/// `int`, und eine Oberflaeche, die daraus eine Fliesskommazahl macht, gibt
/// einen anderen Wert zurueck, als sie bekam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatesView {
    pub lat_e7: i32,
    pub lon_e7: i32,
}

/// Der Zeitraum eines Einsatzes: Beginn und OPTIONALES Ende.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OccurredAtView {
    pub start: UnixMillis,
    pub end: Option<UnixMillis>,
}

/// Das Einsatzstichwort — Freitext ODER Verweis samt Anzeigetext.
///
/// EIN Typ mit optionaler Kennung und nicht zwei: der Draht traegt beide Formen
/// unter derselben Position, und die Unterscheidung ist genau die Anwesenheit
/// der Kennung.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeywordView {
    pub reference_id: Option<String>,
    pub display_text: String,
}

/// Die strukturierte Adresse, Position fuer Position wie
/// [`StructuredAddressV1`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StructuredAddressView {
    pub street: Option<String>,
    pub house_number: Option<String>,
    pub postal_code: Option<String>,
    pub locality: Option<String>,
    pub admin_area: Option<String>,
    pub country_code: Option<String>,
}

/// Der Einsatzort — Freitext ODER strukturierte Adresse, je mit optionalen
/// Koordinaten.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocationView {
    pub free_text: Option<String>,
    pub address: Option<StructuredAddressView>,
    pub coordinates: Option<CoordinatesView>,
}

/// EINE Personalauswahl der Oberflaeche.
///
/// Sie ist ausdruecklich KEINE Momentaufnahme: eine
/// [`ea_schema::PersonnelSnapshotV1`] mit Stammdatenbezug verlangt Revision und
/// Provenienz, und beide kommen aus der Stammdatenablage und niemals aus einer
/// Eingabe. Traegt die Auswahl eine Stammdatenkennung, LOEST der Wirt sie auf;
/// traegt sie keine, ist sie ein Ad-hoc-Eintrag. Der Anzeigename ist in beiden
/// Faellen nur Anzeige.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonnelSelectionView {
    pub master_personnel_id: Option<String>,
    pub display_name: String,
    pub role_label: Option<String>,
}

/// EINE Fahrzeugauswahl der Oberflaeche, mit derselben Zusage wie
/// [`PersonnelSelectionView`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VehicleSelectionView {
    pub master_vehicle_id: Option<String>,
    pub display_name: String,
    pub radio_call_name: Option<String>,
    pub license_plate: Option<String>,
}

/// Eine beteiligte externe Organisation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalOrganizationView {
    pub id: Option<String>,
    pub display_name: String,
}

/// Der VOLLSTAENDIGE Eingabevertrag des Einsatzrumpfes.
///
/// Zwoelf Positionen in der Reihenfolge von `payload-wire-addendum.md`:102-118.
/// Was hier NICHT steht, ist der Kopf: `recordId`, `finalizedAtDevice`, der
/// `operator`-Snapshot, die `registryVersion`, die Zeitzone und die
/// Quellkennung entstehen im Wirt aus der geprueften Sitzung, der nur lesend
/// geoeffneten Profilzeile und dem gebundenen Head
/// (`ea_writer::FinalizationInputV1`). Stuenden sie hier, koennte eine
/// Oberflaeche einen fremden Bediener in den signierten Kopf schreiben.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentInputView {
    pub human_incident_number: String,
    pub occurred_at: OccurredAtView,
    pub keyword: KeywordView,
    pub location: LocationView,
    pub personnel: Vec<PersonnelSelectionView>,
    pub personnel_empty_reason: Option<String>,
    pub vehicles: Vec<VehicleSelectionView>,
    pub vehicles_empty_reason: Option<String>,
    /// Zustand UND Zahl als EIN Wert.
    ///
    /// Die Drahtform traegt weiterhin die zwei Positionen
    /// `patientCountStatus` und `patientCount`; die Grenze faltet sie mit
    /// [`PatientCountView::from_wire`] fail-closed zusammen. Ein Paar, das
    /// nicht zusammenpasst, kommt deshalb nicht bis hierher — und ab hier kann
    /// die Anzeige nicht mehr etwas anderes sagen als der Draht.
    pub patient_count: PatientCountView,
    pub notes: Option<String>,
    pub external_organizations: Vec<ExternalOrganizationView>,
}

/// Die skalaren Positionen des Einsatzrumpfes als VALIDIERTE Stufe-1-Werte.
///
/// Die zwei Momentaufnahmelisten stehen nicht darin: sie verlangen die
/// Stammdatenablage. Alles andere prueft `ea-schema` hier — Zeichenlaengen,
/// Zeitintervall, Koordinatenbereich, NFC-Form —, und zwar mit denselben
/// Konstruktoren, die die eingefrorenen Bytes bauen. Ein zweiter Pruefpfad
/// entsteht nicht.
pub struct IncidentScalarsV1 {
    pub occurred_at: OccurredAtV1,
    pub keyword: KeywordV1,
    pub location: LocationV1,
    pub patient_count: PatientCount,
    pub external_organizations: Vec<ExternalOrganizationV1>,
}

impl IncidentInputView {
    /// Wandelt die skalaren Positionen in ihre Stufe-1-Werte.
    ///
    /// # Errors
    ///
    /// Der [`SchemaError`] der Stufe 1, unveraendert — samt seinem stabilen
    /// Code und dem Feldnamen.
    pub fn try_into_scalars(&self) -> Result<IncidentScalarsV1, SchemaError> {
        let occurred_at = OccurredAtV1::new(self.occurred_at.start, self.occurred_at.end)?;
        let keyword = match self.keyword.reference_id.as_deref() {
            None => KeywordV1::free_text(self.keyword.display_text.clone()),
            Some(reference) => KeywordV1::reference(reference, self.keyword.display_text.clone()),
        }?;
        let coordinates = match self.location.coordinates {
            None => None,
            Some(pair) => Some(CoordinatesV1::new(pair.lat_e7, pair.lon_e7)?),
        };
        let location = match (&self.location.address, &self.location.free_text) {
            (Some(address), _) => LocationV1::structured(
                StructuredAddressV1::new(
                    address.street.clone(),
                    address.house_number.clone(),
                    address.postal_code.clone(),
                    address.locality.clone(),
                    address.admin_area.clone(),
                    address.country_code.clone(),
                )?,
                coordinates,
            )?,
            (None, Some(free_text)) => LocationV1::free_text(free_text.clone(), coordinates)?,
            // Fail-closed: ohne Ort gibt es keinen Ort, und ein leerer Freitext
            // ist keiner. `LocationV1::free_text` traegt die Laengenpruefung.
            (None, None) => LocationV1::free_text(String::new(), coordinates)?,
        };
        // KEIN Vorgabewert: der Zustand ist schon an der Grenze zu einem Wert
        // gefaltet worden (`PatientCountView::from_wire`), und diese Wandlung
        // traegt ihn nur weiter. Ein `unwrap_or_default` hier machte aus einer
        // fehlenden Zahl die bekannte Null.
        let patient_count = self.patient_count.into_schema();
        let mut external_organizations = Vec::with_capacity(self.external_organizations.len());
        for organization in &self.external_organizations {
            external_organizations.push(ExternalOrganizationV1::new(
                organization.id.as_deref(),
                organization.display_name.clone(),
            )?);
        }
        Ok(IncidentScalarsV1 {
            occurred_at,
            keyword,
            location,
            patient_count,
            external_organizations,
        })
    }
}

/// Der aktive Entwurf samt seinem Speicherzustand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftStateView {
    pub incident: IncidentInputView,
    pub sync: SyncStateView,
}

/// Das Ergebnis einer Stammdatensuche samt den GESAMTZAHLEN der Ablage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasterDataResultView {
    pub personnel: Vec<PersonnelSelectionView>,
    pub vehicles: Vec<VehicleSelectionView>,
    pub personnel_total: u64,
    pub vehicle_total: u64,
}

/// Die Bestaetigung eines veralteten Registry-Head.
///
/// `captured` ist die AUSSAGE DES WIRTS und nicht die eines Klicks. Ohne diese
/// Trennung zeigte die Oberflaeche eine erfasste Bestaetigung, sobald jemand
/// den Knopf drueckt — und der Kern kann sie heute gar nicht ausstellen
/// (`ea-writer`: der Bestaetigungspfad ist eine benannte Auslassung).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaleAcknowledgementView {
    pub captured: bool,
    pub proof_code: String,
}

/// Das Ergebnis einer nativen erneuten Authentisierung.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReauthResultView {
    pub fresh: bool,
    pub purpose_code: String,
}

/// Der Stand eines Verwerfens — dauerhaft gebucht und fortsetzbar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscardStateView {
    pub phase_code: String,
    pub complete: bool,
}

/// Das Ergebnis des Ein-Datei-Buendelexports.
///
/// Kein Inhalt, kein Eintrag, keine Entschluesselung: der Export kopiert
/// versiegelte Bytes, und die Oberflaeche erfaehrt Pfad, Objektzahl und
/// Byteumfang.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleExportView {
    pub path: String,
    pub object_count: u64,
    pub byte_count: u64,
}

/// Die angetroffene Finalisierung: die Fortsetzung ODER die Blockade.
///
/// `blocked_code` traegt den Code des Wirts, der die Fortsetzung verweigert —
/// `EA-WRITER-HEAD-RECONCILIATION-REQUIRED` nach dem Zurueckspielen eines
/// Backups. Genau zwei sichtbare Ausgaenge folgen daraus, und der zweite
/// traegt KEINE Abschlusshandhabe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingResumeOutcomeView {
    pub resume: PendingFinalizationResumeView,
    pub blocked_code: Option<String>,
    pub sync: Option<SyncStateView>,
}

#[cfg(test)]
mod tests {
    use super::{
        ChainSequence, FinalizationPhase, FinalizeOutcome, FinalizeOutcomeView, IncidentInputView,
        KeywordView, LocationView, OccurredAtView, PATIENT_COUNT_STATUS_LITERALS, PatientCountView,
        PendingFinalizationResumeView, RecoveryOutcome, SyncStatus, UnixMillis, hex32,
        patient_count_status_from_wire,
    };

    fn scalar_input(patient_count: PatientCountView) -> IncidentInputView {
        IncidentInputView {
            human_incident_number: "2026-0001".to_owned(),
            occurred_at: OccurredAtView {
                start: UnixMillis::new(1_771_000_000_000),
                end: None,
            },
            keyword: KeywordView {
                reference_id: None,
                display_text: "Verkehrsunfall".to_owned(),
            },
            location: LocationView {
                free_text: Some("Bahnhofstrasse 1".to_owned()),
                address: None,
                coordinates: None,
            },
            personnel: Vec::new(),
            personnel_empty_reason: None,
            vehicles: Vec::new(),
            vehicles_empty_reason: None,
            patient_count,
            notes: None,
            external_organizations: Vec::new(),
        }
    }

    /// Die bekannte NULL und der unbekannte Stand sind zwei verschiedene Werte.
    ///
    /// Der Fehlerfall, den diese Zusicherung faengt: eine Wandlung, die aus
    /// `patientCount = 0` ein `Unknown` macht (oder umgekehrt aus `Unknown` die
    /// Null). Beides ist am Draht eine andere Aussage — `patientCountStatus = 1`
    /// verlangt einen `uint`, `= 0` verlangt `null` —, und ein Einsatzbericht,
    /// der „keine Patienten" mit „Zahl unbekannt" verwechselt, ist falsch.
    #[test]
    fn a_known_zero_is_not_an_unknown_patient_count() {
        let known = scalar_input(PatientCountView::Known(0));
        let Ok(scalars) = known.try_into_scalars() else {
            panic!("bekannte Null ist gueltig")
        };
        assert_eq!(scalars.patient_count.known(), Some(0));
        assert!(!scalars.patient_count.is_unknown());

        let unknown = scalar_input(PatientCountView::Unknown);
        let Ok(scalars) = unknown.try_into_scalars() else {
            panic!("unbekannt ist gueltig")
        };
        assert!(scalars.patient_count.is_unknown());
        assert_eq!(scalars.patient_count.known(), None);
    }

    /// Die Drahtform des Zustands ist GESCHLOSSEN.
    #[test]
    fn only_the_emitted_status_literals_come_back_from_the_wire() {
        for literal in PATIENT_COUNT_STATUS_LITERALS {
            assert_eq!(patient_count_status_from_wire(literal), Some(*literal));
        }
        for foreign in ["known", "0", "1", "Vielleicht", ""] {
            assert_eq!(patient_count_status_from_wire(foreign), None);
        }
    }

    /// Ein Zustand `known` OHNE Zahl ist keine Eingabe — und wird auch nicht zu
    /// einer bekannten Null.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: die Faltung der zwei
    /// Drahtpositionen fuellt die fehlende Zahl mit einem Vorgabewert auf. Dann
    /// zeigte die Bestaetigungsansicht „Patientenzahl unbekannt", waehrend der
    /// Draht `known, 0` truege — die Anzeige und der Eintrag sagten Verschiedenes
    /// ueber dieselbe Zahl. Die zweite Haelfte ist ebenso notwendig: `unknown`
    /// MIT Zahl ist am Draht verboten (`patientCountStatus = 0` verlangt
    /// `null`), und ein stilles Wegwerfen der Zahl waere die andere Richtung
    /// derselben Luege.
    #[test]
    fn a_divergent_status_and_count_pair_is_no_input_at_all() {
        let [unknown, known] = [
            PATIENT_COUNT_STATUS_LITERALS[0],
            PATIENT_COUNT_STATUS_LITERALS[1],
        ];
        assert_eq!(
            PatientCountView::from_wire(known, Some(0)),
            Some(PatientCountView::Known(0))
        );
        assert_eq!(
            PatientCountView::from_wire(unknown, None),
            Some(PatientCountView::Unknown)
        );
        assert_eq!(PatientCountView::from_wire(known, None), None);
        assert_eq!(PatientCountView::from_wire(unknown, Some(7)), None);
        assert_eq!(PatientCountView::from_wire("Vielleicht", Some(1)), None);

        // Und die Rueckrichtung traegt dieselben zwei Positionen.
        assert_eq!(PatientCountView::Known(0).literal(), known);
        assert_eq!(PatientCountView::Known(0).count(), Some(0));
        assert_eq!(PatientCountView::Unknown.literal(), unknown);
        assert_eq!(PatientCountView::Unknown.count(), None);
    }

    /// Nach dem Commit stehen HASHES und Sequenz da — und die Hashes kommen aus
    /// den Bytes des Ergebnisses.
    ///
    /// Der Fehlerfall, den dieser Zeuge faengt: eine Ansicht, die die zwei
    /// Hashes fallen laesst (dann zeigte der `FingerprintBlock` nur eine
    /// Sequenz, und der Bediener haette nach dem unwiderruflichen Schritt
    /// keinen Fingerabdruck) oder sie in einer anderen Schreibweise als
    /// Kleinbuchstaben-Hex ausgibt.
    #[test]
    fn the_finalize_outcome_carries_both_hashes_as_lowercase_hex() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0x0a;
        bytes[31] = 0xff;
        assert_eq!(
            hex32(&bytes),
            "0a000000000000000000000000000000000000000000000000000000000000ff"
        );
        assert!(!hex32(&bytes).chars().any(char::is_uppercase));

        // Und JEDES Feld traegt SEINEN Hash: zwei verschiedene Bytemuster, zwei
        // verschiedene Zeichenketten, jede an ihrer Position. Eine Laengen- oder
        // Ungleichheitspruefung allein liesse die zwei Felder vertauschen.
        let outcome = FinalizeOutcome {
            sequence: ChainSequence::new(7),
            entry_hash: ea_types::EntryHash::try_from([0x11_u8; 32].as_slice())
                .expect("zweiunddreissig Bytes"),
            object_hash: ea_types::ObjectHash::try_from([0x22_u8; 32].as_slice())
                .expect("zweiunddreissig Bytes"),
            sync_status: SyncStatus::LocallySaved,
        };
        let view = FinalizeOutcomeView::new(&outcome, None);
        assert_eq!(view.entry_hash, "11".repeat(32));
        assert_eq!(view.object_hash, "22".repeat(32));
        assert_eq!(view.sequence, ChainSequence::new(7));
        assert_eq!(view.sync.status, SyncStatus::LocallySaved);
        assert_eq!(view.sync.detail_cause, None);
    }

    /// Die skalaren Positionen werden von der STUFE 1 geprueft und nicht hier.
    ///
    /// Drei Ablehnungen mit drei verschiedenen Codes, alle aus `ea-schema`: ein
    /// Ende vor dem Beginn, eine Koordinate jenseits des eingefrorenen Bereichs
    /// und ein leeres Stichwort. Ohne diesen Zeugen koennte die Wandlung jede
    /// Eingabe durchlassen und der Fehler erst tief im Schreibdienst auffallen.
    #[test]
    fn the_scalar_positions_carry_the_stage_one_rejections() {
        let mut input = scalar_input(PatientCountView::Unknown);
        input.occurred_at.end = Some(UnixMillis::new(1_770_999_999_999));
        let Err(error) = input.try_into_scalars() else {
            panic!("ein Ende vor dem Beginn ist kein Zeitraum")
        };
        assert_eq!(error.code(), "EA-SCHEMA-INTERVAL");

        let mut input = scalar_input(PatientCountView::Unknown);
        input.location.coordinates = Some(super::CoordinatesView {
            lat_e7: 900_000_001,
            lon_e7: 0,
        });
        let Err(error) = input.try_into_scalars() else {
            panic!("eine Breite jenseits des Bereichs ist keine Koordinate")
        };
        assert_eq!(error.code(), "EA-SCHEMA-COORDINATES");

        let mut input = scalar_input(PatientCountView::Unknown);
        input.keyword.display_text = String::new();
        assert!(
            input.try_into_scalars().is_err(),
            "ein leeres Stichwort ist keins"
        );
    }

    /// Der Verweis gewinnt gegen den Freitext, und die Adresse gegen den
    /// Freitext — genau die zwei Alternativen des Drahts.
    #[test]
    fn the_two_alternatives_of_keyword_and_location_are_kept_apart() {
        let mut input = scalar_input(PatientCountView::Unknown);
        input.keyword.reference_id = Some("STW-042".to_owned());
        input.location.address = Some(super::StructuredAddressView {
            locality: Some("Koeln".to_owned()),
            ..super::StructuredAddressView::default()
        });
        let Ok(scalars) = input.try_into_scalars() else {
            panic!("beide Alternativen sind gueltig")
        };
        assert!(matches!(
            scalars.keyword,
            ea_schema::KeywordV1::Reference { .. }
        ));
        assert!(matches!(
            scalars.location,
            ea_schema::LocationV1::Structured { .. }
        ));
    }

    /// Sequenz 0 ist der GENESIS-Eintrag und kein Sentinel.
    ///
    /// Der Fehlerfall, den diese Zusicherung faengt: die unterbrochene
    /// Finalisierung des ERSTEN Eintrags eines Archivs liefert
    /// `outcome_code: Some("CommittedFromPreparedBytes")`, und eine Ansicht,
    /// die auf `!= 0` filtert, zeigt dazu „Sequenz unbekannt", obwohl sie
    /// bekannt ist.
    #[test]
    fn resume_of_the_genesis_entry_keeps_sequence_zero() {
        let committed = RecoveryOutcome::CommittedFromPreparedBytes {
            sequence: ChainSequence::new(0),
        };
        let view =
            PendingFinalizationResumeView::new(FinalizationPhase::EntryCommitted, Some(&committed));
        assert_eq!(
            view.outcome_code.as_deref(),
            Some("CommittedFromPreparedBytes")
        );
        assert_eq!(view.outcome_sequence, Some(ChainSequence::new(0)));

        let restored = RecoveryOutcome::DraftRestored {
            unused_sequence: ChainSequence::new(0),
        };
        let view =
            PendingFinalizationResumeView::new(FinalizationPhase::ReversibleDraft, Some(&restored));
        assert_eq!(view.outcome_code.as_deref(), Some("DraftRestored"));
        assert_eq!(view.outcome_sequence, Some(ChainSequence::new(0)));
    }

    /// Der EINE Ausgang ohne Sequenz — und er ist es, weil seine Variante keine
    /// traegt, und nicht, weil ein Zahlenwert null ist.
    #[test]
    fn nothing_pending_carries_no_sequence() {
        let pending = PendingFinalizationResumeView::new(
            FinalizationPhase::ReversibleDraft,
            Some(&RecoveryOutcome::NothingPending),
        );
        assert_eq!(pending.outcome_code.as_deref(), Some("NothingPending"));
        assert_eq!(pending.outcome_sequence, None);

        let absent = PendingFinalizationResumeView::new(FinalizationPhase::ReversibleDraft, None);
        assert_eq!(absent.outcome_code, None);
        assert_eq!(absent.outcome_sequence, None);
    }
}
