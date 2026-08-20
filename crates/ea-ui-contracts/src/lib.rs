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
//! 2. **Artefaktseite, zur Testzeit.** Der eingecheckte Emitterausdruck
//!    `apps/desktop/src/bridge/generated-contracts.ts` wird byteweise gegen
//!    einen frischen Emitterlauf verglichen. Aendert sich ein Literal in seiner
//!    definierenden Crate, faellt dieser Vergleich, bis der Emitter erneut
//!    gelaufen und sein Ergebnis committet ist.

mod emit;

pub use emit::emit_typescript;

// Die Sicherheitsaufzaehlungen bleiben, wo sie definiert wurden. Hier steht
// ausschliesslich die Weitergabe.
pub use ea_archive::QuarantineReason;
pub use ea_archive_fs::{DetailCause, SyncStatus};
pub use ea_crypto::SignerRole;
pub use ea_format::{KeyProtectionProfileV1, LocalAuditOutcomeV1, OperatorRoleV1};
pub use ea_writer::FinalizationPhase;

use ea_archive::QuarantinedObject;
use ea_archive_fs::ArchiveHealthReport;
use ea_schema::IncidentUniquenessKey;
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
pub const WRITER_ENUMS_V1: &[(&str, &[&str])] =
    &[("FinalizationPhase", FINALIZATION_PHASE_LITERALS)];

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizationPreviewView {
    pub proposed_sequence: ChainSequence,
    pub binds_predecessor: bool,
    pub effective_now: UnixMillis,
    pub trust_age_ms: u64,
    pub reader_trust_refresh_ms: u64,
    pub trust_refresh_overdue: bool,
    pub hard_block: bool,
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
            hard_block: preview.decision().is_hard_block(),
        }
    }
}

/// Das Ergebnis eines abgeschlossenen Eintrags — OHNE jede Nutzlast.
///
/// Was die Oberflaeche hier nicht bekommt, ist die Zusage: nach der
/// Finalisierung hat der Writer keinen Zugriff mehr auf den Inhalt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizeOutcomeView {
    pub sequence: ChainSequence,
    pub sync: SyncStateView,
}

impl FinalizeOutcomeView {
    /// Die Ursache kommt als eigener Parameter und nicht aus dem Ergebnis: sie
    /// ist eine Aussage der Publikationsschlange und nicht der Finalisierung.
    #[must_use]
    pub const fn new(outcome: &FinalizeOutcome, detail_cause: Option<DetailCause>) -> Self {
        Self {
            sequence: outcome.sequence,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveHealthSummaryView {
    pub healthy: bool,
    pub finding_codes: Vec<&'static str>,
    pub quarantine_reasons: Vec<QuarantineReason>,
}

impl ArchiveHealthSummaryView {
    #[must_use]
    pub fn new(report: &ArchiveHealthReport, quarantined: &[QuarantinedObject]) -> Self {
        Self {
            healthy: report.is_empty() && quarantined.is_empty(),
            finding_codes: report
                .findings()
                .into_iter()
                .map(|finding| finding.code())
                .collect(),
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
        let summary = recovery.map(RecoveryOutcome::summary);
        Self {
            phase,
            irreversible: phase.is_irreversible(),
            outcome_code: summary.map(|(code, _)| code.to_owned()),
            // `NothingPending` traegt keine Sequenz, und `summary` drueckt das
            // als Null aus. Eine angezeigte Sequenz 0 waere eine erfundene.
            outcome_sequence: summary
                .and_then(|(_, sequence)| (sequence != 0).then_some(sequence))
                .map(ChainSequence::new),
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
