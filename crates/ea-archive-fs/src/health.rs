//! Der Archivgesundheitscheck: zehn Befunde, je ein eigener Erkenner.
//!
//! # Woher die Zehn kommt
//!
//! `design.md` §11.5 zaehlt acht Aufzaehlungspunkte, deren erster und letzter
//! je ZWEI Befunde nennen: „fehlende ODER unerwartet geaenderte Dateien" und
//! „zu wenig freien Speicher UND ungeeignete Dateisystemsemantik". Getrennt
//! ergibt das zehn, und getrennt MUESSEN sie sein: eine fehlende Datei und eine
//! veraenderte Datei verlangen verschiedene Massnahmen, und freier Speicher hat
//! mit Dateisystemsemantik nichts zu tun.

use std::collections::BTreeSet;

use ea_archive::{ArchiveBackendError, QuarantineReason};
use ea_crypto::object_hash;
use ea_format::ArchiveInventoryListV1;
use ea_verify::{ObjectResultKindV1, VerificationReportV1};

use crate::{CAPABILITY_SCRATCH_DIR_V1, CapabilityReportV1, LocalPathBackend};

/// Ein Gesundheitsbefund — GESCHLOSSEN, zehn Arme.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum HealthFinding {
    /// Eine inventarisierte Datei fehlt.
    MissingFile,
    /// Eine inventarisierte Datei traegt andere Bytes als ihr Inhaltshash.
    ModifiedFile,
    /// Hash-, Signatur- oder Kettenfehler im Verifikationsbericht.
    HashSignatureOrChainError,
    /// Ein Pflicht-Grant fehlt.
    MissingMandatoryGrant,
    /// Ein Destroyed-Entry-Stub ist ungueltig oder nicht autorisiert.
    InvalidOrUnauthorizedStub,
    /// Die Vertrauensdaten sind unvollstaendig.
    IncompleteTrustData,
    /// Ein verwaister Grant oder eine liegengebliebene temporaere Datei.
    OrphanGrantOrTemporaryFile,
    /// Unerwartete Sequenz, Fork oder Rollback.
    UnexpectedSequenceForkOrRollback,
    /// Zu wenig freier Speicher.
    InsufficientFreeSpace,
    /// Ungeeignete Dateisystemsemantik.
    UnsuitableFilesystemSemantics,
}

impl HealthFinding {
    /// Alle zehn Befunde, in der Reihenfolge von `design.md` §11.5.
    pub const ALL: [Self; 10] = [
        Self::MissingFile,
        Self::ModifiedFile,
        Self::HashSignatureOrChainError,
        Self::MissingMandatoryGrant,
        Self::InvalidOrUnauthorizedStub,
        Self::IncompleteTrustData,
        Self::OrphanGrantOrTemporaryFile,
        Self::UnexpectedSequenceForkOrRollback,
        Self::InsufficientFreeSpace,
        Self::UnsuitableFilesystemSemantics,
    ];

    /// Der stabile Code. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingFile => "EA-ARCHIVE-HEALTH-MISSING-FILE",
            Self::ModifiedFile => "EA-ARCHIVE-HEALTH-MODIFIED-FILE",
            Self::HashSignatureOrChainError => "EA-ARCHIVE-HEALTH-HASH-SIGNATURE-CHAIN",
            Self::MissingMandatoryGrant => "EA-ARCHIVE-HEALTH-MISSING-GRANT",
            Self::InvalidOrUnauthorizedStub => "EA-ARCHIVE-HEALTH-UNAUTHORIZED-STUB",
            Self::IncompleteTrustData => "EA-ARCHIVE-HEALTH-INCOMPLETE-TRUST",
            Self::OrphanGrantOrTemporaryFile => "EA-ARCHIVE-HEALTH-ORPHAN-OR-TEMPORARY",
            Self::UnexpectedSequenceForkOrRollback => "EA-ARCHIVE-HEALTH-SEQUENCE-FORK-ROLLBACK",
            Self::InsufficientFreeSpace => "EA-ARCHIVE-HEALTH-FREE-SPACE",
            Self::UnsuitableFilesystemSemantics => "EA-ARCHIVE-HEALTH-FILESYSTEM-SEMANTICS",
        }
    }
}

/// Der freie Speicher, wie der Aufrufer ihn meldet.
///
/// Der Wert kommt HEREIN und wird nicht hier ermittelt: eine portable
/// Freispeicherabfrage verlangt plattformspezifische Systemaufrufe, und die
/// Plattformsonde gehoert zur Stufe-7-Zertifizierung. Die REGEL — zu wenig
/// freier Speicher ist ein Gesundheitsbefund — lebt hier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreeSpaceV1 {
    pub required_bytes: u64,
    pub available_bytes: u64,
}

/// Der Gesundheitsbericht: eine duplikatfreie Menge von Befunden.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchiveHealthReport {
    findings: BTreeSet<HealthFinding>,
}

impl ArchiveHealthReport {
    /// Traegt der Bericht KEINEN Befund?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Traegt der Bericht diesen Befund?
    #[must_use]
    pub fn contains(&self, finding: HealthFinding) -> bool {
        self.findings.contains(&finding)
    }

    /// Alle Befunde, aufsteigend.
    #[must_use]
    pub fn findings(&self) -> Vec<HealthFinding> {
        self.findings.iter().copied().collect()
    }

    fn insert(&mut self, finding: HealthFinding) {
        self.findings.insert(finding);
    }
}

/// Ein Gesundheitscheck ueber einen lokalen Bestand.
///
/// Der Verifikationsbericht ist KONSTRUKTORPARAMETER und kein Zusatz: fuenf der
/// zehn Erkenner lesen ausschliesslich ihn, und ein Bericht ohne sie liesse
/// [`ArchiveHealthReport::is_empty`] — das Gesundheitssignal — auch fuer einen
/// Bestand mit Signaturbruch, fehlendem Pflicht-Grant, Fork und
/// unvollstaendigen Vertrauensdaten `true` melden. Ein Gesundheitscheck, den
/// man ohne die Haelfte seiner Erkenner bauen kann, ist fail-open.
pub struct ArchiveHealthCheckV1<'a> {
    backend: &'a LocalPathBackend,
    expected_inventory: &'a ArchiveInventoryListV1,
    free_space: FreeSpaceV1,
    capabilities: &'a CapabilityReportV1,
    verification: &'a VerificationReportV1,
}

impl<'a> ArchiveHealthCheckV1<'a> {
    /// Baut den Check. JEDER Erkenner laeuft danach.
    #[must_use]
    pub const fn new(
        backend: &'a LocalPathBackend,
        expected_inventory: &'a ArchiveInventoryListV1,
        free_space: FreeSpaceV1,
        capabilities: &'a CapabilityReportV1,
        verification: &'a VerificationReportV1,
    ) -> Self {
        Self {
            backend,
            expected_inventory,
            free_space,
            capabilities,
            verification,
        }
    }

    /// Fuehrt ALLE ZEHN Erkenner aus.
    ///
    /// Es gibt keinen Weg, den Lauf zu verkuerzen: ein leerer Bericht ist
    /// deshalb die Aussage „alle zehn Erkenner haben nichts gefunden" und nicht
    /// „einige liefen nicht".
    ///
    /// # Errors
    ///
    /// [`ArchiveBackendError::Io`] beim Lesen des Bestands.
    pub fn run(&self) -> Result<ArchiveHealthReport, ArchiveBackendError> {
        let mut report = ArchiveHealthReport::default();

        // 1 und 2: das erwartete Inventar gegen die tatsaechlichen Bytes.
        for entry in self.expected_inventory.entries() {
            match self.backend.read_relative(entry.relative_path()) {
                None => report.insert(HealthFinding::MissingFile),
                Some(bytes) => {
                    if object_hash(&bytes).as_bytes() != entry.content_hash().as_bytes() {
                        report.insert(HealthFinding::ModifiedFile);
                    }
                }
            }
        }

        // 7: liegengebliebene Staging-Artefakte, Reste eines abgebrochenen
        // Capability-Tests und Grants, die das Inventar nicht fuehrt.
        //
        // Die Kratzwurzel des Capability-Tests wird NICHT aus der Lesesicht
        // ausgeblendet — genau deshalb ist sie hier zu melden. Ein Verzeichnis
        // am Namen auszublenden hiesse, dass seine Bytes nirgends gezaehlt,
        // nirgends verifiziert und nirgends gemeldet wuerden.
        let scratch_prefix = format!("{CAPABILITY_SCRATCH_DIR_V1}/");
        for relative in self.backend.relative_paths()? {
            let temporary =
                ea_archive::is_staging_path(&relative) || relative.starts_with(&scratch_prefix);
            let orphan_grant = relative.starts_with(ea_archive::GRANTS_DIR_V1)
                && self.expected_inventory.content_hash_of(&relative).is_none();
            if temporary || orphan_grant {
                report.insert(HealthFinding::OrphanGrantOrTemporaryFile);
            }
        }

        // 9: freier Speicher.
        if self.free_space.available_bytes < self.free_space.required_bytes {
            report.insert(HealthFinding::InsufficientFreeSpace);
        }

        // 10: Dateisystemsemantik.
        if !self.capabilities.all_proven() {
            report.insert(HealthFinding::UnsuitableFilesystemSemantics);
        }

        {
            let verification = self.verification;
            // Ein Grantbefund traegt einen Code aus der `EA-GRANT-`-Familie
            // (`crates/ea-format/src/object.rs`): fehlender oder doppelter
            // Recovery-Grant, doppelter Empfaengerschluessel, doppeltes
            // Empfaengerzertifikat. Er steht im SELBEN Array wie ein
            // Signaturbefund und wird deshalb am Code unterschieden — nicht am
            // Array, das beide fuehrt.
            let mut grant_defect = false;
            let mut signature_defect = false;
            for error in verification.signature_errors() {
                if error.code().starts_with("EA-GRANT-") {
                    grant_defect = true;
                } else {
                    signature_defect = true;
                }
            }

            // 3: Hash-, Signatur- und Kettenfehler.
            if signature_defect
                || verification.format_errors().len() > 0
                || verification.decryption_errors().len() > 0
                || verification.evidence_errors().len() > 0
            {
                report.insert(HealthFinding::HashSignatureOrChainError);
            }

            // 4: ein fehlender Pflicht-Grant.
            if grant_defect {
                report.insert(HealthFinding::MissingMandatoryGrant);
            }

            // 8: unerwartete Sequenz, Fork und Rollback. Die Rollbackdimension
            // wird NICHT zusaetzlich gelesen: der Bericht haelt selbst fest,
            // dass ihre Befunde "daneben bereits in `gaps` und
            // `quarantinedObjects` abgebildet" sind
            // (`crates/ea-verify/src/report.rs`, Feld `rollback`). Ein zweiter
            // Weg zur selben Aussage waere eine zweite Wahrheit.
            let forked = verification
                .quarantined_objects()
                .any(|object| object.reason() == QuarantineReason::Conflicting);
            if verification.gaps().len() > 0 || forked {
                report.insert(HealthFinding::UnexpectedSequenceForkOrRollback);
            }

            // 6: unvollstaendige Vertrauensdaten. Ohne gewaehlten
            // Registrierungskopf gibt es keine Registrierungsfassung im
            // Bericht, und dann ist ueber kein Objekt etwas gesagt.
            if verification.registry_versions().len() == 0 {
                report.insert(HealthFinding::IncompleteTrustData);
            }

            // 5: jeder abgelegte Stummel MUSS ein autorisiertes Ergebnis
            // tragen. Ein Stummel ohne Autorisierung ist genau der Fall, den
            // `design.md` §11.4 als ungeklaerte Kettenluecke benennt.
            let authorized_destroyed = verification
                .object_results()
                .filter(|result| result.result() == ObjectResultKindV1::AuthorizedDestroyed)
                .count();
            if verification.destroyed_entry_count() > authorized_destroyed {
                report.insert(HealthFinding::InvalidOrUnauthorizedStub);
            }
        }

        Ok(report)
    }
}
