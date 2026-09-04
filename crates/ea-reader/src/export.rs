//! Der authenticator-bestaetigte Einzelexport nach `web-reader-design.md`
//! §8.2 und `design.md` §14.4.
//!
//! # Es gibt keine Methode ueber „alle Datensaetze"
//!
//! [`ReaderExportService::export_one`] nimmt GENAU EINEN
//! [`VerifiedDecryptedRecord`]. Es gibt keine Methode ueber `Vec`, `&[_]`,
//! ein Suchergebnis oder einen Iterator, und das ist mit einem
//! `compile_fail`-Doctest belegt statt behauptet — dieselbe Bauform, mit der
//! `crates/ea-key-provider/src/lib.rs`, `crates/ea-crypto/src/secret.rs`,
//! `crates/ea-trust/src/registry.rs` und `crates/ea-operator/src/lib.rs`
//! ihre Nichtherausgabe belegen. Eine Laufzeitzusicherung koennte eine
//! Massenexportmethode nicht verbieten, die es GIBT.
//!
//! ```compile_fail
//! # use ea_reader::{ReaderExportService, ReaderAuthenticatorConfirmation, ReaderExportTarget};
//! # fn call(
//! #     service: &mut ReaderExportService<'_>,
//! #     records: Vec<ea_reader::VerifiedDecryptedRecord>,
//! #     target: &mut dyn ReaderExportTarget,
//! #     confirmation: ReaderAuthenticatorConfirmation,
//! # ) {
//! service.export_one(records, Some(target), confirmation);
//! # }
//! ```
//!
//! # Die Reihenfolge im Inneren ist die Zusage
//!
//! Zweck und Frische der Bestaetigung pruefen, das Ziel als gewaehlt und frei
//! pruefen, die Sitzung als offen pruefen, dann die Auditzeile mit
//! `LocalAuditOutcomeV1::Accepted` schreiben — sie steht an der
//! UNWIDERRUFLICHEN Grenze, unmittelbar bevor Klartext den WASM-Speicher
//! verlaesst —, dann die Bytes an das Ziel geben, dann `Completed` oder
//! `Failed`. Zwei Zeilen je Versuch, und der Grund ist der Abbruch
//! dazwischen: ein Export, der nach der Bestaetigung und vor dem Schreiben
//! stirbt, hinterliesse sonst keine Spur. `LocalAuditOutcomeV1` traegt dafuer
//! bereits drei Werte; es entsteht kein vierter.
//!
//! # Was `Completed` bezeugt — und was nicht
//!
//! `Completed` sagt: das Ziel hat die Bytes ANGENOMMEN, der Klartext hat den
//! Vertrauensbereich verlassen. Ob der Wirt sie danach dauerhaft abgelegt
//! hat, weiss der Reader nicht — `showSaveFilePicker` schreibt asynchron, ein
//! Download ist Sache des Browsers. Die Zeile bezeugt die Grenze, nicht die
//! Platte. Bereits exportierte Klartexte koennen nicht kryptografisch
//! zurueckgerufen werden (§14.4).
//!
//! # Fehler formatieren AUSSCHLIESSLICH ihren Code
//!
//! Wie `ea_archive::BundleError` und `ea_audit::AuditError`. Ein abgeleitetes
//! `Debug` waere hier der Weg, auf dem ein Entry-Hash in einen Fehlerbericht
//! geraet — WR-082.

use core::fmt;

use ea_format::{ExportContextV1, LocalAuditActionV1, LocalAuditOutcomeV1};
use ea_types::{EntryHash, UnixMillis};

use crate::audit::{ReaderAuditError, ReaderAuditIdentityV1, ReaderAuditSink, ReaderAuditWriter};
use crate::decrypt::VerifiedDecryptedRecord;
use crate::session::{
    ReaderAuthenticatorConfirmation, ReaderConfirmationPurpose, ReaderSession, ReaderSessionError,
};

/// Die Zielarten des Browsers, kodiert als `target-kind` von
/// `export-context-v1`.
///
/// Zwei Arme, und der zweite ist keine Bequemlichkeit: `showSaveFilePicker`
/// fehlt in Safari und Firefox — dieselbe Luecke, aus der §5.2 den
/// universellen Dateiweg erzwingt —, also MUSS der Download-Weg existieren,
/// und beide muessen im Audit unterscheidbar sein. `UserChosenFile` bekommt
/// den Wert `1`, weil der eingefrorene Vektor `event/accepted-plaintext-export`
/// (`crates/ea-testkit/src/lib.rs`, `LOCAL_AUDIT_EXPORT_TARGET_KIND`) diese
/// Zahl bereits traegt; so wird KEIN Vektor neu eingefroren.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReaderExportTargetKindV1 {
    /// Eine Datei, die die Person ueber den Dateidialog gewaehlt hat.
    UserChosenFile = 1,
    /// Ein Download, den die Person angestossen hat.
    UserInitiatedDownload = 2,
}

impl ReaderExportTargetKindV1 {
    /// Der Wert der Position `target-kind`.
    #[must_use]
    pub const fn target_kind(self) -> u64 {
        self as u64
    }

    /// Der stabile Wortlaut der Zielart — fuer DTO und Bruecke.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UserChosenFile => "user-chosen-file",
            Self::UserInitiatedDownload => "user-initiated-download",
        }
    }

    /// Die Zielart aus ihrem Wortlaut; ein fremder Wortlaut ist `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "user-chosen-file" => Some(Self::UserChosenFile),
            "user-initiated-download" => Some(Self::UserInitiatedDownload),
            _ => None,
        }
    }
}

/// Ein Ziel, das die Person BEWUSST gewaehlt hat.
///
/// Der Port ist absichtlich schmal: eine Zielart, die Frage, ob dort schon
/// etwas liegt, und GENAU EIN Schreibvorgang. Es gibt keinen Pfad — der
/// Wirtpfad gehoert dem Wirt und erreicht weder diesen Kern noch das Audit.
pub trait ReaderExportTarget {
    /// Die Zielart, wie sie im Audit steht.
    fn kind(&self) -> ReaderExportTargetKindV1;

    /// Ob unter dem Ziel bereits etwas liegt. Ein besetztes Ziel wird
    /// abgewiesen, nie ueberschrieben.
    fn is_occupied(&self) -> bool;

    /// Nimmt den Klartext entgegen. `Ok` heisst: das Ziel hat die Bytes
    /// angenommen.
    ///
    /// # Errors
    /// Ein einziger, wortloser Fehlschlag: was der Wirt dazu sagt, bleibt beim
    /// Wirt.
    fn write(&mut self, plaintext: &[u8]) -> Result<(), ReaderExportTargetError>;
}

/// Der wortlose Fehlschlag eines Ziels.
///
/// Kein Feld, weil kein Feld ohne Wirtstext auskaeme — und ein Wirtstext
/// nennt einen Pfad.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderExportTargetError;

/// Der Fehlschlag eines Einzelexports. Vier Abweisungen VOR der Grenze, jede
/// mit eigenem Code, und drei Lagen danach.
#[derive(Clone, Eq, PartialEq)]
pub enum ReaderExportError {
    /// Es wurde kein Ziel gewaehlt — die Person hat den Dialog abgebrochen.
    NoTarget,
    /// Unter dem Ziel liegt schon etwas.
    TargetOccupied,
    /// Die Bestaetigung ist abgelaufen oder liegt in der Zukunft.
    ConfirmationStale,
    /// Die Bestaetigung traegt einen anderen Zweck als den Einzelexport.
    ConfirmationPurpose,
    /// Die Sitzung ist gesperrt; kein Tresor, keine Auditsignatur, kein
    /// Export.
    SessionLocked,
    /// Die `Accepted`-Zeile konnte nicht geschrieben werden; KEIN Byte hat
    /// den Speicher verlassen.
    AuditBeforeWrite(ReaderAuditError),
    /// Das Ziel hat die Bytes nicht angenommen; die `Failed`-Zeile steht.
    TargetWrite,
    /// Die Zeile NACH dem Schreiben konnte nicht geschrieben werden. Die
    /// Bytes sind draussen, das Audit ist unvollstaendig — der unangenehme
    /// Fall, und deshalb ein eigener Code statt eines verschluckten Fehlers.
    AuditAfterWrite(ReaderAuditError),
}

impl ReaderExportError {
    /// Stabiler Fehlercode. Zeugen assertieren gegen ihn, nie gegen
    /// Formatierung.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoTarget => "EA-READER-EXPORT-NO-TARGET",
            Self::TargetOccupied => "EA-READER-EXPORT-TARGET-OCCUPIED",
            Self::ConfirmationStale => "EA-READER-EXPORT-CONFIRMATION-STALE",
            Self::ConfirmationPurpose => "EA-READER-EXPORT-CONFIRMATION-PURPOSE",
            Self::SessionLocked => "EA-READER-EXPORT-SESSION-LOCKED",
            Self::AuditBeforeWrite(_) => "EA-READER-EXPORT-AUDIT-BEFORE-WRITE",
            Self::TargetWrite => "EA-READER-EXPORT-TARGET-WRITE",
            Self::AuditAfterWrite(_) => "EA-READER-EXPORT-AUDIT-AFTER-WRITE",
        }
    }

    /// Der Auditbefund hinter den zwei Auditarmen; sonst `None`.
    #[must_use]
    pub const fn audit_error(&self) -> Option<&ReaderAuditError> {
        match self {
            Self::AuditBeforeWrite(error) | Self::AuditAfterWrite(error) => Some(error),
            _ => None,
        }
    }

    /// Ob Klartext den Speicher verlassen hat, als dieser Fehler fiel.
    #[must_use]
    pub const fn plaintext_left(&self) -> bool {
        matches!(self, Self::TargetWrite | Self::AuditAfterWrite(_))
    }
}

impl fmt::Display for ReaderExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReaderExportError {}

/// Der Bericht eines gelungenen Einzelexports: Entry-Hash, Zielart und die
/// exakten Bytes der zwei Auditzeilen — nie der Pfad, nie der Inhalt.
pub struct ReaderExportReport {
    entry_hash: EntryHash,
    target_kind: ReaderExportTargetKindV1,
    accepted_event: Vec<u8>,
    completed_event: Vec<u8>,
}

impl ReaderExportReport {
    /// Der Eintragshash des exportierten Datensatzes.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    /// Die exportierten Eintragshashes — ein Array der Laenge EINS, und die
    /// Laenge steht im Typ.
    #[must_use]
    pub const fn exported_entry_hashes(&self) -> [EntryHash; 1] {
        [self.entry_hash]
    }

    /// Die Zielart.
    #[must_use]
    pub const fn target_kind(&self) -> ReaderExportTargetKindV1 {
        self.target_kind
    }

    /// Die exakten Bytes der `Accepted`-Zeile.
    #[must_use]
    pub fn accepted_event(&self) -> &[u8] {
        &self.accepted_event
    }

    /// Die exakten Bytes der `Completed`-Zeile.
    #[must_use]
    pub fn completed_event(&self) -> &[u8] {
        &self.completed_event
    }
}

impl fmt::Debug for ReaderExportReport {
    /// Hexadezimaler Eintragshash und Zielart; keine Auditbytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderExportReport { entry_hash: ")?;
        for byte in self.entry_hash.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        write!(formatter, ", target_kind: {} }}", self.target_kind.label())
    }
}

/// Der Exportdienst einer Sitzung.
///
/// Er leiht die Sitzung VERAENDERLICH, weil jeder Export die Frist nachrechnet
/// und eine faellige Sperre auslöst, und die Senke, weil jede Zeile angehaengt
/// wird. Die Zeit ist FEST je Dienst — `EffectiveNow` des Aufrufers, wie bei
/// `ea_audit::SignedLocalAuditService`.
pub struct ReaderExportService<'a> {
    session: &'a mut ReaderSession,
    identity: ReaderAuditIdentityV1,
    sink: &'a mut dyn ReaderAuditSink,
    effective_now: UnixMillis,
}

impl<'a> ReaderExportService<'a> {
    /// Oeffnet den Dienst ueber einer Sitzung.
    #[must_use]
    pub fn open(
        session: &'a mut ReaderSession,
        identity: ReaderAuditIdentityV1,
        sink: &'a mut dyn ReaderAuditSink,
        effective_now: UnixMillis,
    ) -> Self {
        Self {
            session,
            identity,
            sink,
            effective_now,
        }
    }

    /// Exportiert GENAU EINEN Datensatz an GENAU EIN gewaehltes Ziel.
    ///
    /// Der Datensatz kommt BESITZEND herein und faellt am Ende dieses Aufrufs
    /// — unter `ZeroizeOnDrop` seiner Nutzlast —, gleich ob der Export gelang.
    /// Die Bestaetigung wird VERBRAUCHT. `target` ist `None`, wenn die Person
    /// den Dialog abgebrochen hat; das ist eine eigene Abweisung und nicht
    /// dieselbe wie ein besetztes Ziel.
    ///
    /// # Errors
    /// Die vier Abweisungen vor der Grenze —
    /// `EA-READER-EXPORT-CONFIRMATION-PURPOSE`,
    /// `EA-READER-EXPORT-CONFIRMATION-STALE`, `EA-READER-EXPORT-NO-TARGET`,
    /// `EA-READER-EXPORT-TARGET-OCCUPIED` — dazu
    /// `EA-READER-EXPORT-SESSION-LOCKED` und die drei Lagen der Grenze:
    /// `EA-READER-EXPORT-AUDIT-BEFORE-WRITE` (nichts ist draussen),
    /// `EA-READER-EXPORT-TARGET-WRITE` (das Ziel hat abgewiesen, die
    /// `Failed`-Zeile steht) und `EA-READER-EXPORT-AUDIT-AFTER-WRITE` (die
    /// Bytes sind draussen, die zweite Zeile fehlt).
    pub fn export_one(
        &mut self,
        record: VerifiedDecryptedRecord,
        target: Option<&mut dyn ReaderExportTarget>,
        confirmation: ReaderAuthenticatorConfirmation,
    ) -> Result<ReaderExportReport, ReaderExportError> {
        let now = self.effective_now;
        confirmation
            .check(ReaderConfirmationPurpose::SingleExport, now)
            .map_err(|error| match error {
                ReaderSessionError::ConfirmationPurpose => ReaderExportError::ConfirmationPurpose,
                _ => ReaderExportError::ConfirmationStale,
            })?;
        let target = target.ok_or(ReaderExportError::NoTarget)?;
        if target.is_occupied() {
            return Err(ReaderExportError::TargetOccupied);
        }
        let operator_binding_hash = self.session.operator_binding_hash();
        let vault = self
            .session
            .vault(now)
            .ok_or(ReaderExportError::SessionLocked)?;
        let mut writer =
            ReaderAuditWriter::open(vault, self.identity, operator_binding_hash, &mut *self.sink);
        let entry_hash = record.entry_hash();
        let target_kind = target.kind();
        let context = || {
            LocalAuditActionV1::PlaintextExport(ExportContextV1::new(
                entry_hash,
                target_kind.target_kind(),
            ))
        };

        // Die unwiderrufliche Grenze: die Zeile steht, BEVOR ein Byte den
        // Speicher verlaesst.
        let accepted_event = writer
            .record(context(), LocalAuditOutcomeV1::Accepted, now)
            .map_err(ReaderExportError::AuditBeforeWrite)?;

        let written = record.with_plaintext(|plaintext| target.write(plaintext));

        match written {
            Ok(()) => {
                let completed_event = writer
                    .record(context(), LocalAuditOutcomeV1::Completed, now)
                    .map_err(ReaderExportError::AuditAfterWrite)?;
                Ok(ReaderExportReport {
                    entry_hash,
                    target_kind,
                    accepted_event,
                    completed_event,
                })
            }
            Err(ReaderExportTargetError) => {
                writer
                    .record(context(), LocalAuditOutcomeV1::Failed, now)
                    .map_err(ReaderExportError::AuditAfterWrite)?;
                Err(ReaderExportError::TargetWrite)
            }
        }
    }
}

impl fmt::Debug for ReaderExportService<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderExportService")
            .field("effective_now", &self.effective_now)
            .finish_non_exhaustive()
    }
}
