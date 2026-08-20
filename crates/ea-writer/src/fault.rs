//! Die dreizehn Schritte der Finalisierung, ihre sieben Phasen und die
//! benannten Unterbrechungspunkte.
//!
//! Die Schrittnamen folgen `design.md` §9.3 Punkt fuer Punkt. Die Punkte
//! folgen der Robustheitszusage (`design.md` §20.4): „Fault Injection VOR und
//! NACH jedem Datei-/Verzeichnis-Flush, Create-if-absent, Rename,
//! Keystore-Delete, Datenbank- und Object-Store-Schritt".
//!
//! Sie folgen dabei DERSELBEN Adjazenzdoktrin wie
//! [`ea_draft::DiscardFaultPoint`]: zwischen zwei benachbarten Punkten liegt
//! GENAU EIN dauerhafter Schritt, das „nach" des einen ist das „vor" des
//! naechsten, und zwei Namen fuer denselben Programmpunkt waeren keine zweite
//! Messung, sondern eine Verdopplung. Aus den sieben Klassen der Norm werden so
//! zwoelf Punkte und nicht vierzehn.

/// Ein Schritt der Finalisierung — die dreizehn von `design.md` §9.3.
///
/// Die Reihenfolge des Feldes IST die Ausfuehrungsreihenfolge, und die
/// eingefrorenen Stufe-1-Konstruktoren erzwingen sie: `entryHash` entsteht als
/// Nebenprodukt von `EntryPackageV1::new`, und der `.eag`-Rumpf verlangt ihn
/// als Pflichtfeld — vor Schritt 6 existiert der Wert nicht, und ohne ihn ist
/// kein `.eag` baubar.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FinalizationStep {
    /// 1. Den vertrauenswuerdigen lokalen Kettenkopf aus Archivobjekten
    ///    rekonstruieren.
    RebuildLocalHead,
    /// 2. Einen erreichbaren signierten Server-Checkpoint vergleichen.
    CompareServerCheckpoint,
    /// 3. Den anwendbaren Registry-Head auswaehlen und den Bediener pruefen.
    SelectRegistryHeadAndOperator,
    /// 4. Nutzlast und Momentaufnahmen validieren und deterministisch
    ///    serialisieren.
    ValidateAndSerialize,
    /// 5. Den initialen Grant-Plan bilden und hashen.
    BuildAndHashGrantPlan,
    /// 6. Die Geheimnisse EINMAL ziehen und den `entryHash` bilden.
    DrawSecretsAndBuildEntryHash,
    /// 7. Jedes `.eag` und dann die endgueltigen `.eip`-Bytes erzeugen.
    ProduceGrantsAndEntryBytes,
    /// 8. Jedes Byte in den Staging-Bereich schreiben und flushen.
    StageAndFlush,
    /// 9. Nullen, leeren und den `draftDEK` loeschen — die unwiderrufliche
    ///    Grenze.
    ZeroAndDeleteDraftKey,
    /// 10. Die Grants create-if-absent veroeffentlichen.
    PublishGrants,
    /// 11. Das `.eip` ZULETZT veroeffentlichen.
    PublishEntryLast,
    /// 12. In das kontrollierte Netzarchiv veroeffentlichen.
    PublishToNetworkArchive,
    /// 13. Abgleichen und einen leeren Entwurf oeffnen.
    ReconcileAndOpenBlankDraft,
}

impl FinalizationStep {
    /// Alle dreizehn Schritte, in Ausfuehrungsreihenfolge.
    ///
    /// Die Laenge ist Teil des Typs: ein vierzehnter Schritt bricht dieses
    /// Literal und erzwingt damit, dass Manifest und Zustandsautomat ihn
    /// mitnehmen statt ihn stillschweigend auszulassen.
    pub const ALL: [Self; 13] = [
        Self::RebuildLocalHead,
        Self::CompareServerCheckpoint,
        Self::SelectRegistryHeadAndOperator,
        Self::ValidateAndSerialize,
        Self::BuildAndHashGrantPlan,
        Self::DrawSecretsAndBuildEntryHash,
        Self::ProduceGrantsAndEntryBytes,
        Self::StageAndFlush,
        Self::ZeroAndDeleteDraftKey,
        Self::PublishGrants,
        Self::PublishEntryLast,
        Self::PublishToNetworkArchive,
        Self::ReconcileAndOpenBlankDraft,
    ];

    /// Der STABILE Name, unter dem das Manifest diesen Schritt fuehrt.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RebuildLocalHead => "RebuildLocalHead",
            Self::CompareServerCheckpoint => "CompareServerCheckpoint",
            Self::SelectRegistryHeadAndOperator => "SelectRegistryHeadAndOperator",
            Self::ValidateAndSerialize => "ValidateAndSerialize",
            Self::BuildAndHashGrantPlan => "BuildAndHashGrantPlan",
            Self::DrawSecretsAndBuildEntryHash => "DrawSecretsAndBuildEntryHash",
            Self::ProduceGrantsAndEntryBytes => "ProduceGrantsAndEntryBytes",
            Self::StageAndFlush => "StageAndFlush",
            Self::ZeroAndDeleteDraftKey => "ZeroAndDeleteDraftKey",
            Self::PublishGrants => "PublishGrants",
            Self::PublishEntryLast => "PublishEntryLast",
            Self::PublishToNetworkArchive => "PublishToNetworkArchive",
            Self::ReconcileAndOpenBlankDraft => "ReconcileAndOpenBlankDraft",
        }
    }

    /// Die Nummer des Schritts in `design.md` §9.3, eins-basiert.
    #[must_use]
    pub const fn spec_number(self) -> u8 {
        match self {
            Self::RebuildLocalHead => 1,
            Self::CompareServerCheckpoint => 2,
            Self::SelectRegistryHeadAndOperator => 3,
            Self::ValidateAndSerialize => 4,
            Self::BuildAndHashGrantPlan => 5,
            Self::DrawSecretsAndBuildEntryHash => 6,
            Self::ProduceGrantsAndEntryBytes => 7,
            Self::StageAndFlush => 8,
            Self::ZeroAndDeleteDraftKey => 9,
            Self::PublishGrants => 10,
            Self::PublishEntryLast => 11,
            Self::PublishToNetworkArchive => 12,
            Self::ReconcileAndOpenBlankDraft => 13,
        }
    }
}

/// Der DAUERHAFTE Zustand, den eine Finalisierung erreicht hat.
///
/// Groeber als [`FinalizationStep`]: eine Phase ist ein Zustand von
/// Dateisystem, Schluesselspeicher und Datenbank, ein Schritt eine Stelle im
/// Programm. Genau sieben; ein halb veroeffentlichter Bestand ist keiner von
/// ihnen, und der Typ ist der Grund, warum ein Test das behaupten KANN.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum FinalizationPhase {
    /// Nichts Dauerhaftes ist geschehen; der Entwurf ist umkehrbar.
    ReversibleDraft,
    /// Jedes Byte liegt geprueft und geflusht im Staging, und die
    /// Abschlussmarke ist dauerhaft.
    PreparedAndFlushed,
    /// Der `draftDEK` ist fort und seine Abwesenheit bestaetigt — ab hier
    /// unwiderruflich.
    DraftKeyAbsent,
    /// Jeder Grant liegt unter seinem Zielnamen.
    GrantsPublished,
    /// Das `.eip` liegt unter seinem Zielnamen; erst jetzt darf die Anwendung
    /// `lokal gesichert` melden.
    EntryCommitted,
    /// Die Netzarchivpublikation ist abgeschlossen.
    NetworkArchivePublished,
    /// Kettenkopf und Queues sind abgeleitet, das Staging bereinigt und ein
    /// leerer Entwurf offen.
    Reconciled,
}

impl FinalizationPhase {
    /// Alle sieben Phasen, in Ausfuehrungsreihenfolge.
    pub const ALL: [Self; 7] = [
        Self::ReversibleDraft,
        Self::PreparedAndFlushed,
        Self::DraftKeyAbsent,
        Self::GrantsPublished,
        Self::EntryCommitted,
        Self::NetworkArchivePublished,
        Self::Reconciled,
    ];

    /// Ob dieser Zustand jenseits der unwiderruflichen Grenze liegt.
    ///
    /// Ab [`Self::DraftKeyAbsent`] MUSS die Transaktion aus den vorbereiteten
    /// Bytes vollendet werden; davor darf der Entwurf wiederhergestellt und
    /// unvollstaendiges Staging verworfen werden, und die Sequenz gilt als
    /// nicht verbraucht (`design.md` §9.4).
    #[must_use]
    pub const fn is_irreversible(self) -> bool {
        !matches!(self, Self::ReversibleDraft | Self::PreparedAndFlushed)
    }
}

/// Der Punkt, an dem eine Finalisierung unterbrochen wird.
///
/// Die Reihenfolge des Feldes ist die Reihenfolge der Ausfuehrung.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FinalizationFaultPoint {
    /// Vor dem ersten Create-if-absent des Staging-Bereichs.
    ///
    /// Ein Abbruch hier aendert NICHTS: es existiert keine Staging-Adresse.
    BeforeStagingCreate,
    /// Nach dem Create-if-absent jeder Staging-Adresse, VOR dem Dateiflush.
    AfterStagingCreateBeforeFileFlush,
    /// Nach dem Dateiflush jeder Staging-Adresse, VOR dem Verzeichnisflush.
    AfterStagingFileFlushBeforeDirectoryFlush,
    /// Nach dem Verzeichnisflush des Stagings, VOR der Datenbanktransaktion.
    ///
    /// Jedes Byte ist dauerhaft, aber NICHTS weist es einer Transaktion zu:
    /// ohne Abschlussmarke sind die Staging-Dateien temporaere Dateien und
    /// werden bereinigt.
    AfterStagingDirectoryFlushBeforeMarker,
    /// Nach dem dauerhaften Buchen der Abschlussmarke — der DATENBANKschritt.
    ///
    /// Der letzte Punkt, an dem ein Neustart noch den Entwurf wiederherstellen
    /// darf: der `draftDEK` ist noch da.
    AfterPreparedMarkerCommit,
    /// Nach dem Loeschen des `draftDEK`, VOR der Bestaetigung seiner
    /// Abwesenheit — der KEYSTOREschritt.
    AfterKeystoreDelete,
    /// Nach der bestaetigten Abwesenheit des `draftDEK`.
    ///
    /// Ab hier MUSS aus den vorbereiteten Bytes vollendet werden.
    AfterAbsenceConfirmation,
    /// Nach der Veroeffentlichung der Grants, VOR dem Rename des `.eip` — der
    /// OBJECT-STORE-Schritt.
    ///
    /// Der Zustand, in dem veroeffentlichte Grants ohne committed `.eip`
    /// liegen. Sie sind keine gueltigen Freigaben und bleiben quarantaeniert,
    /// bis ihre eigene vorbereitete Transaktion sie uebernimmt.
    AfterGrantPublishBeforeEntryRename,
    /// Nach dem atomaren Rename des `.eip`, VOR dem Verzeichnisflush.
    AfterEntryRenameBeforeDirectoryFlush,
    /// Nach dem Verzeichnisflush der Eintraege.
    ///
    /// Der lokale Archiv-Commit ist vollstaendig; das Archivpaket ist jetzt die
    /// Wahrheit, und ein Neustart erzeugt kein Duplikat.
    AfterEntryDirectoryFlush,
    /// Nach dem Abgleich, VOR dem Bereinigen des Stagings und dem Oeffnen des
    /// leeren Entwurfs.
    AfterReconciliationBeforeBlankDraft,
    /// Eine zurueckgespielte Sicherung, NACHDEM der `draftDEK` geloescht war.
    ///
    /// Kein Punkt der Reihenfolge, sondern ein Ereignis von aussen — dieselbe
    /// Klasse wie [`ea_draft::DiscardFaultPoint::BackupRestoreAfterKeyDeletion`]:
    /// die Datenbankdateien kehren zurueck, der geraetegebundene
    /// Schluesselspeichereintrag nicht.
    BackupRestoreAfterKeyDeletion,
}

impl FinalizationFaultPoint {
    /// Alle Unterbrechungspunkte, in Ausfuehrungsreihenfolge.
    ///
    /// Die Laenge ist Teil des Typs: ein dreizehnter Punkt bricht dieses
    /// Literal.
    pub const ALL: [Self; 12] = [
        Self::BeforeStagingCreate,
        Self::AfterStagingCreateBeforeFileFlush,
        Self::AfterStagingFileFlushBeforeDirectoryFlush,
        Self::AfterStagingDirectoryFlushBeforeMarker,
        Self::AfterPreparedMarkerCommit,
        Self::AfterKeystoreDelete,
        Self::AfterAbsenceConfirmation,
        Self::AfterGrantPublishBeforeEntryRename,
        Self::AfterEntryRenameBeforeDirectoryFlush,
        Self::AfterEntryDirectoryFlush,
        Self::AfterReconciliationBeforeBlankDraft,
        Self::BackupRestoreAfterKeyDeletion,
    ];

    /// Der STABILE Name, unter dem das Manifest diesen Punkt fuehrt.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BeforeStagingCreate => "BeforeStagingCreate",
            Self::AfterStagingCreateBeforeFileFlush => "AfterStagingCreateBeforeFileFlush",
            Self::AfterStagingFileFlushBeforeDirectoryFlush => {
                "AfterStagingFileFlushBeforeDirectoryFlush"
            }
            Self::AfterStagingDirectoryFlushBeforeMarker => {
                "AfterStagingDirectoryFlushBeforeMarker"
            }
            Self::AfterPreparedMarkerCommit => "AfterPreparedMarkerCommit",
            Self::AfterKeystoreDelete => "AfterKeystoreDelete",
            Self::AfterAbsenceConfirmation => "AfterAbsenceConfirmation",
            Self::AfterGrantPublishBeforeEntryRename => "AfterGrantPublishBeforeEntryRename",
            Self::AfterEntryRenameBeforeDirectoryFlush => "AfterEntryRenameBeforeDirectoryFlush",
            Self::AfterEntryDirectoryFlush => "AfterEntryDirectoryFlush",
            Self::AfterReconciliationBeforeBlankDraft => "AfterReconciliationBeforeBlankDraft",
            Self::BackupRestoreAfterKeyDeletion => "BackupRestoreAfterKeyDeletion",
        }
    }

    /// Der dauerhafte Schritt, den dieser Punkt klammert.
    #[must_use]
    pub const fn brackets(self) -> &'static str {
        match self {
            Self::BeforeStagingCreate => "vor dem ersten Create-if-absent des Staging-Bereichs",
            Self::AfterStagingCreateBeforeFileFlush => {
                "nach dem Create-if-absent jeder Staging-Adresse und vor dem Dateiflush"
            }
            Self::AfterStagingFileFlushBeforeDirectoryFlush => {
                "nach dem Dateiflush jeder Staging-Adresse und vor dem Verzeichnisflush"
            }
            Self::AfterStagingDirectoryFlushBeforeMarker => {
                "nach dem Verzeichnisflush des Stagings und vor der Datenbanktransaktion"
            }
            Self::AfterPreparedMarkerCommit => {
                "nach dem dauerhaften Buchen der Abschlussmarke in der verschluesselten Ablage"
            }
            Self::AfterKeystoreDelete => {
                "nach dem Loeschen des draftDEK und vor der Bestaetigung seiner Abwesenheit"
            }
            Self::AfterAbsenceConfirmation => "nach der bestaetigten Abwesenheit des draftDEK",
            Self::AfterGrantPublishBeforeEntryRename => {
                "nach der Veroeffentlichung jedes Grants und vor dem Rename des .eip"
            }
            Self::AfterEntryRenameBeforeDirectoryFlush => {
                "nach dem atomaren Rename des .eip und vor dem Verzeichnisflush der Eintraege"
            }
            Self::AfterEntryDirectoryFlush => "nach dem Verzeichnisflush der Eintraege",
            Self::AfterReconciliationBeforeBlankDraft => {
                "nach dem Abgleich und vor dem Bereinigen des Stagings samt leerem Entwurf"
            }
            Self::BackupRestoreAfterKeyDeletion => {
                "nach dem Loeschen des draftDEK, mit zurueckgespielten Datenbankdateien"
            }
        }
    }

    /// Die Phase, in der ein Neustart diesen Punkt vorfindet.
    #[must_use]
    pub const fn phase(self) -> FinalizationPhase {
        match self {
            Self::BeforeStagingCreate
            | Self::AfterStagingCreateBeforeFileFlush
            | Self::AfterStagingFileFlushBeforeDirectoryFlush
            | Self::AfterStagingDirectoryFlushBeforeMarker => FinalizationPhase::ReversibleDraft,
            Self::AfterPreparedMarkerCommit => FinalizationPhase::PreparedAndFlushed,
            Self::AfterKeystoreDelete
            | Self::AfterAbsenceConfirmation
            | Self::BackupRestoreAfterKeyDeletion => FinalizationPhase::DraftKeyAbsent,
            Self::AfterGrantPublishBeforeEntryRename => FinalizationPhase::GrantsPublished,
            Self::AfterEntryRenameBeforeDirectoryFlush | Self::AfterEntryDirectoryFlush => {
                FinalizationPhase::EntryCommitted
            }
            Self::AfterReconciliationBeforeBlankDraft => FinalizationPhase::NetworkArchivePublished,
        }
    }
}
