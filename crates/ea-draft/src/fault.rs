//! Die benannten Unterbrechungspunkte des Verwerfens und die Zustaende, in die
//! ein Neustart fuehren kann.
//!
//! Die Robustheitszusage (`design.md`:2024) verlangt, dass ein Abbruch VOR und
//! NACH jedem dauerhaften Schritt geprueft wird. Diese Datei benennt genau
//! diese Punkte, damit sie aufzaehlbar sind — ein Test, der ueber
//! [`DiscardFaultPoint::ALL`] laeuft, kann keinen Punkt auslassen, und das
//! eingecheckte Manifest `docs/traceability/stage-2-fault-points.json` haelt
//! sie fest.
//!
//! [`PREPARED_FINALIZATION_BEATS_DISCARD_INTENT`] ist AUSDRUECKLICH kein
//! Mitglied von [`DiscardFaultPoint::ALL`]: jeder Punkt jenes Feldes muss in
//! einen unveraenderten oder einen dauerhaft leeren Entwurf neu starten,
//! waehrend die Vorrangregel in [`RestartState::PreparedFinalizationPending`]
//! neu startet — und zwar mit Absicht.

/// Der Punkt, an dem ein Verwerfen unterbrochen wird.
///
/// Die Reihenfolge des Feldes ist die Reihenfolge der Ausfuehrung. Zwischen
/// zwei benachbarten Punkten liegt GENAU ein dauerhafter Schritt: das
/// „nach" des einen ist das „vor" des naechsten, und zwei Namen fuer denselben
/// Programmpunkt waeren keine zweite Messung, sondern eine Verdopplung.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiscardFaultPoint {
    /// Vor dem dauerhaften Buchen der Verwerfensabsicht.
    ///
    /// Ein Abbruch hier aendert NICHTS: der Entwurf bleibt bearbeitbar.
    BeforeIntentCommit,
    /// Nach dem dauerhaften Buchen der Verwerfensabsicht.
    ///
    /// Der Schritt, hinter dem alles Weitere eine FORTSETZUNG ist: ein Neustart
    /// bietet den Entwurf nicht mehr zur Bearbeitung an, sondern fuehrt
    /// dieselbe Operation weiter (`design.md`:432).
    AfterIntentCommit,
    /// Nach dem Loeschen des `draftDEK` aus dem Schluesselspeicher, aber VOR
    /// der Bestaetigung seiner Abwesenheit.
    AfterKeystoreDelete,
    /// Nach der bestaetigten Abwesenheit des `draftDEK`.
    AfterAbsenceConfirmation,
    /// Nach dem transaktionalen Entfernen von Chiffrat und Absicht samt Anlegen
    /// des leeren Entwurfs.
    ///
    /// Entfernen und Anlegen sind EINE Transaktion von
    /// `remove_ciphertext_and_intent_create_blank`. Ein Punkt DAZWISCHEN ist
    /// dauerhaft nicht erreichbar — ein Absturz dort rollt die Transaktion
    /// zurueck und hinterlaesst genau den Zustand von
    /// [`Self::AfterAbsenceConfirmation`] —, und dieser Punkt klammert deshalb
    /// beide Schritte.
    AfterDraftRemoval,
    /// Eine zurueckgespielte Sicherung, NACHDEM der `draftDEK` geloescht war.
    ///
    /// Kein Punkt der Reihenfolge, sondern ein Ereignis von aussen: die
    /// Datenbankdateien kehren zurueck, der Schluesselspeichereintrag nicht.
    /// Er ist geraetegebunden und aus der gewoehnlichen Anwendungs- und
    /// Systemsicherung ausgenommen (`design.md`:428, :1491), also findet eine
    /// zurueckgelegte Datenbankdatei keinen Schluessel.
    BackupRestoreAfterKeyDeletion,
}

impl DiscardFaultPoint {
    /// Alle Unterbrechungspunkte, in Ausfuehrungsreihenfolge.
    ///
    /// Die Laenge ist Teil des Typs: ein siebter Punkt bricht dieses Literal
    /// und erzwingt damit, dass Manifest und Wiederherstellungstest ihn
    /// mitnehmen statt ihn stillschweigend auszulassen.
    pub const ALL: [Self; 6] = [
        Self::BeforeIntentCommit,
        Self::AfterIntentCommit,
        Self::AfterKeystoreDelete,
        Self::AfterAbsenceConfirmation,
        Self::AfterDraftRemoval,
        Self::BackupRestoreAfterKeyDeletion,
    ];

    /// Der STABILE Name, unter dem das Manifest diesen Punkt fuehrt.
    ///
    /// Er ist stabil, weil Task 17 und Task 18 ihn lesen; eine Umbenennung ist
    /// eine Aenderung am eingecheckten Artefakt und nicht am Namen allein.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BeforeIntentCommit => "BeforeIntentCommit",
            Self::AfterIntentCommit => "AfterIntentCommit",
            Self::AfterKeystoreDelete => "AfterKeystoreDelete",
            Self::AfterAbsenceConfirmation => "AfterAbsenceConfirmation",
            Self::AfterDraftRemoval => "AfterDraftRemoval",
            Self::BackupRestoreAfterKeyDeletion => "BackupRestoreAfterKeyDeletion",
        }
    }

    /// Der dauerhafte Schritt, den dieser Punkt klammert.
    #[must_use]
    pub const fn brackets(self) -> &'static str {
        match self {
            Self::BeforeIntentCommit => "vor dem dauerhaften Buchen der Verwerfensabsicht",
            Self::AfterIntentCommit => "nach dem dauerhaften Buchen der Verwerfensabsicht",
            Self::AfterKeystoreDelete => {
                "nach dem Loeschen des draftDEK und vor der Bestaetigung seiner Abwesenheit"
            }
            Self::AfterAbsenceConfirmation => "nach der bestaetigten Abwesenheit des draftDEK",
            Self::AfterDraftRemoval => {
                "nach der Transaktion, die Chiffrat und Absicht entfernt und den leeren Entwurf anlegt"
            }
            Self::BackupRestoreAfterKeyDeletion => {
                "nach dem Loeschen des draftDEK, mit zurueckgespielten Datenbankdateien"
            }
        }
    }
}

/// Der benannte Punkt der Vorrangregel.
///
/// Ein durabler `PreparedFinalization` gewinnt an JEDEM Eingang gegen ein
/// Verwerfen: nach dem unwiderruflichen Schritt MUSS die Transaktion aus den
/// vorbereiteten Bytes vollendet werden (`design.md`:456, :467). Task 11 und
/// Task 18 verweisen auf genau diesen Namen; er steht deshalb als Konstante
/// hier und nicht als Zeichenkette an drei Stellen.
pub const PREPARED_FINALIZATION_BEATS_DISCARD_INTENT: &str =
    "PreparedFinalizationBeatsDiscardIntent";

/// Was ein Bediener nach einem Neustart vorfindet.
///
/// GENAU drei Zustaende. Ein halb verworfener Entwurf ist keiner von ihnen, und
/// der Typ ist der Grund, warum ein Test das behaupten KANN: es gibt keine
/// vierte Variante, in die ein Zwischenzustand fallen koennte.
///
/// `Eq` und `PartialEq` sind da, damit ein zweites `resume` gegen das erste
/// verglichen werden kann — die Zusage „ein zweites resume ist ein no-op" ist
/// eine GLEICHHEIT und keine Beschreibung.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RestartState {
    /// Der Entwurf steht unveraendert und traegt weiterhin Inhalt.
    OriginalDraftUnchanged,
    /// Es steht ein leerer Entwurf mit frischer Kennung und frischem
    /// `draftDEK`.
    ///
    /// Er ist DAUERHAFT leer: es gibt keine Folge, keinen Kettenschritt und
    /// keine wiederherstellbare Papierkorbkopie, und die alten Datenbankseiten
    /// bleiben ohne den geloeschten `draftDEK` unlesbar.
    ///
    /// Ein leerer Originalentwurf ist von diesem Zustand ununterscheidbar, und
    /// das ist die Zusage des unwiderruflichen Verwerfens und kein Mangel der
    /// Messung: nach dem Verwerfen darf NICHTS mehr davon zeugen, dass es
    /// einen Entwurf gab.
    NewBlankDraft,
    /// Eine vorbereitete Abschlussmarke liegt, und sie hat Vorrang.
    ///
    /// Der Neustart fuehrt kein Verwerfen fort, solange sie liegt; der
    /// benannte Punkt dieser Regel ist
    /// [`PREPARED_FINALIZATION_BEATS_DISCARD_INTENT`].
    PreparedFinalizationPending,
}
