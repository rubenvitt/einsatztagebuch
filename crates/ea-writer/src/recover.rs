//! Die Wiederherstellung — das Gegenstueck zur Finalisierung.
//!
//! Sie ist der EINE Neustartpfad, und sie unterscheidet genau zwei Seiten der
//! unwiderruflichen Grenze (`design.md` §9.4):
//!
//! - **Vor** der bestaetigten Loeschung des `draftDEK` darf sie den Entwurf
//!   wiederherstellen und unvollstaendiges Staging verwerfen; die Sequenz gilt
//!   dann als NICHT verbraucht.
//! - **Nach** der Loeschung vollendet sie die Transaktion AUSSCHLIESSLICH aus
//!   den gespeicherten exakten Bytes. Sie serialisiert nichts neu, zieht keine
//!   Zufallswerte, praegt keine neue Kennung und benutzt die Sequenz nirgends
//!   sonst.
//!
//! Die Unterscheidung haengt NICHT an einem Feld der Marke, sondern an der
//! Wirklichkeit: liegt der `draftDEK` noch, ist die Grenze nicht ueberschritten.
//! Ein Feld waere eine Behauptung, der Schluesselspeicher ist der Zeuge.

use ea_types::ChainSequence;

use crate::{
    WriterError,
    finalize::{ReachedState, WriterService},
    marker::PreparedTransactionV1,
};

/// Was ein Neustart vorgefunden und daraus gemacht hat.
///
/// GENAU drei Ausgaenge. Ein halb veroeffentlichter Bestand ist keiner von
/// ihnen.
#[derive(Clone, Eq, PartialEq)]
pub enum RecoveryOutcome {
    /// Es lag nichts an: der Entwurf steht unveraendert.
    NothingPending,
    /// Die Grenze war NICHT ueberschritten: das Staging ist verworfen, die
    /// Marke geloescht, der Entwurf steht, die Sequenz ist unverbraucht.
    DraftRestored { unused_sequence: ChainSequence },
    /// Die Grenze WAR ueberschritten: die Transaktion ist aus den vorbereiteten
    /// Bytes vollendet.
    ///
    /// Ob dabei vorab veroeffentlichte Grants UEBERNOMMEN wurden, sagt dieser
    /// Wert ABSICHTLICH nicht. Die Uebernahme ist eine Aussage darueber, ob
    /// eine Zieladresse schon belegt war, und der Schreibport hat keine
    /// Leseprimitive, mit der sich das VOR dem Rename feststellen liesse. Ein
    /// Feld, das ueber das Inventar geraten waere, haette dabei jede gestagte
    /// Datei mitgezaehlt — Staging-Dateien tragen das Objektpraefix und stehen
    /// damit im Inventar. Der Quarantaenepfad ist eine offengelegte Auslassung
    /// dieses Tasks und kein stiller Zustand.
    CommittedFromPreparedBytes { sequence: ChainSequence },
}

impl RecoveryOutcome {
    /// Ob der Originalentwurf wiederhergestellt wurde.
    #[must_use]
    pub const fn is_original_draft(&self) -> bool {
        matches!(self, Self::NothingPending | Self::DraftRestored { .. })
    }

    /// Die VERGLEICHBARE Zusammenfassung.
    ///
    /// Die Zusage „ein zweites recover ist ein no-op" ist eine GLEICHHEIT und
    /// keine Beschreibung; dieser Wert ist die Seite, gegen die verglichen wird.
    #[must_use]
    pub const fn summary(&self) -> (&'static str, u64) {
        match self {
            Self::NothingPending => ("NothingPending", 0),
            Self::DraftRestored { unused_sequence } => ("DraftRestored", unused_sequence.get()),
            Self::CommittedFromPreparedBytes { sequence } => {
                ("CommittedFromPreparedBytes", sequence.get())
            }
        }
    }
}

impl core::fmt::Debug for RecoveryOutcome {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (name, sequence) = self.summary();
        write!(formatter, "{name}({sequence})")
    }
}

impl WriterService<'_> {
    /// Loest eine liegende Abschlussmarke auf.
    ///
    /// Idempotent: ein zweiter Aufruf findet keine Marke mehr und liefert
    /// [`RecoveryOutcome::NothingPending`].
    ///
    /// # Errors
    ///
    /// [`WriterError::PreparedFinalizationUnreadable`], wenn die Marke nicht
    /// die Gestalt dieses Baustands hat — fail-closed, denn aus halb gelesenen
    /// Bytes darf kein Bestand entstehen; sonst der Fehler des Ports.
    pub fn recover_pending(&self) -> Result<RecoveryOutcome, WriterError> {
        let _writer_lock = self.backend.acquire_writer_lock()?;
        let _draft_lock = self.repository.acquire_draft_lock()?;
        let Some(marker) = self.repository.prepared_finalization_marker()? else {
            return Ok(RecoveryOutcome::NothingPending);
        };
        let transaction = PreparedTransactionV1::decode(marker.as_bytes())?;
        // NACHGERECHNET, bevor irgendetwas anderes geschieht — und ausdruecklich
        // VOR der Frage nach der Grenze. Hinter der Grenze ist diese Marke die
        // einzige Quelle des Bestands, und dann gibt es keine zweite Pruefung
        // mehr; VOR der Grenze ist eine sich selbst widersprechende Marke ein
        // Manipulationsbefund und keine Lage, aus der ein Programm sich selbst
        // heraushilft. Fail-closed heisst hier in beide Richtungen: abbrechen,
        // ohne ein Byte zu veroeffentlichen und ohne die Marke zu loesen.
        transaction.verify(marker.as_bytes())?;

        // Der ZEUGE der Grenze ist der ENTWURF SELBST, und nicht ein Feld der
        // Marke: laesst er sich laden, war sein `draftDEK` da und
        // entschluesselte seine Bytes. Ein Feld waere eine Behauptung.
        //
        // GENAU ZWEI Fehler heissen „der Schluessel ist fort", und beide sind
        // dauerhaft — dieselbe enge Aufzaehlung und dieselbe Begruendung wie in
        // `DiscardService::resume_after_restart`: `Key(NotFound)` heisst, der
        // Eintrag ist geloescht, `Crypto(AeadOpen)` heisst, an seiner Adresse
        // liegt das Material eines anderen Entwurfs. Jeder ANDERE
        // Schluesselfehler ist eine Aussage ueber JETZT — Geraet gesperrt, TPM
        // belegt — und darf nicht als „unwiderruflich" gelesen werden; er
        // bricht ab.
        let key_present = match self.repository.load_or_create() {
            Ok(_) => true,
            Err(ea_draft::DraftError::Key(ea_key_provider::KeyError::NotFound))
            | Err(ea_draft::DraftError::Crypto(ea_crypto::CryptoError::AeadOpen)) => false,
            Err(other) => return Err(WriterError::Draft(other)),
        };

        if key_present {
            // Vor der Grenze: unvollstaendiges Staging verwerfen und die Marke
            // loesen. Die Staging-Dateien bleiben liegen und sind ein
            // Gesundheitsbefund (temporaere Datei); sie zu entfernen verlangt
            // eine Loeschprimitive, die der Port bewusst nicht hat.
            self.repository.replace_prepared_finalization_marker(None)?;
            return Ok(RecoveryOutcome::DraftRestored {
                unused_sequence: transaction.sequence,
            });
        }

        // Nach der Grenze: AUSSCHLIESSLICH aus den vorbereiteten Bytes
        // vollenden. Derselbe Veroeffentlichungspfad wie im glatten Lauf, und
        // deshalb keine zweite Gelegenheit, andere Bytes zu schreiben.
        let mut state = ReachedState::for_recovery();
        self.publish_from_prepared(
            &transaction,
            crate::finalize::Stop::After(crate::FinalizationStep::ReconcileAndOpenBlankDraft),
            &mut state,
        )?;
        Ok(RecoveryOutcome::CommittedFromPreparedBytes {
            sequence: transaction.sequence,
        })
    }
}
