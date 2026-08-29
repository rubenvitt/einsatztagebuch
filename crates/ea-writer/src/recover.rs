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

use ea_archive::{ArchiveBlob, ArchivePath, GRANTS_DIR_V1, is_staging_path};
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
    /// Bytes darf kein Bestand entstehen.
    ///
    /// [`WriterError::PreparedFinalizationInconsistent`], wenn sie die Gestalt
    /// zwar hat, sich aber selbst widerspricht: abweichender Objekthash,
    /// `entryHash`, Sequenz oder Grant-Plan-Hash, oder eine leere Grantliste
    /// (siehe [`PreparedTransactionV1::verify`]). Auch dieser Ausgang
    /// veroeffentlicht KEIN Byte und loest die Marke NICHT.
    ///
    /// Sonst der Fehler des Ports.
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
            // loesen. Die Staging-Dateien bleiben HIER liegen, und das ist die
            // Zusage und keine Auslassung: solange dieser Aufruf laeuft, ist
            // der Ausgang noch nicht NACHGEWIESEN — die Marke faellt erst mit
            // der naechsten Zeile. Bereinigt wird ausschliesslich in
            // [`Self::reconcile_to_completion`], hinter dem Nachweis. Bis
            // dahin sind sie ein Gesundheitsbefund (temporaere Datei).
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

/// Was eine Bereinigung vorgefunden und daraus gemacht hat.
///
/// GENAU zwei Ausgaenge. Ein halb bereinigter Bestand ist keiner von ihnen:
/// entweder der Ausgang ist NACHGEWIESEN und die Reste fallen, oder es wird
/// kein Byte angefasst.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationOutcomeV1 {
    /// Es liegt noch eine Abschlussmarke. Der Ausgang ist damit NICHT
    /// nachgewiesen, und es wird nichts entfernt.
    NotProven,
    /// Der Ausgang ist nachgewiesen; die Reste sind fort.
    Reconciled {
        /// Liegengebliebene Staging-Dateien.
        removed_staging: usize,
        /// Vorab veroeffentlichte Grants ohne committetes `.eip`.
        removed_orphan_grants: usize,
    },
}

impl WriterService<'_> {
    /// Bereinigt die Reste — und AUSSCHLIESSLICH hinter einem nachgewiesenen
    /// Ausgang.
    ///
    /// # Die zwei Stellen, die `design.md` §9.3/§9.4 erlaubt
    ///
    /// 1. **Staging nach VOLLSTAENDIGER Reconciliation** (§9.3 Schritt 13:
    ///    „Kettenkopf und Queues ausschliesslich aus der lokalen committed
    ///    Archivkomponente ableiten, Staging nach vollstaendiger Reconciliation
    ///    bereinigen"). Im glatten Lauf gibt es dabei nichts zu tun — dort ist
    ///    der Rename selbst die Bereinigung und laesst keine Staging-Adresse
    ///    zurueck. Etwas zu tun gibt es genau dort, wo ein Abbruch Staging
    ///    liegengelassen hat.
    /// 2. **Vorab veroeffentlichte Grants ohne committetes `.eip` nach
    ///    NACHGEWIESENEM Abbruch** (§9.4: „Sie werden quarantaenisiert und nur
    ///    von der zugehoerigen vorbereiteten Transaktion uebernommen oder nach
    ///    nachgewiesenem Abbruch bereinigt").
    ///
    /// # Was der NACHWEIS ist
    ///
    /// Die AUFGELOESTE Abschlussmarke. Liegt sie noch, kann dieselbe
    /// vorbereitete Transaktion die Reste noch uebernehmen — sie zu entfernen
    /// waere dann kein Bereinigen, sondern das Zerstoeren der einzigen Quelle,
    /// aus der ein Neustart hinter der Grenze vollenden darf. Deshalb steht
    /// dieser Aufruf NEBEN [`Self::recover_pending`] und nicht darin: die
    /// Wiederherstellung LOEST die Marke, und erst danach ist der Ausgang
    /// nachgewiesen. Vor der unwiderruflichen Grenze faellt damit zu keinem
    /// Zeitpunkt ein Byte.
    ///
    /// Idempotent: ein zweiter Aufruf findet nichts mehr und entfernt nichts.
    ///
    /// # Errors
    ///
    /// [`WriterError::Draft`], wenn die Marke nicht lesbar ist; sonst der
    /// Fehler des Ports.
    pub fn reconcile_to_completion(&self) -> Result<ReconciliationOutcomeV1, WriterError> {
        let _writer_lock = self.backend.acquire_writer_lock()?;
        let _draft_lock = self.repository.acquire_draft_lock()?;
        if self.repository.prepared_finalization_marker()?.is_some() {
            return Ok(ReconciliationOutcomeV1::NotProven);
        }

        // Die committeten Eintragskennungen und die Reste, in EINEM Durchlauf.
        // Ein zweiter Durchlauf sähe einen anderen Bestand, wenn dazwischen
        // etwas geschieht — die Schreibersperre oben schliesst das aus, und
        // genau deshalb steht sie vor dieser Zeile.
        //
        // Die Staging-Adressen kommen aus dem SCHREIBPORT und die committeten
        // Objekte aus der LESESICHT, und das ist keine Umstaendlichkeit: die
        // Lesesicht blendet jede Staging-Adresse aus, damit eine vorbereitete
        // Datei nie als Kettenknoten zaehlt. Genau deshalb kann sie die zu
        // bereinigenden Reste gar nicht nennen, und genau deshalb traegt der
        // Schreibport dafuer `staged_paths`.
        let mut committed_entry_hashes = std::collections::BTreeSet::new();
        let staging: Vec<String> = self.backend.staged_paths()?;
        let mut grants: Vec<(String, ea_types::EntryHash)> = Vec::new();
        self.source.visit_blobs(&mut |blob: ArchiveBlob<'_>| {
            let hint = blob.path_hint();
            if is_staging_path(hint) {
                return Ok(());
            }
            match ea_format::decode_exact_object(blob.bytes()) {
                Ok(ea_format::ParsedArchiveObject::Entry(entry)) => {
                    committed_entry_hashes.insert(entry.value().entry_hash());
                }
                Ok(ea_format::ParsedArchiveObject::Grant(grant))
                    if hint.starts_with(GRANTS_DIR_V1) =>
                {
                    grants.push((
                        hint.to_owned(),
                        grant.value().grant_body().fields().entry_hash,
                    ));
                }
                _ => {}
            }
            Ok(())
        })?;

        let mut removed_staging = 0_usize;
        for relative in &staging {
            self.backend
                .remove_if_present(&archive_path_of(relative)?)?;
            removed_staging += 1;
        }
        let mut removed_orphan_grants = 0_usize;
        for (relative, entry_hash) in &grants {
            if committed_entry_hashes.contains(entry_hash) {
                continue;
            }
            self.backend
                .remove_if_present(&archive_path_of(relative)?)?;
            removed_orphan_grants += 1;
        }
        Ok(ReconciliationOutcomeV1::Reconciled {
            removed_staging,
            removed_orphan_grants,
        })
    }
}

/// Die wurzelrelative Adresse als validierte Transportadresse.
fn archive_path_of(relative: &str) -> Result<ArchivePath, WriterError> {
    let (directory, name) = relative
        .split_once('/')
        .ok_or(ea_archive::ArchiveBackendError::Path)?;
    Ok(ArchivePath::in_dir(&format!("{directory}/"), name)?)
}
