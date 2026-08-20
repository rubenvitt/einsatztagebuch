//! Die Abschlussvorschau — der bestaetigbare Zustand VOR der unwiderruflichen
//! Reihenfolge.
//!
//! Sie traegt `previewHash` ueber `finalization-preview-core-v1`
//! (`schemas/reports/v1/finalization-preview.cddl`), das Alter des gebundenen
//! Vertrauensbestands und die Policyfrist `readerTrustRefreshMs`, damit Task 15
//! und Task 16 die Auffrischungsaufforderung als sichtbare WARNUNG zeigen
//! koennen und niemals als Blockade.
//!
//! # Warum die Vorschau den `recordId` schon traegt
//!
//! `finalization-preview-core-v1` deckt an Position 10 den `recordDigest` ueber
//! die deterministisch serialisierten Nutzlastbytes von Spec-Schritt 4. Diese
//! Bytes ENTHALTEN den `recordId` des Kopfes (`crates/ea-schema/src/encode.rs`,
//! `CommonHeaderV1::record_id`), und `CommonHeaderV1::new` erzwingt einen
//! gueltigen UUIDv7. Ohne den Wert ist Schritt 4 also gar nicht ausfuehrbar.
//!
//! Der UUIDv7 wird deshalb EINMAL hier gezogen und von `finalize` UNVERAENDERT
//! uebernommen — nicht neu gezogen. `design.md` §9.3 nennt ihn in Schritt 6 in
//! einem Atem mit CEK und AEAD-Nonce; das ist an dieser Stelle nicht
//! durchhaltbar, weil Schritt 4 vor Schritt 6 liegt und die Nutzlast den Wert
//! braucht. Die Zusage, die dahinter steht, bleibt unberuehrt und ist die
//! eigentliche: **kein Geheimnis** ueberdauert den Bestaetigungsdialog. CEK und
//! AEAD-Nonce entstehen erst in Schritt 6, unter der Sperre, und ein UUIDv7 ist
//! kein Geheimnis.

use ea_format::{FinalizationPreviewCoreFieldsV1, FinalizationPreviewCoreV1};
use ea_types::{ChainSequence, EntryHash, Hash32, UnixMillis};

use crate::WriterError;

/// Was die Vorschau ueber den Zeitstatus des gebundenen Head sagt.
///
/// GESCHLOSSEN, drei Arme. Ein „vielleicht" gibt es nicht: entweder der Head
/// ist frisch, oder seine Veralterung ist bestaetigungsfaehig, oder sie
/// blockiert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleDecision {
    /// Der Head ist frisch: die BEOBACHTETE Zeit liegt nicht hinter
    /// `notAfter`.
    ///
    /// Ausdruecklich nicht das `effectiveNow` dieses Urbilds (Position 12) —
    /// das ist die Zeit ZUM AUSWAHLZEITPUNKT, und gegen sie ist jeder
    /// ausgelieferte Head immer frisch: `select_registry_head` gibt einen
    /// aktuellen Head nur bei `rawNow <= notAfter` heraus. Die Zeit der
    /// Feststellung kommt vom Wirt, mit dem Auswahlzeitpunkt als Boden.
    Fresh,
    /// Standardprofil MIT signiertem `warn`: nach nicht uebergehbarer sichtbarer
    /// Warnung, frischer `RegistryStaleFinalize`-Wiederanmeldung und
    /// ausdruecklicher Bestaetigung darf finalisiert werden
    /// (`design.md`:1447).
    StaleAcknowledgeable,
    /// Evidence Grade, signiertes `block` oder eine erschoepfte Sequenz-Lease.
    /// IMMER ein harter Fehler, unabhaengig vom gespeicherten Wert
    /// (`design.md`:269).
    HardBlock,
}

impl StaleDecision {
    /// Ob diese Entscheidung eine harte Blockade ist.
    #[must_use]
    pub const fn is_hard_block(self) -> bool {
        matches!(self, Self::HardBlock)
    }
}

/// Der bestaetigbare Zustand vor der Finalisierung.
///
/// Die Konstruktoren sind privat; ein Aufrufer kann keine Vorschau bauen, deren
/// `previewHash` niemand nachrechnen kann. `Clone` ist da, weil der Brieftest
/// dieselbe Vorschau zweimal braucht — einmal fuer die Bestaetigung und einmal
/// fuer `finalize`.
#[derive(Clone)]
pub struct FinalizationPreview {
    core: FinalizationPreviewCoreV1,
    preview_hash: Hash32,
    record_id: [u8; 16],
    decision: StaleDecision,
    trust_age_ms: u64,
    reader_trust_refresh_ms: u64,
}

impl FinalizationPreview {
    pub(crate) fn new(
        fields: FinalizationPreviewCoreFieldsV1,
        record_id: [u8; 16],
        decision: StaleDecision,
        trust_age_ms: u64,
        reader_trust_refresh_ms: u64,
    ) -> Result<Self, WriterError> {
        let core = FinalizationPreviewCoreV1::new(fields);
        let exact = ea_format::encode_finalization_preview_core(&core)?;
        Ok(Self {
            core,
            preview_hash: ea_crypto::finalization_preview_digest(&exact),
            record_id,
            decision,
            trust_age_ms,
            reader_trust_refresh_ms,
        })
    }

    /// `previewHash` — `SHA-256(DOMAIN || deterministicCbor(core))`.
    ///
    /// `finalize` rechnet ihn unter dem Writer-Lock NEU und weist jede
    /// Abweichung fail-closed ab.
    #[must_use]
    pub const fn preview_hash(&self) -> Hash32 {
        self.preview_hash
    }

    /// Der Zeitstatus des gebundenen Head.
    #[must_use]
    pub const fn decision(&self) -> StaleDecision {
        self.decision
    }

    /// Das ALTER des gebundenen Vertrauensbestands in Millisekunden — die
    /// BEOBACHTETE Zeit (mit dem Auswahlzeitpunkt als Boden) minus
    /// `SelectedRegistryHead::issued_at` des GEBUNDENEN Head.
    ///
    /// Der Bezugspunkt ist damit eine Aussage ueber den gebundenen Head und
    /// nicht ueber eine Zahl, die ein Aufrufer daneben mitfuehrt.
    #[must_use]
    pub const fn trust_age_ms(&self) -> u64 {
        self.trust_age_ms
    }

    /// Die Policyfrist `readerTrustRefreshMs` des gebundenen Head
    /// (`schemas/archive/v1/trust.cddl`).
    #[must_use]
    pub const fn reader_trust_refresh_ms(&self) -> u64 {
        self.reader_trust_refresh_ms
    }

    /// Ob das Alter die Auffrischungsfrist ueberschritten hat.
    ///
    /// Eine WARNUNG und nie eine Blockade: die Frist beschreibt, wann ein Leser
    /// seinen Vertrauensbestand auffrischen SOLL, nicht wann ein Writer
    /// aufhoert zu duerfen. Der blockierende Zeitbegriff ist `notAfter`, und
    /// der steht in [`Self::decision`].
    #[must_use]
    pub const fn trust_refresh_overdue(&self) -> bool {
        self.trust_age_ms > self.reader_trust_refresh_ms
    }

    /// Die vorgeschlagene Sequenz dieser Finalisierung.
    #[must_use]
    pub const fn proposed_sequence(&self) -> ChainSequence {
        self.core.fields().proposed_sequence
    }

    /// Der direkte Vorgaenger, den diese Finalisierung binden wird.
    #[must_use]
    pub const fn previous_entry_hash(&self) -> Option<EntryHash> {
        self.core.fields().previous_entry_hash
    }

    /// Die wirksame Zeit, gegen die diese Vorschau entstanden ist.
    #[must_use]
    pub const fn effective_now(&self) -> UnixMillis {
        self.core.fields().effective_now
    }

    /// Der `recordId` des Nutzlastkopfes — EINMAL gezogen, hier gehalten.
    pub(crate) const fn record_id(&self) -> [u8; 16] {
        self.record_id
    }
}
