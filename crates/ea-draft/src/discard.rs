//! Der Verwerfensdienst — die EINE Stelle, an der ein Entwurf unwiderruflich
//! verschwindet.
//!
//! Er ist ein DIENST und keine Methode von [`DraftRepository`]: er haelt die
//! Ablage UND den Schluesselport und ordnet beide. Eine Ablage, die den
//! Schluesselspeicher loescht, waere eine Ablage mit einer zweiten Aufgabe, und
//! die Reihenfolge der zwei dauerhaften Schritte — Absicht buchen, DANN
//! loeschen — laege dann in ihr verborgen.
//!
//! Verwerfen ist KEINE Auditaktion. `local-audit-action-v1 = 0..11` ist
//! geschlossen (`schemas/reports/v1/local-audit.cddl`:3) und traegt keinen
//! Verwerfenseintrag, also entsteht hier keine dreizehnte Aktion und keine
//! Auditzeile.

use std::sync::Arc;

use ea_crypto::CryptoError;
use ea_key_provider::{KeyError, KeyHandle, KeyProvider};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_trust::PreexistingEffectiveNow;

use crate::{
    fault::{DiscardFaultPoint, RestartState},
    model::{DiscardIntent, DiscardOutcome, DraftError, SavedDraft},
    repository::DraftRepository,
};

/// Die Phase, die ein Verwerfen erreicht hat.
///
/// Vier Phasen, und jede hat GENAU EINEN Neustartausgang. Sie sind groeber als
/// [`DiscardFaultPoint`]: eine Phase ist ein Zustand der Datenbank und des
/// Schluesselspeichers, ein Unterbrechungspunkt eine Stelle im Programm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiscardPhase {
    /// Nichts Dauerhaftes ist geschehen; der Entwurf ist bearbeitbar.
    Editable,
    /// Die Verwerfensabsicht ist gebucht.
    IntentDurable,
    /// Der `draftDEK` ist fort, und seine Abwesenheit ist bestaetigt.
    KeyAbsent,
    /// Chiffrat und Absicht sind fort, und der leere Entwurf steht.
    DraftRemoved,
}

impl DiscardPhase {
    /// Alle Phasen, in Ausfuehrungsreihenfolge.
    pub const ALL: [Self; 4] = [
        Self::Editable,
        Self::IntentDurable,
        Self::KeyAbsent,
        Self::DraftRemoved,
    ];
}

/// Der Zustandsautomat des Verwerfens.
///
/// Er BORGT die Zeit des gewaehlten Registry-Head und haelt keine
/// Momentaufnahme davon: eine gehaltene Zeit veraltete, und
/// `OperatorSessionProof::is_valid_for` nimmt ausdruecklich nur die Zeit eines
/// Head und niemals einen freien Wert.
pub struct DiscardService<'now> {
    repository: Arc<dyn DraftRepository>,
    key_provider: Arc<dyn KeyProvider>,
    now: &'now PreexistingEffectiveNow,
}

impl<'now> DiscardService<'now> {
    #[must_use]
    pub fn new(
        repository: Arc<dyn DraftRepository>,
        key_provider: Arc<dyn KeyProvider>,
        now: &'now PreexistingEffectiveNow,
    ) -> Self {
        Self {
            repository,
            key_provider,
            now,
        }
    }

    /// Beginnt ein Verwerfen und fuehrt es zu Ende.
    ///
    /// Unter der AUSSCHLIESSLICHEN Entwurfssperre wird die Verwerfensabsicht
    /// mit der Entwurfskennung ZUERST dauerhaft gebucht. Vor diesem Buchen
    /// aendert ein Absturz nichts; danach bietet ein Neustart den Entwurf nicht
    /// mehr zur Bearbeitung an, sondern setzt dieselbe Operation fort
    /// (`design.md`:432).
    ///
    /// Der Nachweis wird VERBRAUCHT. Ein Verwerfen ist unwiderruflich, und ein
    /// zweites Verwerfen ist eine zweite Wiederanmeldung — deshalb nimmt diese
    /// Methode den Nachweis als Wert und nicht als Ausleihe.
    ///
    /// Was diese Crate NICHT kann: Oberflaechen- und Rust-Puffer leeren. Der
    /// Entwurfstext lebt in [`crate::Draft`], und der gehoert dem Aufrufer;
    /// der Dienst haelt keine Kopie davon, die er leeren koennte.
    ///
    /// # Errors
    ///
    /// [`DraftError::ReauthRequired`] bei einem veralteten oder entwerteten
    /// Nachweis, [`DraftError::ReauthPurposeMismatch`] bei einem Nachweis eines
    /// anderen Zwecks, [`DraftError::PreparedFinalizationPresent`], solange
    /// eine Abschlussmarke liegt, [`DraftError::LockHeld`], wenn die Sperre
    /// jemand haelt, sonst der Fehler der Ablage oder des Schluesselports.
    pub fn begin_discard(&self, proof: OperatorSessionProof) -> Result<DiscardOutcome, DraftError> {
        let _lock = self.repository.acquire_draft_lock()?;
        self.enter(&proof)?;
        let intent = self.commit_intent()?;
        self.complete(&intent)
    }

    /// Setzt ein unterbrochenes Verwerfen fort.
    ///
    /// # Errors
    ///
    /// Wie [`Self::begin_discard`], zusaetzlich
    /// [`DraftError::NoPendingDiscard`], wenn keine Absicht gebucht ist.
    pub fn resume_discard(
        &self,
        proof: &OperatorSessionProof,
    ) -> Result<DiscardOutcome, DraftError> {
        let _lock = self.repository.acquire_draft_lock()?;
        self.enter(proof)?;
        let intent = self
            .repository
            .pending_discard()?
            .ok_or(DraftError::NoPendingDiscard)?;
        self.complete(&intent)
    }

    /// Der NEUSTARTPFAD: sagt, was der Bediener vorfindet, und raeumt dabei
    /// jeden Zwischenzustand auf.
    ///
    /// Er ist die Stelle, an der die Vorrangregel wirkt: liegt eine
    /// Abschlussmarke, wird KEIN Verwerfen fortgesetzt, weil nach dem
    /// unwiderruflichen Schritt die Transaktion aus den vorbereiteten Bytes
    /// vollendet werden MUSS (`design.md`:456, :467).
    ///
    /// Findet er weder Marke noch Absicht, aber einen Entwurf, dessen
    /// `draftDEK` fort ist — der Fall der zurueckgespielten Sicherung —, dann
    /// ersetzt er ihn durch einen leeren. Ein Entwurf, der nie mehr zu oeffnen
    /// ist, ist kein Entwurf, und ihn liegen zu lassen hiesse, dem Bediener
    /// eine Zeile anzubieten, die sich nicht laden laesst.
    ///
    /// # Errors
    ///
    /// Wie [`Self::begin_discard`].
    pub fn resume_after_restart(
        &self,
        proof: &OperatorSessionProof,
    ) -> Result<RestartState, DraftError> {
        let _lock = self.repository.acquire_draft_lock()?;
        require_fresh_proof(proof, self.now)?;
        if self.repository.prepared_finalization_marker()?.is_some() {
            return Ok(RestartState::PreparedFinalizationPending);
        }
        if let Some(intent) = self.repository.pending_discard()? {
            self.complete(&intent)?;
            return Ok(RestartState::NewBlankDraft);
        }
        match self.repository.load_or_create() {
            Ok(draft) if draft.revision() == 0 && draft.notes().is_empty() => {
                Ok(RestartState::NewBlankDraft)
            }
            Ok(_) => Ok(RestartState::OriginalDraftUnchanged),
            // GENAU zwei Fehler, und beide sind DAUERHAFT.
            //
            // `KeyError::NotFound` — der Eintrag des `draftDEK` ist fort, die
            // zurueckgespielte Datenbankdatei findet keinen Schluessel.
            // `CryptoError::AeadOpen` — der Eintrag liegt, traegt aber das
            // Material eines ANDEREN Entwurfs, weil ein abgeschlossenes
            // Verwerfen einen frischen `draftDEK` an dieselbe Adresse
            // geschrieben hat.
            //
            // Die Aufzaehlung ist ABSICHTLICH eng und nicht `Key(_) |
            // Crypto(_)`. Jeder andere Schluesselfehler ist eine Aussage
            // ueber JETZT und nicht ueber den Entwurf:
            // `UnreachableProtectionProfile`, `ProtectionProfileMismatch` oder
            // `PurposeMismatch` eines nativen Speichers heissen „ich konnte den
            // Schluessel gerade nicht erreichen" — Geraet gesperrt, TPM belegt,
            // Praesenz nicht verfuegbar. Sie in ein `replace_with_blank` zu
            // uebersetzen hiesse, einen voruebergehenden Fehler in eine
            // UNWIDERRUFLICHE Vernichtung zu verwandeln, und das ist die
            // Umkehrung von fail-closed. Sie fallen deshalb durch den Zweig
            // darunter und brechen ab.
            Err(DraftError::Key(KeyError::NotFound))
            | Err(DraftError::Crypto(CryptoError::AeadOpen)) => {
                self.repository.replace_with_blank()?;
                Ok(RestartState::NewBlankDraft)
            }
            Err(other) => Err(other),
        }
    }

    /// Beginnt ein Verwerfen, das an GENAU `point` abbricht.
    ///
    /// Diese Methode existiert AUSSCHLIESSLICH, damit die
    /// Wiederherstellungspruefung jeden Punkt von [`DiscardFaultPoint::ALL`]
    /// wirklich erreichen kann. Sie eroeffnet keinen Zustand, den ein Absturz
    /// nicht ohnehin hinterlaesst — jeder Abbruchpunkt ist ein Zustand, den
    /// [`Self::resume_after_restart`] aufloest —, und deshalb ist sie kein
    /// zweiter, ungeschuetzter Weg in die Ablage.
    ///
    /// [`DiscardFaultPoint::BackupRestoreAfterKeyDeletion`] haelt an derselben
    /// Stelle wie [`DiscardFaultPoint::AfterAbsenceConfirmation`]: die
    /// Rueckspielung selbst ist ein Ereignis am Dateisystem und nicht in diesem
    /// Programm.
    ///
    /// # Errors
    ///
    /// Wie [`Self::begin_discard`].
    pub fn begin_discard_interrupted_at(
        &self,
        proof: OperatorSessionProof,
        point: DiscardFaultPoint,
    ) -> Result<(), DraftError> {
        let _lock = self.repository.acquire_draft_lock()?;
        self.enter(&proof)?;
        if point == DiscardFaultPoint::BeforeIntentCommit {
            return Ok(());
        }
        let intent = self.commit_intent()?;
        if point == DiscardFaultPoint::AfterIntentCommit {
            return Ok(());
        }
        let handle = self.draft_dek_handle(&intent)?;
        self.key_provider.delete(&handle)?;
        if point == DiscardFaultPoint::AfterKeystoreDelete {
            return Ok(());
        }
        self.confirm_absence(&handle)?;
        if matches!(
            point,
            DiscardFaultPoint::AfterAbsenceConfirmation
                | DiscardFaultPoint::BackupRestoreAfterKeyDeletion
        ) {
            return Ok(());
        }
        self.repository
            .remove_ciphertext_and_intent_create_blank(&intent)?;
        Ok(())
    }

    /// Die zwei Bedingungen, die JEDER Eingang stellt: frischer,
    /// zweckgleicher Nachweis, und keine liegende Abschlussmarke.
    fn enter(&self, proof: &OperatorSessionProof) -> Result<(), DraftError> {
        require_fresh_proof(proof, self.now)?;
        if self.repository.prepared_finalization_marker()?.is_some() {
            return Err(DraftError::PreparedFinalizationPresent);
        }
        Ok(())
    }

    fn commit_intent(&self) -> Result<DiscardIntent, DraftError> {
        let draft = self.repository.load_or_create()?;
        self.repository
            .commit_discard_intent(&SavedDraft::new(draft.draft_id(), draft.revision()))
    }

    /// Loescht den `draftDEK`, bestaetigt seine Abwesenheit und entfernt danach
    /// Chiffrat und Absicht in EINER Transaktion.
    ///
    /// Die Reihenfolge ist die Zusage: der Schluessel geht ZUERST, denn danach
    /// sind die alten Datenbankseiten unlesbar, auch wenn das Entfernen
    /// scheitert. Ginge das Chiffrat zuerst, laege zwischen den zwei Schritten
    /// ein Fenster, in dem der Schluessel zu Seiten passt, die noch auf der
    /// Platte stehen.
    fn complete(&self, intent: &DiscardIntent) -> Result<DiscardOutcome, DraftError> {
        let handle = self.draft_dek_handle(intent)?;
        self.key_provider.delete(&handle)?;
        self.confirm_absence(&handle)?;
        self.repository
            .remove_ciphertext_and_intent_create_blank(intent)
    }

    fn draft_dek_handle(&self, intent: &DiscardIntent) -> Result<KeyHandle, DraftError> {
        self.repository
            .draft_dek_handle(&SavedDraft::new(intent.draft_id(), intent.revision()))
    }

    /// Fragt den Schluesselspeicher ZURUECK, ob der Eintrag wirklich fort ist.
    ///
    /// Ein `Ok` von `delete` ist die Aussage des Providers ueber sich selbst.
    /// Die Zusage „kein entschluesselbarer `draftDEK` bleibt zurueck" haengt an
    /// der Abwesenheit und nicht an einer gemeldeten Absicht, also wird sie
    /// nachgesehen.
    fn confirm_absence(&self, handle: &KeyHandle) -> Result<(), DraftError> {
        if self.key_provider.contains(handle)? {
            return Err(DraftError::KeyDeletionNotConfirmed);
        }
        Ok(())
    }
}

/// Verlangt einen FRISCHEN Nachweis fuer [`ReauthPurpose::DiscardDraft`].
///
/// Die Entscheidung faellt in der ERSTEN Zeile, und sie ist fail-closed: nur
/// ein Nachweis, der GENAU diesen Zweck zur Zeit des gewaehlten Head
/// autorisiert, laesst ein Verwerfen zu. Verwerfen ist auf einem unbeaufsichtigt
/// stehenden Geraet genauso unwiderruflich wie ein Abschluss
/// (`design.md`:256, :432).
///
/// Der Rest waehlt NUR den Fehlercode. `OperatorSessionProof` gibt seinen Zweck
/// bewusst nicht heraus — er beantwortet ausschliesslich die Frage „autorisierst
/// du Zweck P jetzt?" —, also wird nach der gefallenen Ablehnung gefragt, ob der
/// Nachweis IRGENDEINEN anderen Zweck autorisiert. Tut er das, ist er frisch und
/// nur zweckfremd; tut er es nicht, ist er veraltet oder entwertet. Die
/// Unterscheidung ist diagnostisch, die Ablehnung war schon gefallen.
fn require_fresh_proof(
    proof: &OperatorSessionProof,
    now: &PreexistingEffectiveNow,
) -> Result<(), DraftError> {
    if proof.is_valid_for(ReauthPurpose::DiscardDraft, now) {
        return Ok(());
    }
    let authorizes_another_purpose = ReauthPurpose::ALL
        .iter()
        .copied()
        .filter(|purpose| *purpose != ReauthPurpose::DiscardDraft)
        .any(|purpose| proof.is_valid_for(purpose, now));
    if authorizes_another_purpose {
        Err(DraftError::ReauthPurposeMismatch)
    } else {
        Err(DraftError::ReauthRequired)
    }
}
