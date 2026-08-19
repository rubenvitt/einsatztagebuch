//! Der Vertrag der Entwurfsablage — VOLLSTAENDIG, einschliesslich der Arme,
//! die erst Task 7 und Task 11 rufen.
//!
//! Der Vertrag ist mit diesem Task gegated. Ihn spaeter zu erweitern hiesse,
//! eine geschlossene Schnittstelle wieder zu oeffnen; deshalb stehen die
//! Uebergangsarme — LESEN UND SCHREIBEN — von Anfang an darin, obwohl ihre
//! Rumpfe die Tabelle `draft_transition` beruehren, die erst
//! `0002_discard.sql` anlegt.

use ea_key_provider::KeyHandle;

use crate::{
    DraftLock,
    model::{
        DiscardIntent, DiscardOutcome, Draft, DraftError, PreparedFinalizationMarker, SavedDraft,
    },
};

/// Die Ablage des EINEN aktiven Entwurfs.
///
/// Jede Methode ist synchron, wie der ganze Rust-Kern. Async lebt
/// ausschliesslich in `apps/desktop/src-tauri`, wo jeder
/// `#[tauri::command]`-Handler die synchrone Kernoperation ueber
/// `tauri::async_runtime::spawn_blocking` ausfuehrt.
pub trait DraftRepository: Send + Sync {
    /// Gibt den aktiven Entwurf zurueck oder legt den einen an, den es geben
    /// darf.
    ///
    /// # Errors
    ///
    /// [`DraftError`], wenn die Ablage, der Schluesselport oder die
    /// Entschluesselung ablehnt.
    fn load_or_create(&self) -> Result<Draft, DraftError>;

    /// Speichert als Vergleich-und-Setze ueber die Fassung.
    ///
    /// # Errors
    ///
    /// [`DraftError::RevisionConflict`], wenn die gelesene Fassung nicht mehr
    /// die gespeicherte ist — dann wird NICHTS geschrieben.
    fn save(&self, draft: Draft) -> Result<SavedDraft, DraftError>;

    /// Der Griff auf den eingepackten `draftDEK` dieses Entwurfs.
    ///
    /// # Errors
    ///
    /// [`DraftError::NoDraft`], wenn die Zeile fort ist oder einen anderen
    /// Entwurf traegt.
    fn draft_dek_handle(&self, draft: &SavedDraft) -> Result<KeyHandle, DraftError>;

    /// Bucht die Verwerfensabsicht dauerhaft.
    ///
    /// # Errors
    ///
    /// [`DraftError::TransitionUnavailable`], solange `0002_discard.sql` nicht
    /// registriert ist.
    fn commit_discard_intent(&self, draft: &SavedDraft) -> Result<DiscardIntent, DraftError>;

    /// Die gebuchte, noch nicht ausgefuehrte Verwerfensabsicht.
    ///
    /// # Errors
    ///
    /// [`DraftError`], wenn die Ablage ablehnt.
    fn pending_discard(&self) -> Result<Option<DiscardIntent>, DraftError>;

    /// Ersetzt den Entwurf durch einen leeren mit frischem `draftDEK`.
    ///
    /// # Errors
    ///
    /// [`DraftError`], wenn die Ablage oder der Schluesselport ablehnt.
    fn replace_with_blank(&self) -> Result<SavedDraft, DraftError>;

    /// Entfernt Chiffrat und Absicht und legt in derselben Transaktion einen
    /// leeren Entwurf an.
    ///
    /// # Errors
    ///
    /// [`DraftError::TransitionUnavailable`], solange `0002_discard.sql` nicht
    /// registriert ist.
    fn remove_ciphertext_and_intent_create_blank(
        &self,
        intent: &DiscardIntent,
    ) -> Result<DiscardOutcome, DraftError>;

    /// Die vorbereitete Abschlussmarke, falls eine liegt.
    ///
    /// # Errors
    ///
    /// [`DraftError`], wenn die Ablage ablehnt.
    fn prepared_finalization_marker(
        &self,
    ) -> Result<Option<PreparedFinalizationMarker>, DraftError>;

    /// Setzt oder loescht die Abschlussmarke — EIN Aufruf.
    ///
    /// Es gibt bewusst keine zweite Schreibstelle: die gegenseitige
    /// Ausschliessung von Verwerfensabsicht und Abschlussmarke kann so nicht
    /// auf zwei Schreibvorgaenge zerfallen.
    ///
    /// # Errors
    ///
    /// [`DraftError::TransitionUnavailable`], solange `0002_discard.sql` nicht
    /// registriert ist.
    fn replace_prepared_finalization_marker(
        &self,
        marker: Option<PreparedFinalizationMarker>,
    ) -> Result<(), DraftError>;

    /// Nimmt die AUSSCHLIESSLICHE Entwurfssperre.
    ///
    /// Sie ist eine ANDERE Sperre als die archivseitige `acquire_writer_lock`
    /// aus Task 9. Beide sind getrennt benannt, damit Verwerfens- und
    /// Abschlussfortsetzung nie versehentlich denselben Waechter teilen.
    ///
    /// # Errors
    ///
    /// [`DraftError::LockHeld`], wenn sie bereits jemand haelt.
    fn acquire_draft_lock(&self) -> Result<DraftLock, DraftError>;
}
