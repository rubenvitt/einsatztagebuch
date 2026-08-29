//! Die dreizehnstufige Finalisierung, woertlich nach `design.md` §9.3.
//!
//! # Die Reihenfolge ist ERZWUNGEN und nicht gewaehlt
//!
//! `entryHash` wird nicht „ermittelt", sondern entsteht als Nebenprodukt von
//! [`EntryPackageV1::new`], das aus `signedManifest`, Ciphertext und
//! Writer-Signatur zuerst den `recordDigest` und daraus den `entryHash` bildet.
//! Vorher existiert der Wert nicht. Der `.eag`-Rumpf verlangt ihn als
//! Pflichtfeld ohne Default, also ist kein `.eag` ohne vorher konstruiertes
//! [`EntryPackageV1`] baubar — Schritt 7 ist damit die EINZIGE konstruierbare
//! Reihenfolge und nicht eine von zweien.
//!
//! Umgekehrt bindet `ManifestCoreFieldsV1` die Grants ausschliesslich ueber
//! `initial_grant_plan_hash` und NIE ueber eine Liste erzeugter
//! Grant-`objectHash`-Werte; die finalen `.eip`-Bytes haengen deshalb an keinem
//! einzigen `.eag`, und die Ordnung zwischen `.eip`-Bytes und `.eag` ist
//! innerhalb von Schritt 7 frei.
//!
//! # Der Staging-Bereich
//!
//! Er ist der Suffix [`ea_archive::STAGING_SUFFIX_V1`] im ZIELVERZEICHNIS und kein
//! Sammelverzeichnis. Zwei Gruende, beide aus dem Bestand: [`ArchivePath`]
//! kann keine Adresse ausserhalb von `LAYOUT_PATHS_V1` bilden, und der Suffix
//! im Zielverzeichnis macht [`ArchiveBackend::atomic_rename_same_fs`] schon
//! durch die Bauweise zu einem Rename innerhalb desselben Dateisystems. Eine
//! liegengebliebene Datei mit diesem Suffix ist ein Gesundheitsbefund
//! (temporaere Datei) und kein Archivobjekt.
//!
//! [`ArchiveTransaction`](ea_archive::ArchiveTransaction) wird ABSICHTLICH
//! nicht benutzt: sein `commit()` faltet Staging, Dateiflush, Verzeichnisflush,
//! Rename und Zielflush in EINEN Aufruf, und damit waeren die Schritte 8, 10
//! und 11 ein Schritt und der Unterbrechungspunkt
//! [`FinalizationFaultPoint::AfterGrantPublishBeforeEntryRename`] unerreichbar.
//! Diese Datei fuehrt die Portprimitiven selbst; `ea-archive` bleibt
//! unberuehrt.

use std::sync::Arc;

use ea_archive::{ArchiveBackend, ArchiveBlob, ArchiveError, ArchivePath, ArchiveSource};
use ea_chain::{
    ChainNode, ChainNodeKind, CheckpointClaim, RollbackAssessment, assess_rollback, build_chain,
};
use ea_crypto::{
    AEAD_NONCE_SIZE, CEK_SIZE, ContentType, HPKE_ENCAPSULATED_KEY_SIZE, HPKE_WRAPPED_CEK_SIZE,
    HpkeRecipientPublicKey, SecretBytes, SecretVec, aead_seal, hpke_aad, hpke_info, hpke_seal,
    object_hash, payload_aad,
};
use ea_draft::{
    DraftRepository, IncidentNumberRegister, OperatorProfileRepository, PreparedFinalizationMarker,
};
use ea_format::{
    EntryPackageV1, FinalizationPreviewCoreFieldsV1, GrantBodyFieldsV1, GrantBodyV1, GrantKindV1,
    GrantPlanItemV1, GrantPlanV1, GrantV1, ManifestCoreFieldsV1, ManifestCoreV1, SignedManifestV1,
    encode_entry_package, encode_grant,
};
use ea_key_provider::{KeyHandle, KeyProvider};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_schema::{CommonHeaderV1, IncidentV1, OperatorSnapshotV1, PayloadV1, encode_payload};
use ea_trust::SelectedRegistryHead;
use ea_types::{
    CertificateHash, ChainId, ChainSequence, EntryHash, Hash32, ObjectHash, UnixMillis,
};
use zeroize::Zeroize;

use crate::{
    FinalizationFaultPoint, FinalizationPhase, FinalizationPreview, FinalizationStep,
    StaleDecision, WriterError,
    entropy::{self, EntropyKind},
    grant_plan::build_grant_plan,
    incident::FinalizationInputV1,
    marker::PreparedTransactionV1,
    operator_commitment::operator_profile_commitment,
};

/// Das Ergebnis eines abgeschlossenen Eintrags — OHNE jede Nutzlast.
///
/// Was ein Aufrufer hier NICHT bekommt, ist die Zusage: nach der Finalisierung
/// hat der Writer keinen Zugriff mehr auf den Inhalt, also gibt auch das
/// Ergebnis keinen heraus.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FinalizeOutcome {
    pub sequence: ChainSequence,
    pub entry_hash: EntryHash,
    pub object_hash: ObjectHash,
    pub sync_status: ea_archive_fs::SyncStatus,
}

impl core::fmt::Debug for FinalizeOutcome {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "FinalizeOutcome {{ sequence: {}, sync_status: {:?} }}",
            self.sequence.get(),
            self.sync_status
        )
    }
}

/// Die vorbereitete, noch nicht veroeffentlichte Transaktion.
///
/// Die Konstruktoren sind privat und `exact_bytes` liest nur: aus dieser Marke
/// entsteht nach der unwiderruflichen Grenze GENAU derselbe Bestand, und ein
/// Aufrufer, der die Bytes ersetzen koennte, koennte den Eintrag ersetzen.
pub struct PreparedFinalization {
    transaction: PreparedTransactionV1,
    exact: Vec<u8>,
}

impl PreparedFinalization {
    /// Die exakten Bytes der Abschlussmarke, wie sie in der verschluesselten
    /// Ablage liegen.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    /// Die Sequenz, die diese Transaktion beansprucht.
    #[must_use]
    pub const fn sequence(&self) -> ChainSequence {
        self.transaction.sequence
    }

    /// Der `entryHash` dieser Transaktion.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.transaction.entry_hash
    }

    pub(crate) const fn transaction(&self) -> &PreparedTransactionV1 {
        &self.transaction
    }
}

impl core::fmt::Debug for PreparedFinalization {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "PreparedFinalization {{ sequence: {} }}",
            self.transaction.sequence.get()
        )
    }
}

/// Der Zustandsautomat der Finalisierung.
///
/// Alle oeffentlichen Methoden nehmen `&self` und erreichen ihren Zustand ueber
/// die ZWEI Sperren — genau wie [`ea_draft::DiscardService`]. Der Fortschritt
/// ist KEIN veraenderliches Feld des Dienstes: der einzige dauerhafte
/// Fortschrittsmarker ist die Abschlussmarke in der verschluesselten Ablage.
///
/// Die zwei Sperren sind VERSCHIEDEN und beide benannt: die archivseitige
/// [`ArchiveBackend::acquire_writer_lock`] und die
/// [`DraftRepository::acquire_draft_lock`].
pub struct WriterService<'a> {
    pub(crate) repository: Arc<dyn DraftRepository>,
    pub(crate) key_provider: Arc<dyn KeyProvider>,
    pub(crate) backend: &'a dyn ArchiveBackend,
    pub(crate) source: &'a dyn ArchiveSource,
    head: &'a SelectedRegistryHead,
    checkpoint_claims: &'a [CheckpointClaim],
    incident_numbers: IncidentNumberRegister,
    operator_profiles: OperatorProfileRepository,
    binding: WriterBindingV1,
}

/// Alles, was diese Finalisierung an das gebundene Geraet knuepft.
///
/// Als eigener Wert und nicht als sechs Konstruktorargumente: die sechs gehoeren
/// zusammen, und ein Aufrufer, der fuenf von ihnen aus einem Head und das
/// sechste aus einem anderen nimmt, hat einen Fehler gemacht, den kein Typ
/// bemerken wuerde.
#[derive(Clone, Copy)]
pub struct WriterBindingV1 {
    /// Der Bindungsobjekthash des `BoundOperator`, gegen den diese Sitzung
    /// handelt. PFLICHT und keine Option:
    /// `OperatorSessionProof::is_valid_for` prueft die Bindung ausdruecklich
    /// nicht, also muss der Verbraucher vergleichen.
    pub binding_object_hash: ObjectHash,
    pub writer_certificate_hash: CertificateHash,
    /// Der Abdruck des Writer-Signaturschluessels — `issuerKeyThumbprint`
    /// jedes erzeugten Grants.
    pub writer_key_thumbprint: ea_types::KeyThumbprint,
    pub writer_signing_handle: KeyHandle,
    pub chain_id: ChainId,
    /// Der `archiveProfileHash` des konfigurierten Backends. Er wird gegen
    /// `allowed_archive_profile_hashes` DESSELBEN gebundenen Head geprueft.
    pub archive_profile_hash: Hash32,
}

impl<'a> WriterService<'a> {
    /// Baut den Dienst FUER GENAU EINE Bedienerbindung und EINEN Bestand.
    ///
    /// Neun Argumente, und keines davon ist zusammenlegbar: die drei Ports
    /// (Ablage, Schluesselspeicher, Bestand), die zwei Lesequellen (Bestand,
    /// Head), die zwei Register (Einsatznummern, Profilzeile), die
    /// Checkpointaussagen und die Geraetebindung. Ein Sammeltyp darueber waere
    /// ein Name ohne eigene Zusage.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: Arc<dyn DraftRepository>,
        key_provider: Arc<dyn KeyProvider>,
        backend: &'a dyn ArchiveBackend,
        source: &'a dyn ArchiveSource,
        head: &'a SelectedRegistryHead,
        checkpoint_claims: &'a [CheckpointClaim],
        incident_numbers: IncidentNumberRegister,
        operator_profiles: OperatorProfileRepository,
        binding: WriterBindingV1,
    ) -> Self {
        Self {
            repository,
            key_provider,
            backend,
            source,
            head,
            checkpoint_claims,
            incident_numbers,
            operator_profiles,
            binding,
        }
    }

    /// Die Vorschau: Schritte 1 bis 5 unter beiden Sperren.
    ///
    /// Sie zieht KEIN Geheimnis. Der `recordId` entsteht hier, weil Schritt 4
    /// ohne ihn nicht serialisierbar ist (siehe [`crate::preview`]); CEK und
    /// AEAD-Nonce entstehen erst in Schritt 6.
    ///
    /// `observed_now` ist die Uhr des WIRTS. Sie ist ein Argument JE AUFRUF und
    /// kein Feld des Dienstes, weil `finalize` „Registry und Zeit vor der
    /// `draftDEK`-Grenze neu bewertet" — eine erneute Bewertung gegen denselben
    /// gespeicherten Messwert waere keine.
    ///
    /// # Errors
    ///
    /// Jeder Blockadegrund der Schritte 1 bis 5, mit seinem stabilen Code.
    pub fn preview(
        &self,
        proof: &OperatorSessionProof,
        input: FinalizationInputV1,
        observed_now: UnixMillis,
    ) -> Result<FinalizationPreview, WriterError> {
        let _writer_lock = self.backend.acquire_writer_lock()?;
        let _draft_lock = self.repository.acquire_draft_lock()?;
        let reached = self.run(
            proof,
            input,
            observed_now,
            Stop::After(FinalizationStep::BuildAndHashGrantPlan),
        )?;
        reached.preview.ok_or(WriterError::NoDraftContent)
    }

    /// Der Abschluss: die Vorschau nachrechnen und dann Schritte 6 bis 13.
    ///
    /// # Errors
    ///
    /// [`WriterError::StaleAckPreviewMismatch`], wenn die unter der Sperre neu
    /// gerechnete Vorschau eine andere ist; [`WriterError::StaleAckRequired`],
    /// wenn der Head veraltet ist und keine Bestaetigung vorliegt; sonst jeder
    /// Blockadegrund der dreizehn Schritte.
    pub fn finalize(
        &self,
        proof: &OperatorSessionProof,
        input: FinalizationInputV1,
        confirmed: &FinalizationPreview,
        observed_now: UnixMillis,
    ) -> Result<FinalizeOutcome, WriterError> {
        let _writer_lock = self.backend.acquire_writer_lock()?;
        let _draft_lock = self.repository.acquire_draft_lock()?;
        let reached = self.run(proof, input, observed_now, Stop::Confirmed(confirmed))?;
        reached.outcome.ok_or(WriterError::NoDraftContent)
    }

    /// Laeuft die Reihenfolge und haelt NACH `step` an.
    ///
    /// AUSSCHLIESSLICH fuer den Nachweis, dass jeder der dreizehn Schritte eine
    /// eigene beobachtbare Nachbedingung hat. Sie eroeffnet keinen Zustand, den
    /// ein Absturz nicht ohnehin hinterlaesst.
    ///
    /// # Errors
    ///
    /// Wie [`Self::finalize`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn finalize_up_to(
        &self,
        proof: &OperatorSessionProof,
        input: FinalizationInputV1,
        observed_now: UnixMillis,
        step: FinalizationStep,
    ) -> Result<ReachedState, WriterError> {
        let _writer_lock = self.backend.acquire_writer_lock()?;
        let _draft_lock = self.repository.acquire_draft_lock()?;
        self.run(proof, input, observed_now, Stop::After(step))
    }

    /// Laeuft die Reihenfolge und bricht an GENAU `point` ab.
    ///
    /// # Errors
    ///
    /// Wie [`Self::finalize`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn finalize_interrupted_at(
        &self,
        proof: &OperatorSessionProof,
        input: FinalizationInputV1,
        observed_now: UnixMillis,
        point: FinalizationFaultPoint,
    ) -> Result<ReachedState, WriterError> {
        let _writer_lock = self.backend.acquire_writer_lock()?;
        let _draft_lock = self.repository.acquire_draft_lock()?;
        self.run(proof, input, observed_now, Stop::AtFault(point))
    }
}

/// Eine dauerhaft beanspruchte Einsatznummer samt allem, was ihre Freigabe
/// braucht.
///
/// Der Schluessel des Registers und nichts sonst (`design.md`:361-373). Er
/// reist ausschliesslich im Prozessspeicher zwischen Anspruch und Freigabe;
/// eine Protokollzeile bekommt er nie, und deshalb traegt der Typ auch kein
/// `Debug`.
struct ClaimedIncidentNumber {
    organization_id: ea_types::OrganizationId,
    local_civil_year: i32,
    human_incident_number: String,
}

/// Wo der Lauf anhaelt.
#[derive(Clone, Copy)]
pub(crate) enum Stop<'p> {
    /// Nach diesem Schritt.
    After(FinalizationStep),
    /// An diesem Unterbrechungspunkt.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    AtFault(FinalizationFaultPoint),
    /// Vollstaendig, gegen diese bestaetigte Vorschau.
    Confirmed(&'p FinalizationPreview),
}

impl Stop<'_> {
    /// Ob der Lauf nach `step` endet.
    fn ends_after(self, step: FinalizationStep) -> bool {
        matches!(self, Self::After(stop) if stop == step)
    }

    /// Ob der Lauf an `point` abbricht.
    fn breaks_at(self, point: FinalizationFaultPoint) -> bool {
        matches!(self, Self::AtFault(stop) if stop == point)
    }
}

/// Der Zustand, den ein Lauf erreicht hat.
///
/// EIN fortschreitender Wert mit `Option`-Feldern und nicht dreizehn Typen:
/// jeder Schritt fuegt genau sein benanntes Zwischenergebnis hinzu, und ein
/// Test kann fuer jeden Schritt genau das lesen, was er erzeugt hat. Wer ein
/// Feld liest, das der erreichte Schritt nicht gesetzt hat, bekommt `None` —
/// und nicht einen plausiblen Vorgabewert, der jede Zusicherung gruen faerbt.
pub struct ReachedState {
    pub(crate) phase: FinalizationPhase,
    pub(crate) reached_step: Option<FinalizationStep>,
    pub(crate) head_from_committed_bytes: bool,
    pub(crate) rollback: Option<RollbackAssessment>,
    pub(crate) selected_registry_version: Option<ea_types::RegistryVersion>,
    pub(crate) active_recovery_recipient_count: usize,
    pub(crate) draft_record_bytes: Vec<u8>,
    pub(crate) grant_plan: Option<GrantPlanV1>,
    pub(crate) preview: Option<FinalizationPreview>,
    pub(crate) manifest_core: Option<ManifestCoreV1>,
    pub(crate) signed_manifest_bytes: Vec<u8>,
    pub(crate) writer_signature: Vec<u8>,
    pub(crate) entry_package: Option<EntryPackageV1>,
    pub(crate) grants: Vec<(Hash32, Vec<u8>)>,
    pub(crate) entry_bytes: Vec<u8>,
    pub(crate) prepared: Option<PreparedFinalization>,
    pub(crate) outcome: Option<FinalizeOutcome>,
}

impl ReachedState {
    /// Ein Zustand, der ausschliesslich die Veroeffentlichung tragen soll.
    ///
    /// Die Wiederherstellung nach der Grenze fuehrt keine Schritte 1 bis 9 aus
    /// — sie DARF es nicht —, und deshalb bleibt jedes Zwischenergebnis leer.
    pub(crate) fn for_recovery() -> Self {
        Self {
            phase: FinalizationPhase::DraftKeyAbsent,
            ..Self::empty()
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            phase: FinalizationPhase::ReversibleDraft,
            reached_step: None,
            head_from_committed_bytes: false,
            rollback: None,
            selected_registry_version: None,
            active_recovery_recipient_count: 0,
            draft_record_bytes: Vec::new(),
            grant_plan: None,
            preview: None,
            manifest_core: None,
            signed_manifest_bytes: Vec::new(),
            writer_signature: Vec::new(),
            entry_package: None,
            grants: Vec::new(),
            entry_bytes: Vec::new(),
            prepared: None,
            outcome: None,
        }
    }

    /// Die erreichte dauerhafte Phase.
    #[must_use]
    pub const fn phase(&self) -> FinalizationPhase {
        self.phase
    }

    /// Der letzte AUSGEFUEHRTE Schritt.
    #[must_use]
    pub const fn reached_step(&self) -> Option<FinalizationStep> {
        self.reached_step
    }

    /// Ob der Kettenkopf aus committed Archivbytes entstanden ist — und nicht
    /// aus dem SQLite-Zustand.
    #[must_use]
    pub const fn head_source_is_committed_archive_bytes(&self) -> bool {
        self.head_from_committed_bytes
    }

    /// Der Rollbackbefund von Schritt 2. `None` heisst: Schritt 2 lief nicht.
    #[must_use]
    pub const fn rollback_assessment(&self) -> Option<&RollbackAssessment> {
        self.rollback.as_ref()
    }

    #[must_use]
    pub const fn selected_registry_version(&self) -> Option<ea_types::RegistryVersion> {
        self.selected_registry_version
    }

    #[must_use]
    pub const fn active_recovery_recipient_count(&self) -> usize {
        self.active_recovery_recipient_count
    }

    #[must_use]
    pub fn draft_record_bytes(&self) -> &[u8] {
        &self.draft_record_bytes
    }

    #[must_use]
    pub const fn grant_plan(&self) -> Option<&GrantPlanV1> {
        self.grant_plan.as_ref()
    }

    #[must_use]
    pub const fn preview(&self) -> Option<&FinalizationPreview> {
        self.preview.as_ref()
    }

    #[must_use]
    pub const fn manifest_core(&self) -> Option<&ManifestCoreV1> {
        self.manifest_core.as_ref()
    }

    #[must_use]
    pub fn signed_manifest_bytes(&self) -> &[u8] {
        &self.signed_manifest_bytes
    }

    #[must_use]
    pub fn writer_signature(&self) -> &[u8] {
        &self.writer_signature
    }

    #[must_use]
    pub const fn entry_package(&self) -> Option<&EntryPackageV1> {
        self.entry_package.as_ref()
    }

    /// Die erzeugten Grants als `(objectHash, exakte Bytes)`.
    #[must_use]
    pub fn grants(&self) -> &[(Hash32, Vec<u8>)] {
        &self.grants
    }

    #[must_use]
    pub fn entry_bytes(&self) -> &[u8] {
        &self.entry_bytes
    }

    #[must_use]
    pub const fn prepared(&self) -> Option<&PreparedFinalization> {
        self.prepared.as_ref()
    }

    #[must_use]
    pub const fn outcome(&self) -> Option<FinalizeOutcome> {
        self.outcome
    }

    /// Der Grant zu einem Empfaengerabdruck, falls einer erzeugt wurde.
    #[must_use]
    pub fn grant_for(&self, thumbprint: ea_types::KeyThumbprint) -> Option<&[u8]> {
        let plan = self.grant_plan.as_ref()?;
        let position = plan
            .items()
            .iter()
            .position(|item| item.recipient_key_thumbprint() == thumbprint)?;
        self.grants.get(position).map(|(_, bytes)| bytes.as_slice())
    }
}

impl core::fmt::Debug for ReachedState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReachedState")
            .field("phase", &self.phase)
            .field("reached_step", &self.reached_step)
            .finish_non_exhaustive()
    }
}

impl WriterService<'_> {
    /// Laeuft die Reihenfolge und GIBT die beanspruchte Einsatznummer wieder
    /// frei, wenn der Lauf vor der unwiderruflichen Grenze scheitert.
    ///
    /// # Warum die Freigabe HIER steht und nicht im Rumpf
    ///
    /// Zwischen dem Anspruch (Schritt 5) und der Grenze (Schritt 9) liegen ein
    /// gutes Dutzend `?`-Ausgaenge — Entropie, Signatur, Staging, Datenbank.
    /// Sie einzeln zu bedienen hiesse, die Freigabe an ein Dutzend Stellen zu
    /// wiederholen und beim naechsten hinzukommenden Ausgang zu vergessen.
    /// [`Self::run_claiming`] meldet den Anspruch stattdessen nach aussen und
    /// nimmt ihn zurueck, sobald die Grenze ueberschritten ist; dieser Rahmen
    /// gibt frei, was dann noch gemeldet ist.
    ///
    /// AUSSCHLIESSLICH am FEHLERausgang. Ein frueher `Ok`-Ausgang gibt nichts
    /// frei — er ist ein Halt der Fehlerinjektion, und die beansprucht gar
    /// nicht erst (siehe die Klausel `matches!(stop, Stop::Confirmed(_))` am
    /// Anspruch).
    fn run(
        &self,
        proof: &OperatorSessionProof,
        input: FinalizationInputV1,
        observed_now: UnixMillis,
        stop: Stop<'_>,
    ) -> Result<ReachedState, WriterError> {
        let mut claimed = None;
        let reached = self.run_claiming(proof, input, observed_now, stop, &mut claimed);
        let Err(error) = reached else {
            return reached;
        };
        if let Some(claim) = claimed {
            // Der GRUND des Abbruchs gewinnt, und der Fehlschlag einer
            // Freigabe wird nicht an seiner Stelle gemeldet: er liesse die
            // Nummer stehen — den Zustand VOR dieser Zusage — und ist damit
            // fail-closed, waehrend ein vertauschter Code dem Bediener den
            // Abbruchgrund verschwiege.
            let _ = self.incident_numbers.release(
                claim.organization_id,
                claim.local_civil_year,
                &claim.human_incident_number,
            );
        }
        Err(error)
    }

    /// Die dreizehn Schritte, in der einzigen konstruierbaren Reihenfolge.
    ///
    /// `claimed` ist der Kanal nach aussen: er traegt die dauerhaft
    /// beanspruchte Einsatznummer, solange sie sich noch zuruecknehmen laesst,
    /// und wird geleert, sobald die unwiderrufliche Grenze ueberschritten oder
    /// UNGEKLAERT ist.
    #[allow(clippy::too_many_lines)]
    fn run_claiming(
        &self,
        proof: &OperatorSessionProof,
        input: FinalizationInputV1,
        observed_now: UnixMillis,
        stop: Stop<'_>,
        claimed: &mut Option<ClaimedIncidentNumber>,
    ) -> Result<ReachedState, WriterError> {
        let mut state = ReachedState::empty();

        // Eine liegende Abschlussmarke hat an JEDEM Eingang Vorrang: nach dem
        // unwiderruflichen Schritt MUSS aus den vorbereiteten Bytes vollendet
        // werden, und ein zweiter Anlauf wuerde eine zweite Sequenz ziehen.
        if self.repository.prepared_finalization_marker()?.is_some() {
            return Err(WriterError::PreparedFinalizationPresent);
        }

        // ---- 1. Den vertrauenswuerdigen lokalen Kettenkopf rekonstruieren ----
        let published = PublishedObjectsOnly { inner: self.source };
        let inventory = ea_archive::ArchiveInventory::build(&published)?;
        let nodes = chain_nodes(&inventory);
        let chain = build_chain(self.binding.chain_id, &nodes)?;
        state.head_from_committed_bytes = true;
        state.reached_step = Some(FinalizationStep::RebuildLocalHead);
        if stop.ends_after(FinalizationStep::RebuildLocalHead) {
            return Ok(state);
        }

        // ---- 2. Einen erreichbaren signierten Server-Checkpoint vergleichen ----
        let assessment = assess_rollback(&chain, self.checkpoint_claims);
        if let RollbackAssessment::Rollback(_) = assessment {
            return Err(WriterError::RollbackDetected);
        }
        state.rollback = Some(assessment);
        state.reached_step = Some(FinalizationStep::CompareServerCheckpoint);
        if stop.ends_after(FinalizationStep::CompareServerCheckpoint) {
            return Ok(state);
        }

        // ---- 3. Head auswaehlen und Bediener pruefen ----
        let proposed = self.head.proposed_sequence();
        let verified_head = chain.verified_head();
        let expected_sequence = verified_head.map_or(ChainSequence::new(0), |head| {
            ChainSequence::new(head.chain_sequence().get().saturating_add(1))
        });
        if proposed != expected_sequence {
            return Err(WriterError::HeadReconciliationRequired);
        }
        if proposed < self.head.effective_from_sequence()
            || proposed > self.head.valid_through_sequence()
        {
            return Err(WriterError::SequenceLeaseExhausted);
        }
        require_fresh_proof(
            proof,
            ReauthPurpose::Finalize,
            self.binding.binding_object_hash,
            self.head,
        )?;
        let binding_fields = self
            .head
            .active_operator_binding_fields(self.binding.binding_object_hash)
            .ok_or(WriterError::ReauthBindingMismatch)?
            .clone();
        state.active_recovery_recipient_count = self
            .head
            .active_certificates()
            .filter(|(_, fields)| {
                fields.certificate_kind == ea_format::CertificateKindV1::RecoveryRecipient
            })
            .count();
        if state.active_recovery_recipient_count == 0 {
            return Err(WriterError::NoActiveRecoveryRecipient);
        }
        if !self
            .head
            .policy_fields()
            .allowed_archive_profile_hashes
            .contains(&self.binding.archive_profile_hash)
        {
            return Err(WriterError::ArchiveProfileNotAllowed);
        }
        // Die vierte Pruefung der Bindung gegen DENSELBEN Head, und die
        // asymmetrischste der vier: `binding_object_hash`,
        // `archive_profile_hash` und das Bedienerprofil wurden hier immer gegen
        // ihn geprueft, die `chain_id` nicht — obwohl Schritt 1 sie unbesehen
        // an `build_chain` uebergibt.
        //
        // Der einzige andere Waechter (`ea_chain`, `ForeignChainId`) greift
        // NUR, wenn schon ein Knoten mit anderer Kennung liegt. Auf einem
        // LEEREN Bestand greift er nicht: der Kopf ist `None`, Schritt 3
        // rechnet Sequenz 0, und die Finalisierung mintet Genesis in einer
        // Kette, die die Vertrauenslinie nicht kennt. Danach ist derselbe
        // Bestand mit `ForeignChainId` DAUERHAFT nicht mehr finalisierbar —
        // ein Fehler, der sich nur durch das Verwerfen von Archivbytes heilen
        // liesse, und die werden nicht verworfen.
        if self.binding.chain_id != self.head.chain_id() {
            return Err(WriterError::ChainIdMismatch);
        }
        state.selected_registry_version = Some(self.head.registry_version());
        state.reached_step = Some(FinalizationStep::SelectRegistryHeadAndOperator);
        if stop.ends_after(FinalizationStep::SelectRegistryHeadAndOperator) {
            return Ok(state);
        }

        // ---- 4. Validieren und deterministisch serialisieren ----
        let effective_now = self.head.preexisting_effective_now().value();
        let profile = self
            .operator_profiles
            .load()?
            .ok_or(WriterError::OperatorProfileMissing)?;
        let recomputed = operator_profile_commitment(&profile)?;
        if recomputed != binding_fields.operator_profile_commitment {
            return Err(WriterError::OperatorProfileCommitment);
        }
        // Der `recordId` wird EINMAL gezogen — hier, weil Schritt 4 ohne ihn
        // nicht serialisierbar ist — oder aus der bestaetigten Vorschau
        // uebernommen. Ein zweiter Zug wuerde andere Nutzlastbytes und damit
        // eine andere Vorschau ergeben.
        let record_id = match stop {
            Stop::Confirmed(confirmed) => confirmed.record_id(),
            _ => entropy::uuid_v7(effective_now.get())?,
        };
        let incident_number = input.human_incident_number.clone();
        let incident = self.build_incident(input, &profile, record_id, effective_now)?;
        let uniqueness = incident.incident_uniqueness_key()?;
        let year = i32::from(uniqueness.local_civil_year());
        // GEFRAGT wird hier, BEANSPRUCHT wird nach dem letzten fail-closed
        // Tor (Schritt 5, unten). Der Brief verlangt den Anspruch „unter dieser
        // Sperre, vor dem Serialisieren", und sein GRUND — „refuse a taken
        // number before serializing" — ist mit der Frage vollstaendig erfuellt.
        //
        // Der DAUERHAFTE Anspruch darf hier nicht stehen:
        // `IncidentNumberRegister` hat `claim` und `contains` und KEINE
        // Freigabe. Faellt danach noch ein Tor — ein geaenderter Head, eine
        // geaenderte Policy, ein fortgeschrittenes `effectiveNow`, alles Faelle,
        // die laut Addendum „eine neue Vorschau und eine neue Bestaetigung"
        // ergeben sollen und keine Umgehung —, waere die Nummer fuer immer
        // verbrannt, und der Bediener muesste sich fuer denselben realen Einsatz
        // eine andere ausdenken.
        if self
            .incident_numbers
            .contains(profile.organization_id(), year, &incident_number)?
        {
            return Err(WriterError::IncidentNumberTaken);
        }
        state.draft_record_bytes = encode_payload(&PayloadV1::Incident(incident))?;
        state.reached_step = Some(FinalizationStep::ValidateAndSerialize);
        if stop.ends_after(FinalizationStep::ValidateAndSerialize) {
            return Ok(state);
        }

        // ---- 5. Den Grant-Plan bilden, hashen und die Vorschau rechnen ----
        let plan = build_grant_plan(self.head)?;
        let preview = FinalizationPreview::new(
            FinalizationPreviewCoreFieldsV1 {
                organization_id: profile.organization_id(),
                chain_id: self.binding.chain_id,
                registry_head_hash: Hash32::try_from(
                    self.head.registry_head_hash().as_bytes().as_slice(),
                )
                .map_err(|_| WriterError::PreparedFinalizationUnreadable)?,
                registry_version: self.head.registry_version(),
                registry_not_after: self.head.not_after(),
                policy_object_hash: self.head.policy_object_hash(),
                proposed_sequence: proposed,
                previous_entry_hash: verified_head.map(|head| head.entry_hash()),
                record_digest: ea_crypto::record_digest(&state.draft_record_bytes),
                grant_plan_digest: plan.hash(),
                effective_now,
            },
            record_id,
            self.stale_decision(observed_now),
            self.trust_age_ms(observed_now),
            self.head.policy_fields().reader_trust_refresh_ms,
        )?;
        state.grant_plan = Some(plan);
        state.preview = Some(preview);
        state.reached_step = Some(FinalizationStep::BuildAndHashGrantPlan);
        if stop.ends_after(FinalizationStep::BuildAndHashGrantPlan) {
            return Ok(state);
        }

        // Die Bestaetigung wird GENAU HIER geprueft: nach der Vorschau und VOR
        // der ersten Ziehung eines Geheimnisses. Frueher gaebe es nichts zu
        // vergleichen, spaeter waere die CEK schon gezogen.
        let decision = state
            .preview
            .as_ref()
            .expect("Schritt 5 setzt die Vorschau")
            .decision();
        if decision.is_hard_block() {
            return Err(WriterError::RegistryStaleBlocked);
        }
        if let Stop::Confirmed(confirmed) = stop {
            let recomputed = state
                .preview
                .as_ref()
                .expect("Schritt 5 setzt die Vorschau")
                .preview_hash();
            if recomputed != confirmed.preview_hash() {
                return Err(WriterError::StaleAckPreviewMismatch);
            }
            if decision == StaleDecision::StaleAcknowledgeable {
                // Der Bestaetigungspfad selbst ist NICHT geliefert (siehe
                // `crate::stale_registry`); fail-closed heisst hier: ohne den
                // Pfad gibt es keine Bestaetigung, und ein veralteter Head
                // blockiert.
                return Err(WriterError::StaleAckRequired);
            }
        } else if decision == StaleDecision::StaleAcknowledgeable {
            return Err(WriterError::StaleAckRequired);
        }

        // Der DAUERHAFTE Anspruch auf die Einsatznummer — hinter dem letzten
        // fail-closed Tor und vor der ersten Ziehung eines Geheimnisses. Nur
        // der abschliessende Lauf beansprucht; eine Vorschau, die sie
        // verbrauchte, machte ihren eigenen Abschluss unmoeglich.
        //
        // JEDER Fehler des Anspruchs bricht ab, und nicht nur der belegte Name.
        // Die Asymmetrie waere das Leck: die FRAGE dreissig Zeilen darueber
        // reicht ihren Speicherfehler mit `?` weiter, also ist derselbe Ausfall
        // auf der Leseseite fail-closed. Verschluckte ihn die Schreibseite,
        // committete der Lauf einen Eintrag, dessen Einsatznummer NIE dauerhaft
        // beansprucht wurde — eine stille Herabstufung.
        //
        // Der Anspruch ist RUECKNEHMBAR, solange die Grenze nicht ueberschritten
        // ist: er wird an [`Self::run`] gemeldet, und der gibt ihn frei, falls
        // dieser Lauf mit einem Fehler endet. Zurueckgenommen wird die Meldung
        // in Schritt 9, unmittelbar mit der bestaetigten Abwesenheit des
        // `draftDEK` — ab da traegt ein Eintrag die Nummer, der sich nicht mehr
        // zuruecknehmen laesst.
        if matches!(stop, Stop::Confirmed(_)) {
            match self
                .incident_numbers
                .claim(profile.organization_id(), year, &incident_number)
            {
                Ok(()) => {
                    *claimed = Some(ClaimedIncidentNumber {
                        organization_id: profile.organization_id(),
                        local_civil_year: year,
                        human_incident_number: incident_number.clone(),
                    });
                }
                Err(ea_draft::DraftError::IncidentNumberTaken) => {
                    return Err(WriterError::IncidentNumberTaken);
                }
                Err(other) => return Err(WriterError::Draft(other)),
            }
        }

        // ---- 6. Die Geheimnisse EINMAL ziehen und den entryHash bilden ----
        let mut cek_bytes = [0_u8; CEK_SIZE];
        entropy::draw(EntropyKind::Cek, &mut cek_bytes)?;
        let mut nonce_bytes = [0_u8; AEAD_NONCE_SIZE];
        entropy::draw(EntropyKind::Nonce, &mut nonce_bytes)?;
        let cek = SecretBytes::new(cek_bytes);
        let nonce = SecretBytes::new(nonce_bytes);
        cek_bytes.zeroize();

        let plan_hash = *state
            .grant_plan
            .as_ref()
            .expect("Schritt 5 setzt den Plan")
            .hash()
            .as_bytes();
        let manifest_fields = || ManifestCoreFieldsV1 {
            organization_id: profile.organization_id(),
            chain_id: self.binding.chain_id,
            chain_sequence: proposed,
            previous_entry_hash: verified_head.map(|head| head.entry_hash()),
            writer_certificate_hash: self.binding.writer_certificate_hash,
            writer_transition_event_hash: None,
            registry_version: self.head.registry_version(),
            registry_head_hash: *self.head.registry_head_hash().as_bytes(),
            initial_grant_plan_hash: plan_hash,
            nonce: nonce_bytes,
        };
        // ZWEI DURCHGAENGE, und das ist kein Umweg: `manifestCore` traegt die
        // LAENGE des Ciphertexts und nicht dessen Bytes. Der erste Durchgang
        // ueber einen Platzhalter GLEICHER Laenge liefert exakt die AAD-Bytes.
        let placeholder = vec![0_u8; state.draft_record_bytes.len() + ea_crypto::AEAD_OVERHEAD];
        let draft_core = ManifestCoreV1::new(manifest_fields(), &placeholder)?;
        let aad = payload_aad(draft_core.exact_bytes());
        let ciphertext = aead_seal(
            &cek,
            &nonce,
            SecretVec::new(state.draft_record_bytes.clone()),
            &aad,
        )?;
        let manifest = ManifestCoreV1::new(manifest_fields(), &ciphertext)?;
        if manifest.exact_bytes() != draft_core.exact_bytes() {
            return Err(WriterError::PreparedFinalizationUnreadable);
        }
        nonce_bytes.zeroize();
        let signed = SignedManifestV1::new(manifest.clone(), &ciphertext)?;
        let writer_signature = self
            .key_provider
            .sign(
                &self.binding.writer_signing_handle,
                ContentType::RecordDigest,
                self.binding.writer_certificate_hash,
                // Der DIGEST und nicht der Kern. `ContentType::is_digest` ist
                // wahr fuer `RecordDigest`, und `validate_payload` verlangt
                // dann genau zweiunddreissig Bytes
                // (`crates/ea-crypto/src/cose.rs`). Der Port signiert die
                // Nutzlast, die er bekommt — er bildet keinen Digest.
                ea_crypto::record_digest(signed.exact_bytes()).as_bytes(),
            )?
            .as_bytes()
            .to_vec();
        let entry_package =
            EntryPackageV1::new(signed.clone(), ciphertext.clone(), writer_signature.clone())?;
        state.signed_manifest_bytes = signed.exact_bytes().to_vec();
        state.writer_signature = writer_signature;
        state.manifest_core = Some(manifest);
        let entry_hash = entry_package.entry_hash();
        state.entry_package = Some(entry_package);
        state.reached_step = Some(FinalizationStep::DrawSecretsAndBuildEntryHash);
        if stop.ends_after(FinalizationStep::DrawSecretsAndBuildEntryHash) {
            return Ok(state);
        }

        // ---- 7. Jedes .eag und dann die endgueltigen .eip-Bytes ----
        for item in state
            .grant_plan
            .as_ref()
            .expect("Schritt 5 setzt den Plan")
            .items()
        {
            let bytes = self.produce_grant(item, entry_hash, effective_now, &cek)?;
            let hash = Hash32::try_from(object_hash(&bytes).as_bytes().as_slice())
                .map_err(|_| WriterError::PreparedFinalizationUnreadable)?;
            state.grants.push((hash, bytes));
        }
        let entry_bytes = encode_entry_package(
            state
                .entry_package
                .as_ref()
                .expect("Schritt 6 setzt das Eintragspaket"),
        )?
        .into_vec();
        let entry_object_hash = object_hash(&entry_bytes);
        state.entry_bytes = entry_bytes;
        state.reached_step = Some(FinalizationStep::ProduceGrantsAndEntryBytes);
        if stop.ends_after(FinalizationStep::ProduceGrantsAndEntryBytes) {
            return Ok(state);
        }

        // ---- 8. Stagen und flushen ----
        let transaction = PreparedTransactionV1 {
            sequence: proposed,
            entry_hash,
            entry_object_hash,
            entry_bytes: state.entry_bytes.clone(),
            grant_object_hashes: state.grants.iter().map(|(hash, _)| *hash).collect(),
            grant_bytes: state
                .grants
                .iter()
                .map(|(_, bytes)| bytes.clone())
                .collect(),
            grant_plan_hash: state
                .grant_plan
                .as_ref()
                .expect("Schritt 5 setzt den Plan")
                .hash()
                .as_bytes()
                .to_vec(),
        };
        let targets = transaction.targets()?;
        if stop.breaks_at(FinalizationFaultPoint::BeforeStagingCreate) {
            return Ok(state);
        }
        for (staging, bytes) in transaction.staged_pairs(&targets)? {
            // `create_if_absent` und NICHT `create_non_object_if_absent`: diese
            // Bytes TRAGEN das 9-Byte-Exact-Object-Praefix, und der
            // Typunterschied ist die Klassifikation. Die
            // [`ea_format::ExactObjectBytes`] entstehen dabei durch ein
            // Dekodieren der vorbereiteten Bytes — es gibt keinen anderen Weg
            // zu dem Typ, und das ist die erste der zwei Pruefungen, die
            // dieselben Bytes bestehen muessen.
            let parsed = ea_format::decode_exact_object(bytes)?;
            let exact = match &parsed {
                ea_format::ParsedArchiveObject::Entry(entry) => entry.exact_bytes(),
                ea_format::ParsedArchiveObject::Grant(grant) => grant.exact_bytes(),
                _ => return Err(WriterError::PreparedFinalizationUnreadable),
            };
            self.backend.create_if_absent(&staging, exact)?;
        }
        if stop.breaks_at(FinalizationFaultPoint::AfterStagingCreateBeforeFileFlush) {
            return Ok(state);
        }
        // Jede Datei ERNEUT lesen ist Sache des Wirts; hier wird jedes Byte
        // dauerhaft gemacht — Datei zuerst, Verzeichnis danach, denn ohne den
        // zweiten Flush kann ein geschriebener Name nach einem Stromausfall
        // fehlen.
        for (staging, _) in transaction.staged_pairs(&targets)? {
            self.backend.sync_file(&staging)?;
        }
        if stop.breaks_at(FinalizationFaultPoint::AfterStagingFileFlushBeforeDirectoryFlush) {
            return Ok(state);
        }
        for (staging, _) in transaction.staged_pairs(&targets)? {
            self.backend.sync_directory(&staging)?;
        }
        if stop.breaks_at(FinalizationFaultPoint::AfterStagingDirectoryFlushBeforeMarker) {
            return Ok(state);
        }
        let exact_marker = transaction.encode()?;
        self.repository.replace_prepared_finalization_marker(Some(
            PreparedFinalizationMarker::new(exact_marker.clone()),
        ))?;
        state.phase = FinalizationPhase::PreparedAndFlushed;
        state.prepared = Some(PreparedFinalization {
            transaction,
            exact: exact_marker,
        });
        state.reached_step = Some(FinalizationStep::StageAndFlush);
        if stop.breaks_at(FinalizationFaultPoint::AfterPreparedMarkerCommit)
            || stop.ends_after(FinalizationStep::StageAndFlush)
        {
            return Ok(state);
        }

        // ---- 9. Nullen, leeren, den draftDEK loeschen — die Grenze ----
        drop(cek);
        drop(nonce);
        state.draft_record_bytes.zeroize();
        // Der SERIALISIERUNGSPUFFER ist damit genullt — der KLARTEXT noch
        // nicht. `design.md`:456 verlangt beides („CEK und Serialisierungspuffer
        // bestmoeglich nullen, fachlichen UI-Zustand leeren"), und der zweite
        // Teil liegt nicht hier, sondern am TYP: [`ea_draft::Draft`] traegt
        // `ZeroizeOnDrop` (`crates/ea-draft/src/model.rs`), also nullt der
        // geladene Entwurf unten seinen Text, sobald `save` ihn am Ende seines
        // Rumpfes fallen laesst. Ein `with_notes("")` an dieser Stelle waere
        // KEINE Verbesserung, sondern ein Datenverlust: `save` schriebe den
        // leeren Text dauerhaft, und scheiterte danach das Loeschen des
        // `draftDEK`, stellte die Wiederaufnahme einen LEEREN Entwurf her.
        //
        // Der Griff auf den `draftDEK` verlangt einen `SavedDraft`, und dessen
        // Konstruktor ist in `ea-draft` `pub(crate)`. Der EINZIGE Weg von
        // aussen ist eine Vergleich-und-Setze-Speicherung — und die ist hier
        // keine Verlegenheit, sondern die Sache selbst: sie PINNT die Fassung
        // unter der Sperre, unmittelbar bevor der Schluessel geloescht wird.
        // Eine dazwischenliegende Autospeicherung faellt damit als
        // `RevisionConflict` auf, statt still eine andere Fassung zu treffen.
        let draft = self.repository.load_or_create()?;
        let saved = self.repository.save(draft)?;
        let handle = self.repository.draft_dek_handle(&saved)?;
        match self.key_provider.delete(&handle) {
            Ok(()) | Err(ea_key_provider::KeyError::NotFound) => {}
            Err(other) => {
                // Die Grenze ist UNGEKLAERT: ein gescheitertes `delete` sagt
                // nicht, ob der Schluessel noch liegt, und eine Wiederaufnahme
                // koennte den Eintrag aus den vorbereiteten Bytes vollenden.
                // Fail-closed heisst hier: die Nummer bleibt verbraucht.
                *claimed = None;
                return Err(WriterError::Key(other));
            }
        }
        if stop.breaks_at(FinalizationFaultPoint::AfterKeystoreDelete) {
            return Ok(state);
        }
        match self.key_provider.contains(&handle) {
            // POSITIV festgestellt: der Schluessel liegt noch, die Grenze ist
            // NICHT ueberschritten, der Entwurf ist wiederherstellbar. Die
            // gemeldete Beanspruchung bleibt stehen, und [`Self::run`] gibt die
            // Nummer frei.
            Ok(true) => return Err(WriterError::KeyDeletionNotConfirmed),
            Ok(false) => {}
            // Wie oben ungeklaert.
            Err(error) => {
                *claimed = None;
                return Err(WriterError::Key(error));
            }
        }
        // AB HIER unwiderruflich: die Nummer ist verbraucht, auch wenn die
        // Schritte 10 bis 13 noch scheitern — die Wiederaufnahme vollendet
        // dann aus denselben vorbereiteten Bytes, und der Eintrag traegt sie.
        *claimed = None;
        state.phase = FinalizationPhase::DraftKeyAbsent;
        state.reached_step = Some(FinalizationStep::ZeroAndDeleteDraftKey);
        if stop.breaks_at(FinalizationFaultPoint::AfterAbsenceConfirmation)
            || stop.breaks_at(FinalizationFaultPoint::BackupRestoreAfterKeyDeletion)
            || stop.ends_after(FinalizationStep::ZeroAndDeleteDraftKey)
        {
            return Ok(state);
        }

        // ---- 10 bis 13 ----
        // Die Marke wird HERAUSGENOMMEN und nach der Veroeffentlichung
        // zurueckgelegt: `publish_from_prepared` schreibt in denselben Zustand,
        // und eine gleichzeitige Ausleihe waere ein Aliasfehler.
        let prepared = state
            .prepared
            .take()
            .expect("Schritt 8 setzt die Abschlussmarke");
        let outcome = self.publish_from_prepared(prepared.transaction(), stop, &mut state)?;
        state.prepared = Some(prepared);
        state.outcome = outcome;
        Ok(state)
    }
}

impl WriterService<'_> {
    /// Baut den Einsatz samt Kopf — Kopfposition 7 aus der verifizierten
    /// Sitzung und der NUR LESEND geoeffneten Profilzeile.
    fn build_incident(
        &self,
        input: FinalizationInputV1,
        profile: &ea_draft::OperatorProfile,
        record_id: [u8; 16],
        effective_now: UnixMillis,
    ) -> Result<IncidentV1, WriterError> {
        let number = input.human_incident_number;
        let operator = OperatorSnapshotV1::new(
            profile.organization_id(),
            profile.operator_subject_id(),
            profile.display_name(),
            profile.function_label(),
            *profile.profile_commitment_salt(),
            profile.operator_binding_object_hash(),
        )?;
        let header = CommonHeaderV1::new(
            ea_types::RecordId::try_from(record_id.as_slice())
                .map_err(|_| WriterError::LocalRng)?,
            effective_now,
            input.timezone,
            operator,
            input.source,
            self.head.registry_version(),
        )?;
        Ok(IncidentV1::new(
            header,
            number,
            input.occurred_at,
            input.keyword,
            input.location,
            input.personnel,
            input.personnel_empty_reason,
            input.vehicles,
            input.vehicles_empty_reason,
            input.patient_count,
            input.notes,
            input.external_organizations,
        )?)
    }

    /// Die beobachtete Zeit, mit dem Auswahlzeitpunkt als BODEN.
    ///
    /// Der Rust-Kern fragt keine Uhr — `SystemTime::now()` steht im Wirt und
    /// nirgends sonst (`apps/cli/src/main.rs`) —, also ist die beobachtete Zeit
    /// ein Argument. Der Boden macht sie MONOTON gegen die Auswahl: eine
    /// zurueckgedrehte Uhr kann das gemeldete Vertrauensalter nicht unter das
    /// Alter druecken, das der Head bei seiner Auswahl schon hatte.
    ///
    /// Was er NICHT leistet, und das gehoert hierher statt in eine Zusage: ein
    /// Aufrufer, der eine Zeit VOR `notAfter` einreicht, laesst einen
    /// veralteten Head frisch erscheinen. Der Auswahlzeitpunkt liegt immer vor
    /// `notAfter`, also ist der Boden dagegen kein Schutz. Die Uhr des Wirts
    /// ist Vertrauensgrundlage dieser Feststellung; der blockierende
    /// Zeitbegriff, den der Kern selbst haelt, ist der Vertrauensboden von
    /// `ea-time` bei der AUSWAHL.
    fn floored_now(&self, observed_now: UnixMillis) -> UnixMillis {
        let floor = self.head.preexisting_effective_now().value();
        if observed_now.get() < floor.get() {
            floor
        } else {
            observed_now
        }
    }

    /// Der Zeitstatus des gebundenen Head, gegen die BEOBACHTETE Zeit.
    ///
    /// `stale` heisst `effectiveNow > notAfter` (`design.md`:1447). Der Head war
    /// bei seiner AUSWAHL frisch — `select_registry_head` weist einen schon
    /// veralteten aktuellen Head fail-closed ab —, und veraltet erst, waehrend
    /// er gebunden ist. Genau deshalb ist die Feststellung hier und nicht in
    /// der Auswahl.
    ///
    /// Die Zeit MUSS deshalb von aussen kommen und darf NICHT
    /// [`SelectedRegistryHead::preexisting_effective_now`] sein: dieser Wert ist
    /// die Zeit ZUM AUSWAHLZEITPUNKT, und gegen ihn ist die Veralterung
    /// strukturell unerreichbar — die Auswahl gibt einen aktuellen Head nur
    /// heraus, wenn `raw_now <= notAfter` gilt. Mit ihm waere dieser Zweig
    /// immer `Fresh`, und der harte Block fuer Evidence Grade eine Attrappe.
    /// [`Self::floored_now`] nennt, was die beobachtete Zeit leisten kann und
    /// was nicht.
    ///
    /// Evidence Grade (`operatingProfile == 1`) und der signierte Wert `block`
    /// (`registryExpiryBehavior == 1`) blockieren; nur das Standardprofil mit
    /// signiertem `warn` ist bestaetigungsfaehig.
    fn stale_decision(&self, observed_now: UnixMillis) -> StaleDecision {
        if self.floored_now(observed_now).get() <= self.head.not_after().get() {
            return StaleDecision::Fresh;
        }
        let policy = self.head.policy_fields();
        if policy.operating_profile == 1 || policy.registry_expiry_behavior == 1 {
            return StaleDecision::HardBlock;
        }
        StaleDecision::StaleAcknowledgeable
    }

    /// Das Alter des GEBUNDENEN Vertrauensbestands in Millisekunden.
    ///
    /// Der Bezugspunkt kommt aus [`SelectedRegistryHead::issued_at`] und
    /// ausdruecklich NICHT aus einem Feld, das der Aufrufer neben der Bindung
    /// mitfuehrt: das Alter ist eine Aussage UEBER DEN GEBUNDENEN HEAD, und ein
    /// freies Feld waere eine Warnung, die der Aufrufer abschalten kann, indem
    /// er den Bezugspunkt naeher an die Gegenwart legt.
    fn trust_age_ms(&self, observed_now: UnixMillis) -> u64 {
        u64::try_from(
            i128::from(self.floored_now(observed_now).get())
                - i128::from(self.head.issued_at().get()),
        )
        .unwrap_or(0)
    }

    /// Ein `.eag` mit ECHTER Kapselung — ZWEI Durchgaenge, ohne Zirkel.
    ///
    /// `grant-context-v1` traegt WEDER die Kapselung NOCH den umschlossenen
    /// CEK. Der erste Durchgang liefert deshalb bereits die endgueltigen
    /// Kontextbytes, aus denen `hpkeInfo` und `hpkeAad` entstehen; der zweite
    /// setzt die Kapselung ein. Die Zusicherung dazwischen MISST, dass der
    /// Kontext unveraendert ist, statt es zu glauben.
    ///
    /// Der Schnitt kommt aus [`GrantBodyV1::exact_grant_context`] — derselben
    /// Funktion, mit der `ea-verify` oeffnet. Eine zweite Kopie waere die
    /// zweite Gelegenheit, beide Seiten mit verschiedenen Bytes zu speisen.
    fn produce_grant(
        &self,
        item: &GrantPlanItemV1,
        entry_hash: EntryHash,
        effective_now: UnixMillis,
        cek: &SecretBytes<CEK_SIZE>,
    ) -> Result<Vec<u8>, WriterError> {
        let certificate = self
            .head
            .active_certificate_fields(item.recipient_certificate_hash())
            .ok_or(WriterError::ReaderWithoutKemKey)?;
        let cose = certificate
            .kem_public_cose_key
            .as_ref()
            .ok_or(WriterError::ReaderWithoutKemKey)?;
        let recipient = match ea_crypto::CanonicalPublicCoseKey::from_deterministic_cbor(cose)? {
            ea_crypto::CanonicalPublicCoseKey::X25519(bytes) => {
                HpkeRecipientPublicKey::from_bytes(bytes)?
            }
            ea_crypto::CanonicalPublicCoseKey::Ed25519(_) => {
                return Err(WriterError::ReaderWithoutKemKey);
            }
        };
        let purpose = item.purpose();
        let fields = |encapsulated_key, wrapped_cek| GrantBodyFieldsV1 {
            organization_id: self.head.policy_fields().organization_id,
            chain_id: self.binding.chain_id,
            entry_hash,
            kind: GrantKindV1::Initial,
            purpose,
            recipient_key_thumbprint: item.recipient_key_thumbprint(),
            recipient_certificate_hash: item.recipient_certificate_hash(),
            issuer_key_thumbprint: self.binding.writer_key_thumbprint,
            issuer_certificate_hash: self.binding.writer_certificate_hash,
            registry_version: self.head.registry_version(),
            registry_head_hash: Hash32::try_from(
                self.head.registry_head_hash().as_bytes().as_slice(),
            )
            .unwrap_or_else(|_| unreachable_hash()),
            created_at_device: effective_now,
            original_recovery_grant_object_hash: None,
            grant_authorization_object_hash: None,
            encapsulated_key,
            wrapped_cek,
        };
        let draft = GrantBodyV1::new(fields(
            [0_u8; HPKE_ENCAPSULATED_KEY_SIZE],
            [0_u8; HPKE_WRAPPED_CEK_SIZE],
        ))?;
        let context = draft
            .exact_grant_context()
            .ok_or(WriterError::PreparedFinalizationUnreadable)?
            .to_vec();
        let sealed = hpke_seal(&recipient, cek, &hpke_info(&context), &hpke_aad(&context))?;
        let body = GrantBodyV1::new(fields(*sealed.encapsulated_key(), *sealed.wrapped_cek()))?;
        if body.exact_grant_context() != Some(context.as_slice()) {
            return Err(WriterError::PreparedFinalizationUnreadable);
        }
        let signature = self
            .key_provider
            .sign(
                &self.binding.writer_signing_handle,
                ContentType::GrantDigest,
                self.binding.writer_certificate_hash,
                ea_crypto::grant_digest(body.exact_bytes()).as_bytes(),
            )?
            .as_bytes()
            .to_vec();
        Ok(encode_grant(&GrantV1::new(body, signature)?)?.into_vec())
    }

    /// Die Schritte 10 bis 13, AUSSCHLIESSLICH aus den vorbereiteten Bytes.
    ///
    /// Sie ist der GEMEINSAME Weg des glatten Laufs und der Wiederherstellung:
    /// es gibt nur EINEN Veroeffentlichungspfad, und er liest die Bytes aus der
    /// Marke. Jede Datei wird vor der Veroeffentlichung ERNEUT dekodiert — das
    /// ist die „erneute Pruefung" von Schritt 8, und sie liefert zugleich die
    /// [`ea_format::ExactObjectBytes`], die der Port verlangt.
    pub(crate) fn publish_from_prepared(
        &self,
        transaction: &PreparedTransactionV1,
        stop: Stop<'_>,
        state: &mut ReachedState,
    ) -> Result<Option<FinalizeOutcome>, WriterError> {
        let targets = transaction.targets()?;

        // ---- 10. Die Grants create-if-absent veroeffentlichen ----
        //
        // Veroeffentlicht wird durch RENAME der in Schritt 8 gestagten Datei
        // auf ihren Zielnamen. `atomic_rename_same_fs` TRAEGT die
        // Create-if-absent-Semantik: eine bytegleiche Wiederholung gelingt,
        // abweichende Bytes am Ziel sind `EA-ARCHIVE-BYTE-CONFLICT`
        // (`crates/ea-archive/src/backend.rs`). Der Rename ist zugleich die
        // Bereinigung — er laesst keine temporaere Datei zurueck. Im glatten
        // Lauf hat Schritt 13 deshalb nichts zu raeumen, und das ist der
        // Grund, warum `WriterService::reconcile_to_completion` hier nicht
        // gerufen wird: sie raeumt, was ein ABBRUCH liegengelassen hat, und
        // ausschliesslich hinter einem nachgewiesenen Ausgang.
        //
        // Vor jedem Rename werden die Bytes ERNEUT dekodiert. Das ist die
        // „erneute Pruefung" von Schritt 8, sie belegt, dass die vorbereiteten
        // Bytes ein wohlgeformtes Archivobjekt sind, und sie ist der Grund,
        // warum die Wiederherstellung DIESEN Weg mitbenutzen darf.
        for (target, bytes) in targets.grants.iter().zip(&transaction.grant_bytes) {
            let parsed = ea_format::decode_exact_object(bytes)?;
            let ea_format::ParsedArchiveObject::Grant(grant) = &parsed else {
                return Err(WriterError::PreparedFinalizationUnreadable);
            };
            self.publish_object(target, grant.exact_bytes())?;
        }
        if let Some(first) = targets.grants.first() {
            self.backend.sync_directory(first)?;
        }
        state.phase = FinalizationPhase::GrantsPublished;
        state.reached_step = Some(FinalizationStep::PublishGrants);
        if stop.breaks_at(FinalizationFaultPoint::AfterGrantPublishBeforeEntryRename)
            || stop.ends_after(FinalizationStep::PublishGrants)
        {
            return Ok(None);
        }

        // ---- 11. Das .eip ZULETZT: atomarer Same-Filesystem-Rename ----
        let parsed = ea_format::decode_exact_object(&transaction.entry_bytes)?;
        let ea_format::ParsedArchiveObject::Entry(entry) = &parsed else {
            return Err(WriterError::PreparedFinalizationUnreadable);
        };
        self.publish_object(&targets.entry, entry.exact_bytes())?;
        state.phase = FinalizationPhase::EntryCommitted;
        state.reached_step = Some(FinalizationStep::PublishEntryLast);
        if stop.breaks_at(FinalizationFaultPoint::AfterEntryRenameBeforeDirectoryFlush) {
            return Ok(None);
        }
        self.backend.sync_directory(&targets.entry)?;
        if stop.breaks_at(FinalizationFaultPoint::AfterEntryDirectoryFlush)
            || stop.ends_after(FinalizationStep::PublishEntryLast)
        {
            return Ok(None);
        }

        // ---- 12. Netzarchiv ----
        //
        // Beim LOKALEN Profil ist dieser Schritt vollstaendig und ohne
        // Publikation abgeschlossen: es gibt kein entferntes Archivziel, und
        // `lokal gesichert` IST der Endzustand (`design.md` §9.3 Schritt 12
        // gilt „bei einem kontrollierten Netzlaufwerkprofil"). Der
        // Netzprofilweg gehoert zu den offengelegten Auslassungen dieses
        // Tasks.
        state.phase = FinalizationPhase::NetworkArchivePublished;
        state.reached_step = Some(FinalizationStep::PublishToNetworkArchive);
        if stop.ends_after(FinalizationStep::PublishToNetworkArchive) {
            return Ok(None);
        }
        if stop.breaks_at(FinalizationFaultPoint::AfterReconciliationBeforeBlankDraft) {
            return Ok(None);
        }

        // ---- 13. Abgleichen, Staging bereinigen, leeren Entwurf oeffnen ----
        //
        // EIN Aufruf und EINE Transaktion, und das ist die Zusage:
        // [`DraftRepository::replace_with_blank`] raeumt den geteilten
        // Uebergangsplatz GANZ — die Abschlussmarke eingeschlossen — und legt
        // den leeren Entwurf in DERSELBEN Datenbanktransaktion an
        // (`crates/ea-draft/src/autosave.rs`, `replace_with_blank`).
        //
        // Ein zweiter, vorangestellter `replace_prepared_finalization_marker(None)`
        // waere kein zusaetzlicher Schutz, sondern ein zweiter DAUERHAFTER
        // Schritt ohne Abbruchpunkt dazwischen: stirbt der Prozess danach,
        // steht die alte Entwurfszeile noch, ihr `draftDEK` ist in Schritt 9
        // aber geloescht, `load_or_create` scheitert an `unwrap_secret`, und
        // `recover_pending` findet keine Marke mehr — das Geraet waere ohne
        // Eingriff in die Datenbank unbenutzbar. Mit der EINEN Transaktion
        // gibt es diesen Zwischenzustand nicht: entweder liegen Marke UND
        // alter Entwurf (ein Neustart ist dann eine Fortsetzung, und die
        // vollendet aus denselben vorbereiteten Bytes), oder es liegt der
        // leere Entwurf ohne Marke. Ein Fehlschlag im Anlegen des leeren
        // Entwurfs — der Schluesselport zieht den frischen `draftDEK` INNERHALB
        // der Transaktion — rollt beides zurueck und laesst die Marke stehen.
        self.repository.replace_with_blank()?;
        state.phase = FinalizationPhase::Reconciled;
        state.reached_step = Some(FinalizationStep::ReconcileAndOpenBlankDraft);
        Ok(Some(FinalizeOutcome {
            sequence: transaction.sequence,
            entry_hash: transaction.entry_hash,
            object_hash: transaction.entry_object_hash,
            sync_status: ea_archive_fs::SyncStatus::LocallySaved,
        }))
    }
}

impl WriterService<'_> {
    /// Veroeffentlicht ein vorbereitetes Objekt unter seinem Zielnamen.
    ///
    /// Der REGELWEG ist der atomare Rename aus dem Staging, und das ist keine
    /// Vorliebe: `create_if_absent` legt die Zieladresse an und schreibt DANN
    /// (`create_new` auf der ENDADRESSE), also waere ein Absturz zwischen
    /// Anlegen und fertigem Schreiben eine halb geschriebene Datei UNTER ihrem
    /// endgueltigen Commit-Marker-Namen — genau der Fall, den die Reihenfolge
    /// der Archivtransaktion ausschliesst („ohne diese Reihenfolge waere ein
    /// halb geschriebenes Objekt unter seinem endgueltigen Namen sichtbar",
    /// `crates/ea-archive/src/transaction.rs`). Schritt 8 hat jedes Byte
    /// geschrieben, gegengelesen und geflusht; veroeffentlicht wird aus GENAU
    /// diesen Bytes.
    ///
    /// Der Rename ist zugleich IDEMPOTENT, wie `design.md` §9.3 Schritt 10 es
    /// verlangt („Bereits vorhandene Zielnamen sind nur bei bytegleichem Objekt
    /// zulaessig"): `atomic_rename_same_fs` traegt eine bytegleiche
    /// Wiederholung und verwirft dabei die Quelladresse.
    ///
    /// `create_if_absent` kommt NUR zum Zug, wenn die ZIELADRESSE schon liegt —
    /// der Wiederholungsfall einer Wiederherstellung, deren erster Anlauf diese
    /// Adresse bereits veroeffentlicht hatte. Dort ist nichts mehr zu
    /// schreiben: `create_if_absent` liest die liegenden Bytes und
    /// BESTAETIGT sie, oder es faellt fail-closed auf
    /// `EA-ARCHIVE-BYTE-CONFLICT`.
    ///
    /// # Warum das Ziel geprueft wird und nicht bloss der Fehler
    ///
    /// `atomic_rename_same_fs` meldet JEDES Scheitern des Wirts als
    /// `ArchiveBackendError::Io` (`crates/ea-archive-fs/src/local_path.rs`) —
    /// ein volles Medium und eine verbrauchte Staging-Adresse sind daran nicht
    /// zu unterscheiden. Wer aus JEDEM Renamefehler in `create_if_absent`
    /// faellt, laesst dessen `create_new` + `write_all` auf die ENDADRESSE
    /// laufen; bricht dieser Schreibvorgang mittendrin ab, liegt eine
    /// ABGESCHNITTENE Datei unter ihrem endgueltigen Commit-Marker-Namen, und
    /// jeder weitere Anlauf trifft sie mit `EA-ARCHIVE-BYTE-CONFLICT`. Genau
    /// die Reihenfolge der Archivtransaktion schliesst das aus.
    ///
    /// Liegt die Zieladresse dagegen SCHON, kann `create_if_absent` keine
    /// Bytes mehr etablieren: sein erster Zweig liest und vergleicht. Der
    /// Zweig ist damit auf seinen dokumentierten Fall eingeengt, und jeder
    /// andere Renamefehler PROPAGIERT — das unversehrte Staging bleibt liegen,
    /// und die Wiederaufnahme benennt daraus erneut um.
    fn publish_object(
        &self,
        target: &ArchivePath,
        bytes: &ea_format::ExactObjectBytes,
    ) -> Result<(), WriterError> {
        let staging = crate::marker::staging_path(target)?;
        if let Err(error) = self.backend.atomic_rename_same_fs(&staging, target) {
            if !self.object_is_published(target)? {
                return Err(WriterError::Backend(error));
            }
            self.backend.create_if_absent(target, bytes)?;
        }
        self.backend.sync_file(target)?;
        Ok(())
    }

    /// Ob unter `target` schon ein Objekt im Bestand liegt.
    ///
    /// Gelesen wird ueber [`ArchiveSource`] und damit ueber dieselbe Sicht, aus
    /// der Schritt 1 den Kettenkopf bildet — nicht ueber eine zweite,
    /// backendeigene Leseflaeche, die etwas anderes sehen koennte. Der
    /// Pfadhinweis ist hier eine ADRESSE und keine Identitaet: gefragt ist, ob
    /// die Commit-Adresse belegt ist, und das ist eine Aussage ueber den Namen.
    ///
    /// # Errors
    ///
    /// Der Fehler der Lesequelle.
    fn object_is_published(&self, target: &ArchivePath) -> Result<bool, WriterError> {
        let mut found = false;
        self.source.visit_blobs(&mut |blob| {
            if blob.path_hint() == target.as_str() {
                found = true;
            }
            Ok(())
        })?;
        Ok(found)
    }
}

/// Der Bestand OHNE die Staging-Adressen dieses Schreibpfades.
///
/// # Warum das noetig ist
///
/// [`ea_archive::ArchiveInventory`] klassifiziert AUSSCHLIESSLICH ueber das
/// 9-Byte-Exact-Object-Praefix, und der Pfadhinweis ist dort ausdruecklich keine
/// Identitaet. Die gestagten Bytes von Schritt 8 SIND das exakte Archivobjekt —
/// Schritt 8 dekodiert sie sogar dafuer. Ohne diesen Filter wuerde eine
/// liegengebliebene `entries/<seq>_<hash>.eip.staging` also zu einem
/// [`ChainNode`]: `verified_head` stuende auf einem Objekt, das NIE
/// veroeffentlicht wurde, Schritt 3 verlangte den externen Kopfabgleich auf
/// einem Bestand, in dem nichts liegt, und der naechste Eintrag bindet einen
/// Vorgaenger, den es nicht gibt. Die Zusage „die Sequenz gilt dann als NICHT
/// verbraucht" (`design.md` §9.4) waere gebrochen.
///
/// # Warum der NAME hier entscheiden DARF
///
/// Er entscheidet nicht, ob Bytes ein Archivobjekt sind — das bleibt Sache des
/// Praefix. Er entscheidet, ob ein Objekt VEROEFFENTLICHT ist, und genau das
/// ist eine Aussage ueber den Namen: §11.4 macht den Zielnamen zum
/// Commit-Marker, und veroeffentlicht wird durch Rename AUF ihn. Eine Adresse
/// mit [`ea_archive::STAGING_SUFFIX_V1`] ist per Konstruktion dieses Schreibpfades eine
/// temporaere Datei und damit ein Gesundheitsbefund.
///
/// # Warum der Filter BLEIBT, obwohl die Lesesicht ihn schon hat
///
/// Die REGEL steht genau einmal, in [`ea_archive::is_staging_path`], und
/// [`ea_archive_fs::LocalPathArchiveSource`] wendet sie inzwischen selbst an —
/// darum sieht auch jeder ANDERE Verbraucher derselben Bytes denselben Bestand,
/// und ein falscher Fork-Befund nach einem zweiten Anlauf entsteht nicht mehr.
/// Dieser Wrapper ist deshalb keine zweite Regel, sondern die Zusage AN DIESEM
/// PORT: [`WriterService`] nimmt ein beliebiges [`ArchiveSource`], und ein
/// fremdes Backend, das seine Staging-Adressen mitliefert, darf den Kettenkopf
/// dieser Finalisierung nicht verschieben.
struct PublishedObjectsOnly<'a> {
    inner: &'a dyn ArchiveSource,
}

impl ArchiveSource for PublishedObjectsOnly<'_> {
    fn visit_blobs(
        &self,
        visitor: &mut dyn FnMut(ArchiveBlob<'_>) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        self.inner.visit_blobs(&mut |blob| {
            if ea_archive::is_staging_path(blob.path_hint()) {
                return Ok(());
            }
            visitor(blob)
        })
    }
}

/// Uebersetzt die Eintragspakete und Stubs des Inventars in Kettenknoten.
///
/// Der Kopf entsteht damit AUSSCHLIESSLICH aus committed Archivbytes und
/// niemals aus dem SQLite-Zustand.
fn chain_nodes(inventory: &ea_archive::ArchiveInventory) -> Vec<ChainNode> {
    let mut nodes = Vec::new();
    for entry in inventory.entries() {
        let fields = entry.value().manifest().fields();
        nodes.push(ChainNode {
            chain_id: fields.chain_id,
            chain_sequence: fields.chain_sequence,
            previous_entry_hash: fields.previous_entry_hash,
            entry_hash: entry.value().entry_hash(),
            object_hash: entry.object_hash(),
            writer_certificate_hash: fields.writer_certificate_hash,
            writer_transition_event_hash: fields.writer_transition_event_hash,
            kind: ChainNodeKind::EntryPackage,
        });
    }
    // Ein Stub eines autorisiert geloeschten Eintrags BESETZT seine Sequenz.
    // Liesse man ihn weg, sahe `build_chain` dort eine Luecke, `verified_head`
    // hielte darunter an, und Schritt 3 verlangte auf einem GESUNDEN Bestand
    // den externen Kopfabgleich. `ChainNodeKind::DestroyedStub` existiert
    // genau dafuer.
    for stub in inventory.destroyed() {
        let fields = stub.value().signed_manifest().manifest().fields();
        nodes.push(ChainNode {
            chain_id: fields.chain_id,
            chain_sequence: fields.chain_sequence,
            previous_entry_hash: fields.previous_entry_hash,
            entry_hash: stub.value().entry_hash(),
            object_hash: stub.object_hash(),
            writer_certificate_hash: fields.writer_certificate_hash,
            writer_transition_event_hash: fields.writer_transition_event_hash,
            kind: ChainNodeKind::DestroyedStub,
        });
    }
    nodes
}

/// Verlangt einen Nachweis der EIGENEN Bindung, FRISCH und fuer `purpose`.
///
/// ZWEI Pruefungen, und die BINDUNG kommt zuerst — dieselbe Reihenfolge und
/// dieselbe Begruendung wie in [`ea_draft::DiscardService`]: ein Nachweis einer
/// fremden Bindung ist auch dann keine Autorisierung, wenn er taufrisch ist.
/// `OperatorSessionProof::is_valid_for` prueft die Bindung AUSDRUECKLICH nicht.
fn require_fresh_proof(
    proof: &OperatorSessionProof,
    purpose: ReauthPurpose,
    bound_binding_object_hash: ObjectHash,
    head: &SelectedRegistryHead,
) -> Result<(), WriterError> {
    if proof.binding_object_hash() != bound_binding_object_hash {
        return Err(WriterError::ReauthBindingMismatch);
    }
    let now = head.preexisting_effective_now();
    if proof.is_valid_for(purpose, now) {
        return Ok(());
    }
    let authorizes_another = ReauthPurpose::ALL
        .iter()
        .copied()
        .filter(|candidate| *candidate != purpose)
        .any(|candidate| proof.is_valid_for(candidate, now));
    if authorizes_another {
        Err(WriterError::ReauthPurposeMismatch)
    } else {
        Err(WriterError::ReauthRequired)
    }
}

/// Ein 32-Byte-Hash ist immer ein 32-Byte-Hash; dieser Zweig ist unerreichbar.
fn unreachable_hash() -> Hash32 {
    Hash32::try_from([0_u8; 32].as_slice()).expect("32 Byte sind 32 Byte")
}
