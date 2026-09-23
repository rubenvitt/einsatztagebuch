//! Der Trust-Kern des Reader-Key-Escrows (v1.1-Profil §3.1).
//!
//! # Eine Regel je Familie
//!
//! Dieses Modul trägt genau EIN privates Prädikat je Familie. Alle Aufrufer —
//! die native Zeremonie, die Familien-Admission des Servers, der Bestand für
//! Reader und Prüfung — laufen durch dieselben Prädikate und erhalten
//! Beweistypen mit Accessoren. Kein Aufrufer vergleicht Felder selbst.
//!
//! # Die Publikationsfreigabe
//!
//! Genau eine Signatur des benannten aktiven `OrganizationAdmin`-Zertifikats
//! mit `organizationAdminApprove`, gepaart mit der benannten aktiven nativen
//! Bedienerbindung desselben Autoritätssubjekts — dieselbe Regel wie die der
//! Administrationsautorisierung ([`crate::admin_authorization`]), nur über den
//! Kontext der Freigabe. Organisation, Kopf und Sequenz kommen aus der
//! gewählten geprüften Registry, nie aus Nutzlastbehauptungen. Abgelaufen ist
//! `now > expires-at` (Entscheidung 10); die Höchstdauer von 300 000 ms prüft
//! der Codec.
//!
//! # Das Escrow
//!
//! Genau eine Wurzelsignatur über den gepinnten Anker, dazu die Bindungen aus
//! Profil §3.1: eine vollständig geprüfte Freigabe desselben Cores, das exakte
//! Reader-Zertifikat im Registry-Zustand seiner Aktivierung (Enrollment-
//! Bindung über das aktivierende Ereignis, nicht über die historische
//! Autorität — ein Folgekopf mit derselben Sequenz ist legal) und ein zum
//! Enrollment aktiver Recovery-Empfänger. Die „Recovery-Recipient-Capability“
//! des Profils gibt es im Baum nicht; verlangt werden die Art
//! `RecoveryRecipient`, ein X25519-KEM und dessen Abdruck.

use std::{collections::BTreeMap, sync::Arc};

use ea_crypto::{CanonicalPublicCoseKey, VerificationContext};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, ParsedArchiveObject, ReaderKeyEscrowApprovalCoreV1,
    ReaderKeyEscrowCoreV1, ReaderKeyEscrowHpkeContextV1, ReaderKeyEscrowPayloadV1,
    RegistryChangeV1, TrustObjectV1, TrustSubtypeV1,
};
use ea_types::{
    CertificateHash, ChainSequence, Hash32, ObjectHash, OrganizationId, RegistryVersion, SubjectId,
    UnixMillis,
};

use crate::{
    AdminAuthorizationReplayKey, RegistryError, RegistryHeadPin, SelectedRegistryHead, TrustError,
    TrustStateStore, VerifiedTrust,
    admin_authorization::{AdminSignerClaim, consume_replay_keys, verify_admin_signer_claim},
    registry::replay_to_exact_pin,
    resolver::PreviousHeadState,
};

/// Wie die `authorization-sequence` einer Autorisierung an den Zustand
/// gebunden ist, gegen den sie geprüft wird.
#[derive(Clone, Copy)]
pub(crate) enum SequenceRule {
    /// Gleich der vorgeschlagenen Sequenz des gewählten Kopfes — die frische
    /// Zeremonie, nach dem Vorbild `verify_grant_authorization`.
    Exact(ChainSequence),
    /// Im signierten Lease-Fenster des Zustands — Aufnahme und Historie.
    Lease,
}

/// Gegen welche Zeit das Gültigkeitsfenster gemessen wird.
#[derive(Clone, Copy)]
pub(crate) enum WindowRule {
    /// `t < issued-at` ist noch nicht gültig, `t > expires-at` abgelaufen;
    /// `t == expires-at` ist gültig (Entscheidung 10).
    At(UnixMillis),
}

/// Eine Publikationsfreigabe, die [`approval_rule`] bestanden hat.
///
/// Nur in diesem Modul konstruierbar:
///
/// ```compile_fail
/// let _ = ea_trust::VerifiedReaderKeyEscrowApproval { inner: panic!() };
/// ```
pub struct VerifiedReaderKeyEscrowApproval {
    inner: ApprovalInner,
}

struct ApprovalInner {
    exact_bytes: Vec<u8>,
    object_hash: ObjectHash,
    fields: ReaderKeyEscrowApprovalCoreV1,
    signer_authority_subject_id: SubjectId,
    replay_keys: [AdminAuthorizationReplayKey; 2],
    verified_registry_version: RegistryVersion,
    verified_registry_head_hash: ObjectHash,
}

impl VerifiedReaderKeyEscrowApproval {
    /// Die Version des Kopfes, GEGEN den geprüft wurde.
    #[must_use]
    pub const fn verified_registry_version(&self) -> RegistryVersion {
        self.inner.verified_registry_version
    }

    /// Der Hash des Kopfes, GEGEN den geprüft wurde.
    #[must_use]
    pub const fn verified_registry_head_hash(&self) -> ObjectHash {
        self.inner.verified_registry_head_hash
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.inner.exact_bytes
    }

    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.inner.object_hash
    }

    #[must_use]
    pub const fn fields(&self) -> &ReaderKeyEscrowApprovalCoreV1 {
        &self.inner.fields
    }

    #[must_use]
    pub const fn signer_authority_subject_id(&self) -> SubjectId {
        self.inner.signer_authority_subject_id
    }

    /// Die beiden Sperrzeilen der Freigabe, `authorization-id` zuerst, dann
    /// `nonce` — im selben Namensraum wie jede Administrationsautorisierung.
    #[must_use]
    pub const fn replay_keys(&self) -> &[AdminAuthorizationReplayKey; 2] {
        &self.inner.replay_keys
    }
}

/// Prüft eine FRISCHE Publikationsfreigabe in der Zeremonie (Profil §5
/// Schritt 4).
///
/// Die Bytes müssen NICHT im Katalog liegen: die Freigabe entsteht in der
/// Zeremonie und wird erst mit dem Escrow veröffentlicht. Kopf, Sequenz und
/// Organisation kommen aus `head`: die Freigabe muss genau an diesen Kopf und
/// an seine vorgeschlagene Sequenz gebunden sein, und `now` muss in ihrem
/// Fenster liegen.
///
/// Die Einmal-Nutzung sitzt NICHT hier: verbraucht wird über
/// [`consume_reader_key_escrow_approval`].
///
/// # Errors
///
/// [`TrustError::Source`] für Bytes, die keine Publikationsfreigabe sind,
/// [`TrustError::ActionMismatch`] für fremde Organisation, fremden Kopf oder
/// fremde Sequenz, jeden Befund der Signiererregel
/// ([`TrustError::Signature`], [`TrustError::SignerInactive`],
/// [`TrustError::SubjectMismatch`]) sowie [`TrustError::AuthNotYetValid`] und
/// [`TrustError::AuthExpired`].
pub fn verify_reader_key_escrow_approval(
    trust: &VerifiedTrust,
    head: &SelectedRegistryHead,
    exact_approval_bytes: &[u8],
    now: UnixMillis,
) -> Result<VerifiedReaderKeyEscrowApproval, TrustError> {
    let (object_hash, object, fields) = decode_approval(exact_approval_bytes)?;
    let state = head.candidate_state();
    if fields.organization_id != trust.organization_id() {
        return Err(TrustError::ActionMismatch);
    }
    let signer_authority_subject_id = approval_rule(
        state,
        &object,
        &fields,
        SequenceRule::Exact(head.proposed_sequence()),
        WindowRule::At(now),
    )?;
    Ok(VerifiedReaderKeyEscrowApproval {
        inner: ApprovalInner {
            exact_bytes: exact_approval_bytes.to_vec(),
            object_hash,
            replay_keys: AdminAuthorizationReplayKey::pair_from_verified_escrow_approval(&fields),
            fields,
            signer_authority_subject_id,
            verified_registry_version: head.registry_version(),
            verified_registry_head_hash: head.registry_head_hash(),
        },
    })
}

/// Verbraucht eine geprüfte Publikationsfreigabe EIN Mal, organisationsweit
/// und laufübergreifend: beide Zeilen im bestehenden zweidimensionalen
/// Einmal-Speicher, `authorization-id` zuerst.
///
/// # Errors
///
/// [`TrustError::AuthReplay`], wenn die `authorization-id` ODER die `nonce`
/// schon verbraucht ist — auch durch eine Administrationsautorisierung oder
/// eine Öffnungsautorisierung (geteilter Namensraum). Sonst jeden Befund der
/// Ablage, insbesondere [`TrustError::StateUnavailable`] für einen Speicher,
/// der die Sperre nicht führt.
pub fn consume_reader_key_escrow_approval(
    store: &mut dyn TrustStateStore,
    approval: &VerifiedReaderKeyEscrowApproval,
) -> Result<(), TrustError> {
    consume_replay_keys(store, approval.replay_keys())
}

/// Dekodiert exakte Bytes als Publikationsfreigabe.
pub(crate) fn decode_approval(
    exact_bytes: &[u8],
) -> Result<(ObjectHash, TrustObjectV1, ReaderKeyEscrowApprovalCoreV1), TrustError> {
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact_bytes).map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    let DecodedTrustPayloadV1::ReaderKeyEscrowApproval(fields) = parsed
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    Ok((parsed.object_hash(), parsed.value().clone(), fields))
}

/// Die EINE Regel der Publikationsfreigabe.
///
/// `state` ist der Zustand, an dessen Kopf die Freigabe gebunden sein muss —
/// der gewählte Kopf in Zeremonie und Aufnahme, der exakt nachgespielte
/// Pin-Zustand in der Historie. Die Reihenfolge der Befunde:
///
/// 1. Organisation (`ActionMismatch`);
/// 2. Kopf gleich dem Zustand (`ActionMismatch`);
/// 3. Sequenz nach `sequence` (`ActionMismatch`);
/// 4. Signierer über die geteilte Administrator-Regel zur
///    `authorization-sequence`;
/// 5. Fenster nach `window`.
pub(crate) fn approval_rule(
    state: &PreviousHeadState,
    object: &TrustObjectV1,
    fields: &ReaderKeyEscrowApprovalCoreV1,
    sequence: SequenceRule,
    window: WindowRule,
) -> Result<SubjectId, TrustError> {
    if fields.organization_id != state.root.fields.organization_id {
        return Err(TrustError::ActionMismatch);
    }
    if fields.registry_version != state.registry_version
        || fields.registry_head_hash != state.registry_head_hash
    {
        return Err(TrustError::ActionMismatch);
    }
    let authorization_sequence = ChainSequence::new(fields.authorization_sequence);
    require_sequence(state, authorization_sequence, sequence)?;
    let signer = verify_admin_signer_claim(
        state,
        object,
        &AdminSignerClaim {
            organization_id: fields.organization_id,
            admin_certificate_hash: fields.admin_certificate_object_hash,
            admin_key_thumbprint: fields.admin_key_thumbprint,
            admin_operator_binding_object_hash: fields.admin_operator_binding_object_hash,
        },
        VerificationContext::reader_key_escrow_approval_trust_digest,
        authorization_sequence,
    )?;
    require_window(fields.issued_at, fields.expires_at, window)?;
    Ok(signer)
}

pub(crate) fn require_sequence(
    state: &PreviousHeadState,
    authorization_sequence: ChainSequence,
    rule: SequenceRule,
) -> Result<(), TrustError> {
    let bound = match rule {
        SequenceRule::Exact(expected) => authorization_sequence == expected,
        SequenceRule::Lease => {
            authorization_sequence >= state.effective_from_sequence
                && authorization_sequence <= state.valid_through_sequence
        }
    };
    if bound {
        Ok(())
    } else {
        Err(TrustError::ActionMismatch)
    }
}

pub(crate) fn require_window(
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    rule: WindowRule,
) -> Result<(), TrustError> {
    let WindowRule::At(use_time) = rule;
    if use_time < issued_at {
        return Err(TrustError::AuthNotYetValid);
    }
    if use_time > expires_at {
        return Err(TrustError::AuthExpired);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Das Escrow
// ---------------------------------------------------------------------------

/// Wie ein voll geprüftes Escrow relativ zum gewählten Kopf steht.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderKeyEscrowStanding {
    /// Zählt zur Eindeutigkeit und ist zu öffnen.
    Valid,
    /// Enrollment- oder Freigabe-Pin liegt jenseits des gewählten Kopfes: das
    /// Objekt ist voll geprüft, gilt aber für diesen Kopf noch nicht.
    NotYetEffective,
}

/// Der Schlüssel der Eindeutigkeit, aus dem GEPRÜFTEN Core.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReaderKeyEscrowUniquenessKey {
    organization_id: OrganizationId,
    reader_certificate_object_hash: CertificateHash,
    reader_subject_id: SubjectId,
}

impl ReaderKeyEscrowUniquenessKey {
    #[must_use]
    pub const fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    #[must_use]
    pub const fn reader_certificate_object_hash(&self) -> CertificateHash {
        self.reader_certificate_object_hash
    }

    #[must_use]
    pub const fn reader_subject_id(&self) -> SubjectId {
        self.reader_subject_id
    }
}

/// Ein voll geprüftes Escrow: Freigabe, Enrollment, Recovery-Empfänger,
/// Wurzelsignatur — und sein Stand zum gewählten Kopf.
///
/// Nur in diesem Modul konstruierbar:
///
/// ```compile_fail
/// let _ = ea_trust::VerifiedReaderKeyEscrow { inner: panic!() };
/// ```
#[derive(Clone)]
pub struct VerifiedReaderKeyEscrow {
    inner: Arc<EscrowInner>,
}

struct EscrowInner {
    exact_bytes: Vec<u8>,
    object_hash: ObjectHash,
    payload: ReaderKeyEscrowPayloadV1,
    reader_kem_key: CanonicalPublicCoseKey,
    standing: ReaderKeyEscrowStanding,
}

impl VerifiedReaderKeyEscrow {
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.inner.exact_bytes
    }

    #[must_use]
    pub fn object_hash(&self) -> ObjectHash {
        self.inner.object_hash
    }

    #[must_use]
    pub fn core(&self) -> &ReaderKeyEscrowCoreV1 {
        self.inner.payload.core()
    }

    #[must_use]
    pub fn approval_object_hash(&self) -> ObjectHash {
        self.inner.payload.approval_object_hash()
    }

    #[must_use]
    pub fn standing(&self) -> ReaderKeyEscrowStanding {
        self.inner.standing
    }

    /// Der Schlüssel, unter dem der Server die Eindeutigkeit sperrt.
    #[must_use]
    pub fn uniqueness_key(&self) -> ReaderKeyEscrowUniquenessKey {
        let core = self.core();
        ReaderKeyEscrowUniquenessKey {
            organization_id: core.organization_id,
            reader_certificate_object_hash: core.reader_certificate_object_hash,
            reader_subject_id: core.reader_subject_id,
        }
    }

    /// Der HPKE-Kontext der Kapselung, abgeleitet aus dem GEPRÜFTEN Core —
    /// nie übertragen.
    #[must_use]
    pub fn hpke_context(&self) -> ReaderKeyEscrowHpkeContextV1 {
        ReaderKeyEscrowHpkeContextV1::from_escrow_core(self.core())
    }

    /// Profil §6 Schritt 5: der aus dem entkapselten Geheimnis abgeleitete
    /// öffentliche Schlüssel MUSS der KEM des Reader-Zertifikats sein.
    ///
    /// # Errors
    ///
    /// [`TrustError::ActionMismatch`], wenn er es nicht ist.
    pub fn require_reader_kem_public_key(
        &self,
        derived: &CanonicalPublicCoseKey,
    ) -> Result<(), TrustError> {
        if *derived == self.inner.reader_kem_key {
            Ok(())
        } else {
            Err(TrustError::ActionMismatch)
        }
    }
}

/// Relativ wozu „gültig“ gemeint ist.
#[derive(Clone, Copy)]
pub enum ReaderKeyEscrowHead<'a> {
    /// Der gewählte Kopf — Server, native Zeremonie, Reader.
    Selected(&'a SelectedRegistryHead),
}

/// Alle Escrows des Katalogs, jedes voll geprüft.
///
/// Nur in diesem Modul konstruierbar:
///
/// ```compile_fail
/// let _ = ea_trust::VerifiedReaderKeyEscrowSet { escrows: panic!() };
/// ```
pub struct VerifiedReaderKeyEscrowSet {
    escrows: BTreeMap<ObjectHash, VerifiedReaderKeyEscrow>,
}

impl VerifiedReaderKeyEscrowSet {
    #[must_use]
    pub fn get(&self, escrow_object_hash: ObjectHash) -> Option<&VerifiedReaderKeyEscrow> {
        self.escrows.get(&escrow_object_hash)
    }

    pub fn iter(&self) -> impl Iterator<Item = &VerifiedReaderKeyEscrow> {
        self.escrows.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.escrows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.escrows.is_empty()
    }
}

/// Prüft JEDES Escrow-Familienobjekt des Katalogs, aus dem `trust`
/// entstanden ist.
///
/// `verify_trust` allein prüft keins davon: wer Escrows benutzt, MUSS diese
/// Funktion rufen. Fail-closed für den ganzen Bestand — ein einziges
/// ungültiges Objekt lässt die Menge scheitern (Ruling Q11, Profil §9).
///
/// # Errors
///
/// Jeder Befund der Escrow-Regel über irgendein Objekt.
pub fn verify_reader_key_escrows(
    trust: &VerifiedTrust,
    head: ReaderKeyEscrowHead<'_>,
) -> Result<VerifiedReaderKeyEscrowSet, TrustError> {
    let ReaderKeyEscrowHead::Selected(selected) = head;
    let head_state = selected.candidate_state();
    let mut pins = PinStates::new(trust);
    let catalog = &trust.inner.catalog;
    // Die Öffnungsautorisierung hat hier noch keine historische Regel: bis
    // sie steht, scheitert der Bestand an ihr, statt sie zu überspringen.
    if !catalog
        .hashes_for_subtype(TrustSubtypeV1::ReaderKeyEscrowRecoveryAuthorization)
        .is_empty()
    {
        return Err(TrustError::ActionMismatch);
    }
    let mut escrows = BTreeMap::new();
    for object_hash in catalog.hashes_for_subtype(TrustSubtypeV1::ReaderKeyEscrow) {
        let record = catalog.get(object_hash).ok_or(TrustError::Source)?;
        let escrow = escrow_rule(
            trust,
            &mut pins,
            head_state,
            *object_hash,
            record.value(),
            record.exact_bytes().as_bytes(),
        )?;
        escrows.insert(*object_hash, escrow);
    }
    Ok(VerifiedReaderKeyEscrowSet { escrows })
}

/// Zeremonie A VOR der Wurzelsignatur: alles außer der Signatur, gegen die
/// frische Freigabe und den gewählten Kopf.
///
/// Nur in diesem Modul konstruierbar:
///
/// ```compile_fail
/// let _ = ea_trust::VerifiedReaderKeyEscrowIntent { inner: panic!() };
/// ```
pub struct VerifiedReaderKeyEscrowIntent {
    inner: IntentInner,
}

struct IntentInner {
    payload: ReaderKeyEscrowPayloadV1,
    root_public_key: CanonicalPublicCoseKey,
    root_certificate_hash: CertificateHash,
    reader_kem_key: CanonicalPublicCoseKey,
}

impl VerifiedReaderKeyEscrowIntent {
    /// Die Nutzlast, die Root signieren darf — genau diese.
    #[must_use]
    pub const fn payload(&self) -> &ReaderKeyEscrowPayloadV1 {
        &self.inner.payload
    }

    /// Das Wurzelzertifikat, dessen Schlüssel signieren muss.
    #[must_use]
    pub const fn root_certificate_hash(&self) -> CertificateHash {
        self.inner.root_certificate_hash
    }
}

/// Prüft ein BEABSICHTIGTES Escrow, bevor Root signiert (Profil §5).
///
/// Die Freigabe muss gegen GENAU diesen Kopf geprüft sein; eine gegen einen
/// älteren Kopf geprüfte trägt keinen Intent.
///
/// # Errors
///
/// [`TrustError::ActionMismatch`] für einen fremden Kopf der Freigabe, eine
/// andere Freigabe in der Nutzlast, jede Feldabweichung zwischen Freigabe und
/// Core und einen fremden Wurzelabdruck,
/// [`TrustError::EscrowEnrollmentMismatch`] für jeden Befund der
/// Enrollment- und Recovery-Bindung, [`TrustError::EscrowInactive`], wenn das
/// Escrow für diesen Kopf nicht gültig wäre.
pub fn verify_intended_reader_key_escrow(
    trust: &VerifiedTrust,
    head: &SelectedRegistryHead,
    approval: &VerifiedReaderKeyEscrowApproval,
    intended: &ReaderKeyEscrowPayloadV1,
) -> Result<VerifiedReaderKeyEscrowIntent, TrustError> {
    if approval.verified_registry_version() != head.registry_version()
        || approval.verified_registry_head_hash() != head.registry_head_hash()
    {
        return Err(TrustError::ActionMismatch);
    }
    if intended.approval_object_hash() != approval.object_hash() {
        return Err(TrustError::ActionMismatch);
    }
    let head_state = head.candidate_state();
    let mut pins = PinStates::new(trust);
    let reader_kem_key =
        escrow_binding_rule(trust, &mut pins, approval.fields(), head_state, intended)?;
    if standing(head_state, intended.core(), approval.fields()) != ReaderKeyEscrowStanding::Valid {
        return Err(TrustError::EscrowInactive);
    }
    Ok(VerifiedReaderKeyEscrowIntent {
        inner: IntentInner {
            payload: intended.clone(),
            root_public_key: root_public_key(head_state)?,
            root_certificate_hash: CertificateHash::from(head_state.root.object_hash),
            reader_kem_key,
        },
    })
}

/// Zeremonie A NACH der Wurzelsignatur: die Bytes tragen genau die Nutzlast
/// des Intents, und die Wurzelsignatur trägt.
///
/// # Errors
///
/// [`TrustError::Source`] für Bytes, die kein Escrow sind,
/// [`TrustError::ActionMismatch`] für eine andere Nutzlast,
/// [`TrustError::Signature`], wenn die Wurzelsignatur nicht trägt.
pub fn verify_signed_reader_key_escrow(
    intent: &VerifiedReaderKeyEscrowIntent,
    exact_escrow_bytes: &[u8],
) -> Result<VerifiedReaderKeyEscrow, TrustError> {
    let ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact_escrow_bytes).map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    let DecodedTrustPayloadV1::ReaderKeyEscrow(payload) = parsed
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    if payload != intent.inner.payload {
        return Err(TrustError::ActionMismatch);
    }
    verify_escrow_root_signature(
        &intent.inner.root_public_key,
        intent.inner.root_certificate_hash,
        parsed.value(),
    )?;
    Ok(VerifiedReaderKeyEscrow {
        inner: Arc::new(EscrowInner {
            exact_bytes: exact_escrow_bytes.to_vec(),
            object_hash: parsed.object_hash(),
            payload,
            reader_kem_key: intent.inner.reader_kem_key.clone(),
            standing: ReaderKeyEscrowStanding::Valid,
        }),
    })
}

/// Die nachgespielten Pin-Zustände eines Prüflaufs, je `(version, hash)`
/// einmal.
pub(crate) struct PinStates<'t> {
    trust: &'t VerifiedTrust,
    states: BTreeMap<(RegistryVersion, [u8; 32]), Result<Arc<PreviousHeadState>, RegistryError>>,
}

impl<'t> PinStates<'t> {
    pub(crate) fn new(trust: &'t VerifiedTrust) -> Self {
        Self {
            trust,
            states: BTreeMap::new(),
        }
    }

    pub(crate) fn state(
        &mut self,
        version: RegistryVersion,
        head_hash: Hash32,
    ) -> Result<Arc<PreviousHeadState>, RegistryError> {
        let trust = self.trust;
        self.states
            .entry((version, *head_hash.as_bytes()))
            .or_insert_with(|| {
                replay_to_exact_pin(
                    trust,
                    RegistryHeadPin::new(version, ObjectHash::from(head_hash)),
                )
                .map(Arc::new)
            })
            .clone()
    }
}

/// Ein Pin, der sich nicht nachspielen lässt: ein Befund des Trust-Kerns
/// bleibt er selbst, jeder Registry-Befund wird `fallback`.
pub(crate) const fn pin_error(error: RegistryError, fallback: TrustError) -> TrustError {
    match error {
        RegistryError::Trust(error) => error,
        _ => fallback,
    }
}

/// Die EINE Regel des veröffentlichten Escrows.
fn escrow_rule(
    trust: &VerifiedTrust,
    pins: &mut PinStates<'_>,
    head_state: &PreviousHeadState,
    object_hash: ObjectHash,
    object: &TrustObjectV1,
    exact_bytes: &[u8],
) -> Result<VerifiedReaderKeyEscrow, TrustError> {
    let DecodedTrustPayloadV1::ReaderKeyEscrow(payload) =
        object.decoded_payload().map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source);
    };
    let core = payload.core();
    if core.organization_id != trust.organization_id() {
        return Err(TrustError::ActionMismatch);
    }
    // E1: die Freigabe liegt im Katalog und besteht ihre Regel historisch,
    // gemessen an der wurzelsignierten Zeit des Escrows (Ruling Q10).
    let approval_record = trust
        .previous_head()
        .catalog_object(payload.approval_object_hash())
        .ok_or(TrustError::Source)?;
    let DecodedTrustPayloadV1::ReaderKeyEscrowApproval(approval) = approval_record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::ActionMismatch);
    };
    let approval_state = pins
        .state(approval.registry_version, approval.registry_head_hash)
        .map_err(|error| pin_error(error, TrustError::ActionMismatch))?;
    approval_rule(
        &approval_state,
        approval_record.value(),
        &approval,
        SequenceRule::Lease,
        WindowRule::At(core.issued_at),
    )?;
    // E2–E5.
    let reader_kem_key = escrow_binding_rule(trust, pins, &approval, &approval_state, &payload)?;
    verify_escrow_root_signature(
        &root_public_key(&approval_state)?,
        CertificateHash::from(approval_state.root.object_hash),
        object,
    )?;
    let standing = standing(head_state, core, &approval);
    Ok(VerifiedReaderKeyEscrow {
        inner: Arc::new(EscrowInner {
            exact_bytes: exact_bytes.to_vec(),
            object_hash,
            payload,
            reader_kem_key,
            standing,
        }),
    })
}

/// Die Bindungen eines Escrows an seine Freigabe, sein Enrollment, seinen
/// Recovery-Empfänger und die Wurzel des Freigabe-Pins — alles außer der
/// Freigaberegel selbst und der Wurzelsignatur. Gibt den geprüften
/// Reader-KEM zurück.
fn escrow_binding_rule(
    trust: &VerifiedTrust,
    pins: &mut PinStates<'_>,
    approval: &ReaderKeyEscrowApprovalCoreV1,
    approval_state: &PreviousHeadState,
    payload: &ReaderKeyEscrowPayloadV1,
) -> Result<CanonicalPublicCoseKey, TrustError> {
    let core = payload.core();
    // E0/E2: Organisation und Freigabebindung, Feld für Feld.
    if core.organization_id != trust.organization_id()
        || approval.organization_id != core.organization_id
        || approval.escrow_core_hash != ea_crypto::reader_key_escrow_core_hash(payload.exact_core())
        || approval.reader_certificate_object_hash != core.reader_certificate_object_hash
        || approval.reader_subject_id != core.reader_subject_id
    {
        return Err(TrustError::ActionMismatch);
    }

    // E3: der Registry-Zustand, in dem das Reader-Zertifikat aktiv wurde.
    let enrollment_state = pins
        .state(
            core.enrollment_registry_version,
            core.enrollment_registry_head_hash,
        )
        .map_err(|error| pin_error(error, TrustError::EscrowEnrollmentMismatch))?;
    let activated_reader = enrollment_state.head_event.as_ref().is_some_and(|event| {
        matches!(
            event.change,
            RegistryChangeV1::Certificate { object_hash }
                if CertificateHash::from(object_hash) == core.reader_certificate_object_hash
        )
    });
    if !activated_reader
        || enrollment_state.effective_from_sequence != core.enrollment_sequence
        || core.enrollment_registry_version > approval.registry_version
    {
        return Err(TrustError::EscrowEnrollmentMismatch);
    }
    let reader = enrollment_state
        .certificates
        .get(&core.reader_certificate_object_hash)
        .ok_or(TrustError::EscrowEnrollmentMismatch)?;
    if reader.fields.certificate_kind != CertificateKindV1::Reader
        || !matches!(
            parse_key(reader.fields.signing_public_cose_key.as_deref()),
            Some(CanonicalPublicCoseKey::Ed25519(_))
        )
    {
        return Err(TrustError::EscrowEnrollmentMismatch);
    }
    let Some(reader_kem_key @ CanonicalPublicCoseKey::X25519(_)) =
        parse_key(reader.fields.kem_public_cose_key.as_deref())
    else {
        return Err(TrustError::EscrowEnrollmentMismatch);
    };
    // Zur Freigabe ist der Reader weiter aktiv: eine Freigabe für ein bereits
    // widerrufenes Zertifikat bindet nichts.
    if approval_state
        .active_certificate(
            core.reader_certificate_object_hash,
            ChainSequence::new(approval.authorization_sequence),
        )
        .is_none()
    {
        return Err(TrustError::EscrowEnrollmentMismatch);
    }

    // E4: der Recovery-Empfänger, aktiv zum Enrollment.
    let recovery = enrollment_state
        .active_certificate(
            core.recovery_certificate_object_hash,
            core.enrollment_sequence,
        )
        .ok_or(TrustError::EscrowEnrollmentMismatch)?;
    let recovery_kem = parse_key(recovery.fields.kem_public_cose_key.as_deref());
    if recovery.fields.certificate_kind != CertificateKindV1::RecoveryRecipient
        || !matches!(recovery_kem, Some(CanonicalPublicCoseKey::X25519(_)))
        || recovery_kem.map(|key| key.thumbprint()) != Some(core.recovery_kem_key_thumbprint)
    {
        return Err(TrustError::EscrowEnrollmentMismatch);
    }

    // E5: die Wurzel des Freigabe-Pins. Sie überlebt eine spätere Rotation.
    if core.root_key_thumbprint != approval_state.root.fields.root_key_thumbprint {
        return Err(TrustError::ActionMismatch);
    }
    Ok(reader_kem_key)
}

fn parse_key(exact: Option<&[u8]>) -> Option<CanonicalPublicCoseKey> {
    CanonicalPublicCoseKey::from_deterministic_cbor(exact?).ok()
}

fn root_public_key(state: &PreviousHeadState) -> Result<CanonicalPublicCoseKey, TrustError> {
    CanonicalPublicCoseKey::from_deterministic_cbor(&state.root.fields.root_public_cose_key)
        .map_err(|_| TrustError::Signature)
}

fn verify_escrow_root_signature(
    root_public_key: &CanonicalPublicCoseKey,
    root_certificate_hash: CertificateHash,
    object: &TrustObjectV1,
) -> Result<(), TrustError> {
    let [signature] = object.signatures() else {
        return Err(TrustError::Signature);
    };
    ea_crypto::verify_reader_key_escrow_trust_signature(
        signature,
        root_public_key,
        root_certificate_hash,
        object.exact_digest_input(),
    )
    .map_err(|_| TrustError::Signature)
}

/// Der Stand eines voll geprüften Escrows zum gewählten Kopf.
fn standing(
    head_state: &PreviousHeadState,
    core: &ReaderKeyEscrowCoreV1,
    approval: &ReaderKeyEscrowApprovalCoreV1,
) -> ReaderKeyEscrowStanding {
    if core.enrollment_registry_version > head_state.registry_version
        || approval.registry_version > head_state.registry_version
    {
        return ReaderKeyEscrowStanding::NotYetEffective;
    }
    ReaderKeyEscrowStanding::Valid
}
