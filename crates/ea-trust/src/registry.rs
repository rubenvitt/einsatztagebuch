use std::{collections::BTreeMap, sync::Arc};

use ea_crypto::{CanonicalPublicCoseKey, validate_signer_certificate};
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, DeviceCertificateFieldsV1, OperatorBindingFieldsV1,
    OperatorRoleV1, PolicyFieldsV1, RegistryChangeV1, RegistryEventFieldsV1,
    RootCertificateFieldsV1, TrustSubtypeV1, WriterTransitionFieldsV1,
};
use ea_time::{FutureSkew, TimeWarnings, TrustedTimeState, advance_registry_floor};
use ea_types::{
    CertificateHash, ChainId, ChainSequence, Hash32, ObjectHash, RegistryVersion, UnixMillis,
};

use crate::{
    ClockReleaseReplayKey, LocalTimeBlock, RegistryError, RegistryHeadPin, RegistrySelectionCommit,
    TrustError, VerifiedClockRelease, VerifiedTrust,
    admin_authorization::{AdminAuthorizationReplay, verify_admin_authorization},
    catalog::TrustCatalog,
    certificate::{ActiveCertificate, RootAuthority},
    clock_release::into_selection_replay_key,
    operator_binding::ActiveOperatorBinding,
    policy::ResolvedPolicy,
    resolver::PreviousHeadState,
    state::map_store_error,
};

pub struct PreexistingRegistryAuthority {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) inner: Arc<PreviousHeadState>,
}

pub struct PreexistingEffectiveNow {
    value: UnixMillis,
}

impl PreexistingEffectiveNow {
    #[must_use]
    pub const fn value(&self) -> UnixMillis {
        self.value
    }
}

#[cfg_attr(not(test), allow(dead_code))]
struct SelectedHeadInner {
    candidate_state: Arc<PreviousHeadState>,
    /// Die Kettenkennung DES ANKERS, gegen den dieser Head gewaehlt wurde.
    ///
    /// Sie reist mit der Auswahl, weil sie sonst nirgends autoritativ zu haben
    /// ist: `PreviousHeadState`, `RegistryEventFieldsV1` und
    /// `OperatorBindingFieldsV1` fuehren keine, und ein Verbraucher, der seine
    /// eigene `chain_id` gegen NICHTS pruefen kann, mintet auf einem leeren
    /// Bestand einen Genesis-Knoten in einer Phantomkette.
    chain_id: ChainId,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    policy: ResolvedPolicy,
    effective_from_sequence: ChainSequence,
    valid_through_sequence: ChainSequence,
    proposed_sequence: ChainSequence,
    /// `notAfter` des Head-Ereignisses. NUR lesend nach aussen; die
    /// Veralterungspruefung der Auswahl liest `candidate.head_event.not_after`
    /// unveraendert an ihrer eigenen Stelle.
    head_event_not_after: UnixMillis,
    /// `issuedAt` des Head-Ereignisses — der Bezugspunkt des
    /// Vertrauensalters. NUR lesend nach aussen; die Zeitpruefungen der
    /// Auswahl lesen `candidate.head_event.issued_at` unveraendert an ihren
    /// eigenen Stellen.
    head_event_issued_at: UnixMillis,
    preexisting_effective_now: PreexistingEffectiveNow,
    warnings: TimeWarnings,
    committed_revision: u64,
}

/// A committed, operation-authoritative Registry Head selection.
///
/// Callers cannot construct the proof state directly:
///
/// ```compile_fail
/// use ea_trust::SelectedRegistryHead;
/// let _ = SelectedRegistryHead { inner: panic!() };
/// ```
pub struct SelectedRegistryHead {
    inner: Arc<SelectedHeadInner>,
}

impl SelectedRegistryHead {
    #[must_use]
    pub fn registry_version(&self) -> RegistryVersion {
        self.inner.registry_version
    }

    #[must_use]
    pub fn registry_head_hash(&self) -> ObjectHash {
        self.inner.registry_head_hash
    }

    /// Die Kettenkennung des Ankers, gegen den dieser Head gewaehlt wurde.
    ///
    /// Sie ist die AUTORITAET fuer die Frage „in welche Kette schreibe ich
    /// hier". Ein Verbraucher, der eine eigene `chain_id` traegt, vergleicht
    /// sie gegen DIESE — auf einem leeren Bestand gibt es keinen Knoten, der
    /// die Frage sonst beantworten koennte.
    #[must_use]
    pub fn chain_id(&self) -> ChainId {
        self.inner.chain_id
    }

    #[must_use]
    pub fn policy_object_hash(&self) -> ObjectHash {
        self.inner.policy.object_hash
    }

    #[must_use]
    pub fn policy_fields(&self) -> &PolicyFieldsV1 {
        &self.inner.policy.fields
    }

    #[must_use]
    pub fn effective_from_sequence(&self) -> ChainSequence {
        self.inner.effective_from_sequence
    }

    #[must_use]
    pub fn valid_through_sequence(&self) -> ChainSequence {
        self.inner.valid_through_sequence
    }

    #[must_use]
    pub fn proposed_sequence(&self) -> ChainSequence {
        self.inner.proposed_sequence
    }

    #[must_use]
    pub fn active_certificate_fields(
        &self,
        certificate_hash: CertificateHash,
    ) -> Option<&DeviceCertificateFieldsV1> {
        self.inner
            .candidate_state
            .active_certificate(certificate_hash, self.inner.proposed_sequence)
            .map(|certificate| &certificate.fields)
    }

    /// Every certificate active at the proposed sequence, ascending by
    /// `CertificateHash`.
    ///
    /// Gate `grant-plan` (design.md §14.1 step 6) has to reconstruct the initial
    /// grant plan, which needs the *set* of active recipients — the point
    /// lookups above cannot answer that. The order is deterministic so a
    /// reconstructed plan is byte-stable.
    ///
    /// Callers decide which of these certificates are grant recipients: a
    /// certificate whose `kem_key_thumbprint` is `None` cannot receive a key
    /// envelope and is not part of a grant plan.
    pub fn active_certificates(
        &self,
    ) -> impl Iterator<Item = (CertificateHash, &DeviceCertificateFieldsV1)> {
        self.inner
            .candidate_state
            .active_certificates(self.inner.proposed_sequence)
            .map(|(hash, certificate)| (hash, &certificate.fields))
    }

    #[must_use]
    pub fn active_capabilities(&self, certificate_hash: CertificateHash) -> Option<&[String]> {
        self.active_certificate_fields(certificate_hash)
            .map(|certificate| certificate.capabilities.as_slice())
    }

    #[must_use]
    pub fn active_operator_binding_fields(
        &self,
        object_hash: ObjectHash,
    ) -> Option<&OperatorBindingFieldsV1> {
        self.inner
            .candidate_state
            .active_operator_binding(object_hash, self.inner.proposed_sequence)
            .map(|binding| &binding.fields)
    }

    /// `notAfter` des gebundenen Head — die Zeitgrenze, ab der er `stale` ist.
    ///
    /// Sie ist LESEND und aendert an der Auswahl nichts: `select_registry_head`
    /// weist einen bei der Auswahl schon veralteten AKTUELLEN Head weiterhin
    /// fail-closed ab, und dieser Zugriff kommt an jener Stelle nicht vor.
    ///
    /// Er existiert, weil [`Self::preexisting_effective_now`] die Zeit ZUM
    /// AUSWAHLZEITPUNKT ist. Ein bei der Auswahl frischer Head wird veraltet,
    /// waehrend dieser Wert weiterlebt — genau der Fall, den
    /// `registryExpiryBehavior` regelt (`design.md`:1447, :1455: das Feld
    /// steuert AUSSCHLIESSLICH die Finalisierung). Wer `stale` feststellen
    /// will, braucht deshalb eine FRISCHE Zeit gegen genau diese Grenze; ohne
    /// diesen Zugriff waere die Grenze nach aussen unsichtbar und die
    /// Feststellung nicht moeglich.
    ///
    /// Sie ist zugleich Pflichtposition sechs des Vorschauurbilds
    /// `finalization-preview-core-v1`
    /// (`schemas/reports/v1/finalization-preview.cddl`), damit eine bestaetigte
    /// Vorschau die Zeitgrenze mit abdeckt, gegen die sie bestaetigt wurde.
    #[must_use]
    pub fn not_after(&self) -> UnixMillis {
        self.inner.head_event_not_after
    }

    /// `issuedAt` des gebundenen Head — der Bezugspunkt des Vertrauensalters.
    ///
    /// Dieselbe Bauart und dieselbe Begruendung wie [`Self::not_after`]: rein
    /// lesend, an der Auswahl aendert er nichts. Er existiert, weil das ALTER
    /// des gebundenen Vertrauensbestands eine Aussage UEBER DEN GEBUNDENEN
    /// HEAD ist und nicht ueber eine Zahl, die ein Aufrufer daneben mitfuehrt:
    /// wer `effectiveNow - issuedAt` rechnen will, muss `issuedAt` DIESES Head
    /// lesen koennen, sonst zeigt die Auffrischungswarnung des Writers
    /// (`readerTrustRefreshMs`, `design.md`:1447) das Alter eines Head, den
    /// niemand gebunden hat.
    #[must_use]
    pub fn issued_at(&self) -> UnixMillis {
        self.inner.head_event_issued_at
    }

    #[must_use]
    pub fn preexisting_effective_now(&self) -> &PreexistingEffectiveNow {
        &self.inner.preexisting_effective_now
    }

    #[must_use]
    pub fn warnings(&self) -> &TimeWarnings {
        &self.inner.warnings
    }

    pub(crate) fn candidate_state(&self) -> &PreviousHeadState {
        &self.inner.candidate_state
    }
}

#[cfg_attr(not(test), allow(dead_code))]
struct PendingSuccessorProof {
    candidate_state: Arc<PreviousHeadState>,
    preexisting_state: Arc<PreviousHeadState>,
    state_key: crate::TrustStateKey,
    expected_revision: u64,
    trusted_time: TrustedTimeState,
    pinned_head: Option<RegistryHeadPin>,
    observed_os_wall_clock: UnixMillis,
    candidate_registry_version: RegistryVersion,
    candidate_registry_head_hash: ObjectHash,
    guard_policy_object_hash: ObjectHash,
    proposed_sequence: ChainSequence,
    pre_transition_sequence: ChainSequence,
    raw_now: UnixMillis,
    warnings: TimeWarnings,
    future_skew: FutureSkew,
    successor_event: RegistryEventFieldsV1,
}

/// Opaque, single-use proof that one direct successor is only temporally future.
///
/// Its private state cannot be constructed by callers:
///
/// ```compile_fail
/// use ea_trust::PendingFutureSuccessor;
/// let _ = PendingFutureSuccessor { inner: panic!() };
/// ```
///
/// It cannot be duplicated:
///
/// ```compile_fail
/// use ea_trust::PendingFutureSuccessor;
/// fn require_clone<T: Clone>() {}
/// require_clone::<PendingFutureSuccessor>();
/// ```
pub struct PendingFutureSuccessor {
    inner: Box<PendingSuccessorProof>,
}

#[cfg_attr(not(test), allow(dead_code))]
struct CommittedCatchUpProof {
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    committed_revision: u64,
}

/// Non-authoritative diagnostics for one atomically pinned catch-up Head.
///
/// Its private state cannot be constructed by callers:
///
/// ```compile_fail
/// use ea_trust::AdvancedRegistryHead;
/// let _ = AdvancedRegistryHead { inner: panic!() };
/// ```
///
/// It cannot be duplicated:
///
/// ```compile_fail
/// use ea_trust::AdvancedRegistryHead;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AdvancedRegistryHead>();
/// ```
pub struct AdvancedRegistryHead {
    inner: CommittedCatchUpProof,
}

impl AdvancedRegistryHead {
    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.inner.registry_version
    }

    #[must_use]
    pub const fn registry_head_hash(&self) -> ObjectHash {
        self.inner.registry_head_hash
    }

    #[must_use]
    pub const fn committed_revision(&self) -> u64 {
        self.inner.committed_revision
    }
}

pub enum RegistrySelectionOutcome {
    Selected(SelectedRegistryHead),
    Advanced(AdvancedRegistryHead),
    PendingFuture(PendingFutureSuccessor),
}

struct FallbackSuccessorBarrier {
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    event: RegistryEventFieldsV1,
}

pub struct RegistryCandidate {
    /// Die Kettenkennung des Ankers, gegen den dieser Kandidat geprueft wurde.
    chain_id: ChainId,
    registry_version: RegistryVersion,
    registry_head_hash: ObjectHash,
    preexisting_authority: Option<PreexistingRegistryAuthority>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) candidate_state: Arc<PreviousHeadState>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) target_policy: ResolvedPolicy,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) guard_policy: ResolvedPolicy,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) head_event: RegistryEventFieldsV1,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) state_key: crate::TrustStateKey,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) state_revision: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) trusted_time: ea_time::TrustedTimeState,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) original_pin: Option<RegistryHeadPin>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) proposed_sequence: ChainSequence,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) pre_transition_sequence: ChainSequence,
    fallback_barrier: Option<FallbackSuccessorBarrier>,
}

impl RegistryCandidate {
    #[must_use]
    pub const fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    #[must_use]
    pub const fn registry_head_hash(&self) -> ObjectHash {
        self.registry_head_hash
    }

    #[must_use]
    pub const fn preexisting_authority(&self) -> Option<&PreexistingRegistryAuthority> {
        self.preexisting_authority.as_ref()
    }
}

#[derive(Clone, Copy)]
struct TopologyEvent {
    object_hash: ObjectHash,
    previous_registry_hash: Option<Hash32>,
}

struct RegistryTopology {
    by_version: BTreeMap<RegistryVersion, Vec<TopologyEvent>>,
}

impl RegistryTopology {
    fn build(trust: &VerifiedTrust) -> Result<Self, RegistryError> {
        let mut by_version: BTreeMap<RegistryVersion, Vec<TopologyEvent>> = BTreeMap::new();
        for object_hash in trust
            .inner
            .catalog
            .hashes_for_subtype(TrustSubtypeV1::RegistryEvent)
        {
            let record = trust
                .inner
                .catalog
                .get(object_hash)
                .ok_or(TrustError::Source)?;
            let DecodedTrustPayloadV1::RegistryEvent(core) = record
                .value()
                .decoded_payload()
                .map_err(|_| TrustError::Source)?
            else {
                return Err(TrustError::Source.into());
            };
            let fields = core.fields();
            if fields.organization_id != trust.organization_id() {
                continue;
            }
            by_version
                .entry(fields.registry_version)
                .or_default()
                .push(TopologyEvent {
                    object_hash: *object_hash,
                    previous_registry_hash: fields.previous_registry_hash,
                });
        }
        for events in by_version.values_mut() {
            events.sort_unstable_by_key(|event| event.object_hash);
        }
        Ok(Self { by_version })
    }

    fn exact(
        &self,
        version: RegistryVersion,
        previous_registry_hash: Option<Hash32>,
    ) -> Result<Option<TopologyEvent>, RegistryError> {
        let Some(events) = self.by_version.get(&version) else {
            return Ok(None);
        };
        if events.len() != 1 {
            return Err(RegistryError::Fork);
        }
        let event = events[0];
        if event.previous_registry_hash != previous_registry_hash {
            return Err(RegistryError::Previous);
        }
        Ok(Some(event))
    }

    fn has_later_than(&self, version: RegistryVersion) -> bool {
        self.by_version
            .range((
                std::ops::Bound::Excluded(version),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .is_some()
    }
}

struct RegistryEvent {
    object_hash: ObjectHash,
    fields: RegistryEventFieldsV1,
    authorization_object_hash: ObjectHash,
}

struct AuthorizedDeviceTarget {
    fields: DeviceCertificateFieldsV1,
    authorization_object_hash: ObjectHash,
    exact_bytes: Vec<u8>,
}

struct AuthorizedBindingTarget {
    fields: OperatorBindingFieldsV1,
    authorization_object_hash: ObjectHash,
}

struct AuthorizedPolicyTarget {
    fields: PolicyFieldsV1,
    authorization_object_hash: ObjectHash,
}

struct AuthorizedWriterTransitionTarget {
    fields: WriterTransitionFieldsV1,
    authorization_object_hash: ObjectHash,
}

struct AuthorizedRootTarget {
    fields: RootCertificateFieldsV1,
    authorization_object_hash: ObjectHash,
    exact_bytes: Vec<u8>,
}

enum TransitionEffect {
    ActivateCertificate(ActiveCertificate),
    RevokeCertificate(CertificateHash),
    RevokeBinding(ObjectHash),
    ActivateBinding(ActiveOperatorBinding),
    Policy(ResolvedPolicy),
    Root(RootAuthority),
    WriterTransition {
        object_hash: ObjectHash,
        old_writer: CertificateHash,
        new_writer: CertificateHash,
    },
}

pub fn verify_registry_candidate(
    trust: &VerifiedTrust,
    proposed_sequence: ChainSequence,
) -> Result<RegistryCandidate, RegistryError> {
    if trust
        .pinned_head()
        .is_some_and(|pin| pin.registry_version().get() == u64::MAX)
    {
        return Err(RegistryError::Overflow);
    }

    let topology = RegistryTopology::build(trust)?;
    let mut state = trust.previous_head().clone();
    let mut replay = AdminAuthorizationReplay::default();

    let pinned = trust.pinned_head().copied();
    if let Some(pin) = pinned {
        replay_to_pin(trust, &topology, &mut state, &mut replay, pin)?;
    }

    let next_version = match pinned {
        Some(pin) => RegistryVersion::new(
            pin.registry_version()
                .get()
                .checked_add(1)
                .ok_or(RegistryError::Overflow)?,
        ),
        None => RegistryVersion::new(1),
    };
    let previous_hash = pinned
        .map(|pin| object_hash_as_hash32(pin.registry_head_hash()))
        .transpose()?;
    let direct = topology.exact(next_version, previous_hash)?;

    let Some(direct) = direct else {
        if topology.has_later_than(next_version) {
            return Err(RegistryError::Gap);
        }
        let Some(pin) = pinned else {
            return Err(RegistryError::Rollback);
        };
        return current_candidate(trust, state, pin, proposed_sequence);
    };

    let event = load_registry_event(&trust.inner.catalog, direct.object_hash)?;
    if event.fields.effective_from_sequence > proposed_sequence {
        let Some(pin) = pinned else {
            return Err(RegistryError::SequenceLease);
        };
        return current_candidate(trust, state, pin, proposed_sequence);
    }

    let authority_state = pinned.map(|_| Arc::new(state.clone()));
    let guard_policy = state.policy.clone();
    let pre_transition_sequence =
        verify_and_apply_registry_event(trust, &mut state, &event, &mut replay)?;
    let target_policy = state.policy.clone().ok_or(TrustError::ActionMismatch)?;
    let guard_policy = guard_policy.unwrap_or_else(|| target_policy.clone());
    Ok(RegistryCandidate {
        chain_id: trust.chain_id(),
        registry_version: event.fields.registry_version,
        registry_head_hash: event.object_hash,
        preexisting_authority: authority_state
            .as_ref()
            .map(|state| PreexistingRegistryAuthority {
                inner: Arc::clone(state),
            }),
        candidate_state: Arc::new(state),
        target_policy,
        guard_policy,
        head_event: event.fields,
        state_key: trust.state_key(),
        state_revision: trust.state_revision(),
        trusted_time: trust.trusted_time().clone(),
        original_pin: pinned,
        proposed_sequence,
        pre_transition_sequence,
        fallback_barrier: None,
    })
}

fn current_candidate(
    trust: &VerifiedTrust,
    state: PreviousHeadState,
    pin: RegistryHeadPin,
    proposed_sequence: ChainSequence,
) -> Result<RegistryCandidate, RegistryError> {
    if proposed_sequence < state.effective_from_sequence
        || proposed_sequence > state.valid_through_sequence
    {
        return Err(RegistryError::SequenceLease);
    }
    let target_policy = state.policy.clone().ok_or(TrustError::ActionMismatch)?;
    let head_event = state.head_event.clone().ok_or(RegistryError::Rollback)?;
    let authority_state = Arc::new(state);
    Ok(RegistryCandidate {
        chain_id: trust.chain_id(),
        registry_version: pin.registry_version(),
        registry_head_hash: pin.registry_head_hash(),
        preexisting_authority: Some(PreexistingRegistryAuthority {
            inner: Arc::clone(&authority_state),
        }),
        candidate_state: authority_state,
        guard_policy: target_policy.clone(),
        target_policy,
        head_event,
        state_key: trust.state_key(),
        state_revision: trust.state_revision(),
        trusted_time: trust.trusted_time().clone(),
        original_pin: Some(pin),
        proposed_sequence,
        pre_transition_sequence: proposed_sequence,
        fallback_barrier: None,
    })
}

pub fn select_registry_head(
    candidate: RegistryCandidate,
    mut local_time: LocalTimeBlock<'_>,
    release: Option<VerifiedClockRelease>,
) -> Result<RegistrySelectionOutcome, RegistryError> {
    require_candidate_local_time(&candidate, &local_time)?;
    let replay_key = require_release_pairing(&candidate, &local_time, release)?;
    let raw_now = local_time.evaluation.raw_now();
    let warnings = *local_time.evaluation.warnings();
    let is_current = candidate_is_current(&candidate);

    if !is_current
        && (raw_now < candidate.head_event.issued_at || raw_now < candidate.head_event.not_before)
    {
        let previous = candidate
            .preexisting_authority
            .as_ref()
            .ok_or(RegistryError::PendingFuture)?;
        if candidate.proposed_sequence < previous.inner.effective_from_sequence
            || candidate.proposed_sequence > previous.inner.valid_through_sequence
        {
            return Err(RegistryError::PendingFuture);
        }
        let preexisting_state = Arc::clone(&previous.inner);
        return Ok(RegistrySelectionOutcome::PendingFuture(
            PendingFutureSuccessor {
                inner: Box::new(PendingSuccessorProof {
                    candidate_state: candidate.candidate_state,
                    preexisting_state,
                    state_key: local_time.state_key,
                    expected_revision: local_time.expected_revision,
                    trusted_time: local_time.trusted_time,
                    pinned_head: local_time.pinned_head,
                    observed_os_wall_clock: local_time.observed_os_wall_clock,
                    candidate_registry_version: local_time.candidate_registry_version,
                    candidate_registry_head_hash: local_time.candidate_registry_head_hash,
                    guard_policy_object_hash: local_time.guard_policy_object_hash,
                    proposed_sequence: local_time.proposed_sequence,
                    pre_transition_sequence: local_time.pre_transition_sequence,
                    raw_now,
                    warnings,
                    future_skew: local_time.evaluation.future_skew(),
                    successor_event: candidate.head_event,
                }),
            },
        ));
    }

    let stale = raw_now > candidate.head_event.not_after;
    let lease_miss = candidate.proposed_sequence < candidate.head_event.effective_from_sequence
        || candidate.proposed_sequence > candidate.head_event.valid_through_sequence;

    if is_current {
        if let Some(barrier) = candidate.fallback_barrier.as_ref() {
            if barrier.registry_version <= candidate.registry_version
                || barrier.registry_head_hash == candidate.registry_head_hash
                || barrier.event.registry_version != barrier.registry_version
            {
                return Err(TrustError::StateConflict.into());
            }
            if raw_now >= barrier.event.issued_at && raw_now >= barrier.event.not_before {
                return Err(RegistryError::SuccessorReady);
            }
        }
        if stale {
            return Err(RegistryError::Stale);
        }
        if lease_miss {
            return Err(RegistryError::SequenceLease);
        }
        let current_head = candidate.original_pin.ok_or(TrustError::StateConflict)?;
        let commit = RegistrySelectionCommit::compare_and_affirm(
            local_time.trusted_time.clone(),
            current_head,
            replay_key,
        );
        let committed_revision = commit_selection(&mut local_time, &commit)?;
        return Ok(RegistrySelectionOutcome::Selected(selected_head(
            candidate,
            raw_now,
            warnings,
            committed_revision,
        )));
    }

    let next_head = RegistryHeadPin::new(candidate.registry_version, candidate.registry_head_hash);
    let next_trusted_time = advance_registry_floor(
        &local_time.trusted_time,
        candidate.head_event.issued_at,
        candidate.head_event.not_before,
    );
    let commit = RegistrySelectionCommit::advance_head(next_trusted_time, next_head, replay_key);
    let committed_revision = commit_selection(&mut local_time, &commit)?;
    if stale || lease_miss {
        return Ok(RegistrySelectionOutcome::Advanced(AdvancedRegistryHead {
            inner: CommittedCatchUpProof {
                registry_version: candidate.registry_version,
                registry_head_hash: candidate.registry_head_hash,
                committed_revision,
            },
        }));
    }

    Ok(RegistrySelectionOutcome::Selected(selected_head(
        candidate,
        raw_now,
        warnings,
        committed_revision,
    )))
}

pub fn verify_current_head_fallback(
    trust: &VerifiedTrust,
    pending: PendingFutureSuccessor,
) -> Result<RegistryCandidate, RegistryError> {
    let proof = *pending.inner;
    if trust.state_key() != proof.state_key
        || trust.state_revision() != proof.expected_revision
        || trust.trusted_time() != &proof.trusted_time
        || trust.pinned_head().copied() != proof.pinned_head
    {
        return Err(TrustError::StateConflict.into());
    }

    let direct = verify_registry_candidate(trust, proof.proposed_sequence)?;
    if direct.registry_version != proof.candidate_registry_version {
        return Err(TrustError::StateConflict.into());
    }
    if direct.registry_head_hash != proof.candidate_registry_head_hash {
        return Err(RegistryError::Fork);
    }
    if direct.head_event != proof.successor_event
        || direct.pre_transition_sequence != proof.pre_transition_sequence
        || direct.guard_policy.object_hash != proof.guard_policy_object_hash
    {
        return Err(RegistryError::Fork);
    }
    let expected_candidate_hash = object_hash_as_hash32(proof.candidate_registry_head_hash)?;
    if proof.candidate_state.registry_version != proof.candidate_registry_version
        || proof.candidate_state.registry_head_hash != expected_candidate_hash
    {
        return Err(TrustError::StateConflict.into());
    }
    let pinned_head = proof.pinned_head.ok_or(TrustError::StateConflict)?;
    let expected_previous_hash = object_hash_as_hash32(pinned_head.registry_head_hash())?;
    if proof.preexisting_state.registry_version != pinned_head.registry_version()
        || proof.preexisting_state.registry_head_hash != expected_previous_hash
        || proof.successor_event.previous_registry_hash != Some(expected_previous_hash)
    {
        return Err(TrustError::StateConflict.into());
    }
    let previous = direct
        .preexisting_authority
        .as_ref()
        .ok_or(TrustError::StateConflict)?;
    let mut current = current_candidate(
        trust,
        (*previous.inner).clone(),
        pinned_head,
        proof.proposed_sequence,
    )?;
    current.fallback_barrier = Some(FallbackSuccessorBarrier {
        registry_version: proof.candidate_registry_version,
        registry_head_hash: proof.candidate_registry_head_hash,
        event: proof.successor_event,
    });
    Ok(current)
}

fn require_candidate_local_time(
    candidate: &RegistryCandidate,
    local_time: &LocalTimeBlock<'_>,
) -> Result<(), RegistryError> {
    if !Arc::ptr_eq(&candidate.candidate_state, &local_time.candidate_state)
        || candidate.state_key != local_time.state_key
        || local_time.expected_revision < candidate.state_revision
        || candidate.original_pin != local_time.pinned_head
        || candidate.registry_version != local_time.candidate_registry_version
        || candidate.registry_head_hash != local_time.candidate_registry_head_hash
        || candidate.guard_policy.object_hash != local_time.guard_policy_object_hash
        || candidate.proposed_sequence != local_time.proposed_sequence
        || candidate.pre_transition_sequence != local_time.pre_transition_sequence
    {
        return Err(TrustError::StateConflict.into());
    }
    Ok(())
}

fn require_release_pairing(
    candidate: &RegistryCandidate,
    local_time: &LocalTimeBlock<'_>,
    release: Option<VerifiedClockRelease>,
) -> Result<Option<ClockReleaseReplayKey>, RegistryError> {
    match (local_time.evaluation.future_skew(), release) {
        (FutureSkew::Blocked, Some(release)) => {
            into_selection_replay_key(release, candidate, local_time)
                .map(Some)
                .map_err(|()| RegistryError::FutureSkew)
        }
        (FutureSkew::Blocked, None)
        | (FutureSkew::WithinLimit, Some(_))
        | (FutureSkew::UnprovableWithoutIndependentReference, Some(_)) => {
            Err(RegistryError::FutureSkew)
        }
        (FutureSkew::WithinLimit, None)
        | (FutureSkew::UnprovableWithoutIndependentReference, None) => Ok(None),
    }
}

fn candidate_is_current(candidate: &RegistryCandidate) -> bool {
    candidate.original_pin.is_some_and(|pin| {
        pin.registry_version() == candidate.registry_version
            && pin.registry_head_hash() == candidate.registry_head_hash
            && candidate
                .preexisting_authority
                .as_ref()
                .is_some_and(|authority| Arc::ptr_eq(&authority.inner, &candidate.candidate_state))
    })
}

fn commit_selection(
    local_time: &mut LocalTimeBlock<'_>,
    commit: &RegistrySelectionCommit,
) -> Result<u64, RegistryError> {
    let committed = local_time
        .store
        .commit_registry_selection(local_time.state_key, local_time.expected_revision, commit)
        .map_err(map_store_error)?;
    if committed.revision() <= local_time.expected_revision
        || committed.trusted_time() != commit.next_trusted_time()
        || committed.pinned_head() != Some(commit.next_head())
    {
        return Err(TrustError::StateConflict.into());
    }
    Ok(committed.revision())
}

fn selected_head(
    candidate: RegistryCandidate,
    raw_now: UnixMillis,
    warnings: TimeWarnings,
    committed_revision: u64,
) -> SelectedRegistryHead {
    SelectedRegistryHead {
        inner: Arc::new(SelectedHeadInner {
            candidate_state: candidate.candidate_state,
            chain_id: candidate.chain_id,
            registry_version: candidate.registry_version,
            registry_head_hash: candidate.registry_head_hash,
            policy: candidate.target_policy,
            effective_from_sequence: candidate.head_event.effective_from_sequence,
            valid_through_sequence: candidate.head_event.valid_through_sequence,
            proposed_sequence: candidate.proposed_sequence,
            head_event_not_after: candidate.head_event.not_after,
            head_event_issued_at: candidate.head_event.issued_at,
            preexisting_effective_now: PreexistingEffectiveNow { value: raw_now },
            warnings,
            committed_revision,
        }),
    }
}

fn replay_to_pin(
    trust: &VerifiedTrust,
    topology: &RegistryTopology,
    state: &mut PreviousHeadState,
    replay: &mut AdminAuthorizationReplay,
    pin: RegistryHeadPin,
) -> Result<(), RegistryError> {
    if pin.registry_version().get() == 0 {
        return Err(RegistryError::Rollback);
    }
    let mut version = RegistryVersion::new(1);
    let mut previous = None;
    loop {
        let Some(topology_event) = topology.exact(version, previous)? else {
            return if version < pin.registry_version() && topology.has_later_than(version) {
                Err(RegistryError::Gap)
            } else {
                Err(RegistryError::Rollback)
            };
        };
        if version == pin.registry_version()
            && topology_event.object_hash != pin.registry_head_hash()
        {
            return Err(RegistryError::Rollback);
        }
        let event = load_registry_event(&trust.inner.catalog, topology_event.object_hash)?;
        verify_and_apply_registry_event(trust, state, &event, replay)?;
        if version == pin.registry_version() {
            return Ok(());
        }
        previous = Some(object_hash_as_hash32(topology_event.object_hash)?);
        version = RegistryVersion::new(
            version
                .get()
                .checked_add(1)
                .ok_or(RegistryError::Overflow)?,
        );
    }
}

fn verify_and_apply_registry_event(
    trust: &VerifiedTrust,
    state: &mut PreviousHeadState,
    event: &RegistryEvent,
    replay: &mut AdminAuthorizationReplay,
) -> Result<ChainSequence, RegistryError> {
    let bootstrap = state.registry_version == RegistryVersion::new(0);
    if event.fields.organization_id != trust.organization_id()
        || event.fields.root_key_thumbprint != state.root.fields.root_key_thumbprint
    {
        return Err(TrustError::ActionMismatch.into());
    }
    if event.fields.effective_from_sequence > event.fields.valid_through_sequence {
        return Err(RegistryError::SequenceLease);
    }
    let pre_transition_sequence = if bootstrap {
        event.fields.effective_from_sequence
    } else {
        pre_transition_sequence(state, event.fields.effective_from_sequence)?
    };
    if bootstrap && !matches!(event.fields.change, RegistryChangeV1::Policy { .. }) {
        return Err(TrustError::ActionMismatch.into());
    }

    let effect = prepare_effect(trust, state, event, pre_transition_sequence, replay)?;
    let target_policy = match &effect {
        TransitionEffect::Policy(policy) => policy,
        _ => state.policy.as_ref().ok_or(TrustError::ActionMismatch)?,
    };
    if event.fields.policy_object_hash != target_policy.object_hash {
        return Err(RegistryError::PolicyMismatch);
    }
    validate_event_time_shape(&event.fields, &target_policy.fields)?;

    verify_bound_authorization(
        state,
        event.authorization_object_hash,
        event.object_hash,
        event.fields.issued_at,
        pre_transition_sequence,
        replay,
    )?;

    apply_effect(state, effect, event.fields.effective_from_sequence)?;
    state.registry_version = event.fields.registry_version;
    state.registry_head_hash = object_hash_as_hash32(event.object_hash)?;
    state.effective_from_sequence = event.fields.effective_from_sequence;
    state.valid_through_sequence = event.fields.valid_through_sequence;
    state.head_event = Some(event.fields.clone());
    Ok(pre_transition_sequence)
}

fn pre_transition_sequence(
    state: &PreviousHeadState,
    successor_effective: ChainSequence,
) -> Result<ChainSequence, RegistryError> {
    if successor_effective < state.effective_from_sequence {
        return Err(RegistryError::SequenceLease);
    }
    if successor_effective <= state.valid_through_sequence {
        return Ok(successor_effective);
    }
    if state
        .valid_through_sequence
        .get()
        .checked_add(1)
        .is_some_and(|next| successor_effective == ChainSequence::new(next))
    {
        return Ok(state.valid_through_sequence);
    }
    Err(RegistryError::SequenceLease)
}

fn prepare_effect(
    trust: &VerifiedTrust,
    state: &PreviousHeadState,
    event: &RegistryEvent,
    pre_transition_sequence: ChainSequence,
    replay: &mut AdminAuthorizationReplay,
) -> Result<TransitionEffect, RegistryError> {
    match &event.fields.change {
        RegistryChangeV1::Certificate { object_hash } => {
            let target = authorized_device_target(state, *object_hash)?;
            if target.fields.certificate_kind == CertificateKindV1::OrganizationAdmin
                || state
                    .certificates
                    .contains_key(&CertificateHash::from(*object_hash))
            {
                return Err(TrustError::ActionMismatch.into());
            }
            validate_device_target(
                &target,
                trust.organization_id(),
                event.fields.effective_from_sequence,
            )?;
            verify_bound_authorization(
                state,
                target.authorization_object_hash,
                *object_hash,
                event.fields.issued_at,
                pre_transition_sequence,
                replay,
            )?;
            Ok(TransitionEffect::ActivateCertificate(ActiveCertificate {
                object_hash: *object_hash,
                fields: target.fields,
            }))
        }
        RegistryChangeV1::Target {
            target_kind,
            object_hash,
        } => prepare_revocation(state, *target_kind, *object_hash, pre_transition_sequence),
        RegistryChangeV1::Policy { object_hash } => {
            let target = authorized_policy_target(state, *object_hash)?;
            validate_policy_target(state, &target.fields, *object_hash, event)?;
            verify_bound_authorization(
                state,
                target.authorization_object_hash,
                *object_hash,
                event.fields.issued_at,
                pre_transition_sequence,
                replay,
            )?;
            Ok(TransitionEffect::Policy(ResolvedPolicy {
                object_hash: *object_hash,
                fields: target.fields,
            }))
        }
        RegistryChangeV1::WriterTransition { object_hash } => {
            let target = authorized_writer_transition_target(state, *object_hash)?;
            validate_writer_transition_target(
                state,
                &target.fields,
                trust.chain_id(),
                trust.organization_id(),
                event.fields.effective_from_sequence,
                pre_transition_sequence,
            )?;
            verify_bound_authorization(
                state,
                target.authorization_object_hash,
                *object_hash,
                event.fields.issued_at,
                pre_transition_sequence,
                replay,
            )?;
            Ok(TransitionEffect::WriterTransition {
                object_hash: *object_hash,
                old_writer: target.fields.old_writer_certificate_hash,
                new_writer: target.fields.new_writer_certificate_hash,
            })
        }
        RegistryChangeV1::OperatorBinding { object_hash } => {
            let target = authorized_binding_target(state, *object_hash)?;
            validate_binding_target(
                state,
                &target.fields,
                trust.organization_id(),
                event.fields.effective_from_sequence,
            )?;
            verify_bound_authorization(
                state,
                target.authorization_object_hash,
                *object_hash,
                event.fields.issued_at,
                pre_transition_sequence,
                replay,
            )?;
            Ok(TransitionEffect::ActivateBinding(ActiveOperatorBinding {
                object_hash: *object_hash,
                fields: target.fields,
            }))
        }
        RegistryChangeV1::AdminCertificate {
            object_hash,
            effect,
        } => prepare_admin_change(
            trust,
            state,
            event,
            *object_hash,
            *effect,
            pre_transition_sequence,
            replay,
        ),
        RegistryChangeV1::RootCertificate { object_hash } => {
            let target = authorized_root_target(state, *object_hash)?;
            validate_root_target(state, &target, trust.organization_id(), event)?;
            verify_bound_authorization(
                state,
                target.authorization_object_hash,
                *object_hash,
                event.fields.issued_at,
                pre_transition_sequence,
                replay,
            )?;
            Ok(TransitionEffect::Root(RootAuthority {
                object_hash: *object_hash,
                fields: target.fields,
            }))
        }
    }
}

fn prepare_revocation(
    state: &PreviousHeadState,
    target_kind: u8,
    object_hash: ObjectHash,
    at_sequence: ChainSequence,
) -> Result<TransitionEffect, RegistryError> {
    match target_kind {
        0 | 2 => {
            let certificate_hash = CertificateHash::from(object_hash);
            let Some(certificate) = state.certificates.get(&certificate_hash) else {
                return classify_missing_certificate_target(state, object_hash, target_kind);
            };
            let class_matches = match target_kind {
                0 => matches!(
                    certificate.fields.certificate_kind,
                    CertificateKindV1::Writer
                        | CertificateKindV1::Reader
                        | CertificateKindV1::KeyApprover
                        | CertificateKindV1::RecoveryRecipient
                        | CertificateKindV1::HistoricalGrantAuthority
                ),
                2 => matches!(
                    certificate.fields.certificate_kind,
                    CertificateKindV1::ServerReceipt | CertificateKindV1::DeletionAttest
                ),
                _ => false,
            };
            if !class_matches || !certificate_active(certificate, at_sequence) {
                return Err(TrustError::ActionMismatch.into());
            }
            if target_kind == 0
                && certificate.fields.certificate_kind == CertificateKindV1::Writer
                && state.current_writer_certificate_hash == Some(certificate_hash)
            {
                return Err(TrustError::ActionMismatch.into());
            }
            Ok(TransitionEffect::RevokeCertificate(certificate_hash))
        }
        1 => {
            let Some(binding) = state.admin_bindings.get(&object_hash) else {
                return classify_missing_binding_target(state, object_hash);
            };
            if !binding_active(binding, at_sequence) {
                return Err(TrustError::ActionMismatch.into());
            }
            Ok(TransitionEffect::RevokeBinding(object_hash))
        }
        _ => Err(TrustError::ActionMismatch.into()),
    }
}

fn prepare_admin_change(
    trust: &VerifiedTrust,
    state: &PreviousHeadState,
    event: &RegistryEvent,
    object_hash: ObjectHash,
    effect: u8,
    pre_transition_sequence: ChainSequence,
    replay: &mut AdminAuthorizationReplay,
) -> Result<TransitionEffect, RegistryError> {
    match effect {
        0 => {
            if state
                .admin_certificates
                .contains_key(&CertificateHash::from(object_hash))
            {
                return Err(TrustError::ActionMismatch.into());
            }
            let target = authorized_device_target(state, object_hash)?;
            if target.fields.certificate_kind != CertificateKindV1::OrganizationAdmin
                || target.fields.authority_subject_id.is_none()
                || !target
                    .fields
                    .capabilities
                    .iter()
                    .any(|capability| capability == "organizationAdminApprove")
            {
                return Err(TrustError::ActionMismatch.into());
            }
            validate_device_target(
                &target,
                trust.organization_id(),
                event.fields.effective_from_sequence,
            )?;
            verify_bound_authorization(
                state,
                target.authorization_object_hash,
                object_hash,
                event.fields.issued_at,
                pre_transition_sequence,
                replay,
            )?;
            Ok(TransitionEffect::ActivateCertificate(ActiveCertificate {
                object_hash,
                fields: target.fields,
            }))
        }
        1 => {
            let certificate_hash = CertificateHash::from(object_hash);
            let Some(certificate) = state.admin_certificates.get(&certificate_hash) else {
                if state.catalog_object(object_hash).is_some() {
                    return Err(TrustError::ActionMismatch.into());
                }
                return Err(RegistryError::ActivationMissing);
            };
            if certificate.fields.certificate_kind != CertificateKindV1::OrganizationAdmin
                || !certificate_active(certificate, pre_transition_sequence)
            {
                return Err(TrustError::ActionMismatch.into());
            }
            Ok(TransitionEffect::RevokeCertificate(certificate_hash))
        }
        _ => Err(TrustError::ActionMismatch.into()),
    }
}

fn validate_device_target(
    target: &AuthorizedDeviceTarget,
    organization_id: ea_types::OrganizationId,
    effective_from: ChainSequence,
) -> Result<(), RegistryError> {
    if target.fields.organization_id != organization_id
        || target.fields.effective_from_sequence != effective_from
        || validate_signer_certificate(&target.exact_bytes).is_err()
    {
        return Err(TrustError::ActionMismatch.into());
    }
    Ok(())
}

fn validate_policy_target(
    state: &PreviousHeadState,
    fields: &PolicyFieldsV1,
    object_hash: ObjectHash,
    event: &RegistryEvent,
) -> Result<(), RegistryError> {
    let expected_version = state
        .policy
        .as_ref()
        .map_or(Some(1), |policy| {
            policy.fields.policy_version.checked_add(1)
        })
        .ok_or(RegistryError::PolicyMismatch)?;
    let expected_previous = state.policy.as_ref().map(|policy| policy.object_hash);
    if fields.organization_id != event.fields.organization_id
        || fields.effective_from_sequence != event.fields.effective_from_sequence
    {
        return Err(TrustError::ActionMismatch.into());
    }
    if fields.policy_version != expected_version
        || fields.previous_policy_object_hash != expected_previous
        || event.fields.policy_object_hash != object_hash
    {
        return Err(RegistryError::PolicyMismatch);
    }
    Ok(())
}

fn validate_writer_transition_target(
    state: &PreviousHeadState,
    fields: &WriterTransitionFieldsV1,
    chain_id: ChainId,
    organization_id: ea_types::OrganizationId,
    effective_from: ChainSequence,
    pre_transition_sequence: ChainSequence,
) -> Result<(), RegistryError> {
    if fields.organization_id != organization_id
        || fields.chain_id != chain_id
        || fields.effective_from_sequence != effective_from
        || fields.old_writer_certificate_hash == fields.new_writer_certificate_hash
    {
        return Err(TrustError::ActionMismatch.into());
    }
    let Some(old_writer) = state.certificates.get(&fields.old_writer_certificate_hash) else {
        return classify_writer_reference(state, fields.old_writer_certificate_hash);
    };
    if old_writer.fields.certificate_kind != CertificateKindV1::Writer
        || !certificate_active(old_writer, pre_transition_sequence)
    {
        return Err(TrustError::ActionMismatch.into());
    }
    let Some(new_writer) = state.certificates.get(&fields.new_writer_certificate_hash) else {
        return classify_writer_reference(state, fields.new_writer_certificate_hash);
    };
    if new_writer.fields.certificate_kind != CertificateKindV1::Writer
        || !certificate_active(new_writer, effective_from)
    {
        return Err(TrustError::ActionMismatch.into());
    }
    if state.current_writer_certificate_hash != Some(fields.old_writer_certificate_hash) {
        return Err(TrustError::ActionMismatch.into());
    }
    Ok(())
}

fn validate_binding_target(
    state: &PreviousHeadState,
    fields: &OperatorBindingFieldsV1,
    organization_id: ea_types::OrganizationId,
    effective_from: ChainSequence,
) -> Result<(), RegistryError> {
    if fields.organization_id != organization_id || fields.effective_from_sequence != effective_from
    {
        return Err(TrustError::ActionMismatch.into());
    }
    let Some(certificate) = state.certificates.get(&fields.device_certificate_hash) else {
        return classify_binding_certificate_reference(state, fields);
    };
    if !certificate_active(certificate, effective_from)
        || !role_matches(certificate.fields.certificate_kind, fields.operator_role)
        || certificate.fields.signing_key_thumbprint
            == Some(fields.operator_instance_key_thumbprint)
    {
        return Err(TrustError::ActionMismatch.into());
    }
    if fields.operator_role == OperatorRoleV1::OrganizationAdmin
        && certificate
            .fields
            .authority_subject_id
            .is_none_or(|subject| subject.as_bytes() != fields.operator_subject_id.as_bytes())
    {
        return Err(TrustError::ActionMismatch.into());
    }
    Ok(())
}

fn validate_root_target(
    state: &PreviousHeadState,
    target: &AuthorizedRootTarget,
    organization_id: ea_types::OrganizationId,
    event: &RegistryEvent,
) -> Result<(), RegistryError> {
    let key = CanonicalPublicCoseKey::from_deterministic_cbor(&target.fields.root_public_cose_key)
        .map_err(|_| TrustError::ActionMismatch)?;
    if target.fields.organization_id != organization_id
        || target.fields.previous_root_certificate_object_hash != Some(state.root.object_hash)
        || target.fields.effective_from_registry_version != event.fields.registry_version
        || target.fields.root_key_thumbprint != key.thumbprint()
        || !matches!(key, CanonicalPublicCoseKey::Ed25519(_))
        || validate_signer_certificate(&target.exact_bytes).is_err()
    {
        return Err(TrustError::ActionMismatch.into());
    }
    Ok(())
}

fn validate_event_time_shape(
    event: &RegistryEventFieldsV1,
    target_policy: &PolicyFieldsV1,
) -> Result<(), RegistryError> {
    if event.not_before > event.issued_at || event.issued_at >= event.not_after {
        return Err(RegistryError::PolicyMismatch);
    }
    let age = u64::try_from(i128::from(event.not_after.get()) - i128::from(event.issued_at.get()))
        .map_err(|_| RegistryError::PolicyMismatch)?;
    if age > target_policy.max_registry_age_ms {
        return Err(RegistryError::PolicyMismatch);
    }
    Ok(())
}

fn verify_bound_authorization(
    state: &PreviousHeadState,
    authorization_object_hash: ObjectHash,
    target_object_hash: ObjectHash,
    authorization_use_time: UnixMillis,
    pre_transition_sequence: ChainSequence,
    replay: &mut AdminAuthorizationReplay,
) -> Result<(), RegistryError> {
    let record = state
        .catalog_object(authorization_object_hash)
        .ok_or(RegistryError::ActivationMissing)?;
    let fields = match record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    {
        DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) => fields,
        _ => return Err(TrustError::ActionMismatch.into()),
    };
    if fields.registry_version != state.registry_version
        || fields.registry_head_hash != state.registry_head_hash
    {
        return Err(RegistryError::ActivationHead);
    }
    verify_admin_authorization(
        state,
        authorization_object_hash,
        target_object_hash,
        authorization_use_time,
        pre_transition_sequence,
        replay,
    )?;
    Ok(())
}

fn apply_effect(
    state: &mut PreviousHeadState,
    effect: TransitionEffect,
    revoked_from: ChainSequence,
) -> Result<(), RegistryError> {
    match effect {
        TransitionEffect::ActivateCertificate(certificate) => {
            let certificate_hash = CertificateHash::from(certificate.object_hash);
            let is_writer = certificate.fields.certificate_kind == CertificateKindV1::Writer;
            if state
                .certificates
                .insert(certificate_hash, certificate.clone())
                .is_some()
            {
                return Err(TrustError::ActionMismatch.into());
            }
            if certificate.fields.certificate_kind == CertificateKindV1::OrganizationAdmin
                && state
                    .admin_certificates
                    .insert(certificate_hash, certificate)
                    .is_some()
            {
                return Err(TrustError::ActionMismatch.into());
            }
            if is_writer && state.current_writer_certificate_hash.is_none() {
                state.current_writer_certificate_hash = Some(certificate_hash);
            }
        }
        TransitionEffect::RevokeCertificate(certificate_hash) => {
            state
                .certificates
                .get_mut(&certificate_hash)
                .ok_or(RegistryError::ActivationMissing)?
                .fields
                .revoked_from_sequence = Some(revoked_from);
            if let Some(certificate) = state.admin_certificates.get_mut(&certificate_hash) {
                certificate.fields.revoked_from_sequence = Some(revoked_from);
            }
        }
        TransitionEffect::RevokeBinding(object_hash) => {
            state
                .admin_bindings
                .get_mut(&object_hash)
                .ok_or(RegistryError::ActivationMissing)?
                .fields
                .revoked_from_sequence = Some(revoked_from);
        }
        TransitionEffect::ActivateBinding(binding) => {
            if state
                .admin_bindings
                .insert(binding.object_hash, binding)
                .is_some()
            {
                return Err(TrustError::ActionMismatch.into());
            }
        }
        TransitionEffect::Policy(policy) => state.policy = Some(policy),
        TransitionEffect::Root(root) => state.root = root,
        TransitionEffect::WriterTransition {
            object_hash,
            old_writer,
            new_writer,
        } => {
            if !state.apply_writer_transition(object_hash, old_writer, new_writer, revoked_from) {
                return Err(RegistryError::ActivationMissing);
            }
        }
    }
    Ok(())
}

fn certificate_active(certificate: &ActiveCertificate, at_sequence: ChainSequence) -> bool {
    certificate.fields.effective_from_sequence <= at_sequence
        && certificate
            .fields
            .revoked_from_sequence
            .is_none_or(|revoked| at_sequence < revoked)
}

fn binding_active(binding: &ActiveOperatorBinding, at_sequence: ChainSequence) -> bool {
    binding.fields.effective_from_sequence <= at_sequence
        && binding
            .fields
            .revoked_from_sequence
            .is_none_or(|revoked| at_sequence < revoked)
}

fn role_matches(kind: CertificateKindV1, role: OperatorRoleV1) -> bool {
    matches!(
        (kind, role),
        (CertificateKindV1::Writer, OperatorRoleV1::Writer)
            | (CertificateKindV1::Reader, OperatorRoleV1::Reader)
            | (
                CertificateKindV1::OrganizationAdmin,
                OperatorRoleV1::OrganizationAdmin
            )
    )
}

fn classify_missing_certificate_target(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
    target_kind: u8,
) -> Result<TransitionEffect, RegistryError> {
    let Some(record) = state.catalog_object(object_hash) else {
        return Err(RegistryError::ActivationMissing);
    };
    match record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    {
        DecodedTrustPayloadV1::AuthorizedDevice(core) => {
            let valid_class = match target_kind {
                0 => matches!(
                    core.fields().certificate_kind,
                    CertificateKindV1::Writer
                        | CertificateKindV1::Reader
                        | CertificateKindV1::KeyApprover
                        | CertificateKindV1::RecoveryRecipient
                        | CertificateKindV1::HistoricalGrantAuthority
                ),
                2 => matches!(
                    core.fields().certificate_kind,
                    CertificateKindV1::ServerReceipt | CertificateKindV1::DeletionAttest
                ),
                _ => false,
            };
            if valid_class {
                Err(RegistryError::ActivationMissing)
            } else {
                Err(TrustError::ActionMismatch.into())
            }
        }
        _ => Err(TrustError::ActionMismatch.into()),
    }
}

fn classify_missing_binding_target(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
) -> Result<TransitionEffect, RegistryError> {
    let Some(record) = state.catalog_object(object_hash) else {
        return Err(RegistryError::ActivationMissing);
    };
    match record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    {
        DecodedTrustPayloadV1::AuthorizedOperatorBinding(_) => {
            Err(RegistryError::ActivationMissing)
        }
        _ => Err(TrustError::ActionMismatch.into()),
    }
}

fn classify_writer_reference(
    state: &PreviousHeadState,
    certificate_hash: CertificateHash,
) -> Result<(), RegistryError> {
    let object_hash = object_hash_from_certificate(certificate_hash)?;
    let Some(record) = state.catalog_object(object_hash) else {
        return Err(RegistryError::ActivationMissing);
    };
    match record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    {
        DecodedTrustPayloadV1::AuthorizedDevice(core)
            if core.fields().certificate_kind == CertificateKindV1::Writer =>
        {
            Err(RegistryError::ActivationMissing)
        }
        _ => Err(TrustError::ActionMismatch.into()),
    }
}

fn classify_binding_certificate_reference(
    state: &PreviousHeadState,
    fields: &OperatorBindingFieldsV1,
) -> Result<(), RegistryError> {
    let object_hash = object_hash_from_certificate(fields.device_certificate_hash)?;
    let Some(record) = state.catalog_object(object_hash) else {
        return Err(RegistryError::ActivationMissing);
    };
    match record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    {
        DecodedTrustPayloadV1::AuthorizedDevice(core)
            if role_matches(core.fields().certificate_kind, fields.operator_role) =>
        {
            Err(RegistryError::ActivationMissing)
        }
        _ => Err(TrustError::ActionMismatch.into()),
    }
}

fn authorized_device_target(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
) -> Result<AuthorizedDeviceTarget, RegistryError> {
    let record = state
        .catalog_object(object_hash)
        .ok_or(RegistryError::ActivationMissing)?;
    let decoded = record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?;
    let DecodedTrustPayloadV1::AuthorizedDevice(core) = decoded else {
        return Err(TrustError::ActionMismatch.into());
    };
    Ok(AuthorizedDeviceTarget {
        fields: core.fields().clone(),
        authorization_object_hash: core.authorization_object_hash(),
        exact_bytes: record.exact_bytes().as_bytes().to_vec(),
    })
}

fn authorized_binding_target(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
) -> Result<AuthorizedBindingTarget, RegistryError> {
    let record = state
        .catalog_object(object_hash)
        .ok_or(RegistryError::ActivationMissing)?;
    let decoded = record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?;
    let DecodedTrustPayloadV1::AuthorizedOperatorBinding(core) = decoded else {
        return Err(TrustError::ActionMismatch.into());
    };
    Ok(AuthorizedBindingTarget {
        fields: core.fields().clone(),
        authorization_object_hash: core.authorization_object_hash(),
    })
}

fn authorized_policy_target(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
) -> Result<AuthorizedPolicyTarget, RegistryError> {
    let record = state
        .catalog_object(object_hash)
        .ok_or(RegistryError::ActivationMissing)?;
    let decoded = record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?;
    let DecodedTrustPayloadV1::Policy(core) = decoded else {
        return Err(TrustError::ActionMismatch.into());
    };
    Ok(AuthorizedPolicyTarget {
        fields: core.fields().clone(),
        authorization_object_hash: core.authorization_object_hash(),
    })
}

fn authorized_writer_transition_target(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
) -> Result<AuthorizedWriterTransitionTarget, RegistryError> {
    let record = state
        .catalog_object(object_hash)
        .ok_or(RegistryError::ActivationMissing)?;
    let decoded = record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?;
    let DecodedTrustPayloadV1::WriterTransition(core) = decoded else {
        return Err(TrustError::ActionMismatch.into());
    };
    Ok(AuthorizedWriterTransitionTarget {
        fields: core.fields().clone(),
        authorization_object_hash: core.authorization_object_hash(),
    })
}

fn authorized_root_target(
    state: &PreviousHeadState,
    object_hash: ObjectHash,
) -> Result<AuthorizedRootTarget, RegistryError> {
    let record = state
        .catalog_object(object_hash)
        .ok_or(RegistryError::ActivationMissing)?;
    let decoded = record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?;
    let DecodedTrustPayloadV1::AuthorizedRoot(core) = decoded else {
        return Err(TrustError::ActionMismatch.into());
    };
    Ok(AuthorizedRootTarget {
        fields: core.fields().clone(),
        authorization_object_hash: core.authorization_object_hash(),
        exact_bytes: record.exact_bytes().as_bytes().to_vec(),
    })
}

fn load_registry_event(
    catalog: &TrustCatalog,
    object_hash: ObjectHash,
) -> Result<RegistryEvent, RegistryError> {
    let record = catalog.get(&object_hash).ok_or(TrustError::Source)?;
    let DecodedTrustPayloadV1::RegistryEvent(core) = record
        .value()
        .decoded_payload()
        .map_err(|_| TrustError::Source)?
    else {
        return Err(TrustError::Source.into());
    };
    Ok(RegistryEvent {
        object_hash,
        fields: core.fields().clone(),
        authorization_object_hash: core.authorization_object_hash(),
    })
}

fn object_hash_as_hash32(object_hash: ObjectHash) -> Result<Hash32, RegistryError> {
    Hash32::try_from(&object_hash.as_bytes()[..]).map_err(|_| TrustError::Source.into())
}

fn object_hash_from_certificate(
    certificate_hash: CertificateHash,
) -> Result<ObjectHash, RegistryError> {
    ObjectHash::try_from(&certificate_hash.as_bytes()[..]).map_err(|_| TrustError::Source.into())
}

#[cfg(test)]
#[path = "registry/tests.rs"]
mod selection_tests;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ea_crypto::object_hash;
    use ea_format::{FreeTextPolicyFieldsV1, RetentionPolicyFieldsV1};
    use ea_time::TrustedTimeState;
    use ea_types::DeviceId;

    use super::*;
    use crate::{
        PersistedTrustRecord, TrustStateKey, decode_trust_anchor, load_trust_state,
        resolver::tests::{
            ADMIN_PUBLIC, ADMIN_TWO_PUBLIC, CatalogSource, SnapshotStore, exact_admin_binding,
            exact_admin_certificate, exact_anchor, exact_root_certificate, hash32, organization,
        },
        verify_trust,
    };

    #[test]
    fn current_candidate_owns_the_exact_reload_and_authority_context() {
        let root_bytes = exact_root_certificate();
        let root_hash = object_hash(&root_bytes);
        let admin_one = exact_admin_certificate(root_hash.into(), ADMIN_PUBLIC, 0x51, 0x41, None);
        let admin_two =
            exact_admin_certificate(root_hash.into(), ADMIN_TWO_PUBLIC, 0x52, 0x42, None);
        let admin_one_hash = object_hash(&admin_one);
        let admin_two_hash = object_hash(&admin_two);
        let binding_one = exact_admin_binding(
            root_hash.into(),
            admin_one_hash.into(),
            0x41,
            0x81,
            0x91,
            None,
        );
        let binding_two = exact_admin_binding(
            root_hash.into(),
            admin_two_hash.into(),
            0x42,
            0x82,
            0x92,
            None,
        );
        let binding_one_hash = object_hash(&binding_one);
        let binding_two_hash = object_hash(&binding_two);
        let anchor = decode_trust_anchor(&exact_anchor(
            root_hash,
            &[admin_one_hash, admin_two_hash],
            &[binding_one_hash, binding_two_hash],
        ))
        .unwrap();
        let source =
            CatalogSource::new([root_bytes, admin_one, admin_two, binding_one, binding_two]);
        let state_key = TrustStateKey {
            organization_id: organization(),
            device_id: DeviceId::try_from(&[0xf0; 16][..]).unwrap(),
        };
        let mut store = SnapshotStore {
            key: state_key,
            record: Some(PersistedTrustRecord::new(
                17,
                TrustedTimeState::initial(UnixMillis::new(1_700_000_000_000)),
                None,
            )),
        };
        let snapshot = load_trust_state(&mut store, state_key).unwrap();
        let trust = verify_trust(&anchor, &source, snapshot).unwrap();

        let policy_hash = object_hash(b"resolved current Policy");
        let policy = ResolvedPolicy {
            object_hash: policy_hash,
            fields: PolicyFieldsV1 {
                organization_id: organization(),
                policy_version: 1,
                previous_policy_object_hash: None,
                operating_profile: 0,
                max_registry_age_ms: 86_400_000,
                max_future_clock_skew_ms: 300_000,
                registry_expiry_behavior: 0,
                evidence_max_delay_ms: 60_000,
                reader_inactivity_ms: 900_000,
                reader_trust_refresh_ms: 86_400_000,
                reader_history_access_allowed: true,
                allowed_archive_profile_hashes: vec![hash32(0xa1)],
                backup_frequency_ms: 86_400_000,
                restore_test_interval_ms: 2_592_000_000,
                retention_policy: RetentionPolicyFieldsV1 {
                    minimum_retention_ms: Some(86_400_000),
                    destruction_enabled: true,
                    eds_privacy_decision_document_hash: Some(hash32(0xa2)),
                },
                free_text_policy: FreeTextPolicyFieldsV1 {
                    free_text_allowed: false,
                    rule_set_version: "candidate-contract".into(),
                    local_pattern_warning_enabled: true,
                },
                allowed_crypto_suite_ids: vec!["EINSATZARCHIV-SUITE-1".into()],
                allowed_format_versions: vec![1],
                effective_from_sequence: ChainSequence::new(1),
            },
        };
        let pin_hash = object_hash(b"selected Registry Head 1");
        let pin = RegistryHeadPin::new(RegistryVersion::new(1), pin_hash);
        let mut state = trust.previous_head().clone();
        state.registry_version = pin.registry_version();
        state.registry_head_hash = object_hash_as_hash32(pin_hash).unwrap();
        state.policy = Some(policy.clone());
        state.effective_from_sequence = ChainSequence::new(1);
        state.valid_through_sequence = ChainSequence::new(100);
        state.head_event = Some(RegistryEventFieldsV1 {
            organization_id: organization(),
            registry_version: pin.registry_version(),
            previous_registry_hash: None,
            effective_from_sequence: ChainSequence::new(1),
            valid_through_sequence: ChainSequence::new(100),
            issued_at: UnixMillis::new(100),
            not_before: UnixMillis::new(90),
            not_after: UnixMillis::new(1_000),
            policy_object_hash: policy_hash,
            change: RegistryChangeV1::Policy {
                object_hash: policy_hash,
            },
            root_key_thumbprint: state.root.fields.root_key_thumbprint,
        });

        let proposed_sequence = ChainSequence::new(50);
        let candidate = current_candidate(&trust, state, pin, proposed_sequence).unwrap();
        let authority = candidate.preexisting_authority.as_ref().unwrap();
        assert!(Arc::ptr_eq(&authority.inner, &candidate.candidate_state));
        assert!(candidate.target_policy.object_hash == policy_hash);
        assert!(candidate.guard_policy.object_hash == policy_hash);
        assert_eq!(
            candidate.head_event.registry_version,
            RegistryVersion::new(1)
        );
        assert!(candidate.state_key == state_key);
        assert_eq!(candidate.state_revision, 17);
        assert!(candidate.trusted_time == *trust.trusted_time());
        assert!(candidate.original_pin == Some(pin));
        assert_eq!(candidate.proposed_sequence, proposed_sequence);
        assert_eq!(candidate.pre_transition_sequence, proposed_sequence);
    }
}
