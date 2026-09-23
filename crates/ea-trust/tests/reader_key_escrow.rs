//! Zeugen des Trust-Kerns für Publikationsfreigabe und Escrow
//! (v1.1-Profil §3.1, DRK-457).
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;

use ea_trust::{
    AdminAuthorizationReplayDimension, AdminAuthorizationReplayKey, ClockReleaseReplayKey,
    IndependentTimeCommit, PersistedTrustRecord, RegistrySelectionCommit, StateStoreError,
    TrustError, TrustStateKey, TrustStateStore, consume_admin_authorization_intent,
    consume_reader_key_escrow_approval, verify_intended_trust_target,
    verify_reader_key_escrow_approval,
};
use ea_types::{CertificateHash, ObjectHash, OrganizationId};
use escrow_support::{
    Basis, EscrowLine, EscrowLineOptions, approval_core, escrow_line, select, signed_approval,
    tip_sequence,
};
use support::{ActionSpec, HeadOptions};

fn code<T>(result: Result<T, TrustError>) -> &'static str {
    match result {
        Ok(_) => "OK",
        Err(error) => error.code(),
    }
}

/// Eine Freigabe, gebunden an den gewählten Kopf der Linie.
fn fresh_approval(escrow: &EscrowLine, window: (u64, u64)) -> Vec<u8> {
    let (_, head) = select(&escrow.line, tip_sequence(&escrow.line));
    signed_approval(
        &escrow.line,
        &approval_core(&escrow.line, Basis::of_selected(&head), window, 0xa1),
    )
}

// ---------------------------------------------------------------------------
// Freigabe: Fenster, Kopf, Sequenz
// ---------------------------------------------------------------------------

#[test]
fn approval_is_valid_at_expires_at_and_expired_one_millisecond_later() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let bytes = fresh_approval(&escrow, (1_000, 1_300));
    let at_expiry = verify_reader_key_escrow_approval(&trust, &head, &bytes, millis(1_300));
    assert_eq!(code(at_expiry), "OK", "expiresAt itself is still valid");
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &bytes,
            millis(1_301)
        )),
        "EA-TRUST-AUTH-EXPIRED"
    );
}

#[test]
fn approval_before_issued_at_is_not_yet_valid() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let bytes = fresh_approval(&escrow, (1_000, 1_300));
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &bytes,
            millis(999)
        )),
        "EA-TRUST-AUTH-NOT-YET-VALID"
    );
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &bytes,
            millis(1_000)
        )),
        "OK"
    );
}

#[test]
fn approval_bound_to_another_registry_head_is_refused() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let previous = escrow.line.heads()[escrow.line.heads().len() - 2];
    let current = Basis::of_selected(&head);
    // Die Sequenz ist jeweils die vorgeschlagene des gewählten Kopfes, damit
    // allein die Kopfbindung abweist.
    let foreign_heads = [
        (
            "an older head of the line",
            Basis::of(&previous, current.sequence),
        ),
        (
            "the current version under a foreign hash",
            Basis {
                head_hash: support::hash32(0x5e),
                ..current
            },
        ),
    ];
    for (label, basis) in foreign_heads {
        let bytes = signed_approval(
            &escrow.line,
            &approval_core(&escrow.line, basis, (1_000, 1_300), 0xa2),
        );
        assert_eq!(
            code(verify_reader_key_escrow_approval(
                &trust,
                &head,
                &bytes,
                millis(1_100)
            )),
            "EA-TRUST-ACTION-MISMATCH",
            "{label}"
        );
    }
}

#[test]
fn approval_with_a_foreign_sequence_is_refused() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let mut basis = Basis::of_selected(&head);
    // Im Lease des Kopfes, aber nicht die vorgeschlagene Sequenz.
    basis.sequence += 1;
    let bytes = signed_approval(
        &escrow.line,
        &approval_core(&escrow.line, basis, (1_000, 1_300), 0xa3),
    );
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &bytes,
            millis(1_100)
        )),
        "EA-TRUST-ACTION-MISMATCH"
    );
}

#[test]
fn approval_of_a_foreign_organization_is_refused() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let mut core = approval_core(
        &escrow.line,
        Basis::of_selected(&head),
        (1_000, 1_300),
        0xa4,
    );
    core.organization_id = OrganizationId::try_from([0x99; 16].as_slice()).unwrap();
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &signed_approval(&escrow.line, &core),
            millis(1_100)
        )),
        "EA-TRUST-ACTION-MISMATCH"
    );
}

// ---------------------------------------------------------------------------
// Freigabe: Signierer
// ---------------------------------------------------------------------------

#[test]
fn approval_naming_the_root_or_a_key_approver_as_admin_is_refused() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    for (label, certificate, seed) in [
        (
            "root",
            CertificateHash::from(escrow.line.current_root_hash()),
            support::root_signing_secret(),
        ),
        (
            "key approver",
            escrow.approvers[0],
            support::device_signing_secret(),
        ),
    ] {
        let mut core = approval_core(
            &escrow.line,
            Basis::of_selected(&head),
            (1_000, 1_300),
            0xa5,
        );
        core.admin_certificate_object_hash = certificate;
        core.admin_key_thumbprint = support::device_signing_key(seed).thumbprint();
        let bytes = ea_testkit::reader_key_escrow_fixture::signed_reader_key_escrow_approval(
            &core,
            &ea_testkit::reader_key_escrow_fixture::FixtureTrustSigner {
                seed,
                certificate_hash: certificate,
            },
        );
        assert_eq!(
            code(verify_reader_key_escrow_approval(
                &trust,
                &head,
                &bytes,
                millis(1_100)
            )),
            "EA-TRUST-SIGNATURE",
            "{label}"
        );
    }
}

#[test]
fn approval_with_a_foreign_operator_binding_is_refused() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let mut core = approval_core(
        &escrow.line,
        Basis::of_selected(&head),
        (1_000, 1_300),
        0xa6,
    );
    // Die Bindung des ERSTEN Administrators neben dem Zertifikat des zweiten.
    core.admin_operator_binding_object_hash = escrow.line.bootstrap_admin_binding_hash();
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &signed_approval(&escrow.line, &core),
            millis(1_100)
        )),
        "EA-TRUST-SUBJECT-MISMATCH"
    );
}

/// Zusatzauflage aus dem Vertragsreview von (a): Ein widerrufener
/// Administrator darf seinen Widerruf weder über den Kopf VOR dem Widerruf
/// noch über eine ältere Sequenz umgehen. Kopf und Sequenz kommen aus dem
/// gewählten Kopf.
#[test]
fn a_revoked_admin_cannot_sign_with_an_older_head_or_an_older_sequence() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let before = *escrow.line.heads().last().unwrap();
    let revocation = escrow.line.push(
        ActionSpec::AdminRevoke {
            object_hash: escrow.line.second_bootstrap_admin_hash(),
        },
        HeadOptions::default(),
    );
    let (trust, head) = select(&escrow.line, revocation.effective_from.get());

    // Positivkontrolle der Lage: vor dem Widerruf trug dieselbe Freigabe.
    let (old_trust, old_head) = select(&escrow.line, before.effective_from.get());
    let old_basis = Basis::of_selected(&old_head);
    let old = signed_approval(
        &escrow.line,
        &approval_core(&escrow.line, old_basis, (1_000, 1_300), 0xa7),
    );
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &old_trust,
            &old_head,
            &old,
            millis(1_100)
        )),
        "OK"
    );

    // Fremder (älterer) Kopf nach dem Widerruf.
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &old,
            millis(1_100)
        )),
        "EA-TRUST-ACTION-MISMATCH",
        "the head before the revocation"
    );

    // Aktueller Kopf, aber eine ältere Sequenz, zu der der Administrator noch
    // aktiv war.
    let mut older_sequence = Basis::of_selected(&head);
    older_sequence.sequence = before.effective_from.get();
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &signed_approval(
                &escrow.line,
                &approval_core(&escrow.line, older_sequence, (1_000, 1_300), 0xa8),
            ),
            millis(1_100)
        )),
        "EA-TRUST-ACTION-MISMATCH",
        "an older sequence under the current head"
    );

    // Aktueller Kopf und seine Sequenz: der Administrator ist widerrufen.
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            &signed_approval(
                &escrow.line,
                &approval_core(
                    &escrow.line,
                    Basis::of_selected(&head),
                    (1_000, 1_300),
                    0xa9
                ),
            ),
            millis(1_100)
        )),
        "EA-TRUST-SIGNER-INACTIVE"
    );
}

#[test]
fn bytes_of_another_family_are_not_an_approval() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let policy = escrow
        .line
        .exact_object_bytes(escrow.line.current_policy_hash().unwrap());
    assert_eq!(
        code(verify_reader_key_escrow_approval(
            &trust,
            &head,
            policy,
            millis(1_100)
        )),
        "EA-TRUST-SOURCE"
    );
}

// ---------------------------------------------------------------------------
// Freigabe: Einmal-Speicher
// ---------------------------------------------------------------------------

/// Ein Einmal-Speicher im Speicher, der jeden Verbrauch protokolliert.
#[derive(Default)]
struct ReplayStore {
    consumed: Vec<(OrganizationId, AdminAuthorizationReplayDimension)>,
    calls: Vec<AdminAuthorizationReplayDimension>,
}

impl TrustStateStore for ReplayStore {
    fn load(&mut self, _key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn admin_authorization_consumed(
        &mut self,
        key: &AdminAuthorizationReplayKey,
    ) -> Result<bool, StateStoreError> {
        self.calls.push(key.dimension());
        let row = (key.organization_id(), key.dimension());
        if self.consumed.contains(&row) {
            return Ok(true);
        }
        self.consumed.push(row);
        Ok(false)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
}

/// Der Speicher ohne Sperre: die Vorgabe des Ports.
struct NoReplayStore;

impl TrustStateStore for NoReplayStore {
    fn load(&mut self, _key: TrustStateKey) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_independent_time(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &IndependentTimeCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn clock_release_consumed(
        &mut self,
        _key: &ClockReleaseReplayKey,
    ) -> Result<bool, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }

    fn commit_registry_selection(
        &mut self,
        _key: TrustStateKey,
        _expected_revision: u64,
        _commit: &RegistrySelectionCommit,
    ) -> Result<PersistedTrustRecord, StateStoreError> {
        Err(StateStoreError::Unavailable)
    }
}

#[test]
fn approval_spends_authorization_id_before_nonce() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let approval = verify_reader_key_escrow_approval(
        &trust,
        &head,
        &fresh_approval(&escrow, (1_000, 1_300)),
        millis(1_100),
    )
    .unwrap();
    let mut store = ReplayStore::default();
    consume_reader_key_escrow_approval(&mut store, &approval).unwrap();
    assert!(
        store.calls
            == [
                AdminAuthorizationReplayDimension::AuthorizationId(
                    approval.fields().authorization_id
                ),
                AdminAuthorizationReplayDimension::Nonce(approval.fields().nonce),
            ],
        "authorization-id first, then nonce, and nothing else"
    );
    assert!(approval.replay_keys()[0].organization_id() == support::organization());
}

#[test]
fn a_spent_approval_is_refused_twice() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let approval = verify_reader_key_escrow_approval(
        &trust,
        &head,
        &fresh_approval(&escrow, (1_000, 1_300)),
        millis(1_100),
    )
    .unwrap();
    let mut store = ReplayStore::default();
    consume_reader_key_escrow_approval(&mut store, &approval).unwrap();
    assert_eq!(
        code(consume_reader_key_escrow_approval(&mut store, &approval)),
        "EA-TRUST-AUTH-REPLAY"
    );
}

/// Der geteilte Namensraum (F8): eine Administrationsautorisierung und eine
/// Freigabe teilen `authorization-id` und `nonce` organisationsweit.
#[test]
fn an_approval_reusing_an_admin_authorization_id_or_nonce_is_a_replay() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    // Eine vorbereitete Administrationsautorisierung mit Kennung 0xa1 und
    // Nonce 0xe1 — genau die Werte, die `fresh_approval` trägt.
    let (_, intended) = escrow.line.prepare_unsigned(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::Reader,
            marker: 0x91,
            effective_from: None,
        },
        HeadOptions {
            direct_authorization_id: Some(0xa1),
            direct_nonce: Some(0xe1),
            ..HeadOptions::default()
        },
    );
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let admin_intent = verify_intended_trust_target(
        &trust,
        Some(&head),
        &intended,
        millis(100),
        head.proposed_sequence(),
    )
    .unwrap();
    let approval = verify_reader_key_escrow_approval(
        &trust,
        &head,
        &fresh_approval(&escrow, (1_000, 1_300)),
        millis(1_100),
    )
    .unwrap();

    let mut store = ReplayStore::default();
    consume_admin_authorization_intent(&mut store, &admin_intent).unwrap();
    assert_eq!(
        code(consume_reader_key_escrow_approval(&mut store, &approval)),
        "EA-TRUST-AUTH-REPLAY",
        "the authorization-id is already spent"
    );

    // Nur die Nonce geteilt: die Kennung ist frisch, die Nonce nicht.
    let mut store = ReplayStore::default();
    store.consumed.push((
        support::organization(),
        AdminAuthorizationReplayDimension::Nonce(approval.fields().nonce),
    ));
    assert_eq!(
        code(consume_reader_key_escrow_approval(&mut store, &approval)),
        "EA-TRUST-AUTH-REPLAY",
        "the nonce is already spent"
    );
}

#[test]
fn approval_consumption_without_a_replay_store_is_unavailable() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let approval = verify_reader_key_escrow_approval(
        &trust,
        &head,
        &fresh_approval(&escrow, (1_000, 1_300)),
        millis(1_100),
    )
    .unwrap();
    assert_eq!(
        code(consume_reader_key_escrow_approval(
            &mut NoReplayStore,
            &approval
        )),
        "EA-TRUST-STATE-UNAVAILABLE"
    );
}

#[test]
fn the_verified_approval_names_the_head_it_was_checked_against() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let bytes = fresh_approval(&escrow, (1_000, 1_300));
    let approval = verify_reader_key_escrow_approval(&trust, &head, &bytes, millis(1_100)).unwrap();
    assert!(approval.verified_registry_version() == head.registry_version());
    assert!(approval.verified_registry_head_hash() == head.registry_head_hash());
    assert!(approval.object_hash() == ea_crypto::object_hash(&bytes));
    assert_eq!(approval.exact_bytes(), bytes.as_slice());
    assert!(
        approval.signer_authority_subject_id()
            == ea_types::SubjectId::try_from([0x42; 16].as_slice()).unwrap()
    );
    let _: ObjectHash = approval.object_hash();
}

fn millis(value: i64) -> ea_types::UnixMillis {
    ea_types::UnixMillis::new(value)
}

// ---------------------------------------------------------------------------
// Escrow: Aufbau
// ---------------------------------------------------------------------------

use ea_format::{DecodedTrustPayloadV1, ReaderKeyEscrowCoreV1, TrustPayloadV1};
use ea_testkit::reader_key_escrow_fixture::{
    FixtureTrustSigner, escrow_core_hash, signed_reader_key_escrow,
    signed_reader_key_escrow_approval,
};
use ea_trust::{
    ReaderKeyEscrowHead, ReaderKeyEscrowStanding, SelectedRegistryHead, VerifiedReaderKeyEscrowSet,
    VerifiedTrust, verify_intended_reader_key_escrow, verify_reader_key_escrows,
    verify_signed_reader_key_escrow,
};
use escrow_support::{
    Enrollment, READER_KEM_SEED, escrow_bytes, escrow_core, publish_escrow, push_filler, root,
    subject, x25519_key,
};

const ESCROW_ISSUED_AT: u64 = 1_200;
const APPROVAL_WINDOW: (u64, u64) = (1_000, 1_300);

fn reader_subject() -> ea_types::SubjectId {
    subject(0xc1)
}

/// Die Freigabe-Basis: der letzte Kopf der Linie, Sequenz im Lease.
fn tip_basis(escrow: &EscrowLine) -> Basis {
    let tip = *escrow.line.heads().last().unwrap();
    Basis::of(&tip, tip.effective_from.get())
}

/// Ein Core für das Reader-Zertifikat der Linie.
fn reader_core(escrow: &EscrowLine) -> ReaderKeyEscrowCoreV1 {
    escrow_core(
        escrow,
        &escrow.reader,
        READER_KEM_SEED,
        reader_subject(),
        ESCROW_ISSUED_AT,
    )
}

/// Freigabe und Escrow zu `core`, konsistent gebunden, im Katalog.
fn publish(escrow: &mut EscrowLine, core: &ReaderKeyEscrowCoreV1, id: u8) -> ObjectHash {
    let approval = approval_core(&escrow.line, tip_basis(escrow), APPROVAL_WINDOW, id);
    publish_escrow(escrow, core, &approval).1
}

fn escrows_at_tip(escrow: &EscrowLine) -> Result<VerifiedReaderKeyEscrowSet, TrustError> {
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::Selected(&head))
}

fn escrows_at(
    trust: &VerifiedTrust,
    head: &SelectedRegistryHead,
) -> Result<VerifiedReaderKeyEscrowSet, TrustError> {
    verify_reader_key_escrows(trust, ReaderKeyEscrowHead::Selected(head))
}

fn set_code(result: Result<VerifiedReaderKeyEscrowSet, TrustError>) -> &'static str {
    code(result)
}

// ---------------------------------------------------------------------------
// Escrow: Positivkontrolle
// ---------------------------------------------------------------------------

#[test]
fn an_intact_escrow_chain_is_valid_and_exposes_its_bindings() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let escrow_hash = publish(&mut escrow, &core, 0xb1);
    let set = escrows_at_tip(&escrow).unwrap();
    assert_eq!(set.len(), 1);
    let verified = set.get(escrow_hash).unwrap();
    assert_eq!(verified.standing(), ReaderKeyEscrowStanding::Valid);
    assert!(verified.core() == &core);
    let key = verified.uniqueness_key();
    assert!(key.reader_certificate_object_hash() == escrow.reader.certificate);
    assert!(key.reader_subject_id() == reader_subject());
    assert!(key.organization_id() == support::organization());
    assert_eq!(
        verified.hpke_context().encode(),
        ea_format::ReaderKeyEscrowHpkeContextV1::from_escrow_core(&core).encode()
    );
    assert_eq!(
        code(verified.require_reader_kem_public_key(&x25519_key(READER_KEM_SEED))),
        "OK"
    );
    assert_eq!(
        code(verified.require_reader_kem_public_key(&x25519_key([0x0d; 32]))),
        "EA-TRUST-ACTION-MISMATCH"
    );
}

/// `verify_trust` prüft die Escrow-Familien NICHT: ein gefälschtes Escrow
/// liegt im Katalog, und erst die Mengenfunktion weist es ab. Konsumenten
/// MÜSSEN sie rufen.
#[test]
fn verify_trust_alone_carries_an_unverified_escrow() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let approval = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xb2);
    let (approval_bytes, _) = escrow_bytes(&escrow, &core, &approval);
    // Eine Wurzelsignatur über den richtigen Digest, aber mit dem falschen
    // Schlüssel.
    let forged = signed_reader_key_escrow(
        &core,
        ea_crypto::object_hash(&approval_bytes),
        &FixtureTrustSigner {
            seed: [0x0f; 32],
            certificate_hash: CertificateHash::from(escrow.line.current_root_hash()),
        },
    );
    escrow.line.add_object(approval_bytes);
    escrow.line.add_object(forged);
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    assert_eq!(set_code(escrows_at(&trust, &head)), "EA-TRUST-SIGNATURE");
}

// ---------------------------------------------------------------------------
// Escrow: Enrollment-Bindung (Pflichtzeuge „abweichende Enrollment-Version“)
// ---------------------------------------------------------------------------

/// Jede Variante ist eine VOLLSTÄNDIG konsistente Kette: der Corehash, die
/// Freigabe und die Wurzelsignatur passen zum veränderten Core. Einziger
/// Defekt ist die Enrollment-Bindung.
#[test]
fn escrow_with_a_deviating_enrollment_is_refused() {
    let base = {
        let mut escrow = escrow_line(EscrowLineOptions::default());
        push_filler(&mut escrow.line);
        escrow
    };
    let reader = base.reader;
    let after = base.line.heads()[reader.head.version.get() as usize];
    let before = base.line.heads()[reader.head.version.get() as usize - 2];
    let variants: [(&str, Enrollment); 4] = [
        // Version, Hash und Sequenz stimmen jeweils MITEINANDER überein —
        // nur hat dieser Kopf das Reader-Zertifikat nicht aktiviert.
        (
            "enrollment version one after the activation",
            Enrollment {
                version: after.version,
                head_hash: escrow_support::hash32_of(after.object_hash),
                sequence: after.effective_from,
                ..reader
            },
        ),
        (
            "enrollment version one before the activation",
            Enrollment {
                version: before.version,
                head_hash: escrow_support::hash32_of(before.object_hash),
                sequence: before.effective_from,
                ..reader
            },
        ),
        (
            "foreign enrollment head hash",
            Enrollment {
                head_hash: support::hash32(0x6e),
                ..reader
            },
        ),
        (
            "foreign enrollment sequence",
            Enrollment {
                sequence: ea_types::ChainSequence::new(reader.sequence.get() + 1),
                ..reader
            },
        ),
    ];
    for (label, enrollment) in variants {
        let mut escrow = EscrowLine {
            line: base.line.clone(),
            recovery: base.recovery,
            approvers: base.approvers.clone(),
            reader: base.reader,
            decoy: base.decoy,
        };
        let core = escrow_core(
            &escrow,
            &enrollment,
            READER_KEM_SEED,
            reader_subject(),
            ESCROW_ISSUED_AT,
        );
        publish(&mut escrow, &core, 0xb3);
        assert_eq!(
            set_code(escrows_at_tip(&escrow)),
            "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH",
            "{label}"
        );
    }

    // Positivkontrolle derselben Linie: die exakte Aktivierung trägt.
    let mut escrow = base;
    let core = reader_core(&escrow);
    publish(&mut escrow, &core, 0xb3);
    assert_eq!(set_code(escrows_at_tip(&escrow)), "OK");
}

#[test]
fn escrow_for_a_non_reader_certificate_is_refused() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    // Der Recovery-Empfänger als „Reader“, mit seinem EIGENEN aktivierenden
    // Kopf: nur die Art ist falsch.
    let recovery_head = escrow.line.heads()[1];
    let wrong = Enrollment {
        certificate: escrow.recovery,
        version: recovery_head.version,
        head_hash: escrow_support::hash32_of(recovery_head.object_hash),
        sequence: recovery_head.effective_from,
        head: recovery_head,
    };
    let core = escrow_core(
        &escrow,
        &wrong,
        READER_KEM_SEED,
        reader_subject(),
        ESCROW_ISSUED_AT,
    );
    publish(&mut escrow, &core, 0xb4);
    assert_eq!(
        set_code(escrows_at_tip(&escrow)),
        "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH"
    );
}

#[test]
fn escrow_with_a_deviating_recovery_certificate_is_refused() {
    let base = escrow_line(EscrowLineOptions::default());
    let mut late_recovery = EscrowLine {
        line: base.line.clone(),
        recovery: base.recovery,
        approvers: base.approvers.clone(),
        reader: base.reader,
        decoy: base.decoy,
    };
    // Ein zweiter Recovery-Empfänger, erst NACH dem Enrollment aktiv.
    let late = late_recovery.line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::RecoveryRecipient,
            marker: 0x62,
            effective_from: None,
        },
        HeadOptions {
            kem_public_key_override: Some(x25519_key(escrow_support::RECOVERY_KEM_SEED)),
            ..HeadOptions::default()
        },
    );
    type Mutation = Box<dyn Fn(&mut ReaderKeyEscrowCoreV1)>;
    let variants: [(&str, EscrowLine, Mutation); 3] = [
        (
            "recovery thumbprint differs",
            EscrowLine {
                line: base.line.clone(),
                recovery: base.recovery,
                approvers: base.approvers.clone(),
                reader: base.reader,
                decoy: base.decoy,
            },
            Box::new(|core| {
                core.recovery_kem_key_thumbprint = x25519_key([0x0e; 32]).thumbprint();
            }),
        ),
        (
            // Ein Reader mit genau dem KEM des Recovery-Empfängers: Abdruck
            // und Aktivität stimmen, nur die Art nicht.
            "recovery certificate of the wrong kind",
            escrow_line(EscrowLineOptions {
                decoy_reader_with_recovery_kem: true,
                ..EscrowLineOptions::default()
            }),
            Box::new(|_| {}),
        ),
        (
            "recovery certificate inactive at the enrollment",
            late_recovery,
            {
                let late = CertificateHash::from(late.direct_object_hash.unwrap());
                Box::new(move |core| core.recovery_certificate_object_hash = late)
            },
        ),
    ];
    for (label, mut escrow, mutate) in variants {
        let mut core = reader_core(&escrow);
        if let Some(decoy) = escrow.decoy {
            core.recovery_certificate_object_hash = decoy;
        }
        mutate(&mut core);
        publish(&mut escrow, &core, 0xb5);
        assert_eq!(
            set_code(escrows_at_tip(&escrow)),
            "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH",
            "{label}"
        );
    }
}

/// F6: Ein Folgekopf mit DERSELBEN `effective_from_sequence` ist legal. Die
/// historische Autorität weist genau diese Lage ab — die Enrollment-Bindung
/// darf deshalb nicht über sie laufen.
#[test]
fn escrow_stays_valid_when_the_next_head_shares_the_activation_sequence() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let reader = escrow.reader;
    escrow.line.push(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            effective_from: Some(reader.sequence.get()),
            valid_through: Some(reader.sequence.get() + 199),
            ..HeadOptions::default()
        },
    );
    let core = reader_core(&escrow);
    let escrow_hash = publish(&mut escrow, &core, 0xb6);
    // Eine Sequenz, die nur im Lease des Folgekopfes liegt.
    let (trust, head) = select(&escrow.line, reader.sequence.get() + 150);
    assert!(
        ea_trust::verify_historical_registry_authority(
            &trust,
            reader.version,
            reader.head.object_hash,
            reader.sequence,
        )
        .is_err(),
        "the historical authority refuses this legal line"
    );
    assert!(head.registry_version() == escrow.line.heads().last().unwrap().version);
    let set = escrows_at(&trust, &head).unwrap();
    assert_eq!(
        set.get(escrow_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::Valid
    );
}

#[test]
fn escrow_stays_valid_after_a_later_root_rotation() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let escrow_hash = publish(&mut escrow, &core, 0xb7);
    escrow.line.push(
        ActionSpec::RootRotate {
            previous_root_hash: None,
            effective_version: None,
        },
        HeadOptions::default(),
    );
    push_filler(&mut escrow.line);
    let set = escrows_at_tip(&escrow).unwrap();
    assert_eq!(
        set.get(escrow_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::Valid
    );
}

// ---------------------------------------------------------------------------
// Escrow: Freigabebindung, Randwert, Wurzel
// ---------------------------------------------------------------------------

#[test]
fn escrow_whose_approval_binds_other_fields_is_refused() {
    type Mutation = fn(&mut ea_format::ReaderKeyEscrowApprovalCoreV1, &EscrowLine);
    let variants: [(&str, Mutation); 3] = [
        ("another core hash", |approval, _| {
            approval.escrow_core_hash = support::hash32(0x7c);
        }),
        ("another reader certificate", |approval, escrow| {
            approval.reader_certificate_object_hash = escrow.recovery;
        }),
        ("another reader subject", |approval, _| {
            approval.reader_subject_id = subject(0xc2);
        }),
    ];
    for (label, mutate) in variants {
        let mut escrow = escrow_line(EscrowLineOptions::default());
        let core = reader_core(&escrow);
        let mut approval = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xb8);
        approval.escrow_core_hash = escrow_core_hash(&core);
        approval.reader_certificate_object_hash = core.reader_certificate_object_hash;
        approval.reader_subject_id = core.reader_subject_id;
        mutate(&mut approval, &escrow);
        let approval_bytes =
            signed_reader_key_escrow_approval(&approval, &escrow_support::admin(&escrow.line));
        let escrow_object = signed_reader_key_escrow(
            &core,
            ea_crypto::object_hash(&approval_bytes),
            &root(&escrow.line),
        );
        escrow.line.add_object(approval_bytes);
        escrow.line.add_object(escrow_object);
        assert_eq!(
            set_code(escrows_at_tip(&escrow)),
            "EA-TRUST-ACTION-MISMATCH",
            "{label}"
        );
    }
}

/// Pflichtzeuge „Freigabe genau auf dem Randwert expiresAt“ in der
/// Historie: die Freigabe wird zur wurzelsignierten Zeit des Escrows
/// bewertet (Ruling Q10).
#[test]
fn escrow_issued_exactly_at_approval_expiry_is_valid_and_one_millisecond_later_expired() {
    for (issued_at, expected) in [
        (APPROVAL_WINDOW.1, "OK"),
        (APPROVAL_WINDOW.1 + 1, "EA-TRUST-AUTH-EXPIRED"),
        (APPROVAL_WINDOW.0 - 1, "EA-TRUST-AUTH-NOT-YET-VALID"),
    ] {
        let mut escrow = escrow_line(EscrowLineOptions::default());
        let core = escrow_core(
            &escrow,
            &escrow.reader,
            READER_KEM_SEED,
            reader_subject(),
            issued_at,
        );
        publish(&mut escrow, &core, 0xb9);
        assert_eq!(
            set_code(escrows_at_tip(&escrow)),
            expected,
            "issued at {issued_at}"
        );
    }
}

#[test]
fn escrow_naming_another_root_thumbprint_is_refused() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let mut core = reader_core(&escrow);
    core.root_key_thumbprint = support::device_signing_key([0x0c; 32]).thumbprint();
    publish(&mut escrow, &core, 0xba);
    assert_eq!(
        set_code(escrows_at_tip(&escrow)),
        "EA-TRUST-ACTION-MISMATCH"
    );
}

#[test]
fn escrow_without_its_approval_in_the_catalog_is_a_source_failure() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let approval = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xbb);
    let (_, escrow_object) = escrow_bytes(&escrow, &core, &approval);
    escrow.line.add_object(escrow_object);
    assert_eq!(set_code(escrows_at_tip(&escrow)), "EA-TRUST-SOURCE");
}

// ---------------------------------------------------------------------------
// Escrow: Zeremonie A (Intent vor, Zuschreibung nach der Wurzelsignatur)
// ---------------------------------------------------------------------------

fn intended_payload(
    core: &ReaderKeyEscrowCoreV1,
    approval: ObjectHash,
) -> ea_format::ReaderKeyEscrowPayloadV1 {
    let payload = TrustPayloadV1::reader_key_escrow(core.clone(), approval).unwrap();
    let DecodedTrustPayloadV1::ReaderKeyEscrow(payload) = payload.decoded_payload().unwrap() else {
        panic!("an escrow payload")
    };
    payload
}

#[test]
fn intended_escrow_is_checked_before_the_root_signs_and_the_signed_bytes_must_match() {
    let escrow = escrow_line(EscrowLineOptions::default());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let core = reader_core(&escrow);
    let mut approval_fields = approval_core(
        &escrow.line,
        Basis::of_selected(&head),
        APPROVAL_WINDOW,
        0xbc,
    );
    approval_fields.escrow_core_hash = escrow_core_hash(&core);
    approval_fields.reader_certificate_object_hash = core.reader_certificate_object_hash;
    approval_fields.reader_subject_id = core.reader_subject_id;
    let approval_bytes = signed_approval(&escrow.line, &approval_fields);
    let approval =
        verify_reader_key_escrow_approval(&trust, &head, &approval_bytes, millis(1_100)).unwrap();

    let intended = intended_payload(&core, approval.object_hash());
    let intent = verify_intended_reader_key_escrow(&trust, &head, &approval, &intended).unwrap();
    assert!(intent.payload() == &intended);
    assert!(
        intent.root_certificate_hash() == CertificateHash::from(escrow.line.current_root_hash())
    );

    let signed = signed_reader_key_escrow(&core, approval.object_hash(), &root(&escrow.line));
    let verified = verify_signed_reader_key_escrow(&intent, &signed).unwrap();
    assert_eq!(verified.standing(), ReaderKeyEscrowStanding::Valid);
    assert!(verified.object_hash() == ea_crypto::object_hash(&signed));

    // Andere Bytes als der Intent: ein anderer Core unter derselben Freigabe.
    let mut other = core.clone();
    other.issued_at = millis(1_250);
    let other_signed =
        signed_reader_key_escrow(&other, approval.object_hash(), &root(&escrow.line));
    assert_eq!(
        code(verify_signed_reader_key_escrow(&intent, &other_signed)),
        "EA-TRUST-ACTION-MISMATCH"
    );
    // Dieselben Bytes, aber nicht von der Wurzel signiert.
    let forged = signed_reader_key_escrow(
        &core,
        approval.object_hash(),
        &FixtureTrustSigner {
            seed: [0x0b; 32],
            certificate_hash: CertificateHash::from(escrow.line.current_root_hash()),
        },
    );
    assert_eq!(
        code(verify_signed_reader_key_escrow(&intent, &forged)),
        "EA-TRUST-SIGNATURE"
    );
    // Eine andere Freigabe in der Nutzlast.
    assert_eq!(
        code(verify_intended_reader_key_escrow(
            &trust,
            &head,
            &approval,
            &intended_payload(&core, support::object_hash_marker(0x3d))
        )),
        "EA-TRUST-ACTION-MISMATCH"
    );
}

#[test]
fn an_approval_verified_against_an_older_head_carries_no_intent() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let (old_trust, old_head) = select(&escrow.line, tip_sequence(&escrow.line));
    let core = reader_core(&escrow);
    let mut approval_fields = approval_core(
        &escrow.line,
        Basis::of_selected(&old_head),
        APPROVAL_WINDOW,
        0xbd,
    );
    approval_fields.escrow_core_hash = escrow_core_hash(&core);
    approval_fields.reader_certificate_object_hash = core.reader_certificate_object_hash;
    approval_fields.reader_subject_id = core.reader_subject_id;
    let approval = verify_reader_key_escrow_approval(
        &old_trust,
        &old_head,
        &signed_approval(&escrow.line, &approval_fields),
        millis(1_100),
    )
    .unwrap();
    push_filler(&mut escrow.line);
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    assert_eq!(
        code(verify_intended_reader_key_escrow(
            &trust,
            &head,
            &approval,
            &intended_payload(&core, approval.object_hash())
        )),
        "EA-TRUST-ACTION-MISMATCH"
    );
}

// ---------------------------------------------------------------------------
// Bestand: Eindeutigkeit, Widerruf, Ersatz (Entscheidungen 3a/5, Ruling F4)
// ---------------------------------------------------------------------------

use escrow_support::{SECOND_READER_KEM_SEED, push_reader, push_revocation};

/// Eine Linie mit ZWEI aktiven Readern.
fn two_reader_line() -> (EscrowLine, Enrollment) {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let second = push_reader(&mut escrow.line, 0x82, SECOND_READER_KEM_SEED);
    (escrow, second)
}

/// Pflichtzeuge: ein zweites Escrow zu derselben Subject-ID mit anderem
/// Reader-Zertifikat. Beide Objekte sind je für sich voll gültig.
#[test]
fn second_escrow_for_the_same_subject_with_another_certificate_is_a_conflict() {
    let (mut escrow, second) = two_reader_line();
    let first_core = reader_core(&escrow);
    publish(&mut escrow, &first_core, 0xc1);
    let mut control = EscrowLine {
        line: escrow.line.clone(),
        recovery: escrow.recovery,
        approvers: escrow.approvers.clone(),
        reader: escrow.reader,
        decoy: None,
    };

    let same_subject = escrow_core(
        &escrow,
        &second,
        SECOND_READER_KEM_SEED,
        reader_subject(),
        ESCROW_ISSUED_AT,
    );
    publish(&mut escrow, &same_subject, 0xc2);
    assert_eq!(
        set_code(escrows_at_tip(&escrow)),
        "EA-TRUST-ESCROW-CONFLICT"
    );

    // Positivkontrolle: dasselbe zweite Escrow unter einem anderen Subjekt.
    let other_subject = escrow_core(
        &control,
        &second,
        SECOND_READER_KEM_SEED,
        subject(0xc9),
        ESCROW_ISSUED_AT,
    );
    publish(&mut control, &other_subject, 0xc2);
    assert_eq!(escrows_at_tip(&control).unwrap().len(), 2);
}

/// Pflichtzeuge: ein zweites Escrow zu demselben Reader-Zertifikat — mit
/// anderer Subject-ID und, als Zweitescrow, mit derselben in anderen Bytes.
#[test]
fn second_escrow_for_the_same_certificate_is_a_conflict() {
    for (label, second_subject, second_issued_at) in [
        ("another subject", subject(0xc3), ESCROW_ISSUED_AT),
        (
            "same subject, other bytes",
            reader_subject(),
            ESCROW_ISSUED_AT + 50,
        ),
    ] {
        let mut escrow = escrow_line(EscrowLineOptions::default());
        let first = reader_core(&escrow);
        publish(&mut escrow, &first, 0xc4);
        let second = escrow_core(
            &escrow,
            &escrow.reader,
            READER_KEM_SEED,
            second_subject,
            second_issued_at,
        );
        publish(&mut escrow, &second, 0xc5);
        assert_eq!(
            set_code(escrows_at_tip(&escrow)),
            "EA-TRUST-ESCROW-CONFLICT",
            "{label}"
        );
    }
}

/// F4: ein Widerspruch lässt den GANZEN Bestand scheitern, auch wenn ein
/// drittes, unbeteiligtes Escrow gültig ist.
#[test]
fn two_contradicting_valid_escrows_fail_the_whole_set() {
    let (mut escrow, second) = two_reader_line();
    let third = push_reader(&mut escrow.line, 0x83, [0xb5; 32]);
    let unrelated = reader_core(&escrow);
    publish(&mut escrow, &unrelated, 0xc6);
    for (enrollment, kem, id) in [
        (second, SECOND_READER_KEM_SEED, 0xc7),
        (third, [0xb5; 32], 0xc8),
    ] {
        let core = escrow_core(&escrow, &enrollment, kem, subject(0xca), ESCROW_ISSUED_AT);
        publish(&mut escrow, &core, id);
    }
    assert_eq!(
        set_code(escrows_at_tip(&escrow)),
        "EA-TRUST-ESCROW-CONFLICT"
    );
}

/// F4: ist das Reader-Zertifikat im gewählten Kopf widerrufen, ist das
/// Escrow voll geprüft, zählt aber nicht zur Eindeutigkeit.
#[test]
fn escrow_of_a_revoked_reader_is_revoked_standing_and_not_counted() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let escrow_hash = publish(&mut escrow, &core, 0xcb);
    push_revocation(&mut escrow.line, escrow.reader.certificate);
    let set = escrows_at_tip(&escrow).unwrap();
    assert_eq!(
        set.get(escrow_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::ReaderRevoked
    );
    assert!(
        set.valid_for_reader_certificate(escrow.reader.certificate)
            .is_none()
    );
    assert!(set.valid_for_subject(reader_subject()).is_none());
}

/// F4/E: Ersatz = altes Zertifikat widerrufen, neues aktivieren, normale
/// Publikation mit EIGENER Freigabe. Das alte Objekt bleibt unverändert.
#[test]
fn replacement_after_revocation_with_its_own_approval_is_valid() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let old_core = reader_core(&escrow);
    let old_hash = publish(&mut escrow, &old_core, 0xcc);
    let before_revocation = *escrow.line.heads().last().unwrap();
    push_revocation(&mut escrow.line, escrow.reader.certificate);
    let replacement_reader = push_reader(&mut escrow.line, 0x84, SECOND_READER_KEM_SEED);
    let new_core = escrow_core(
        &escrow,
        &replacement_reader,
        SECOND_READER_KEM_SEED,
        reader_subject(),
        ESCROW_ISSUED_AT,
    );
    let new_hash = publish(&mut escrow, &new_core, 0xcd);

    let set = escrows_at_tip(&escrow).unwrap();
    assert_eq!(set.len(), 2);
    assert_eq!(
        set.get(old_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::ReaderRevoked
    );
    assert_eq!(
        set.get(new_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::Valid
    );
    assert!(
        set.valid_for_subject(reader_subject())
            .unwrap()
            .object_hash()
            == new_hash
    );

    // F4: ein Kopf VOR dem Widerruf sieht das alte Escrow gültig und das
    // neue noch nicht wirksam — und scheitert nicht.
    let (trust, head) = select(&escrow.line, before_revocation.effective_from.get());
    let old_view = escrows_at(&trust, &head).unwrap();
    assert_eq!(
        old_view.get(old_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::Valid
    );
    assert_eq!(
        old_view.get(new_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::NotYetEffective
    );
}

/// Q2: ein Pin jenseits des gewählten Kopfes wird trotzdem VOLL geprüft.
#[test]
fn an_escrow_beyond_the_selected_head_is_fully_checked() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let before = escrow.line.heads()[escrow.line.heads().len() - 2];
    let core = reader_core(&escrow);
    let valid_hash = publish(&mut escrow, &core, 0xce);
    let (trust, head) = select(&escrow.line, before.effective_from.get());
    assert_eq!(
        escrows_at(&trust, &head)
            .unwrap()
            .get(valid_hash)
            .unwrap()
            .standing(),
        ReaderKeyEscrowStanding::NotYetEffective
    );

    // Dasselbe, aber mit gefälschter Wurzelsignatur: der Bestand scheitert
    // auch am alten Kopf.
    let mut forged_line = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&forged_line);
    let approval = approval_core(
        &forged_line.line,
        tip_basis(&forged_line),
        APPROVAL_WINDOW,
        0xcf,
    );
    let (approval_bytes, _) = escrow_bytes(&forged_line, &core, &approval);
    let forged = signed_reader_key_escrow(
        &core,
        ea_crypto::object_hash(&approval_bytes),
        &FixtureTrustSigner {
            seed: [0x0a; 32],
            certificate_hash: CertificateHash::from(forged_line.line.current_root_hash()),
        },
    );
    forged_line.line.add_object(approval_bytes);
    forged_line.line.add_object(forged);
    let (trust, head) = select(&forged_line.line, before.effective_from.get());
    assert_eq!(set_code(escrows_at(&trust, &head)), "EA-TRUST-SIGNATURE");
}

/// Kein Familienobjekt wird übersprungen: auch eine Freigabe, die kein
/// Escrow nennt, wird geprüft.
#[test]
fn a_forged_orphan_approval_fails_the_set() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xd0);
    let forged = signed_reader_key_escrow_approval(
        &core,
        &FixtureTrustSigner {
            seed: [0x09; 32],
            certificate_hash: CertificateHash::from(escrow.line.second_bootstrap_admin_hash()),
        },
    );
    escrow.line.add_object(forged);
    assert_eq!(set_code(escrows_at_tip(&escrow)), "EA-TRUST-SIGNATURE");

    // Positivkontrolle: eine echte verwaiste Freigabe ist unauffällig.
    let mut control = escrow_line(EscrowLineOptions::default());
    let core = approval_core(&control.line, tip_basis(&control), APPROVAL_WINDOW, 0xd0);
    let approval = signed_approval(&control.line, &core);
    control.line.add_object(approval);
    assert!(escrows_at_tip(&control).unwrap().is_empty());
}

/// Ohne gewählten Kopf (Datei-Modus) gilt das Ende der Katalog-Linie — und es
/// sieht dasselbe wie der gewählte letzte Kopf.
#[test]
fn catalog_line_tip_equals_the_selected_tip() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&escrow);
    let escrow_hash = publish(&mut escrow, &core, 0xd1);
    push_revocation(&mut escrow.line, escrow.reader.certificate);
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let selected = escrows_at(&trust, &head).unwrap();
    let tip = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::CatalogLineTip).unwrap();
    assert_eq!(selected.len(), tip.len());
    assert_eq!(
        tip.get(escrow_hash).unwrap().standing(),
        selected.get(escrow_hash).unwrap().standing()
    );
    assert_eq!(
        tip.get(escrow_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::ReaderRevoked
    );
}

/// Zeremonie A gegen den Bestand: ein Intent für ein Reader-Zertifikat, das
/// schon ein anderes gültiges Escrow trägt, scheitert; für ein widerrufenes
/// Reader-Zertifikat gibt es keinen Intent.
#[test]
fn an_intent_respects_uniqueness_and_revocation() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let existing = reader_core(&escrow);
    publish(&mut escrow, &existing, 0xd2);
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let second = escrow_core(
        &escrow,
        &escrow.reader,
        READER_KEM_SEED,
        subject(0xd3),
        ESCROW_ISSUED_AT,
    );
    let intent_for = |core: &ReaderKeyEscrowCoreV1,
                      trust: &VerifiedTrust,
                      head: &SelectedRegistryHead,
                      line: &EscrowLine| {
        let mut fields = approval_core(&line.line, Basis::of_selected(head), APPROVAL_WINDOW, 0xd4);
        fields.escrow_core_hash = escrow_core_hash(core);
        fields.reader_certificate_object_hash = core.reader_certificate_object_hash;
        fields.reader_subject_id = core.reader_subject_id;
        let approval = verify_reader_key_escrow_approval(
            trust,
            head,
            &signed_approval(&line.line, &fields),
            millis(1_100),
        )
        .unwrap();
        code(verify_intended_reader_key_escrow(
            trust,
            head,
            &approval,
            &intended_payload(core, approval.object_hash()),
        ))
    };
    assert_eq!(
        intent_for(&second, &trust, &head, &escrow),
        "EA-TRUST-ESCROW-CONFLICT"
    );

    let mut revoked = escrow_line(EscrowLineOptions::default());
    push_revocation(&mut revoked.line, revoked.reader.certificate);
    let (trust, head) = select(&revoked.line, tip_sequence(&revoked.line));
    let core = reader_core(&revoked);
    // Die Freigabe selbst scheitert schon daran, dass der Reader zu ihrer
    // Sequenz nicht mehr aktiv ist — die Enrollment-Regel.
    assert_eq!(
        intent_for(&core, &trust, &head, &revoked),
        "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH"
    );
}

// ---------------------------------------------------------------------------
// Datei-Modus ohne Familienobjekte (Scheibe f, F1)
// ---------------------------------------------------------------------------

use escrow_support::recovery_core;
use escrow_support::signed_recovery;

/// Hängt an die Linie einen Kopf, dessen Registry-Version eine Lücke lässt:
/// `replay_to_line_tip` erreicht die Spitze der Katalog-Linie nicht mehr.
/// `verify_trust` selbst bleibt dabei grün — geprüft wird nur der Pin.
fn with_line_gap(line: &mut support::RegistryLineBuilder) {
    let skipped = line.heads().last().unwrap().version.get() + 2;
    line.add_branch(
        ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: None,
        },
        HeadOptions {
            registry_version: Some(skipped),
            ..HeadOptions::default()
        },
    );
}

/// Der Bestand wie im Datei-Modus: frischer flüchtiger Zustand, kein Pin.
fn trust_without_pin(line: &support::RegistryLineBuilder) -> VerifiedTrust {
    let anchor = ea_trust::decode_trust_anchor(line.exact_anchor_bytes()).unwrap();
    let key = state::verification_state_key(anchor.organization_id());
    let mut store = state::EphemeralTrustStateStore::new(key, escrow_support::SELECTION_NOW);
    let snapshot = ea_trust::load_trust_state(&mut store, key).unwrap();
    ea_trust::verify_trust(&anchor, &line.source(), snapshot).unwrap()
}

/// Ein Katalog ohne ein einziges Objekt der drei Escrow-Familien hat keine
/// Escrow-Menge zu prüfen: der Datei-Modus spielt die Linie dann gar nicht
/// erst nach. Sonst kippte das Gate `trust` jedes Archivs ohne Escrow, dessen
/// Katalog-Linie offline nicht bis zur Spitze nachspielbar ist.
#[test]
fn a_catalog_without_escrow_family_objects_is_not_replayed_to_its_line_tip() {
    let mut bare = escrow_line(EscrowLineOptions::default());
    with_line_gap(&mut bare.line);
    let set = verify_reader_key_escrows(
        &trust_without_pin(&bare.line),
        ReaderKeyEscrowHead::CatalogLineTip,
    )
    .unwrap();
    assert!(set.is_empty());
}

/// Gegenprobe zu oben, je Familie: liegt auch nur EIN Objekt einer der drei
/// Familien im selben Katalog, wird nachgespielt, und die Lücke lässt die
/// ganze Menge scheitern (Ruling Q11) — auch eine verwaiste Freigabe oder
/// eine verwaiste Öffnungsautorisierung zählt.
#[test]
fn any_escrow_family_object_forces_the_line_tip_replay() {
    // Kontrolle ohne Lücke: der Befund mit Lücke stammt allein aus dem
    // Nachspielen der Linie (der Registry-Befund wird wie jeder Pin-Fehler
    // als ACTION-MISMATCH gemeldet). Die verwaiste Öffnungsautorisierung nennt
    // ein Escrow, das es nicht gibt — ohne Lücke meldet sie das (SOURCE).
    let gap_code = |escrow: &mut EscrowLine, without_gap: &str| {
        let intact = verify_reader_key_escrows(
            &trust_without_pin(&escrow.line),
            ReaderKeyEscrowHead::CatalogLineTip,
        );
        assert_eq!(set_code(intact), without_gap, "control without gap");
        with_line_gap(&mut escrow.line);
        set_code(verify_reader_key_escrows(
            &trust_without_pin(&escrow.line),
            ReaderKeyEscrowHead::CatalogLineTip,
        ))
    };

    let mut with_escrow = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&with_escrow);
    publish(&mut with_escrow, &core, 0xe1);
    assert_eq!(gap_code(&mut with_escrow, "OK"), "EA-TRUST-ACTION-MISMATCH");

    let mut orphan_approval = escrow_line(EscrowLineOptions::default());
    let fields = approval_core(
        &orphan_approval.line,
        tip_basis(&orphan_approval),
        APPROVAL_WINDOW,
        0xe2,
    );
    let approval = signed_approval(&orphan_approval.line, &fields);
    orphan_approval.line.add_object(approval);
    assert_eq!(
        gap_code(&mut orphan_approval, "OK"),
        "EA-TRUST-ACTION-MISMATCH"
    );

    let mut orphan_recovery = escrow_line(EscrowLineOptions::default());
    let core = reader_core(&orphan_recovery);
    let recovery = signed_recovery(
        &recovery_core(
            ObjectHash::try_from([0xe3; 32].as_slice()).unwrap(),
            &core,
            tip_basis(&orphan_recovery),
            APPROVAL_WINDOW,
            0xe3,
        ),
        &orphan_recovery.approvers,
    );
    orphan_recovery.line.add_object(recovery);
    assert_eq!(
        gap_code(&mut orphan_recovery, "EA-TRUST-SOURCE"),
        "EA-TRUST-ACTION-MISMATCH"
    );
}
