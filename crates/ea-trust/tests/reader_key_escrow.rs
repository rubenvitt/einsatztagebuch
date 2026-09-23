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
