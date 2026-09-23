//! Zeugen des Trust-Kerns für die Öffnungsautorisierung des Reader-Key-Escrows
//! (v1.1-Profil §3.1 und §6, DRK-457).
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;

use ea_format::{
    ParsedArchiveObject, ReaderKeyEscrowCoreV1, ReaderKeyEscrowRecoveryAuthorizationCoreV1,
    TrustObjectV1, TrustPayloadV1, encode_trust,
};
use ea_trust::{
    AdminAuthorizationReplayDimension, AdminAuthorizationReplayKey, ClockReleaseReplayKey,
    IndependentTimeCommit, PersistedTrustRecord, ReaderKeyEscrowHead, ReaderKeyEscrowStanding,
    RegistrySelectionCommit, SelectedRegistryHead, StateStoreError, TrustError, TrustStateKey,
    TrustStateStore, VerifiedTrust, consume_reader_key_escrow_approval,
    consume_reader_key_escrow_recovery_authorization, verify_reader_key_escrow_approval,
    verify_reader_key_escrow_recovery_authorization, verify_reader_key_escrows,
};
use ea_types::{CertificateHash, ObjectHash, OrganizationId, SubjectId, UnixMillis};
use escrow_support::{
    Basis, EscrowLine, EscrowLineOptions, READER_KEM_SEED, TRANSPORT_KEM_SEED, approval_core,
    escrow_core, escrow_line, publish_escrow, push_revocation, recovery_core, select,
    signed_approval, signed_recovery, subject, tip_sequence, x25519_key, x25519_public,
};

const RECOVERY_WINDOW: (u64, u64) = (2_000, 2_900);
const NOW: i64 = 2_100;

fn code<T>(result: Result<T, TrustError>) -> &'static str {
    match result {
        Ok(_) => "OK",
        Err(error) => error.code(),
    }
}

fn millis(value: i64) -> UnixMillis {
    UnixMillis::new(value)
}

/// Eine Linie mit veröffentlichtem, gültigem Escrow.
struct Published {
    escrow: EscrowLine,
    core: ReaderKeyEscrowCoreV1,
    escrow_hash: ObjectHash,
}

fn published(options: EscrowLineOptions) -> Published {
    let mut escrow = escrow_line(options);
    let core = escrow_core(
        &escrow,
        &escrow.reader,
        READER_KEM_SEED,
        subject(0xc1),
        1_200,
    );
    let tip = *escrow.line.heads().last().unwrap();
    let approval = approval_core(
        &escrow.line,
        Basis::of(&tip, tip.effective_from.get()),
        (1_000, 1_300),
        0xe1,
    );
    let (_, escrow_hash) = publish_escrow(&mut escrow, &core, &approval);
    Published {
        escrow,
        core,
        escrow_hash,
    }
}

fn at_tip(published: &Published) -> (VerifiedTrust, SelectedRegistryHead) {
    select(&published.escrow.line, tip_sequence(&published.escrow.line))
}

fn recovery_for(
    published: &Published,
    head: &SelectedRegistryHead,
    id: u8,
) -> ReaderKeyEscrowRecoveryAuthorizationCoreV1 {
    recovery_core(
        published.escrow_hash,
        &published.core,
        Basis::of_selected(head),
        RECOVERY_WINDOW,
        id,
    )
}

fn signed(published: &Published, core: &ReaderKeyEscrowRecoveryAuthorizationCoreV1) -> Vec<u8> {
    signed_recovery(core, &published.escrow.approvers)
}

// ---------------------------------------------------------------------------
// Positivkontrolle
// ---------------------------------------------------------------------------

#[test]
fn recovery_by_two_distinct_approvers_is_authorized() {
    let published = published(EscrowLineOptions::default());
    let (trust, head) = at_tip(&published);
    let fields = recovery_for(&published, &head, 0xf1);
    let bytes = signed(&published, &fields);
    let verified =
        verify_reader_key_escrow_recovery_authorization(&trust, &head, &bytes, millis(NOW))
            .unwrap();
    assert!(verified.fields() == &fields);
    assert!(verified.object_hash() == ea_crypto::object_hash(&bytes));
    assert_eq!(verified.exact_bytes(), bytes.as_slice());
    assert!(verified.escrow().object_hash() == published.escrow_hash);
    assert_eq!(verified.escrow().standing(), ReaderKeyEscrowStanding::Valid);
    assert_eq!(
        verified.restore_context().encode(),
        ea_format::ReaderKeyEscrowRestoreContextV1::from_recovery_authorization(
            &fields,
            ea_crypto::object_hash(&bytes)
        )
        .encode()
    );
}

// ---------------------------------------------------------------------------
// Personen und Signaturen
// ---------------------------------------------------------------------------

/// Pflichtzeuge: Freigaben derselben Person unter zwei Zertifikaten.
#[test]
fn recovery_signed_by_one_person_under_two_certificates_is_insufficient() {
    let published = published(EscrowLineOptions {
        same_approver_person: true,
        ..EscrowLineOptions::default()
    });
    let (trust, head) = at_tip(&published);
    let bytes = signed(&published, &recovery_for(&published, &head, 0xf2));
    assert_eq!(
        code(verify_reader_key_escrow_recovery_authorization(
            &trust,
            &head,
            &bytes,
            millis(NOW)
        )),
        "EA-TRUST-APPROVERS-INSUFFICIENT"
    );
}

#[test]
fn recovery_by_an_approver_without_historical_grant_approve_is_refused() {
    let published = published(EscrowLineOptions {
        approver_without_capability: true,
        ..EscrowLineOptions::default()
    });
    let (trust, head) = at_tip(&published);
    let bytes = signed(&published, &recovery_for(&published, &head, 0xf3));
    assert_eq!(
        code(verify_reader_key_escrow_recovery_authorization(
            &trust,
            &head,
            &bytes,
            millis(NOW)
        )),
        "EA-TRUST-SIGNATURE"
    );
}

/// Die bestehende Totalordnungs- und Duplikatsregel: dieselbe Person darf
/// nicht zweimal unter demselben Zertifikat zählen, und die Reihenfolge ist
/// streng aufsteigend nach Zertifikatshash.
#[test]
fn recovery_signatures_out_of_order_or_duplicated_are_refused() {
    let published = published(EscrowLineOptions::default());
    let (trust, head) = at_tip(&published);
    let fields = recovery_for(&published, &head, 0xf4);
    let ordered = signed(&published, &fields);
    let ParsedArchiveObject::Trust(parsed) = ea_format::decode_exact_object(&ordered).unwrap()
    else {
        panic!("a trust object")
    };
    let signatures = parsed.value().signatures().to_vec();
    let payload = TrustPayloadV1::reader_key_escrow_recovery_authorization(fields.clone()).unwrap();
    for (label, signatures) in [
        (
            "reversed",
            vec![signatures[1].clone(), signatures[0].clone()],
        ),
        (
            "duplicated",
            vec![signatures[0].clone(), signatures[0].clone()],
        ),
    ] {
        let bytes = encode_trust(&TrustObjectV1::new(payload.clone(), signatures).unwrap())
            .unwrap()
            .into_vec();
        assert_eq!(
            code(verify_reader_key_escrow_recovery_authorization(
                &trust,
                &head,
                &bytes,
                millis(NOW)
            )),
            "EA-TRUST-SIGNATURE",
            "{label}"
        );
    }
}

/// Zusatzauflage aus dem Vertragsreview von (a): ein widerrufener Approver
/// darf seinen Widerruf weder über den Kopf VOR dem Widerruf noch über eine
/// ältere Sequenz umgehen.
#[test]
fn a_revoked_approver_cannot_sign_with_an_older_head_or_an_older_sequence() {
    let mut published = published(EscrowLineOptions::default());
    let before = *published.escrow.line.heads().last().unwrap();
    let (old_trust, old_head) = select(&published.escrow.line, before.effective_from.get());
    let old = signed(&published, &recovery_for(&published, &old_head, 0xf5));
    assert_eq!(
        code(verify_reader_key_escrow_recovery_authorization(
            &old_trust,
            &old_head,
            &old,
            millis(NOW)
        )),
        "OK",
        "before the revocation the same authorization carries"
    );

    let revoked = published.escrow.approvers[0];
    push_revocation(&mut published.escrow.line, revoked);
    let (trust, head) = at_tip(&published);
    assert_eq!(
        code(verify_reader_key_escrow_recovery_authorization(
            &trust,
            &head,
            &old,
            millis(NOW)
        )),
        "EA-TRUST-ACTION-MISMATCH",
        "the head before the revocation"
    );
    let mut older_sequence = Basis::of_selected(&head);
    older_sequence.sequence = before.effective_from.get();
    let bytes = signed(
        &published,
        &recovery_core(
            published.escrow_hash,
            &published.core,
            older_sequence,
            RECOVERY_WINDOW,
            0xf6,
        ),
    );
    assert_eq!(
        code(verify_reader_key_escrow_recovery_authorization(
            &trust,
            &head,
            &bytes,
            millis(NOW)
        )),
        "EA-TRUST-ACTION-MISMATCH",
        "an older sequence under the current head"
    );
    let current = signed(&published, &recovery_for(&published, &head, 0xf7));
    assert_eq!(
        code(verify_reader_key_escrow_recovery_authorization(
            &trust,
            &head,
            &current,
            millis(NOW)
        )),
        "EA-TRUST-SIGNATURE",
        "the revoked approver at the current head"
    );
}

// ---------------------------------------------------------------------------
// Fenster und Zielbindung
// ---------------------------------------------------------------------------

#[test]
fn recovery_valid_at_expires_at_and_expired_one_millisecond_later() {
    let published = published(EscrowLineOptions::default());
    let (trust, head) = at_tip(&published);
    let bytes = signed(&published, &recovery_for(&published, &head, 0xf8));
    for (now, expected) in [
        (2_900, "OK"),
        (2_901, "EA-TRUST-AUTH-EXPIRED"),
        (1_999, "EA-TRUST-AUTH-NOT-YET-VALID"),
    ] {
        assert_eq!(
            code(verify_reader_key_escrow_recovery_authorization(
                &trust,
                &head,
                &bytes,
                millis(now)
            )),
            expected,
            "now {now}"
        );
    }
}

/// F4: das Escrow eines widerrufenen Readers ist voll geprüft, aber nicht zu
/// öffnen.
#[test]
fn recovery_of_a_revoked_readers_escrow_is_inactive() {
    let mut published = published(EscrowLineOptions::default());
    let reader = published.escrow.reader.certificate;
    push_revocation(&mut published.escrow.line, reader);
    let (trust, head) = at_tip(&published);
    let bytes = signed(&published, &recovery_for(&published, &head, 0xf9));
    assert_eq!(
        code(verify_reader_key_escrow_recovery_authorization(
            &trust,
            &head,
            &bytes,
            millis(NOW)
        )),
        "EA-TRUST-ESCROW-INACTIVE"
    );
}

#[test]
fn recovery_naming_other_target_fields_is_refused() {
    type Mutation = fn(&mut ReaderKeyEscrowRecoveryAuthorizationCoreV1);
    let variants: [(&str, Mutation, &str); 5] = [
        (
            "another reader subject",
            |fields| fields.reader_subject_id = SubjectId::try_from([0xd9; 16].as_slice()).unwrap(),
            "EA-TRUST-ACTION-MISMATCH",
        ),
        (
            "another enrollment version",
            |fields| {
                fields.enrollment_registry_version =
                    ea_types::RegistryVersion::new(fields.enrollment_registry_version.get() - 1);
            },
            "EA-TRUST-ACTION-MISMATCH",
        ),
        (
            "another enrollment head hash",
            |fields| fields.enrollment_registry_head_hash = support::hash32(0x4e),
            "EA-TRUST-ACTION-MISMATCH",
        ),
        (
            "another reader certificate",
            |fields| {
                fields.reader_certificate_object_hash =
                    CertificateHash::try_from([0x4f; 32].as_slice()).unwrap();
            },
            "EA-TRUST-ACTION-MISMATCH",
        ),
        (
            "an escrow that is not in the catalog",
            |fields| fields.escrow_object_hash = support::object_hash_marker(0x4d),
            "EA-TRUST-SOURCE",
        ),
    ];
    let published = published(EscrowLineOptions::default());
    let (trust, head) = at_tip(&published);
    for (label, mutate, expected) in variants {
        let mut fields = recovery_for(&published, &head, 0xfa);
        mutate(&mut fields);
        assert_eq!(
            code(verify_reader_key_escrow_recovery_authorization(
                &trust,
                &head,
                &signed(&published, &fields),
                millis(NOW)
            )),
            expected,
            "{label}"
        );
    }
    let mut foreign = recovery_for(&published, &head, 0xfa);
    foreign.organization_id = OrganizationId::try_from([0x98; 16].as_slice()).unwrap();
    assert_eq!(
        code(verify_reader_key_escrow_recovery_authorization(
            &trust,
            &head,
            &signed(&published, &foreign),
            millis(NOW)
        )),
        "EA-TRUST-ACTION-MISMATCH",
        "a foreign organization"
    );
}

// ---------------------------------------------------------------------------
// Transport-Schlüssel
// ---------------------------------------------------------------------------

#[test]
fn the_target_transport_key_is_checked_before_the_provider() {
    let published = published(EscrowLineOptions::default());
    let (trust, head) = at_tip(&published);
    let verified = verify_reader_key_escrow_recovery_authorization(
        &trust,
        &head,
        &signed(&published, &recovery_for(&published, &head, 0xfb)),
        millis(NOW),
    )
    .unwrap();
    assert_eq!(
        code(verified.require_target_transport_key([0; 32])),
        "EA-TRUST-ACTION-MISMATCH",
        "all zero"
    );
    assert_eq!(
        code(verified.require_target_transport_key(x25519_public([0x0d; 32]))),
        "EA-TRUST-ACTION-MISMATCH",
        "another key"
    );
    let authorized = verified
        .require_target_transport_key(x25519_public(TRANSPORT_KEM_SEED))
        .unwrap();
    assert!(authorized.public_key() == &x25519_key(TRANSPORT_KEM_SEED));
}

// ---------------------------------------------------------------------------
// Einmal-Speicher (geteilter Namensraum, F8)
// ---------------------------------------------------------------------------

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

#[test]
fn a_spent_recovery_is_refused_twice_and_spends_the_id_first() {
    let published = published(EscrowLineOptions::default());
    let (trust, head) = at_tip(&published);
    let verified = verify_reader_key_escrow_recovery_authorization(
        &trust,
        &head,
        &signed(&published, &recovery_for(&published, &head, 0xfc)),
        millis(NOW),
    )
    .unwrap();
    let mut store = ReplayStore::default();
    consume_reader_key_escrow_recovery_authorization(&mut store, &verified).unwrap();
    assert!(
        store.calls
            == [
                AdminAuthorizationReplayDimension::AuthorizationId(
                    verified.fields().authorization_id
                ),
                AdminAuthorizationReplayDimension::Nonce(verified.fields().nonce),
            ]
    );
    assert_eq!(
        code(consume_reader_key_escrow_recovery_authorization(
            &mut store, &verified
        )),
        "EA-TRUST-AUTH-REPLAY"
    );
}

/// Der geteilte Namensraum: eine als Freigabe verbrauchte Nonce trägt keine
/// Öffnung.
#[test]
fn a_recovery_reusing_an_approval_nonce_is_a_replay() {
    let published = published(EscrowLineOptions::default());
    let (trust, head) = at_tip(&published);
    let approval_fields = approval_core(
        &published.escrow.line,
        Basis::of_selected(&head),
        (1_000, 1_300),
        0xa0,
    );
    let approval = verify_reader_key_escrow_approval(
        &trust,
        &head,
        &signed_approval(&published.escrow.line, &approval_fields),
        millis(1_100),
    )
    .unwrap();
    let mut recovery_fields = recovery_for(&published, &head, 0xfd);
    recovery_fields.nonce = approval_fields.nonce;
    let recovery = verify_reader_key_escrow_recovery_authorization(
        &trust,
        &head,
        &signed(&published, &recovery_fields),
        millis(NOW),
    )
    .unwrap();
    let mut store = ReplayStore::default();
    consume_reader_key_escrow_approval(&mut store, &approval).unwrap();
    assert_eq!(
        code(consume_reader_key_escrow_recovery_authorization(
            &mut store, &recovery
        )),
        "EA-TRUST-AUTH-REPLAY"
    );
}

// ---------------------------------------------------------------------------
// Historie im Bestand
// ---------------------------------------------------------------------------

/// Nach einer Wiederherstellung liegt die Öffnungsautorisierung im Katalog
/// und das alte Escrow ist widerrufen: normale Historie, kein Fehler. Eine
/// gefälschte Öffnungsautorisierung lässt den Bestand dagegen scheitern.
#[test]
fn recovery_authorizations_in_the_catalog_are_checked_historically() {
    let mut published = published(EscrowLineOptions::default());
    let (_, head) = at_tip(&published);
    let bytes = signed(&published, &recovery_for(&published, &head, 0xfe));
    let mut forged_line = published.escrow.line.clone();
    published.escrow.line.add_object(bytes);
    let reader = published.escrow.reader.certificate;
    push_revocation(&mut published.escrow.line, reader);
    let (trust, head) = at_tip(&published);
    let set = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::Selected(&head)).unwrap();
    assert_eq!(
        set.get(published.escrow_hash).unwrap().standing(),
        ReaderKeyEscrowStanding::ReaderRevoked
    );

    // Eine Öffnungsautorisierung mit nur EINER echten Person.
    let (_, old_head) = select(&forged_line, tip_sequence(&forged_line));
    let one_person =
        ea_testkit::reader_key_escrow_fixture::signed_reader_key_escrow_recovery_authorization(
            &recovery_for(&published, &old_head, 0xef),
            &[
                escrow_support::approver(published.escrow.approvers[0]),
                ea_testkit::reader_key_escrow_fixture::FixtureTrustSigner {
                    seed: [0x08; 32],
                    certificate_hash: published.escrow.approvers[1],
                },
            ],
        );
    forged_line.add_object(one_person);
    let (trust, head) = select(&forged_line, tip_sequence(&forged_line));
    assert_eq!(
        code(verify_reader_key_escrows(
            &trust,
            ReaderKeyEscrowHead::Selected(&head)
        )),
        "EA-TRUST-SIGNATURE"
    );
}
