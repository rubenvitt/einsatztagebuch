//! Zeugen der Familien-Admission des Reader-Key-Escrows (Ruling F1,
//! DRK-457): der Registrierungsabschluss bleibt für die drei Familien zu, ihr
//! eigener Einstieg nimmt sie auf.
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;

use ea_format::{ReaderKeyEscrowCoreV1, TrustSubtypeV1};
use ea_trust::{
    ReaderKeyEscrowAdmission, ReaderKeyEscrowHead, ReaderKeyEscrowStanding, SelectedRegistryHead,
    TrustError, VerifiedTrust, is_reader_key_escrow_family, verify_catalogue_admission,
    verify_reader_key_escrow_family_admission, verify_reader_key_escrows,
};
use ea_types::{ObjectHash, OrganizationId, UnixMillis};
use escrow_support::{
    Basis, EscrowLine, EscrowLineOptions, READER_KEM_SEED, approval_core, escrow_bytes,
    escrow_core, escrow_line, recovery_core, select, signed_recovery, subject, tip_sequence,
};

const APPROVAL_WINDOW: (u64, u64) = (1_000, 1_300);
const RECOVERY_WINDOW: (u64, u64) = (2_000, 2_900);

fn code<T>(result: Result<T, TrustError>) -> &'static str {
    match result {
        Ok(_) => "OK",
        Err(error) => error.code(),
    }
}

fn millis(value: i64) -> UnixMillis {
    UnixMillis::new(value)
}

/// Die drei Objekte einer vollständigen Kette, noch NICHT im Katalog.
struct Chain {
    escrow: EscrowLine,
    core: ReaderKeyEscrowCoreV1,
    approval: Vec<u8>,
    escrow_object: Vec<u8>,
}

fn chain(options: EscrowLineOptions) -> Chain {
    let escrow = escrow_line(options);
    let core = escrow_core(
        &escrow,
        &escrow.reader,
        READER_KEM_SEED,
        subject(0xc1),
        1_200,
    );
    // Eine Sequenz im Lease des Kopfes, die NICHT die vorgeschlagene ist:
    // die Aufnahme verlangt nur das Lease.
    let tip = *escrow.line.heads().last().unwrap();
    let fields = approval_core(
        &escrow.line,
        Basis::of(&tip, tip.effective_from.get() + 3),
        APPROVAL_WINDOW,
        0xe1,
    );
    let (approval, escrow_object) = escrow_bytes(&escrow, &core, &fields);
    Chain {
        escrow,
        core,
        approval,
        escrow_object,
    }
}

fn at_tip(escrow: &EscrowLine) -> (VerifiedTrust, SelectedRegistryHead) {
    select(&escrow.line, tip_sequence(&escrow.line))
}

fn recovery_bytes(chain: &Chain, basis: Basis, id: u8) -> Vec<u8> {
    signed_recovery(
        &recovery_core(
            ea_crypto::object_hash(&chain.escrow_object),
            &chain.core,
            basis,
            RECOVERY_WINDOW,
            id,
        ),
        &chain.escrow.approvers,
    )
}

fn admit(
    escrow: &EscrowLine,
    bytes: &[u8],
    now: i64,
) -> Result<ReaderKeyEscrowAdmission, TrustError> {
    let (trust, head) = at_tip(escrow);
    verify_reader_key_escrow_family_admission(&trust, Some(&head), bytes, millis(now))
}

/// F1: der Registrierungsabschluss nimmt KEINE der drei Familien auf — auch
/// nicht gültige Objekte, die im Katalog liegen.
#[test]
fn catalogue_admission_refuses_all_three_escrow_families() {
    let mut chain = chain(EscrowLineOptions::default());
    chain.escrow.line.add_object(chain.approval.clone());
    chain.escrow.line.add_object(chain.escrow_object.clone());
    let (_, head) = at_tip(&chain.escrow);
    let recovery = recovery_bytes(&chain, Basis::of_selected(&head), 0xf1);
    chain.escrow.line.add_object(recovery.clone());
    let (trust, head) = at_tip(&chain.escrow);
    for (label, bytes) in [
        ("approval", &chain.approval),
        ("escrow", &chain.escrow_object),
        ("recovery", &recovery),
    ] {
        assert_eq!(
            code(verify_catalogue_admission(
                &trust,
                Some(&head),
                bytes,
                millis(1_100),
                head.proposed_sequence()
            )),
            "EA-TRUST-ACTION-MISMATCH",
            "{label}"
        );
        // Gegenprobe: der eigene Einstieg nimmt dasselbe Objekt auf.
        let now = if label == "recovery" { 2_100 } else { 1_100 };
        assert_eq!(
            code(verify_reader_key_escrow_family_admission(
                &trust,
                Some(&head),
                bytes,
                millis(now)
            )),
            "OK",
            "{label}"
        );
    }
}

#[test]
fn family_admission_accepts_approval_then_escrow_then_recovery() {
    let mut chain = chain(EscrowLineOptions::default());
    chain.escrow.line.add_object(chain.approval.clone());
    assert!(matches!(
        admit(&chain.escrow, &chain.approval, 1_100),
        Ok(ReaderKeyEscrowAdmission::Approval)
    ));

    chain.escrow.line.add_object(chain.escrow_object.clone());
    // Die Frist der Freigabe ist inzwischen abgelaufen: das Escrow hängt an
    // der wurzelsignierten Zeit, nicht an `now`.
    let admitted = admit(&chain.escrow, &chain.escrow_object, 5_000).unwrap();
    let ReaderKeyEscrowAdmission::Escrow(key) = admitted else {
        panic!("an escrow admission")
    };
    assert_eq!(admitted.subtype(), TrustSubtypeV1::ReaderKeyEscrow);
    assert!(key.reader_certificate_object_hash() == chain.core.reader_certificate_object_hash);
    assert!(key.reader_subject_id() == chain.core.reader_subject_id);

    // Die Öffnung liegt nur im Lease des Kopfes, nicht auf der
    // vorgeschlagenen Sequenz — die Aufnahme verlangt das Lease.
    let (_, head) = at_tip(&chain.escrow);
    let mut basis = Basis::of_selected(&head);
    basis.sequence += 7;
    let recovery = recovery_bytes(&chain, basis, 0xf2);
    chain.escrow.line.add_object(recovery.clone());
    assert!(
        admit(&chain.escrow, &recovery, 2_100).unwrap()
            == ReaderKeyEscrowAdmission::RecoveryAuthorization {
                escrow_object_hash: ea_crypto::object_hash(&chain.escrow_object),
            }
    );
}

#[test]
fn family_admission_of_an_escrow_before_its_approval_is_a_source_failure() {
    let mut chain = chain(EscrowLineOptions::default());
    chain.escrow.line.add_object(chain.escrow_object.clone());
    assert_eq!(
        code(admit(&chain.escrow, &chain.escrow_object, 1_100)),
        "EA-TRUST-SOURCE"
    );
}

#[test]
fn family_admission_refuses_a_foreign_subtype_bytes_outside_the_catalog_and_a_missing_registry() {
    let chain = chain(EscrowLineOptions::default());
    let policy = chain
        .escrow
        .line
        .exact_object_bytes(chain.escrow.line.current_policy_hash().unwrap())
        .to_vec();
    assert_eq!(
        code(admit(&chain.escrow, &policy, 1_100)),
        "EA-TRUST-ACTION-MISMATCH",
        "a foreign subtype"
    );
    assert_eq!(
        code(admit(&chain.escrow, &chain.approval, 1_100)),
        "EA-TRUST-SOURCE",
        "bytes that are not in the catalog"
    );
    let mut with_approval = chain.escrow.line.clone();
    with_approval.add_object(chain.approval.clone());
    let (trust, _) = select(&with_approval, tip_sequence(&with_approval));
    assert_eq!(
        code(verify_reader_key_escrow_family_admission(
            &trust,
            None,
            &chain.approval,
            millis(1_100)
        )),
        "EA-TRUST-ACTION-MISMATCH",
        "no registry head"
    );
    assert!(is_reader_key_escrow_family(TrustSubtypeV1::ReaderKeyEscrow));
    assert!(!is_reader_key_escrow_family(
        TrustSubtypeV1::GrantAuthorization
    ));
}

#[test]
fn family_admission_of_an_approval_at_expires_at_and_one_after() {
    let mut chain = chain(EscrowLineOptions::default());
    chain.escrow.line.add_object(chain.approval.clone());
    assert_eq!(code(admit(&chain.escrow, &chain.approval, 1_300)), "OK");
    assert_eq!(
        code(admit(&chain.escrow, &chain.approval, 1_301)),
        "EA-TRUST-AUTH-EXPIRED"
    );
}

/// Zusatzauflage: auch die Aufnahme lässt einen widerrufenen Administrator
/// nicht über eine ältere Sequenz durch — sie liegt außerhalb des Lease des
/// gewählten Kopfes.
#[test]
fn family_admission_of_an_approval_with_an_older_sequence_after_revocation_is_refused() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let before = *escrow.line.heads().last().unwrap();
    escrow.line.push(
        support::ActionSpec::AdminRevoke {
            object_hash: escrow.line.second_bootstrap_admin_hash(),
        },
        support::HeadOptions::default(),
    );
    let (_, head) = at_tip(&escrow);
    let mut basis = Basis::of_selected(&head);
    basis.sequence = before.effective_from.get();
    let approval = escrow_support::signed_approval(
        &escrow.line,
        &approval_core(&escrow.line, basis, APPROVAL_WINDOW, 0xe2),
    );
    escrow.line.add_object(approval.clone());
    assert_eq!(
        code(admit(&escrow, &approval, 1_100)),
        "EA-TRUST-ACTION-MISMATCH"
    );
    let current = escrow_support::signed_approval(
        &escrow.line,
        &approval_core(
            &escrow.line,
            Basis::of_selected(&head),
            APPROVAL_WINDOW,
            0xe3,
        ),
    );
    escrow.line.add_object(current.clone());
    assert_eq!(
        code(admit(&escrow, &current, 1_100)),
        "EA-TRUST-SIGNER-INACTIVE"
    );
}

#[test]
fn family_admission_of_a_recovery_by_one_person_under_two_certificates() {
    let mut chain = chain(EscrowLineOptions {
        same_approver_person: true,
        ..EscrowLineOptions::default()
    });
    chain.escrow.line.add_object(chain.approval.clone());
    chain.escrow.line.add_object(chain.escrow_object.clone());
    let (_, head) = at_tip(&chain.escrow);
    let recovery = recovery_bytes(&chain, Basis::of_selected(&head), 0xf3);
    chain.escrow.line.add_object(recovery.clone());
    assert_eq!(
        code(admit(&chain.escrow, &recovery, 2_100)),
        "EA-TRUST-APPROVERS-INSUFFICIENT"
    );
}

#[test]
fn family_admission_of_a_second_escrow_for_the_same_certificate() {
    let mut chain = chain(EscrowLineOptions::default());
    chain.escrow.line.add_object(chain.approval.clone());
    chain.escrow.line.add_object(chain.escrow_object.clone());
    let second_core = escrow_core(
        &chain.escrow,
        &chain.escrow.reader,
        READER_KEM_SEED,
        subject(0xc2),
        1_250,
    );
    let tip = *chain.escrow.line.heads().last().unwrap();
    let fields = approval_core(
        &chain.escrow.line,
        Basis::of(&tip, tip.effective_from.get()),
        APPROVAL_WINDOW,
        0xe4,
    );
    let (approval, second) = escrow_bytes(&chain.escrow, &second_core, &fields);
    chain.escrow.line.add_object(approval);
    chain.escrow.line.add_object(second.clone());
    assert_eq!(
        code(admit(&chain.escrow, &second, 1_100)),
        "EA-TRUST-ESCROW-CONFLICT"
    );
}

#[test]
fn family_admission_of_a_foreign_organization_escrow() {
    let mut chain = chain(EscrowLineOptions::default());
    let mut core = chain.core.clone();
    core.organization_id = OrganizationId::try_from([0x97; 16].as_slice()).unwrap();
    let tip = *chain.escrow.line.heads().last().unwrap();
    let mut fields = approval_core(
        &chain.escrow.line,
        Basis::of(&tip, tip.effective_from.get()),
        APPROVAL_WINDOW,
        0xe5,
    );
    fields.organization_id = core.organization_id;
    let (approval, foreign) = escrow_bytes(&chain.escrow, &core, &fields);
    chain.escrow.line.add_object(approval);
    chain.escrow.line.add_object(foreign.clone());
    assert_eq!(
        code(admit(&chain.escrow, &foreign, 1_100)),
        "EA-TRUST-ACTION-MISMATCH"
    );
    let _: ObjectHash = ea_crypto::object_hash(&foreign);
}

/// Review (b) P3-3: die Freigabe gehört der EIGENEN Organisation, nur der
/// Escrow-Core nennt eine fremde. Die Freigabe-Schleife des Bestands lässt
/// sie durch; es entscheidet die Organisationsprüfung des Escrows selbst.
#[test]
fn family_admission_of_an_own_organization_approval_over_a_foreign_organization_core() {
    let mut chain = chain(EscrowLineOptions::default());
    let mut core = chain.core.clone();
    core.organization_id = OrganizationId::try_from([0x97; 16].as_slice()).unwrap();
    let tip = *chain.escrow.line.heads().last().unwrap();
    let fields = approval_core(
        &chain.escrow.line,
        Basis::of(&tip, tip.effective_from.get()),
        APPROVAL_WINDOW,
        0xe7,
    );
    assert!(fields.organization_id != core.organization_id);
    let (approval, foreign) = escrow_bytes(&chain.escrow, &core, &fields);
    chain.escrow.line.add_object(approval.clone());
    // Positivkontrolle: die Freigabe allein besteht.
    assert_eq!(code(admit(&chain.escrow, &approval, 1_100)), "OK");
    chain.escrow.line.add_object(foreign.clone());
    assert_eq!(
        code(admit(&chain.escrow, &foreign, 1_100)),
        "EA-TRUST-ACTION-MISMATCH"
    );
}

/// F4: ein Escrow, dessen Reader im gewählten Kopf widerrufen ist, wird
/// nicht als gültig aufgenommen.
#[test]
fn family_admission_of_an_escrow_of_a_revoked_reader_is_inactive() {
    let mut chain = chain(EscrowLineOptions::default());
    chain.escrow.line.add_object(chain.approval.clone());
    chain.escrow.line.add_object(chain.escrow_object.clone());
    let reader = chain.escrow.reader.certificate;
    escrow_support::push_revocation(&mut chain.escrow.line, reader);
    assert_eq!(
        code(admit(&chain.escrow, &chain.escrow_object, 1_100)),
        "EA-TRUST-ESCROW-INACTIVE"
    );
}

// ---------------------------------------------------------------------------
// Fixrunde 1: Signierer-Stand zur vorgeschlagenen Sequenz
// ---------------------------------------------------------------------------
//
// Ein Geräte- oder Bindungsobjekt trägt sein EIGENES `revoked_from_sequence`.
// Liegt es im Lease des gewählten Kopfes, kommt eine Autorisierung mit einer
// früheren Sequenz desselben Lease durch die Lease-Regel (Q1). Die Aufnahme
// ist eine FRISCHE Annahme und verlangt jeden Signierer zusätzlich zur
// vorgeschlagenen Sequenz aktiv; die historische Bestandsprüfung misst
// weiter an der Sequenz der Autorisierung.

/// Die Sequenz der Autorisierung, relativ zum Beginn des letzten Leases.
const SIGNED_AT: u64 = 10;
/// Ab hier widerruft sich der Signierer selbst — im selben Lease.
const REVOKED_FROM: u64 = 50;
/// Die vorgeschlagene Sequenz der Aufnahme NACH dem Widerruf.
const PROPOSED_AFTER: u64 = 60;
/// Die vorgeschlagene Sequenz der Aufnahme VOR dem Widerruf.
const PROPOSED_BEFORE: u64 = 20;

#[derive(Clone, Copy, Debug)]
enum RevokedPart {
    Certificate,
    Binding,
}

/// Ein dritter Administrator mit eigener Bindung; `part` widerruft sich ab
/// `REVOKED_FROM` im Lease des Bindungskopfes. Zurück kommen die Freigabe
/// (Sequenz `SIGNED_AT`), das Escrow und der Bindungskopf.
fn approval_by_an_admin_revoked_inside_the_lease(
    part: RevokedPart,
) -> (EscrowLine, Vec<u8>, Vec<u8>, support::BuiltHead) {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let admin_from = escrow.line.heads().last().unwrap().valid_through.get() + 1;
    let binding_from = admin_from + 100;
    let revoked = Some(ea_types::ChainSequence::new(binding_from + REVOKED_FROM));
    let admin = escrow.line.push(
        support::ActionSpec::AdminIssue {
            marker: 0x11,
            effective_from: None,
        },
        support::HeadOptions {
            revoked_from_sequence: matches!(part, RevokedPart::Certificate)
                .then_some(revoked)
                .flatten(),
            ..support::HeadOptions::default()
        },
    );
    let binding = escrow.line.push(
        support::ActionSpec::OperatorBinding {
            certificate_hash: admin.direct_object_hash.unwrap(),
            role: ea_format::OperatorRoleV1::OrganizationAdmin,
            marker: 0x11,
            effective_from: None,
        },
        support::HeadOptions {
            revoked_from_sequence: matches!(part, RevokedPart::Binding)
                .then_some(revoked)
                .flatten(),
            ..support::HeadOptions::default()
        },
    );
    assert_eq!(admin.effective_from.get(), admin_from);
    assert_eq!(binding.effective_from.get(), binding_from);
    assert!(binding_from + PROPOSED_AFTER <= binding.valid_through.get());

    let certificate = escrow_support::certificate_of(admin.direct_object_hash.unwrap());
    let mut fields = approval_core(
        &escrow.line,
        Basis::of(&binding, binding_from + SIGNED_AT),
        APPROVAL_WINDOW,
        0xe6,
    );
    fields.admin_key_thumbprint =
        support::device_signing_key(support::device_signing_secret()).thumbprint();
    fields.admin_certificate_object_hash = certificate;
    fields.admin_operator_binding_object_hash = binding.direct_object_hash.unwrap();
    let core = escrow_core(
        &escrow,
        &escrow.reader,
        READER_KEM_SEED,
        subject(0xc1),
        1_200,
    );
    let (approval, escrow_object) = ea_testkit::reader_key_escrow_fixture::escrow_with_approval(
        &core,
        &fields,
        &ea_testkit::reader_key_escrow_fixture::FixtureTrustSigner {
            seed: support::device_signing_secret(),
            certificate_hash: certificate,
        },
        &escrow_support::root(&escrow.line),
    );
    escrow.line.add_object(approval.clone());
    escrow.line.add_object(escrow_object.clone());
    (escrow, approval, escrow_object, binding)
}

#[test]
fn family_admission_refuses_an_approval_whose_admin_is_revoked_inside_the_lease() {
    for part in [RevokedPart::Certificate, RevokedPart::Binding] {
        let (escrow, approval, escrow_object, binding) =
            approval_by_an_admin_revoked_inside_the_lease(part);
        let lease = binding.effective_from.get();

        let (trust, head) = select(&escrow.line, lease + PROPOSED_AFTER);
        assert_eq!(head.proposed_sequence().get(), lease + PROPOSED_AFTER);
        assert!(head.registry_head_hash() == binding.object_hash);
        assert_eq!(
            code(verify_reader_key_escrow_family_admission(
                &trust,
                Some(&head),
                &approval,
                millis(1_100)
            )),
            "EA-TRUST-SIGNER-INACTIVE",
            "{part:?}: the admin is revoked at the proposed sequence"
        );
        // Gegenprobe: die historische Bestandsprüfung misst an der Sequenz der
        // Freigabe, die VOR dem Widerruf liegt — sie trägt, das Escrow gilt.
        let escrows = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::Selected(&head))
            .unwrap_or_else(|error| panic!("{part:?}: {}", error.code()));
        assert_eq!(
            escrows
                .get(ea_crypto::object_hash(&escrow_object))
                .unwrap()
                .standing(),
            ReaderKeyEscrowStanding::Valid,
            "{part:?}"
        );

        // Gegenprobe: vor dem Widerruf nimmt dieselbe Aufnahme sie an.
        let (trust, head) = select(&escrow.line, lease + PROPOSED_BEFORE);
        assert_eq!(
            code(verify_reader_key_escrow_family_admission(
                &trust,
                Some(&head),
                &approval,
                millis(1_100)
            )),
            "OK",
            "{part:?}: the admin is still active at the proposed sequence"
        );
    }
}

#[test]
fn family_admission_refuses_a_recovery_whose_approver_is_revoked_inside_the_lease() {
    let mut chain = chain(EscrowLineOptions::default());
    chain.escrow.line.add_object(chain.approval.clone());
    chain.escrow.line.add_object(chain.escrow_object.clone());
    let lease = chain
        .escrow
        .line
        .heads()
        .last()
        .unwrap()
        .valid_through
        .get()
        + 1;
    let third = chain.escrow.line.push(
        support::ActionSpec::Device {
            kind: ea_format::CertificateKindV1::KeyApprover,
            marker: 0x73,
            effective_from: None,
        },
        support::HeadOptions {
            revoked_from_sequence: Some(ea_types::ChainSequence::new(lease + REVOKED_FROM)),
            ..support::HeadOptions::default()
        },
    );
    assert_eq!(third.effective_from.get(), lease);
    let revoked = escrow_support::certificate_of(third.direct_object_hash.unwrap());
    let recovery = signed_recovery(
        &recovery_core(
            ea_crypto::object_hash(&chain.escrow_object),
            &chain.core,
            Basis::of(&third, lease + SIGNED_AT),
            RECOVERY_WINDOW,
            0xf8,
        ),
        &[chain.escrow.approvers[0], revoked],
    );
    chain.escrow.line.add_object(recovery.clone());

    let (trust, head) = select(&chain.escrow.line, lease + PROPOSED_AFTER);
    assert_eq!(head.proposed_sequence().get(), lease + PROPOSED_AFTER);
    assert_eq!(
        code(verify_reader_key_escrow_family_admission(
            &trust,
            Some(&head),
            &recovery,
            millis(2_100)
        )),
        "EA-TRUST-SIGNER-INACTIVE",
        "the second approver is revoked at the proposed sequence"
    );
    // Gegenprobe: historisch trägt dieselbe Öffnung (Sequenz vor dem
    // Widerruf) im Bestand.
    assert_eq!(
        code(verify_reader_key_escrows(
            &trust,
            ReaderKeyEscrowHead::Selected(&head)
        )),
        "OK"
    );

    // Gegenprobe: vor dem Widerruf nimmt dieselbe Aufnahme sie an.
    let (trust, head) = select(&chain.escrow.line, lease + PROPOSED_BEFORE);
    assert_eq!(
        code(verify_reader_key_escrow_family_admission(
            &trust,
            Some(&head),
            &recovery,
            millis(2_100)
        )),
        "OK"
    );
}

/// Review (b) P3-1: der Escrow-Arm nimmt ebenfalls FRISCH an. Ist der
/// Administrator der referenzierten Freigabe seit ihr widerrufen, wird das
/// Escrow nicht mehr aufgenommen — die historische Bestandsprüfung hält die
/// Freigabe und das Escrow weiter für gültig.
#[test]
fn family_admission_refuses_an_escrow_whose_approval_admin_is_revoked_since() {
    let mut chain = chain(EscrowLineOptions::default());
    chain.escrow.line.add_object(chain.approval.clone());
    chain.escrow.line.add_object(chain.escrow_object.clone());
    // Positivkontrolle: vor dem Widerruf wird das Escrow aufgenommen.
    assert_eq!(
        code(admit(&chain.escrow, &chain.escrow_object, 5_000)),
        "OK"
    );

    let admin = chain.escrow.line.second_bootstrap_admin_hash();
    chain.escrow.line.push(
        support::ActionSpec::AdminRevoke { object_hash: admin },
        support::HeadOptions::default(),
    );
    assert_eq!(
        code(admit(&chain.escrow, &chain.escrow_object, 5_000)),
        "EA-TRUST-SIGNER-INACTIVE"
    );
    // Gegenprobe: der Bestand misst die Freigabe an ihrer eigenen Sequenz.
    let (trust, head) = at_tip(&chain.escrow);
    let escrows = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::Selected(&head))
        .unwrap_or_else(|error| panic!("{}", error.code()));
    assert_eq!(
        escrows
            .get(ea_crypto::object_hash(&chain.escrow_object))
            .unwrap()
            .standing(),
        ReaderKeyEscrowStanding::Valid
    );
}
