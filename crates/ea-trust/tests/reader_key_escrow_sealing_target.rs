//! Zeugen des Siegelziels der Zeremonie A im Browser (DRK-460, Scheibe e).
//!
//! Der Browser leitet das Ziel seines Escrows aus einem geprüften Katalog ab:
//! das EINE aktive Reader-Zertifikat zum KEM-Abdruck seines Tresors, dessen
//! Aktivierungszustand, den EINEN Recovery-Empfänger zum Enrollment und die
//! Wurzel. Die Enrollment- und Recovery-Bindung läuft dabei durch DIESELBE
//! Regel, die ein veröffentlichtes Escrow prüft — Zeuge 1 misst genau das: ein
//! Core aus dem Ziel wird, freigegeben und wurzelsigniert, angenommen.
mod escrow_support;
#[path = "../../ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
mod support;

use ea_crypto::{HpkeRecipientPublicKey, SecretBytes};
use ea_format::{CertificateKindV1, ReaderKeyEscrowCoreV1};
use ea_testkit::reader_key_escrow_fixture::{
    FixtureTrustSigner, seal_reader_kem_key_for_escrow, signed_reader_key_escrow_approval,
};
use ea_trust::{
    ReaderKeyEscrowHead, ReaderKeyEscrowSealingTarget, ReaderKeyEscrowStanding, TrustError,
    VerifiedTrust, verify_reader_key_escrow_sealing_target, verify_reader_key_escrows,
};
use ea_types::{CertificateHash, Hash32, KeyThumbprint, RegistryVersion, SubjectId};
use escrow_support::{
    Basis, EscrowLine, EscrowLineOptions, READER_KEM_SEED, RECOVERY_KEM_SEED,
    SECOND_READER_KEM_SEED, approval_core, certificate_of, escrow_line, millis, publish_escrow,
    push_reader, push_revocation, select, subject, tip_sequence, x25519_key,
};
use support::{ActionSpec, HeadOptions};

const ISSUED_AT: u64 = 1_200;
const APPROVAL_WINDOW: (u64, u64) = (1_000, 1_300);

fn code<T>(result: Result<T, TrustError>) -> &'static str {
    match result {
        Ok(_) => "OK",
        Err(error) => error.code(),
    }
}

fn reader_subject() -> SubjectId {
    subject(0xc1)
}

fn trust_at_tip(escrow: &EscrowLine) -> VerifiedTrust {
    select(&escrow.line, tip_sequence(&escrow.line)).0
}

fn target_for(
    escrow: &EscrowLine,
    kem: KeyThumbprint,
    reader_subject: SubjectId,
) -> Result<ReaderKeyEscrowSealingTarget, TrustError> {
    let trust = trust_at_tip(escrow);
    verify_reader_key_escrow_sealing_target(
        &trust,
        ReaderKeyEscrowHead::CatalogLineTip,
        kem,
        reader_subject,
    )
}

fn reader_kem() -> KeyThumbprint {
    x25519_key(READER_KEM_SEED).thumbprint()
}

/// Ein Core ausschließlich aus den Feldern des Ziels — wie der Browser ihn
/// baut —, mit echtem Chiffrat an den Recovery-Schlüssel des Ziels.
fn core_from_target(
    target: &ReaderKeyEscrowSealingTarget,
    reader_kem_seed: [u8; 32],
) -> ReaderKeyEscrowCoreV1 {
    let (version, head_hash, sequence) = target.enrollment();
    let mut core = ReaderKeyEscrowCoreV1 {
        organization_id: target.organization_id(),
        reader_certificate_object_hash: target.reader_certificate_object_hash(),
        reader_subject_id: target.reader_subject_id(),
        enrollment_registry_version: version,
        enrollment_registry_head_hash: head_hash,
        enrollment_sequence: sequence,
        recovery_certificate_object_hash: target.recovery_certificate_object_hash(),
        recovery_kem_key_thumbprint: target.recovery_kem_key_thumbprint(),
        encapsulated_key: [0; 32],
        encrypted_reader_kem_key: [0; 48],
        issued_at: millis(ISSUED_AT),
        root_key_thumbprint: target.root_key_thumbprint(),
    };
    reseal(&mut core, target.recovery_kem_public_key(), reader_kem_seed);
    core
}

fn reseal(core: &mut ReaderKeyEscrowCoreV1, recovery: HpkeRecipientPublicKey, seed: [u8; 32]) {
    let (encapsulated_key, encrypted) =
        seal_reader_kem_key_for_escrow(&SecretBytes::new(seed), *recovery.as_bytes(), core)
            .unwrap();
    core.encapsulated_key = encapsulated_key;
    core.encrypted_reader_kem_key = encrypted;
}

fn tip_basis(escrow: &EscrowLine) -> Basis {
    let tip = *escrow.line.heads().last().unwrap();
    Basis::of(&tip, tip.effective_from.get())
}

fn publish(escrow: &mut EscrowLine, core: &ReaderKeyEscrowCoreV1, id: u8) {
    let approval = approval_core(&escrow.line, tip_basis(escrow), APPROVAL_WINDOW, id);
    publish_escrow(escrow, core, &approval);
}

fn escrows_code(escrow: &EscrowLine) -> &'static str {
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    code(verify_reader_key_escrows(
        &trust,
        ReaderKeyEscrowHead::Selected(&head),
    ))
}

// ---------------------------------------------------------------------------
// 1. Einheit der Regel
// ---------------------------------------------------------------------------

#[test]
fn a_core_built_from_the_target_is_accepted_by_the_escrow_rule() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let target = target_for(&escrow, reader_kem(), reader_subject()).unwrap();

    // Das Ziel nennt genau die Aktivierung der Linie — und nichts aus einer
    // Nutzlastbehauptung.
    assert!(target.organization_id() == support::organization());
    assert!(target.reader_certificate_object_hash() == escrow.reader.certificate);
    assert!(target.reader_subject_id() == reader_subject());
    assert!(target.reader_kem_public_key() == &x25519_key(READER_KEM_SEED));
    let (version, head_hash, sequence) = target.enrollment();
    assert_eq!(version, escrow.reader.version);
    assert!(head_hash == escrow.reader.head_hash);
    assert_eq!(sequence, escrow.reader.sequence);
    assert!(target.recovery_certificate_object_hash() == escrow.recovery);
    assert!(target.recovery_kem_key_thumbprint() == x25519_key(RECOVERY_KEM_SEED).thumbprint());
    assert_eq!(
        target.recovery_kem_public_key().as_bytes(),
        &escrow_support::x25519_public(RECOVERY_KEM_SEED)
    );
    assert!(
        target.root_key_thumbprint()
            == support::device_signing_key(support::root_signing_secret()).thumbprint()
    );

    let core = core_from_target(&target, READER_KEM_SEED);
    publish(&mut escrow, &core, 0xe1);
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let selected = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::Selected(&head)).unwrap();
    let verified = selected
        .valid_for_reader_certificate(escrow.reader.certificate)
        .unwrap();
    assert_eq!(verified.standing(), ReaderKeyEscrowStanding::Valid);
    assert!(verified.core() == &core);
    assert_eq!(
        code(verified.require_reader_kem_public_key(target.reader_kem_public_key())),
        "OK"
    );
    let tip = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::CatalogLineTip).unwrap();
    assert!(tip.valid_for_subject(reader_subject()).is_some());
}

// ---------------------------------------------------------------------------
// 2. Ein abweichendes Enrollment-Tripel scheitert an derselben Regel
// ---------------------------------------------------------------------------

type Deviation = fn(&mut ReaderKeyEscrowCoreV1);

#[test]
fn a_core_with_a_deviating_enrollment_triple_fails_the_same_rule() {
    let base = escrow_line(EscrowLineOptions::default());
    let target = target_for(&base, reader_kem(), reader_subject()).unwrap();
    let deviations: [(&str, Deviation); 4] = [
        ("version + 1", |core| {
            core.enrollment_registry_version =
                RegistryVersion::new(core.enrollment_registry_version.get() + 1);
        }),
        ("version - 1", |core| {
            core.enrollment_registry_version =
                RegistryVersion::new(core.enrollment_registry_version.get() - 1);
        }),
        ("foreign head hash", |core| {
            core.enrollment_registry_head_hash = Hash32::try_from([0x5e; 32].as_slice()).unwrap();
        }),
        ("other sequence", |core| {
            core.enrollment_sequence =
                ea_types::ChainSequence::new(core.enrollment_sequence.get() + 1);
        }),
    ];
    for (label, deviate) in deviations {
        let mut escrow = escrow_line(EscrowLineOptions::default());
        let mut core = core_from_target(&target, READER_KEM_SEED);
        deviate(&mut core);
        reseal(&mut core, target.recovery_kem_public_key(), READER_KEM_SEED);
        publish(&mut escrow, &core, 0xe2);
        assert_eq!(
            escrows_code(&escrow),
            "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH",
            "{label}"
        );
    }
    // Positivkontrolle: das unveränderte Tripel trägt.
    let mut escrow = escrow_line(EscrowLineOptions::default());
    publish(
        &mut escrow,
        &core_from_target(&target, READER_KEM_SEED),
        0xe2,
    );
    assert_eq!(escrows_code(&escrow), "OK");
}

// ---------------------------------------------------------------------------
// 3. Widerruf, 4. Recovery-Kardinalität, 7. fremder Abdruck
// ---------------------------------------------------------------------------

#[test]
fn a_revoked_reader_has_no_sealing_target() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    assert_eq!(
        code(target_for(&escrow, reader_kem(), reader_subject())),
        "OK"
    );
    push_revocation(&mut escrow.line, escrow.reader.certificate);
    assert_eq!(
        code(target_for(&escrow, reader_kem(), reader_subject())),
        "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH"
    );
}

fn push_recovery(escrow: &mut EscrowLine, marker: u8, seed: [u8; 32]) -> CertificateHash {
    let head = escrow.line.push(
        ActionSpec::Device {
            kind: CertificateKindV1::RecoveryRecipient,
            marker,
            effective_from: None,
        },
        HeadOptions {
            kem_public_key_override: Some(x25519_key(seed)),
            ..HeadOptions::default()
        },
    );
    certificate_of(head.direct_object_hash.unwrap())
}

#[test]
fn two_active_recovery_recipients_at_enrollment_are_refused() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    push_recovery(&mut escrow, 0x62, [0xb5; 32]);
    push_reader(&mut escrow.line, 0x83, SECOND_READER_KEM_SEED);
    assert_eq!(
        code(target_for(
            &escrow,
            x25519_key(SECOND_READER_KEM_SEED).thumbprint(),
            subject(0xc2)
        )),
        "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH"
    );
    // Der erste Reader wurde VOR dem zweiten Empfänger aktiviert: zu seinem
    // Enrollment gab es genau einen, und das Ziel bleibt eindeutig.
    let target = target_for(&escrow, reader_kem(), reader_subject()).unwrap();
    assert!(target.recovery_certificate_object_hash() == escrow.recovery);
}

#[test]
fn a_thumbprint_of_no_reader_has_no_sealing_target() {
    let escrow = escrow_line(EscrowLineOptions {
        decoy_reader_with_recovery_kem: false,
        ..EscrowLineOptions::default()
    });
    for foreign in [
        x25519_key([0x0d; 32]).thumbprint(),
        // Der Recovery-Empfänger trägt diesen KEM, ist aber kein Reader.
        x25519_key(RECOVERY_KEM_SEED).thumbprint(),
    ] {
        assert_eq!(
            code(target_for(&escrow, foreign, reader_subject())),
            "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH"
        );
    }
}

#[test]
fn two_active_readers_with_the_same_kem_are_refused() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    push_reader(&mut escrow.line, 0x84, READER_KEM_SEED);
    assert_eq!(
        code(target_for(&escrow, reader_kem(), reader_subject())),
        "EA-TRUST-ESCROW-ENROLLMENT-MISMATCH"
    );
}

// ---------------------------------------------------------------------------
// 5. Eindeutigkeit, 6. fail-closed
// ---------------------------------------------------------------------------

#[test]
fn an_existing_valid_escrow_for_the_certificate_or_the_subject_is_a_conflict() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let target = target_for(&escrow, reader_kem(), reader_subject()).unwrap();
    publish(
        &mut escrow,
        &core_from_target(&target, READER_KEM_SEED),
        0xe5,
    );
    // Dasselbe Zertifikat, andere Subject-ID.
    assert_eq!(
        code(target_for(&escrow, reader_kem(), subject(0xc9))),
        "EA-TRUST-ESCROW-CONFLICT"
    );
    // Dieselbe Subject-ID, ein anderes Reader-Zertifikat.
    push_reader(&mut escrow.line, 0x85, SECOND_READER_KEM_SEED);
    assert_eq!(
        code(target_for(
            &escrow,
            x25519_key(SECOND_READER_KEM_SEED).thumbprint(),
            reader_subject()
        )),
        "EA-TRUST-ESCROW-CONFLICT"
    );
    // Positivkontrolle: das zweite Zertifikat mit eigener Subject-ID.
    assert_eq!(
        code(target_for(
            &escrow,
            x25519_key(SECOND_READER_KEM_SEED).thumbprint(),
            subject(0xca)
        )),
        "OK"
    );
}

#[test]
fn after_revocation_the_old_escrow_does_not_block_a_new_target() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let target = target_for(&escrow, reader_kem(), reader_subject()).unwrap();
    publish(
        &mut escrow,
        &core_from_target(&target, READER_KEM_SEED),
        0xe6,
    );
    push_revocation(&mut escrow.line, escrow.reader.certificate);
    push_reader(&mut escrow.line, 0x86, SECOND_READER_KEM_SEED);
    assert_eq!(
        code(target_for(
            &escrow,
            x25519_key(SECOND_READER_KEM_SEED).thumbprint(),
            reader_subject()
        )),
        "OK"
    );
}

#[test]
fn one_invalid_family_object_fails_the_target() {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let approval = approval_core(&escrow.line, tip_basis(&escrow), APPROVAL_WINDOW, 0xe7);
    let forged = signed_reader_key_escrow_approval(
        &approval,
        &FixtureTrustSigner {
            seed: [0x09; 32],
            certificate_hash: CertificateHash::from(escrow.line.second_bootstrap_admin_hash()),
        },
    );
    escrow.line.add_object(forged);
    assert_eq!(
        code(target_for(&escrow, reader_kem(), reader_subject())),
        "EA-TRUST-SIGNATURE"
    );
}
