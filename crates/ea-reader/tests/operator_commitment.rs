#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_archive::{ArchiveInventory, QuarantineReason};
use ea_reader::{ReaderMode, ReaderVerifier, SchemaRegistry, SilentObserver, decrypt_verified};
use ea_types::VerificationStatus;
use verify_fixtures::{
    fixtures,
    operator::{self, Defect},
};

fn assert_refused(defect: Defect) {
    let plaintext = operator::genesis_plaintext();
    let plaintexts: Vec<&[u8]> = vec![
        &plaintext;
        if matches!(defect, Defect::RevokedAtEntry) {
            2
        } else {
            1
        }
    ];
    let archive = operator::archive(&plaintexts, defect);
    let vault = fixtures::vault_pinning(archive.anchor_bytes);
    let classification = ReaderVerifier::new(ReaderMode::File, fixtures::EFFECTIVE_NOW)
        .classify(&archive.fixture, &vault, &mut SilentObserver)
        .unwrap();
    assert!(
        classification.report().is_fully_verified(),
        "public archive verification must pass: {defect:?}"
    );
    let entry_hash = operator::entry_hash(&archive.fixture);
    let result = decrypt_verified(
        classification.verified_entry(entry_hash).unwrap(),
        classification.verified_grant(entry_hash).unwrap(),
        &vault,
        &SchemaRegistry::v1(),
        fixtures::EFFECTIVE_NOW,
        &mut SilentObserver,
    );
    let error = result.expect_err(&format!(
        "signed schema-valid forged operator must fail: {defect:?}"
    ));
    assert_eq!(error.code(), "EA-OPERATOR-PROFILE-COMMITMENT", "{defect:?}");
    assert_eq!(format!("{error:?}"), "EA-OPERATOR-PROFILE-COMMITMENT");
}

macro_rules! refusal {
    ($name:ident, $defect:ident) => {
        #[test]
        fn $name() {
            assert_refused(Defect::$defect);
        }
    };
}
refusal!(a_changed_salt_never_discloses_plaintext, Salt);
refusal!(a_changed_name_never_discloses_plaintext, Name);
refusal!(a_changed_function_never_discloses_plaintext, Function);
refusal!(a_changed_subject_never_discloses_plaintext, Subject);
refusal!(
    a_changed_organization_never_discloses_plaintext,
    Organization
);
refusal!(an_unknown_binding_never_discloses_plaintext, UnknownBinding);
refusal!(
    another_subjects_signed_binding_is_not_attribution,
    BorrowedBinding
);
refusal!(
    another_devices_reader_binding_is_not_writer_attribution,
    ReaderBinding
);
refusal!(
    a_payload_cannot_claim_another_registry_version,
    HeaderRegistry
);
/// A manifest naming a Registry head that does not exist on the signed line is
/// refused already by the public pipeline, not only at decryption: gate
/// `registry` resolves the EXACT bound head (`design.md` §14.1 step 3,
/// `crate::historical::historical_registry_head` in `ea-verify`). The entry is
/// isolated as `unattributable`, the report is never fully verified (§14.1),
/// and no decryption witness exists, so `decrypt_verified` is unreachable.
#[test]
fn a_manifest_cannot_borrow_a_different_registry_head_hash() {
    let archive = operator::archive(&[&operator::genesis_plaintext()], Defect::ManifestHead);
    let vault = fixtures::vault_pinning(archive.anchor_bytes);
    let classification = ReaderVerifier::new(ReaderMode::File, fixtures::EFFECTIVE_NOW)
        .classify(&archive.fixture, &vault, &mut SilentObserver)
        .unwrap();
    let report = classification.report();
    assert!(
        !report.is_fully_verified(),
        "a borrowed registry head must never verify publicly"
    );

    let inventory = ArchiveInventory::build(&archive.fixture).unwrap();
    let [entry] = inventory.entries() else {
        panic!("exactly one entry package")
    };
    let quarantined: Vec<_> = report
        .quarantined_objects()
        .map(|object| (*object.object_hash().as_bytes(), object.reason()))
        .collect();
    assert_eq!(
        quarantined,
        [(
            *entry.object_hash().as_bytes(),
            QuarantineReason::Unattributable
        )]
    );

    let entry_hash = operator::entry_hash(&archive.fixture);
    let state = classification.state_of(entry_hash).unwrap();
    assert_eq!(state.verification(), VerificationStatus::Invalid);
    assert_eq!(state.detail_code(), None);
    assert!(classification.verified_entry(entry_hash).is_none());
    assert!(classification.verified_grant(entry_hash).is_none());
}
refusal!(
    a_binding_not_yet_effective_never_discloses_plaintext,
    NotYetEffective
);
refusal!(
    a_binding_revoked_at_the_entry_sequence_never_discloses_plaintext,
    RevokedAtEntry
);

#[test]
fn an_authenticated_historical_snapshot_survives_a_later_binding_revocation() {
    for defect in [Defect::None, Defect::LaterRevocation] {
        let archive = operator::archive(&[&operator::genesis_plaintext()], defect);
        let vault = fixtures::vault_pinning(archive.anchor_bytes.clone());
        let classification = ReaderVerifier::new(ReaderMode::File, fixtures::EFFECTIVE_NOW)
            .classify(&archive.fixture, &vault, &mut SilentObserver)
            .unwrap();
        assert!(classification.report().is_fully_verified());
        let entry_hash = operator::entry_hash(&archive.fixture);
        let record = decrypt_verified(
            classification.verified_entry(entry_hash).unwrap(),
            classification.verified_grant(entry_hash).unwrap(),
            &vault,
            &SchemaRegistry::v1(),
            fixtures::EFFECTIVE_NOW,
            &mut SilentObserver,
        )
        .unwrap();
        let binding_hash = record.with_payload(|payload| {
            let ea_reader::PayloadV1::Genesis(value) = payload else {
                panic!("genesis")
            };
            assert_eq!(value.header().operator().display_name(), "Erika Beispiel");
            value.header().operator().operator_binding_object_hash()
        });
        if matches!(defect, Defect::LaterRevocation) {
            // The later revocation must be a verified, effective action, not
            // merely an extra object in the fixture catalog.
            let head = select_later_head(&archive);
            assert!(head.active_operator_binding_fields(binding_hash).is_none());
            assert!(head.revoked_operator_binding_fields(binding_hash).is_some());
        }
    }
}

fn select_later_head(
    archive: &verify_fixtures::verify_support::CompleteArchive,
) -> ea_trust::SelectedRegistryHead {
    let anchor = ea_trust::decode_trust_anchor(&archive.anchor_bytes).unwrap();
    let inventory = ea_archive::ArchiveInventory::build(&archive.fixture).unwrap();
    let key = ea_verify::verification_state_key(anchor.organization_id());
    let mut store = ea_verify::EphemeralTrustStateStore::new(key, fixtures::EFFECTIVE_NOW);
    for _ in 0..4 {
        let snapshot = ea_trust::load_trust_state(&mut store, key).unwrap();
        let trust = ea_trust::verify_trust(&anchor, &inventory, snapshot).unwrap();
        let candidate =
            ea_trust::verify_registry_candidate(&trust, ea_types::ChainSequence::new(50)).unwrap();
        let time =
            ea_trust::prepare_local_time(&mut store, &candidate, fixtures::EFFECTIVE_NOW, &[])
                .unwrap();
        if let ea_trust::RegistrySelectionOutcome::Selected(head) =
            ea_trust::select_registry_head(candidate, time, None).unwrap()
            && head.registry_version() == ea_types::RegistryVersion::new(4)
        {
            return head;
        }
    }
    panic!("the signed revocation must be selected at sequence 50");
}
