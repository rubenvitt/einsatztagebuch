#[path = "support/mod.rs"]
mod support;
use ea_types::*;
use ea_verify::{ObjectResultKindV1, VerifyOptions, verify_archive};

#[path = "destruction_stub_support/mod.rs"]
mod stub_support;
use stub_support::fixture;

#[test]
fn actual_removal_at_or_after_backup_deadline_restores_stub_continuity() {
    for deadline in [799, 800] {
        let f = stub_support::fixture_with_attestation(true, true, 1, |fields| {
            fields.backup_expiry_at = Some(UnixMillis::new(deadline));
        });
        let key = support::complete_recipient_private_key();
        let report = verify_archive(
            &f.source,
            &f.original.anchor,
            VerifyOptions::new(UnixMillis::new(800))
                .with_recipient(support::complete_recipient_key_thumbprint(), &key),
        )
        .unwrap();
        assert!(
            report
                .object_results()
                .any(|result| result.object_hash() == f.stub_hash
                    && result.result() == ObjectResultKindV1::AuthorizedDestroyed),
            "actual removal after deadline {deadline} must authorize the exact Stub"
        );
        assert!(report.is_fully_verified());
    }
}

#[test]
fn signed_future_removal_or_wrong_replica_never_authorizes_a_stub() {
    for case in 0..5 {
        let f = stub_support::fixture_with_attestation(true, true, 1, |fields| match case {
            0 => fields.backup_expiry_at = Some(UnixMillis::new(801)),
            1 => fields.executed_at = UnixMillis::new(801),
            2 => fields.replica_id = [0xff; 16],
            3 => fields.replica_kind = 99,
            4 => fields.executed_at = UnixMillis::new(-1),
            _ => unreachable!(),
        });
        let key = support::complete_recipient_private_key();
        let report = verify_archive(
            &f.source,
            &f.original.anchor,
            VerifyOptions::new(UnixMillis::new(800))
                .with_recipient(support::complete_recipient_key_thumbprint(), &key),
        )
        .unwrap();
        assert!(
            report
                .object_results()
                .all(|result| result.object_hash() != f.stub_hash),
            "invalid signed attestation case {case} must leave the gap visible"
        );
        assert!(!report.is_fully_verified());
    }
}

#[test]
fn authenticated_encrypted_evidence_restores_stub_chain_continuity() {
    let f = fixture(true, true);
    let key = support::complete_recipient_private_key();
    let report = verify_archive(
        &f.source,
        &f.original.anchor,
        VerifyOptions::new(UnixMillis::new(800))
            .with_recipient(support::complete_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert!(
        report
            .object_results()
            .any(|result| result.object_hash() == f.stub_hash
                && result.result() == ObjectResultKindV1::AuthorizedDestroyed),
        "full signed Evidence must authorize the exact Stub"
    );
    assert_eq!(report.gaps().count(), 0);
    assert!(report.is_fully_verified());
}

#[test]
fn unreadable_unbound_or_unattested_evidence_never_authorizes_a_stub() {
    for (bind, attestation, recipient) in [
        (true, true, false),
        (false, true, true),
        (true, false, true),
    ] {
        let f = fixture(bind, attestation);
        let key = support::complete_recipient_private_key();
        let options = VerifyOptions::new(UnixMillis::new(800));
        let options = if recipient {
            options.with_recipient(support::complete_recipient_key_thumbprint(), &key)
        } else {
            options
        };
        let report = verify_archive(&f.source, &f.original.anchor, options).unwrap();
        assert!(
            report
                .object_results()
                .all(|result| result.object_hash() != f.stub_hash)
        );
        assert!(report.gaps().count() > 0);
    }
}

#[test]
fn disconnected_evidence_cannot_close_a_stub_gap() {
    let f = stub_support::fixture_at(true, true, 2);
    let key = support::complete_recipient_private_key();
    let report = verify_archive(
        &f.source,
        &f.original.anchor,
        VerifyOptions::new(UnixMillis::new(800))
            .with_recipient(support::complete_recipient_key_thumbprint(), &key),
    )
    .unwrap();
    assert!(report.gaps().count() > 0);
    assert!(
        report
            .object_results()
            .all(|result| result.object_hash() != f.stub_hash),
        "Evidence above missing sequence 1 cannot close original Stub"
    );
}
#[test]
fn quarantined_duplicate_approval_or_attestation_cannot_authorize_stub() {
    for path in [
        "destructions/authorization.etb",
        "destructions/attestation.etb",
    ] {
        let mut f = fixture(true, true);
        let bytes = f
            .source
            .blobs()
            .iter()
            .find(|(p, _)| p == path)
            .unwrap()
            .1
            .clone();
        f.source.push_exact_bytes("duplicate.etb", bytes);
        let key = support::complete_recipient_private_key();
        let report = verify_archive(
            &f.source,
            &f.original.anchor,
            VerifyOptions::new(UnixMillis::new(800))
                .with_recipient(support::complete_recipient_key_thumbprint(), &key),
        )
        .unwrap();
        assert!(
            report
                .object_results()
                .all(|result| result.object_hash() != f.stub_hash),
            "isolated {path} must grant no authority"
        );
    }
}

#[test]
fn public_manifest_progress_is_separate_from_unreadable_destruction_evidence() {
    let f = fixture(true, true);
    let report = verify_archive(
        &f.source,
        &f.original.anchor,
        VerifyOptions::new(UnixMillis::new(800)),
    )
    .unwrap();
    assert!(!report.is_fully_verified());
    assert!(
        report
            .object_results()
            .all(|r| r.object_hash() != f.stub_hash)
    );
    assert_eq!(
        report
            .verified_public_chain_head()
            .expect("all public gates prove manifest progression")
            .sequence()
            .get(),
        1
    );
    let f = stub_support::fixture_at(true, true, 2);
    let report = verify_archive(
        &f.source,
        &f.original.anchor,
        VerifyOptions::new(UnixMillis::new(800)),
    )
    .unwrap();
    assert!(
        report.verified_public_chain_head().is_none(),
        "disconnected chain is not progress authority"
    );
}

#[test]
fn public_progress_rejects_tampered_original_signature_and_unknown_exact_objects() {
    for corrupt_signature in [true, false] {
        let f = fixture(true, true);
        let mut source = support::archive_support::ArchiveFixture::new();
        for (path, bytes) in f.source.blobs() {
            let bytes = if corrupt_signature && path == "entries/original.eds" {
                let ea_format::ParsedArchiveObject::Destroyed(stub) =
                    ea_format::decode_exact_object(bytes).unwrap()
                else {
                    panic!()
                };
                let value = stub.value();
                let mut signature = value.writer_signature().to_vec();
                let last = signature.len() - 1;
                signature[last] ^= 1;
                ea_format::encode_destroyed_entry_stub(
                    &ea_format::DestroyedEntryStubV1::new(
                        value.signed_manifest().clone(),
                        signature,
                        value.original_eip_object_hash(),
                        value.destruction_id(),
                        value.destruction_authorization_object_hash(),
                    )
                    .unwrap(),
                )
                .unwrap()
                .into_vec()
            } else {
                bytes.clone()
            };
            source.push_exact_bytes(path, bytes);
        }
        if !corrupt_signature {
            source.push_exact_bytes("unknown.eip", ea_format::EIP_PREFIX_V1.to_vec());
        }
        let report = verify_archive(
            &source,
            &f.original.anchor,
            VerifyOptions::new(UnixMillis::new(800)),
        )
        .unwrap();
        assert!(report.verified_public_chain_head().is_none());
    }
}
