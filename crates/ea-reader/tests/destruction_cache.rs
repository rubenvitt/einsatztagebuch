#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;
use verify_fixtures::verify_support as support;
#[path = "destruction_cache_support/mod.rs"]
mod fixtures;
use ea_reader::VerifiedReaderDestructionInstruction;

#[test]
fn root_review_a_prepared_instruction_cannot_survive_known_registry_expiry() {
    let f = fixtures::Fixture::new();
    let (_, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let cache = ea_reader::ReaderObjectCache::open(&vault);
    let original = cache
        .put_exact_object(&mut store, &f.original.original_bytes)
        .unwrap();
    let source = f.original.source();
    let instruction = ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &source,
        f.input(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::prepare(
            &vault,
            &mut store,
            &source,
            f.input(),
            ea_types::UnixMillis::new(1_000_000),
        )
        .is_err(),
        "the same host has observed an expired Registry"
    );
    assert!(
        ea_reader::ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &instruction,
            f.original.source(),
            ea_types::UnixMillis::new(800)
        )
        .is_err(),
        "an older opaque instruction cannot bypass known action expiry"
    );
    assert!(cache.get_exact_object(&store, original).unwrap().is_some());
}
#[test]
fn signed_job_for_registered_reader_is_verified_before_cache_mutation() {
    let f = fixtures::Fixture::new();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current(),
            f.reader,
            f.input()
        )
        .is_ok()
    );
}
#[test]
fn execution_rechecks_elapsed_time_and_newly_effective_revocation() {
    for revoke in [false, true] {
        let mut f = fixtures::Fixture::new();
        let (_, vault) = vault(&f);
        let mut store = ea_reader::InMemoryReaderBlobStore::new();
        let cache = ea_reader::ReaderObjectCache::open(&vault);
        let original = cache
            .put_exact_object(&mut store, &f.original.original_bytes)
            .unwrap();
        let instruction = ea_reader::ReaderCacheDestruction::prepare(
            &vault,
            &mut store,
            &f.original.source(),
            f.input(),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        if revoke {
            f.revoke_component(f.event_certificate);
        }
        let mut source = f.original.source();
        if revoke {
            f.original
                .append_evidence_entry(&mut source, support::COMPLETE_PLAINTEXT_V1);
        }
        let now = ea_types::UnixMillis::new(if revoke { 801 } else { 1_000_000 });
        assert!(
            ea_reader::ReaderCacheDestruction::execute(
                &vault,
                &mut store,
                &instruction,
                source,
                now,
            )
            .is_err(),
            "preparation cannot override elapsed expiry or a now-effective revocation"
        );
        assert!(cache.get_exact_object(&store, original).unwrap().is_some());
        assert!(
            ea_reader::ReaderCacheDestruction::receipt(&vault, &store, instruction.job_hash(),)
                .unwrap()
                .is_none()
        );
    }
}
#[test]
fn tampered_job_or_foreign_reader_is_not_a_removal_capability() {
    let mut f = fixtures::Fixture::new();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    let current = f.current();
    let index = f.signature.len() - 1;
    f.signature[index] ^= 1;
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &current,
            f.reader,
            f.input()
        )
        .is_err()
    );
}

fn vault(f: &fixtures::Fixture) -> (ea_reader::SealedVaultV1, ea_reader::UnlockedVault) {
    let sealed = ea_reader::ReaderVault::seal(
        ea_reader::VaultContentsV1::new(
            ea_crypto::SecretBytes::new(support::other_recipient_secret_bytes()),
            ea_crypto::SecretBytes::new([0x52; 32]),
            f.original.line.exact_anchor_bytes().to_vec(),
            None,
        ),
        &[verify_fixtures::fixtures::authenticator()],
    )
    .unwrap();
    let vault =
        ea_reader::ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator())
            .unwrap();
    (sealed, vault)
}
#[test]
fn actual_cache_removal_has_a_durable_receipt_and_replay_barrier() {
    let f = fixtures::Fixture::new();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    let proof = VerifiedReaderDestructionInstruction::verify(
        &inventory,
        &f.original.anchor,
        &f.current(),
        f.reader,
        f.input(),
    )
    .unwrap();
    let (sealed, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let cache = ea_reader::ReaderObjectCache::open(&vault);
    let entry = cache
        .put_exact_object(&mut store, &f.original.original_bytes)
        .unwrap();
    let grant = cache
        .put_exact_object(&mut store, &f.original.initial_grant_bytes)
        .unwrap();
    let historical = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 1000);
    assert!(historical.entry_hash == f.original.entry_hash);
    let historical_grants: Vec<_> = historical
        .fixture
        .blobs()
        .iter()
        .filter(|(path, _)| path == "grants/historical.eag")
        .map(|(_, bytes)| cache.put_exact_object(&mut store, bytes).unwrap())
        .collect();
    assert_eq!(historical_grants.len(), 1);
    let state = ea_reader::ReaderBlobKey::new(&format!(
        "entry-state/{}",
        hex::encode(f.original.entry_hash.as_bytes())
    ))
    .unwrap();
    ea_reader::ReaderBlobStore::put(&mut store, &state, b"opaque encrypted indexed state").unwrap();
    let receipt = ea_reader::ReaderCacheDestruction::execute(
        &vault,
        &mut store,
        &proof,
        f.original.source(),
        ea_types::UnixMillis::new(800),
    )
    .expect("verified job must remove actual cache before yielding receipt");
    assert_eq!(receipt.removed_object_hashes().len(), 3);
    assert!(cache.get_exact_object(&store, entry).unwrap().is_none());
    assert!(cache.get_exact_object(&store, grant).unwrap().is_none());
    assert!(
        ea_reader::ReaderBlobStore::get(&store, &state)
            .unwrap()
            .is_none()
    );
    drop(vault);
    let reopened =
        ea_reader::ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator())
            .unwrap();
    let receipt = ea_reader::ReaderCacheDestruction::receipt(&reopened, &store, proof.job_hash())
        .unwrap()
        .expect("receipt must survive reopen");
    assert_eq!(receipt.removed_object_hashes().len(), 3);
    assert!(
        ea_reader::ReaderObjectCache::open(&reopened)
            .put_exact_object(&mut store, &f.original.original_bytes)
            .is_err(),
        "old exports must not repopulate a deleted target"
    );
}

struct FaultStore {
    inner: ea_reader::InMemoryReaderBlobStore,
    fail_delete: bool,
    lose_journal: bool,
    lose_authority: bool,
    complete: bool,
}
impl ea_reader::ReaderBlobStore for FaultStore {
    fn inventory_is_complete(&self) -> bool {
        self.complete
    }
    fn put(
        &mut self,
        key: &ea_reader::ReaderBlobKey,
        bytes: &[u8],
    ) -> Result<(), ea_reader::ReaderBlobError> {
        if (self.lose_journal && key.as_str() == "destruction/v1")
            || (self.lose_authority && key.as_str().starts_with("destruction-authority/"))
        {
            return Ok(());
        }
        self.inner.put(key, bytes)
    }
    fn get(
        &self,
        key: &ea_reader::ReaderBlobKey,
    ) -> Result<Option<Vec<u8>>, ea_reader::ReaderBlobError> {
        self.inner.get(key)
    }
    fn delete(&mut self, key: &ea_reader::ReaderBlobKey) -> Result<(), ea_reader::ReaderBlobError> {
        if self.fail_delete {
            self.fail_delete = false;
            return Err(ea_reader::ReaderBlobError::Host("interrupted".into()));
        }
        self.inner.delete(key)
    }
    fn keys(&self) -> Result<Vec<ea_reader::ReaderBlobKey>, ea_reader::ReaderBlobError> {
        self.inner.keys()
    }
}
#[test]
fn a_lost_flush_or_interrupted_delete_produces_no_success_and_resumes_exactly() {
    for lose_journal in [true, false] {
        let f = fixtures::Fixture::new();
        let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
        let proof = VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current(),
            f.reader,
            f.input(),
        )
        .unwrap();
        let (sealed, vault) = vault(&f);
        let mut store = FaultStore {
            inner: ea_reader::InMemoryReaderBlobStore::new(),
            fail_delete: !lose_journal,
            lose_authority: false,
            lose_journal,
            complete: true,
        };
        let cache = ea_reader::ReaderObjectCache::open(&vault);
        cache
            .put_exact_object(&mut store, &f.original.original_bytes)
            .unwrap();
        cache
            .put_exact_object(&mut store, &f.original.initial_grant_bytes)
            .unwrap();
        assert!(
            ea_reader::ReaderCacheDestruction::execute(
                &vault,
                &mut store,
                &proof,
                f.original.source(),
                ea_types::UnixMillis::new(800)
            )
            .is_err()
        );
        assert!(
            ea_reader::ReaderCacheDestruction::receipt(&vault, &store, proof.job_hash())
                .unwrap()
                .is_none()
        );
        if !lose_journal {
            assert!(
                cache
                    .put_exact_object(&mut store, &f.original.original_bytes)
                    .is_err()
            );
        }
        store.lose_journal = false;
        let reopened =
            ea_reader::ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator())
                .unwrap();
        let receipt = ea_reader::ReaderCacheDestruction::execute(
            &reopened,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        assert_eq!(receipt.removed_object_hashes().len(), 2);
    }
}
#[test]
fn a_subset_store_cannot_claim_complete_local_removal() {
    let f = fixtures::Fixture::new();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    let proof = VerifiedReaderDestructionInstruction::verify(
        &inventory,
        &f.original.anchor,
        &f.current(),
        f.reader,
        f.input(),
    )
    .unwrap();
    let (_, vault) = vault(&f);
    let mut store = FaultStore {
        inner: ea_reader::InMemoryReaderBlobStore::new(),
        fail_delete: false,
        lose_journal: false,
        lose_authority: false,
        complete: false,
    };
    assert!(
        ea_reader::ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800)
        )
        .is_err()
    );
}
#[test]
fn unclassified_local_profile_blob_prevents_a_false_complete_receipt() {
    let f = fixtures::Fixture::new();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    let proof = VerifiedReaderDestructionInstruction::verify(
        &inventory,
        &f.original.anchor,
        &f.current(),
        f.reader,
        f.input(),
    )
    .unwrap();
    let (_, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    ea_reader::ReaderBlobStore::put(
        &mut store,
        &ea_reader::ReaderBlobKey::new("unknown-personal-index").unwrap(),
        b"opaque derived state",
    )
    .unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800)
        )
        .is_err(),
        "unknown managed content cannot be silently omitted"
    );
}

#[test]
fn host_preparation_selects_and_persists_real_current_authority() {
    let f = fixtures::Fixture::new();
    let (_, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let proof = ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &f.original.source(),
        f.input(),
        ea_types::UnixMillis::new(800),
    )
    .expect("actual host composition must yield current verified instruction");
    assert!(proof.job_hash() == ea_crypto::object_hash(&f.core));
    assert!(
        ea_reader::ReaderBlobStore::get(
            &store,
            &ea_reader::ReaderCacheDestruction::authority_key(&vault).unwrap()
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn valid_component_signature_over_an_incomplete_report_is_not_preflight() {
    let mut f = fixtures::Fixture::new();
    f.replace_report(b"{}");
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current(),
            f.reader,
            f.input()
        )
        .is_err(),
        "a formal signature cannot manufacture full pre-state verification"
    );
}

#[test]
fn frozen_backend_and_observed_holding_records_do_not_replace_reader_identity() {
    for kind in [1, 2] {
        let mut f = fixtures::Fixture::new();
        f.add_custody_record(kind);
        let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
        assert!(
            VerifiedReaderDestructionInstruction::verify(
                &inventory,
                &f.original.anchor,
                &f.current(),
                f.reader,
                f.input()
            )
            .is_ok(),
            "known signed operational record {kind}"
        );
    }
    let mut f = fixtures::Fixture::new();
    f.add_custody_record(9);
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current(),
            f.reader,
            f.input()
        )
        .is_err()
    );
}
#[test]
fn a_revoked_reader_remains_a_known_holder_for_current_authorized_cleanup() {
    let mut f = fixtures::Fixture::new();
    f.revoke_reader();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current_at(2),
            f.reader,
            f.input()
        )
        .is_ok(),
        "revocation cannot remove actual custody"
    );
}
#[test]
fn removal_requires_the_current_privacy_document_as_well_as_original_approval() {
    let mut f = fixtures::Fixture::new();
    f.remove_current_privacy_document();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current_at(2),
            f.reader,
            f.input()
        )
        .is_err()
    );
}

#[test]
fn historical_preflight_survives_its_signer_revocation_but_new_action_does_not() {
    let mut f = fixtures::Fixture::with_alternate_event_signer(true);
    f.revoke_component(f.original.deletion);
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current_at(2),
            f.reader,
            f.input()
        )
        .is_ok(),
        "historical report remains valid with an originally eligible, currently active event signer"
    );
    f.revoke_component(f.event_certificate);
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current_at(2),
            f.reader,
            f.input()
        )
        .is_err(),
        "new physical action needs its actual signer active now"
    );
}

/// Web-Reader-Design §3: the reader's own `deletionAttest` key sits on its
/// Reader device and never authorizes a state transition, even though kind
/// and capability alone would admit it.
#[test]
fn an_initiating_event_signed_from_a_reader_device_is_not_a_removal_capability() {
    let verify = |f: &fixtures::Fixture| {
        let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current(),
            f.reader,
            f.input(),
        )
        .map(|_| ())
    };
    let control = fixtures::Fixture::with_reader_attestation_key([0x52; 32]);
    assert!(
        verify(&control).is_ok(),
        "the component on the writer side signs the same start"
    );
    let reader_signed = fixtures::Fixture::with_reader_signed_initiating_event([0x52; 32]);
    assert_eq!(
        Some(*reader_signed.event_certificate.as_bytes()),
        reader_signed
            .reader_attestation_certificate
            .map(|certificate| *certificate.as_bytes()),
        "the initiating event is signed by the reader's own deletionAttest certificate"
    );
    assert!(
        verify(&reader_signed).is_err(),
        "a transition signed from a Reader device is refused"
    );
}

#[test]
fn unparseable_encrypted_cache_holdings_prevent_a_complete_receipt() {
    let f = fixtures::Fixture::new();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    let proof = VerifiedReaderDestructionInstruction::verify(
        &inventory,
        &f.original.anchor,
        &f.current(),
        f.reader,
        f.input(),
    )
    .unwrap();
    let (_, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    ea_reader::ReaderObjectCache::open(&vault)
        .put_exact_object(&mut store, b"unclassifiable encrypted archive bytes")
        .unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800)
        )
        .is_err(),
        "unknown target identity cannot be omitted from measured scope"
    );
}
#[test]
fn host_preparation_preserves_pin_and_time_across_reopen_and_rejects_stale_actions() {
    let mut f = fixtures::Fixture::new();
    let old = f.original.source();
    let mut progressed = f.original.source();
    f.original
        .append_evidence_entry(&mut progressed, support::COMPLETE_PLAINTEXT_V1);
    use support::archive_support::trust_support as trust;
    let head = f.original.line.push(
        trust::ActionSpec::Device {
            kind: ea_format::CertificateKindV1::DeletionAttest,
            marker: 0x7a,
            effective_from: Some(2),
        },
        trust::HeadOptions {
            effective_from: Some(2),
            valid_through: Some(100),
            not_after: ea_types::UnixMillis::new(10000),
            ..Default::default()
        },
    );
    let (sealed, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    // Keep the newer signed HEAD but omit its required certificate object.
    let mut unresolved = ea_reader::DirectoryHandleSource::new();
    for (path, bytes) in f.original.source().blobs() {
        if Some(ea_crypto::object_hash(bytes)) == head.direct_object_hash {
            continue;
        }
        unresolved.push_blob(path, bytes).unwrap();
    }
    assert!(
        ea_reader::ReaderCacheDestruction::prepare(
            &vault,
            &mut store,
            &unresolved,
            f.input(),
            ea_types::UnixMillis::new(800)
        )
        .is_err()
    );
    let mut advanced = f.original.source();
    for (path, bytes) in progressed.blobs() {
        if path == "entries/evidence.eip" || path == "grants/evidence.eag" {
            advanced.push_exact_bytes(path, bytes.clone());
        }
    }
    ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &advanced,
        f.input(),
        ea_types::UnixMillis::new(900),
    )
    .unwrap();
    drop(vault);
    let reopened =
        ea_reader::ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator())
            .unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::prepare(
            &reopened,
            &mut store,
            &old,
            f.input(),
            ea_types::UnixMillis::new(799)
        )
        .is_err(),
        "persistent newer pin cannot roll back to an older complete export"
    );
    ea_reader::ReaderCacheDestruction::prepare(
        &reopened,
        &mut store,
        &advanced,
        f.input(),
        ea_types::UnixMillis::new(799),
    )
    .unwrap();
    assert_eq!(
        ea_reader::ReaderCacheDestruction::observed_authority_time(&reopened, &store).unwrap(),
        ea_types::UnixMillis::new(900)
    );
    assert!(
        ea_reader::ReaderCacheDestruction::prepare(
            &reopened,
            &mut store,
            &advanced,
            f.input(),
            ea_types::UnixMillis::new(10001)
        )
        .is_err(),
        "live removal cannot reuse an expired Registry lease"
    );
}

#[test]
fn late_first_admission_cannot_sign_an_old_authorization_action() {
    let mut f = fixtures::Fixture::new();
    f.admit_late_event_signer();
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current_at(2),
            f.reader,
            f.input()
        )
        .is_err()
    );
}
#[test]
fn missing_durable_authority_flush_cannot_release_a_removal_proof() {
    let f = fixtures::Fixture::new();
    let (_, vault) = vault(&f);
    let mut store = FaultStore {
        inner: ea_reader::InMemoryReaderBlobStore::new(),
        fail_delete: false,
        lose_journal: true,
        lose_authority: true,
        complete: true,
    };
    let hash = ea_reader::ReaderObjectCache::open(&vault)
        .put_exact_object(&mut store, &f.original.original_bytes)
        .unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::prepare(
            &vault,
            &mut store,
            &f.original.source(),
            f.input(),
            ea_types::UnixMillis::new(800)
        )
        .is_err()
    );
    assert!(
        ea_reader::ReaderObjectCache::open(&vault)
            .get_exact_object(&store, hash)
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_signed_unknown_custodian_kind_is_not_a_valid_inventory_record() {
    let mut f = fixtures::Fixture::new();
    f.add_custody_record(8);
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    assert!(
        VerifiedReaderDestructionInstruction::verify(
            &inventory,
            &f.original.anchor,
            &f.current(),
            f.reader,
            f.input()
        )
        .is_err()
    );
}

#[test]
fn direct_opaque_instruction_consumption_also_persists_authority_before_removal() {
    let f = fixtures::Fixture::new();
    let (_, vault) = vault(&f);
    let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
    let proof = VerifiedReaderDestructionInstruction::verify(
        &inventory,
        &f.original.anchor,
        &f.current(),
        f.reader,
        f.input(),
    )
    .unwrap();
    let mut store = FaultStore {
        inner: ea_reader::InMemoryReaderBlobStore::new(),
        fail_delete: false,
        lose_journal: false,
        lose_authority: true,
        complete: true,
    };
    let cache = ea_reader::ReaderObjectCache::open(&vault);
    let hash = cache
        .put_exact_object(&mut store, &f.original.original_bytes)
        .unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800)
        )
        .is_err(),
        "no durable authority means no physical removal even through direct core API"
    );
    assert!(cache.get_exact_object(&store, hash).unwrap().is_some());
}

#[test]
fn signed_duplicate_or_misordered_custody_records_are_refused() {
    for duplicate in [false, true] {
        let mut f = fixtures::Fixture::new();
        f.add_custody_record(1);
        f.add_custody_record(2);
        let inventory = ea_archive::ArchiveInventory::build(&f.original.source()).unwrap();
        assert!(
            VerifiedReaderDestructionInstruction::verify(
                &inventory,
                &f.original.anchor,
                &f.current(),
                f.reader,
                f.input()
            )
            .is_ok()
        );
        f.corrupt_custody_order(duplicate);
        assert!(
            VerifiedReaderDestructionInstruction::verify(
                &inventory,
                &f.original.anchor,
                &f.current(),
                f.reader,
                f.input()
            )
            .is_err(),
            "signed noncanonical custody must be refused; duplicate={duplicate}"
        );
    }
}

#[test]
fn component_attestation_requires_separate_vault_bound_certificate_and_completed_job() {
    let f = fixtures::Fixture::new();
    let (_, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let job = ea_crypto::object_hash(&f.core);
    assert!(
        ea_reader::ReaderCacheDestruction::attest(
            &vault,
            &mut store,
            &f.original.source(),
            job,
            f.event_certificate,
            ea_types::UnixMillis::new(800),
        )
        .is_err()
    );
    let proof = ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &f.original.source(),
        f.input(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    ea_reader::ReaderCacheDestruction::execute(
        &vault,
        &mut store,
        &proof,
        f.original.source(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::attest(
            &vault,
            &mut store,
            &f.original.source(),
            job,
            f.event_certificate,
            ea_types::UnixMillis::new(800),
        )
        .is_err(),
        "controller certificate cannot authorize a Reader vault key"
    );
    assert!(
        ea_reader::ReaderCacheDestruction::historical_attestation(
            &vault,
            &mut store,
            &f.original.source(),
            job,
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn measured_attestation_is_exact_v1_and_byte_identical_after_vault_reopen() {
    let f = fixtures::Fixture::with_reader_attestation_key([0x52; 32]);
    let (sealed, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let removed = ea_reader::ReaderObjectCache::open(&vault)
        .put_exact_object(&mut store, &f.original.original_bytes)
        .unwrap();
    let proof = ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &f.original.source(),
        f.input(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    ea_reader::ReaderCacheDestruction::execute(
        &vault,
        &mut store,
        &proof,
        f.original.source(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    let job = ea_crypto::object_hash(&f.core);
    let certificate = f.reader_attestation_certificate.unwrap();
    let exact = ea_reader::ReaderCacheDestruction::attest(
        &vault,
        &mut store,
        &f.original.source(),
        job,
        certificate,
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&exact).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert_eq!(fields.replica_id, *f.replica.as_bytes());
    assert_eq!(fields.replica_kind, 1);
    assert!(fields.removed_object_hashes == vec![removed]);
    assert_eq!(fields.result, 0);
    let context = ea_crypto::VerificationContext::deletion_attestation_trust_digest(
        parsed.value().exact_digest_input(),
        &f.authorization,
        certificate,
    )
    .unwrap();
    ea_crypto::verify_cose_sign1(&parsed.value().signatures()[0], &f.current(), &context).unwrap();
    drop(vault);
    let reopened =
        ea_reader::ReaderVault::unlock(&sealed, &verify_fixtures::fixtures::authenticator())
            .unwrap();
    assert_eq!(
        ea_reader::ReaderCacheDestruction::historical_attestation(
            &reopened,
            &mut store,
            &f.original.source(),
            job,
        )
        .unwrap()
        .unwrap(),
        exact
    );
    assert_eq!(
        ea_reader::ReaderCacheDestruction::attest(
            &reopened,
            &mut store,
            &f.original.source(),
            job,
            certificate,
            ea_types::UnixMillis::new(801),
        )
        .unwrap(),
        exact
    );
}

#[test]
fn new_attestation_rechecks_revocation_expiry_floor_and_complete_inventory() {
    for case in 0..5 {
        let mut f = fixtures::Fixture::with_reader_attestation_key([0x52; 32]);
        let (_, vault) = vault(&f);
        let mut store = FaultStore {
            inner: ea_reader::InMemoryReaderBlobStore::new(),
            fail_delete: false,
            lose_journal: false,
            lose_authority: false,
            complete: true,
        };
        let proof = ea_reader::ReaderCacheDestruction::prepare(
            &vault,
            &mut store,
            &f.original.source(),
            f.input(),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        ea_reader::ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        let certificate = f.reader_attestation_certificate.unwrap();
        let source = if case == 0 {
            let source = f.revoke_component_after_valid_progress(certificate);
            ea_reader::ReaderCacheDestruction::prepare(
                &vault,
                &mut store,
                &source,
                f.input(),
                ea_types::UnixMillis::new(801),
            )
            .expect("revoked component must be tested with valid current source authority");
            source
        } else {
            f.original.source()
        };
        if case == 2 {
            assert!(
                ea_reader::ReaderCacheDestruction::prepare(
                    &vault,
                    &mut store,
                    &source,
                    f.input(),
                    ea_types::UnixMillis::new(1_000_000),
                )
                .is_err()
            );
        }
        if case == 3 {
            store.complete = false;
        }
        let job = if case == 4 {
            ea_crypto::object_hash(b"other job")
        } else {
            ea_crypto::object_hash(&f.core)
        };
        assert!(
            ea_reader::ReaderCacheDestruction::attest(
                &vault,
                &mut store,
                &source,
                job,
                certificate,
                ea_types::UnixMillis::new(if case == 1 { 1_000_000 } else { 801 }),
            )
            .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn saved_attestation_is_historical_but_reappeared_targets_veto_its_reuse() {
    use ea_reader::ReaderBlobStore;
    let mut f = fixtures::Fixture::with_reader_attestation_key([0x52; 32]);
    let (_, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let hash = ea_reader::ReaderObjectCache::open(&vault)
        .put_exact_object(&mut store, &f.original.original_bytes)
        .unwrap();
    let key =
        ea_reader::ReaderBlobKey::new(&format!("cache/{}", hex::encode(hash.as_bytes()))).unwrap();
    let original_encrypted = store.get(&key).unwrap().unwrap();
    let proof = ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &f.original.source(),
        f.input(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    ea_reader::ReaderCacheDestruction::execute(
        &vault,
        &mut store,
        &proof,
        f.original.source(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    let job = ea_crypto::object_hash(&f.core);
    let certificate = f.reader_attestation_certificate.unwrap();
    let exact = ea_reader::ReaderCacheDestruction::attest(
        &vault,
        &mut store,
        &f.original.source(),
        job,
        certificate,
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    let current_source = f.revoke_component_after_valid_progress(certificate);
    assert_eq!(
        ea_reader::ReaderCacheDestruction::historical_attestation(
            &vault,
            &mut store,
            &f.original.source(),
            job,
        )
        .unwrap()
        .unwrap(),
        exact
    );
    ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &current_source,
        f.input(),
        ea_types::UnixMillis::new(801),
    )
    .expect("the advanced source is valid independently of the revoked Reader component");
    assert!(
        ea_reader::ReaderCacheDestruction::attest(
            &vault,
            &mut store,
            &current_source,
            job,
            certificate,
            ea_types::UnixMillis::new(801),
        )
        .is_err(),
        "current action API cannot silently become historical reading after revocation"
    );
    store.put(&key, &original_encrypted).unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::historical_attestation(
            &vault,
            &mut store,
            &f.original.source(),
            job,
        )
        .is_err()
    );
    assert!(
        ea_reader::ReaderCacheDestruction::attest(
            &vault,
            &mut store,
            &f.original.source(),
            job,
            certificate,
            ea_types::UnixMillis::new(801),
        )
        .is_err()
    );
}

struct AttestationFaultStore {
    inner: ea_reader::InMemoryReaderBlobStore,
    fault: u8,
}
impl ea_reader::ReaderBlobStore for AttestationFaultStore {
    fn inventory_is_complete(&self) -> bool {
        true
    }
    fn keys(&self) -> Result<Vec<ea_reader::ReaderBlobKey>, ea_reader::ReaderBlobError> {
        self.inner.keys()
    }
    fn delete(&mut self, key: &ea_reader::ReaderBlobKey) -> Result<(), ea_reader::ReaderBlobError> {
        self.inner.delete(key)
    }
    fn get(
        &self,
        key: &ea_reader::ReaderBlobKey,
    ) -> Result<Option<Vec<u8>>, ea_reader::ReaderBlobError> {
        let mut bytes = self.inner.get(key)?;
        if self.fault == 2
            && key.as_str().starts_with("destruction-attestation/v1/")
            && let Some(bytes) = bytes.as_mut()
        {
            bytes.pop();
        }
        Ok(bytes)
    }
    fn put(
        &mut self,
        key: &ea_reader::ReaderBlobKey,
        bytes: &[u8],
    ) -> Result<(), ea_reader::ReaderBlobError> {
        if key.as_str().starts_with("destruction-attestation/v1/") {
            if self.fault == 0 {
                return Err(ea_reader::ReaderBlobError::Host("flush failed".into()));
            }
            if self.fault == 1 {
                return self.inner.put(key, &bytes[..bytes.len() / 2]);
            }
        }
        self.inner.put(key, bytes)?;
        if self.fault == 3 && key.as_str().starts_with("destruction-attestation/v1/") {
            return Err(ea_reader::ReaderBlobError::Host(
                "flush failed after full write".into(),
            ));
        }
        Ok(())
    }
}
#[test]
fn attestation_bytes_never_escape_failed_flush_partial_write_or_reread() {
    for fault in 0..3 {
        let f = fixtures::Fixture::with_reader_attestation_key([0x52; 32]);
        let (_, vault) = vault(&f);
        let mut store = AttestationFaultStore {
            inner: ea_reader::InMemoryReaderBlobStore::new(),
            fault,
        };
        let proof = ea_reader::ReaderCacheDestruction::prepare(
            &vault,
            &mut store,
            &f.original.source(),
            f.input(),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        ea_reader::ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        assert!(
            ea_reader::ReaderCacheDestruction::attest(
                &vault,
                &mut store,
                &f.original.source(),
                ea_crypto::object_hash(&f.core),
                f.reader_attestation_certificate.unwrap(),
                ea_types::UnixMillis::new(800),
            )
            .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn component_certificate_must_match_both_actual_vault_key_and_reader_replica() {
    for f in [
        fixtures::Fixture::with_reader_attestation_key([0x53; 32]),
        fixtures::Fixture::with_reader_attestation_identity(
            [0x52; 32],
            ea_types::DeviceId::try_from(&[0xEE; 16][..]).unwrap(),
        ),
    ] {
        let (_, vault) = vault(&f);
        let mut store = ea_reader::InMemoryReaderBlobStore::new();
        let proof = ea_reader::ReaderCacheDestruction::prepare(
            &vault,
            &mut store,
            &f.original.source(),
            f.input(),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        ea_reader::ReaderCacheDestruction::execute(
            &vault,
            &mut store,
            &proof,
            f.original.source(),
            ea_types::UnixMillis::new(800),
        )
        .unwrap();
        assert!(
            ea_reader::ReaderCacheDestruction::attest(
                &vault,
                &mut store,
                &f.original.source(),
                ea_crypto::object_hash(&f.core),
                f.reader_attestation_certificate.unwrap(),
                ea_types::UnixMillis::new(800),
            )
            .is_err()
        );
    }
}

#[test]
fn historical_read_retries_a_failed_full_write_flush_before_releasing_exact_bytes() {
    use ea_reader::ReaderBlobStore;
    let f = fixtures::Fixture::with_reader_attestation_key([0x52; 32]);
    let (_, vault) = vault(&f);
    let mut store = AttestationFaultStore {
        inner: ea_reader::InMemoryReaderBlobStore::new(),
        fault: 3,
    };
    let proof = ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &f.original.source(),
        f.input(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    ea_reader::ReaderCacheDestruction::execute(
        &vault,
        &mut store,
        &proof,
        f.original.source(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    let job = ea_crypto::object_hash(&f.core);
    assert!(
        ea_reader::ReaderCacheDestruction::attest(
            &vault,
            &mut store,
            &f.original.source(),
            job,
            f.reader_attestation_certificate.unwrap(),
            ea_types::UnixMillis::new(800),
        )
        .is_err()
    );
    let key = ea_reader::ReaderCacheDestruction::attestation_key(job).unwrap();
    let unconfirmed = store.get(&key).unwrap().unwrap();
    assert!(
        ea_reader::ReaderCacheDestruction::historical_attestation(
            &vault,
            &mut store,
            &f.original.source(),
            job,
        )
        .is_err(),
        "a readable full write is not a successful flush"
    );
    store.fault = 4;
    let exact = ea_reader::ReaderCacheDestruction::historical_attestation(
        &vault,
        &mut store,
        &f.original.source(),
        job,
    )
    .unwrap()
    .unwrap();
    assert!(ea_format::decode_exact_object(&exact).is_ok());
    assert_eq!(
        store.get(&key).unwrap().unwrap(),
        unconfirmed,
        "retry preserves even the exact encrypted bytes"
    );
}

#[test]
fn current_certificate_cannot_substitute_for_revoked_saved_attestation_signer() {
    let mut f = fixtures::Fixture::with_two_reader_attestation_certificates([0x52; 32]);
    let (_, vault) = vault(&f);
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let proof = ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &f.original.source(),
        f.input(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    ea_reader::ReaderCacheDestruction::execute(
        &vault,
        &mut store,
        &proof,
        f.original.source(),
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    let job = ea_crypto::object_hash(&f.core);
    let saved_signer = f.reader_attestation_certificate.unwrap();
    let alternate = f.alternate_reader_attestation_certificate.unwrap();
    assert!(saved_signer != alternate);
    let exact = ea_reader::ReaderCacheDestruction::attest(
        &vault,
        &mut store,
        &f.original.source(),
        job,
        saved_signer,
        ea_types::UnixMillis::new(800),
    )
    .unwrap();
    let mut before_revocation = f.original.source();
    f.original
        .append_evidence_entry(&mut before_revocation, support::COMPLETE_PLAINTEXT_V1);
    f.revoke_component(saved_signer);
    let mut source = f.original.source();
    for (path, bytes) in before_revocation
        .blobs()
        .iter()
        .filter(|(path, _)| path == "entries/evidence.eip" || path == "grants/evidence.eag")
    {
        source.push_exact_bytes(path, bytes.clone());
    }
    ea_reader::ReaderCacheDestruction::prepare(
        &vault,
        &mut store,
        &source,
        f.input(),
        ea_types::UnixMillis::new(801),
    )
    .expect("the actual advanced source must admit the original instruction");
    let current = f.current_at(2);
    assert!(current.active_certificate_fields(saved_signer).is_none());
    assert!(current.active_certificate_fields(alternate).is_some());
    assert_eq!(ea_reader::ReaderCacheDestruction::historical_attestation(
        &vault, &mut store, &source, job,
    ).unwrap().unwrap(), exact);
    assert!(
        ea_reader::ReaderCacheDestruction::attest(
            &vault,
            &mut store,
            &source,
            job,
            alternate,
            ea_types::UnixMillis::new(801),
        )
        .is_err(),
        "active same-key certificate cannot stand in for revoked saved signer"
    );
    assert_eq!(ea_reader::ReaderCacheDestruction::historical_attestation(
        &vault, &mut store, &source, job,
    ).unwrap().unwrap(), exact);
}
