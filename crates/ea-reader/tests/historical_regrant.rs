#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;
use ea_crypto::SecretBytes;
use ea_reader::{
    ReaderMode, ReaderVault, ReaderVerifier, SchemaRegistry, SilentObserver, VaultContentsV1,
    VerificationStatus, decrypt_verified,
};
use ea_types::UnixMillis;
use verify_fixtures::{fixtures, verify_support as support};

fn sealed_for(f: &support::historical::HistoricalFixture) -> ea_reader::SealedVaultV1 {
    ReaderVault::seal(
        VaultContentsV1::new(
            SecretBytes::new(support::other_recipient_secret_bytes()),
            SecretBytes::new([0x52; 32]),
            f.line.exact_anchor_bytes().to_vec(),
            None,
        ),
        &[fixtures::authenticator()],
    )
    .unwrap()
}

#[test]
fn signed_receipt_time_is_durable_before_cek_use_and_survives_receipt_removal() {
    for expires in [850, 1000] {
        let mut f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, expires);
        let mut older = support::archive_support::ArchiveFixture::new();
        for (path, bytes) in f.fixture.blobs() {
            older.push_exact_bytes(path, bytes.clone());
        }
        f.fixture.push_exact_bytes(
            "receipts/time.esr",
            support::historical::signed_receipt(&f, 900),
        );
        let sealed = sealed_for(&f);
        let vault = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
        let mut store = ea_reader::InMemoryReaderBlobStore::new();
        ea_reader::ReaderGrantTimeStore::observe(&vault, &mut store, UnixMillis::new(800)).unwrap();
        let mut observer = ea_reader::RecordingObserver::new();
        let result = ReaderVerifier::new(ReaderMode::File, UnixMillis::new(800))
            .classify_with_time_store(&f.fixture, &vault, &mut store, &mut observer)
            .unwrap();
        assert_eq!(
            result.report().verified_time_floor(),
            Some(UnixMillis::new(900))
        );
        assert_eq!(
            result.verified_grant(f.entry_hash).is_some(),
            expires >= 900
        );
        drop(vault);
        let reopened = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
        let durable =
            ea_reader::ReaderGrantTimeStore::observe(&reopened, &mut store, UnixMillis::new(800))
                .unwrap();
        assert_eq!(
            durable,
            UnixMillis::new(900),
            "the signed floor must survive before the caller publishes a view"
        );
        let replay = ReaderVerifier::new(ReaderMode::File, UnixMillis::new(800))
            .classify_with_time_store(&older, &reopened, &mut store, &mut SilentObserver)
            .unwrap();
        assert_eq!(
            replay.verified_grant(f.entry_hash).is_some(),
            expires >= 900
        );
    }
}

#[test]
fn failed_signed_time_flush_and_raw_classify_never_reach_hpke() {
    use ea_reader::{ReaderBlobError, ReaderBlobKey, ReaderBlobStore};
    struct Unwritable;
    impl ReaderBlobStore for Unwritable {
        fn get(&self, _: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError> {
            Ok(None)
        }
        fn put(&mut self, _: &ReaderBlobKey, _: &[u8]) -> Result<(), ReaderBlobError> {
            Err(ReaderBlobError::Host("unwritable".into()))
        }
        fn delete(&mut self, _: &ReaderBlobKey) -> Result<(), ReaderBlobError> {
            unreachable!()
        }
        fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError> {
            unreachable!()
        }
    }
    struct Observer(bool);
    impl ea_verify::GateObserver for Observer {
        fn on_gate(&mut self, _: ea_verify::Gate) {}
        fn on_decapsulation(&mut self) {
            self.0 = true;
        }
    }
    let mut f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 1000);
    f.fixture.push_exact_bytes(
        "receipts/time.esr",
        support::historical::signed_receipt(&f, 900),
    );
    let vault = ReaderVault::unlock(&sealed_for(&f), &fixtures::authenticator()).unwrap();
    let verifier = ReaderVerifier::new(ReaderMode::File, UnixMillis::new(800));
    let mut observer = Observer(false);
    assert!(
        verifier
            .classify_with_time_store(&f.fixture, &vault, &mut Unwritable, &mut observer)
            .is_err()
    );
    assert!(!observer.0, "failed persistence cannot follow HPKE");
    assert!(
        verifier
            .classify(&f.fixture, &vault, &mut observer)
            .is_err()
    );
    assert!(
        !observer.0,
        "the lower-level API cannot bypass the persistence prerequisite"
    );
}

#[test]
fn an_unauthenticated_receipt_cannot_raise_the_durable_floor() {
    let mut f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 850);
    let mut receipt = support::historical::signed_receipt(&f, 900);
    *receipt.last_mut().unwrap() ^= 1;
    f.fixture.push_exact_bytes("receipts/forged.esr", receipt);
    let sealed = sealed_for(&f);
    let vault = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let result = ReaderVerifier::new(ReaderMode::File, UnixMillis::new(800))
        .classify_with_time_store(&f.fixture, &vault, &mut store, &mut SilentObserver)
        .unwrap();
    assert_eq!(result.report().verified_time_floor(), None);
    assert_ne!(result.report().signature_errors().len(), 0);
    drop(vault);
    let reopened = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
    assert_eq!(
        ea_reader::ReaderGrantTimeStore::observe(&reopened, &mut store, UnixMillis::new(800))
            .unwrap(),
        UnixMillis::new(800)
    );
}

#[test]
fn corrupt_or_unwritable_expiry_metadata_releases_no_effective_time() {
    use ea_reader::{ReaderBlobError, ReaderBlobKey, ReaderBlobStore, ReaderGrantTimeStore};
    let f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 800);
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            SecretBytes::new(support::other_recipient_secret_bytes()),
            SecretBytes::new([0x52; 32]),
            f.line.exact_anchor_bytes().to_vec(),
            None,
        ),
        &[fixtures::authenticator()],
    )
    .unwrap();
    let vault = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let key = ReaderGrantTimeStore::blob_key(&vault).unwrap();
    ReaderGrantTimeStore::observe(&vault, &mut store, UnixMillis::new(801)).unwrap();
    let mut exact = store.get(&key).unwrap().unwrap();
    *exact.last_mut().unwrap() ^= 1;
    store.put(&key, &exact).unwrap();
    assert_eq!(
        ReaderGrantTimeStore::observe(&vault, &mut store, UnixMillis::new(799))
            .unwrap_err()
            .code(),
        "EA-CRYPTO-AEAD-OPEN"
    );
    struct Unwritable;
    impl ReaderBlobStore for Unwritable {
        fn get(&self, _: &ReaderBlobKey) -> Result<Option<Vec<u8>>, ReaderBlobError> {
            Ok(None)
        }
        fn put(&mut self, _: &ReaderBlobKey, _: &[u8]) -> Result<(), ReaderBlobError> {
            Err(ReaderBlobError::Host("unwritable".into()))
        }
        fn delete(&mut self, _: &ReaderBlobKey) -> Result<(), ReaderBlobError> {
            unreachable!()
        }
        fn keys(&self) -> Result<Vec<ReaderBlobKey>, ReaderBlobError> {
            unreachable!()
        }
    }
    assert_eq!(
        ReaderGrantTimeStore::observe(&vault, &mut Unwritable, UnixMillis::new(799))
            .unwrap_err()
            .code(),
        "EA-READER-BLOB-HOST"
    );
}

#[test]
fn encrypted_time_floor_survives_vault_reopen_and_clock_rollback() {
    let f = support::historical::with_grant(support::COMPLETE_PLAINTEXT_V1, 800);
    let contents = VaultContentsV1::new(
        SecretBytes::new(support::other_recipient_secret_bytes()),
        SecretBytes::new([0x52; 32]),
        f.line.exact_anchor_bytes().to_vec(),
        None,
    );
    let sealed = ReaderVault::seal(contents, &[fixtures::authenticator()]).unwrap();
    let mut storage = ea_reader::InMemoryReaderBlobStore::new();
    let vault = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
    assert_eq!(
        ea_reader::ReaderGrantTimeStore::observe(&vault, &mut storage, UnixMillis::new(801))
            .unwrap()
            .get(),
        801
    );
    drop(vault);
    let reopened = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
    let effective =
        ea_reader::ReaderGrantTimeStore::observe(&reopened, &mut storage, UnixMillis::new(799))
            .unwrap();
    assert_eq!(
        effective.get(),
        801,
        "durable floor survives independent vault unlock"
    );
    let classified = ReaderVerifier::new(ReaderMode::File, effective)
        .classify(&f.fixture, &reopened, &mut SilentObserver)
        .unwrap();
    assert!(classified.verified_grant(f.entry_hash).is_none());
}

#[test]
fn a_new_reader_opens_the_historical_grant_and_cached_witness_expires() {
    let mut expected = Vec::new();
    let f = support::historical::fixture_with_expired_original_head(|version, binding| {
        expected = verify_fixtures::operator::bound_plaintext(
            fixtures::genesis_plaintext(),
            binding,
            version.get(),
            verify_fixtures::operator::Defect::None,
        );
        expected.clone()
    });
    let f = support::historical::install_grant(f, 800);
    let contents = VaultContentsV1::new(
        SecretBytes::new(support::other_recipient_secret_bytes()),
        SecretBytes::new([0x52; 32]),
        f.line.exact_anchor_bytes().to_vec(),
        None,
    );
    let sealed = ReaderVault::seal(contents, &[fixtures::authenticator()]).unwrap();
    let vault = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
    let mut store = ea_reader::InMemoryReaderBlobStore::new();
    let classification = ReaderVerifier::new(ReaderMode::Server, UnixMillis::new(800))
        .classify_with_time_store(&f.fixture, &vault, &mut store, &mut SilentObserver)
        .unwrap();
    let entry = classification
        .verified_entry(f.entry_hash)
        .expect("historical Entry witness");
    let grant = classification
        .verified_grant(f.entry_hash)
        .expect("historical Grant witness");
    let unprepared = ReaderVault::unlock(&sealed, &fixtures::authenticator()).unwrap();
    assert_eq!(
        decrypt_verified(
            entry,
            grant,
            &unprepared,
            &SchemaRegistry::v1(),
            UnixMillis::new(800),
            &mut SilentObserver
        )
        .unwrap_err()
        .code(),
        "EA-GRANT-TIME-NOT-DURABLE",
        "a cached witness cannot bypass durable floor restoration in a new vault session"
    );
    let record = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        UnixMillis::new(800),
        &mut SilentObserver,
    )
    .unwrap();
    assert!(record.with_plaintext(|bytes| bytes == expected));
    let expired = decrypt_verified(
        entry,
        grant,
        &vault,
        &SchemaRegistry::v1(),
        UnixMillis::new(801),
        &mut SilentObserver,
    )
    .unwrap_err();
    assert_eq!(expired.code(), "EA-GRANT-EXPIRED");
    let reopened = ReaderVerifier::new(ReaderMode::Server, UnixMillis::new(801))
        .classify_with_time_store(&f.fixture, &vault, &mut store, &mut SilentObserver)
        .unwrap();
    assert_eq!(
        reopened.state_of(f.entry_hash).unwrap().verification(),
        VerificationStatus::Invalid
    );
    assert!(reopened.verified_grant(f.entry_hash).is_none());
    assert_eq!(
        reopened.state_of(f.entry_hash).unwrap().detail_code(),
        Some("EA-GRANT-EXPIRED")
    );
    let rollback = ReaderVerifier::new(ReaderMode::Server, UnixMillis::new(799))
        .classify_with_time_store(&f.fixture, &vault, &mut store, &mut SilentObserver)
        .unwrap();
    assert!(
        rollback.verified_grant(f.entry_hash).is_none(),
        "clock rollback cannot revive an expired grant in the unlocked vault"
    );
}
