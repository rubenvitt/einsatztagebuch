use super::*;
use ea_admin::seal_native_bootstrap_admin_backup;
use ea_crypto::SecretVec;
use ea_recovery::ContainedKeyKind;

pub(in crate::process_native) fn fixture_admin_seed() -> [u8; 32] {
    ADMIN_SECRET
}

#[test]
fn admin_backup_reads_bound_completed_journal_without_regenerating_participant() {
    let fixture = ParticipantFixture::new();
    let prepared = fixture.prepare("Änne").unwrap();
    let journal_before = journal_bytes(&fixture);
    let generations = fixture.generate_count();
    let offset = calls(fixture.directory.path()).len();
    let mut ceremony = reacquire_lease(fixture.state.clone());
    let passphrase = SecretVec::new(b"synthetic admin backup passphrase".to_vec());
    let container = seal_native_bootstrap_admin_backup(
        &mut ceremony,
        &fixture.database,
        &fixture.native,
        &passphrase,
    )
    .expect("complete bound participant seals existing Admin seed");
    let secret = container
        .open(ContainedKeyKind::Signing, &passphrase)
        .unwrap();
    assert!(CoseSigner::from_secret(secret).public_key().unwrap() == *prepared.admin_public_key());
    assert_eq!(fixture.generate_count(), generations);
    let log = calls(fixture.directory.path());
    assert!(
        log[offset..]
            .lines()
            .any(|line| line == "backup-signing-seed admin-signing")
    );
    drop(ceremony);
    fixture.assert_unchanged_ceremony();
    assert_eq!(journal_bytes(&fixture), journal_before);
}

#[test]
fn admin_backup_refuses_missing_journal_and_wrong_current_database_key_before_export() {
    let fixture = ParticipantFixture::new();
    let passphrase = SecretVec::new(b"synthetic admin backup passphrase".to_vec());
    let mut ceremony = reacquire_lease(fixture.state.clone());
    assert!(
        seal_native_bootstrap_admin_backup(
            &mut ceremony,
            &fixture.database,
            &fixture.native,
            &passphrase
        )
        .is_err()
    );
    assert_eq!(fixture.generate_count(), 0);
    drop(ceremony);
    fixture.prepare("Änne").unwrap();
    fs::write(
        fixture.directory.path().join("participant-db-other-key"),
        b"",
    )
    .unwrap();
    let offset = calls(fixture.directory.path()).len();
    let mut ceremony = reacquire_lease(fixture.state.clone());
    assert!(
        seal_native_bootstrap_admin_backup(
            &mut ceremony,
            &fixture.database,
            &fixture.native,
            &passphrase
        )
        .is_err()
    );
    assert!(!calls(fixture.directory.path())[offset..].contains("backup-signing-seed"));
    assert_eq!(fixture.generate_count(), 2);
}

#[test]
fn admin_backup_recomputes_retained_commitment_before_export() {
    let fixture = ParticipantFixture::new();
    fixture.prepare("Änne").unwrap();
    let mut changed = journal_bytes(&fixture);
    let mut decoder = minicbor::Decoder::new(&changed);
    assert_eq!(decoder.array().unwrap(), Some(14));
    for _ in 0..10 {
        decoder.skip().unwrap();
    }
    assert_eq!(decoder.bytes().unwrap().len(), 32);
    let end = decoder.position();
    changed[end - 32] ^= 1;
    let provider = fixture
        .native
        .signing_provider(ea_admin::native_provider::NativeSigningSlot::Admin);
    let database = EncryptedDatabase::open_existing(
        &fixture.database,
        &provider,
        &provider.handle(SecretPurpose::LocalDatabaseKey),
    )
    .unwrap();
    database
        .transaction(|tx| {
            tx.execute(
                "UPDATE native_bootstrap_participant SET exact_journal=?1 WHERE singleton=1",
                &[ea_local_store::StoreValue::Blob(changed.clone())],
            )
        })
        .unwrap();
    drop(database);
    let offset = calls(fixture.directory.path()).len();
    let mut ceremony = reacquire_lease(fixture.state.clone());
    let result = seal_native_bootstrap_admin_backup(
        &mut ceremony,
        &fixture.database,
        &fixture.native,
        &SecretVec::new(b"synthetic commitment passphrase".to_vec()),
    );
    assert!(matches!(
        result,
        Err(ea_admin::NativeSigningBackupError::Participant(
            OperatorLifecycleError::JournalConflict
        ))
    ));
    assert!(!calls(fixture.directory.path())[offset..].contains("backup-signing-seed"));
    assert_eq!(journal_bytes(&fixture), changed);
}
#[test]
fn admin_backup_watch_loss_during_final_database_unwrap_refuses_after_returned_helper() {
    let fixture = ParticipantFixture::new();
    fixture.prepare("Änne").unwrap();
    let barrier = fixture.directory.path().join("hold-final-backup-unwrap");
    fs::write(&barrier, b"").unwrap();
    let mut ceremony = reacquire_lease(fixture.state.clone());
    let result = std::thread::scope(|scope| {
        let action = scope.spawn(|| {
            seal_native_bootstrap_admin_backup(
                &mut ceremony,
                &fixture.database,
                &fixture.native,
                &SecretVec::new(b"synthetic final watch passphrase".to_vec()),
            )
        });
        super::super::signing_backup::wait_marker(
            &fixture.directory.path().join("backup-final-unwrap-paused"),
        );
        fs::write(
            fixture.directory.path().join("watch-action"),
            b"watch-event",
        )
        .unwrap();
        super::super::signing_backup::wait_marker(
            &fixture.directory.path().join("watch-delivered"),
        );
        assert!(fixture.native.ensure_session_active().is_err());
        fs::remove_file(&barrier).unwrap();
        let result = action.join().unwrap();
        super::super::signing_backup::wait_marker(
            &fixture
                .directory
                .path()
                .join("backup-final-unwrap-returned"),
        );
        result
    });
    assert!(matches!(
        result,
        Err(ea_admin::NativeSigningBackupError::Participant(
            OperatorLifecycleError::Store(ea_local_store::StoreError::Key(
                ea_key_provider::KeyError::ProviderUnavailable
            ))
        ))
    ));
    assert_eq!(fixture.generate_count(), 2);
    drop(ceremony);
    fixture.assert_unchanged_ceremony();
}
