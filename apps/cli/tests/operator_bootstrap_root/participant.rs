//! Fixed-key native helper processes and private SQLCipher TempDirs only.
use super::*;
use ea_admin::{
    BootstrapAdminParticipantIdentity, BootstrapStore, OperatorLifecycleError,
    PreparedNativeBootstrapAdminParticipant, complete_native_root_step,
    prepare_native_bootstrap_admin_participant,
};
use ea_types::{DeviceId, OperatorSubjectId};

const ADMIN_SECRET: [u8; 32] = [0x8a; 32];
const OPERATOR_SECRET: [u8; 32] = [0x8b; 32];

pub(in crate::process_native) fn native_key_response(
    directory: &Path,
    request: &Value,
) -> Option<Value> {
    if !directory.join("bootstrap-participant-fixture").exists() {
        return None;
    }
    let slot = request["slot"].as_str().unwrap_or("");
    let op = request["op"].as_str().unwrap_or("");
    if op == "account" && directory.join("participant-other-account").exists() {
        return Some(account_response_for(true));
    }
    if slot == "root-signing" {
        return Some(json!({"ok":false}));
    }
    if slot == "database-key" {
        let missing = directory.join("participant-db-key-missing").exists();
        return match op {
            "contains" => Some(json!({"contains":!missing})),
            "unwrap-secret" if !missing => {
                let provider = InMemoryKeyProvider::new_for_test(
                    [if directory.join("participant-db-other-key").exists() {
                        0x92
                    } else {
                        0x93
                    }; 32],
                );
                let key = provider
                    .generate(
                        SecretPurpose::LocalDatabaseKey,
                        KeyProtectionProfileV1::OsWrapped,
                    )
                    .unwrap();
                Some(
                    provider
                        .unwrap_database_key(&key)
                        .unwrap()
                        .with_exposed(|bytes| json!({"secret":hex::encode(bytes)})),
                )
            }
            _ => Some(json!({"ok":false})),
        };
    }
    let secret = match slot {
        "admin-signing" => ADMIN_SECRET,
        "operator-instance" if directory.join("participant-equal-keys").exists() => ADMIN_SECRET,
        "operator-instance" if directory.join("participant-foreign-key").exists() => [0x8f; 32],
        "operator-instance" => OPERATOR_SECRET,
        _ => return None,
    };
    let marker = directory.join(format!("participant-key-{slot}"));
    Some(match op {
        "contains" => json!({"contains":marker.exists()}),
        "public-key" => {
            if marker.exists() {
                json!({"public_key":hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())})
            } else {
                json!({"public_key":null})
            }
        }
        "generate" => {
            assert_eq!(request["replace"], false);
            assert_eq!(request["presence"], true);
            assert_eq!(request["kind"], "ed25519");
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)
            {
                Ok(file) => {
                    file.sync_all().unwrap();
                    if directory
                        .join("participant-lost-generation-response")
                        .exists()
                    {
                        json!({"ok":false})
                    } else {
                        json!({})
                    }
                }
                Err(_) => json!({"ok":false}),
            }
        }
        "sign" if marker.exists() => {
            assert_eq!(request["presence"], true);
            let barrier = directory.join("hold-operator-signature");
            if slot == "operator-instance" && barrier.exists() {
                fs::write(directory.join("operator-signature-paused"), b"").unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while barrier.exists() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "bounded participant signature barrier"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            let data = hex::decode(request["data"].as_str().unwrap()).unwrap();
            let signature = SigningKey::from_bytes(&secret).sign(&data).to_bytes();
            fs::write(directory.join("participant-signature-created"), b"").unwrap();
            json!({"signature":hex::encode(signature)})
        }
        _ => json!({"ok":false}),
    })
}

struct ParticipantFixture {
    _root: support::TempDir,
    directory: support::TempDir,
    native: Arc<NativeOperatorProvider>,
    state: PathBuf,
    database: PathBuf,
    state_bytes: Vec<u8>,
    root_bytes: Vec<u8>,
}
impl ParticipantFixture {
    fn new() -> Self {
        let (root, root_native) = installation(true);
        let state = root.path().join("participant.bootstrap-state");
        let mut store = FileBootstrapStore::new(state.clone())
            .acquire_lease()
            .unwrap();
        drop(
            BootstrapCoordinator::begin(
                &mut store,
                &mut SystemRandomSource,
                Some(Hash32::try_from(&[0x45; 32][..]).unwrap()),
            )
            .unwrap(),
        );
        complete_native_root_step(&mut store, &root_native, RegistryVersion::new(7)).unwrap();
        drop(store);
        let (directory, native) = installation(false);
        fs::write(directory.path().join("bootstrap-participant-fixture"), b"").unwrap();
        let database = directory.path().join("participant.sqlcipher");
        let provider = native.signing_provider(ea_admin::native_provider::NativeSigningSlot::Admin);
        let key = provider.handle(SecretPurpose::LocalDatabaseKey);
        drop(EncryptedDatabase::open(&database, &provider, &key).unwrap());
        let state_bytes = fs::read(&state).unwrap();
        let root_bytes = fs::read(step_two::original_path(&state)).unwrap();
        Self {
            _root: root,
            directory,
            native,
            state,
            database,
            state_bytes,
            root_bytes,
        }
    }
    fn identity(&self, name: &str) -> BootstrapAdminParticipantIdentity {
        BootstrapAdminParticipantIdentity::new(
            DeviceId::try_from(&[0x34; 16][..]).unwrap(),
            OperatorSubjectId::try_from(&[0x35; 16][..]).unwrap(),
            name,
            "Fu\u{308}hrung",
            [0x36; 32],
        )
    }
    fn prepare(
        &self,
        name: &str,
    ) -> Result<PreparedNativeBootstrapAdminParticipant, OperatorLifecycleError> {
        let mut store = reacquire_lease(self.state.clone());
        prepare_native_bootstrap_admin_participant(
            &mut store,
            &self.database,
            &self.native,
            self.identity(name),
        )
    }
    fn generate_count(&self) -> usize {
        calls(self.directory.path())
            .lines()
            .filter(|l| l.starts_with("generate "))
            .count()
    }
    fn assert_unchanged_ceremony(&self) {
        assert_eq!(fs::read(&self.state).unwrap(), self.state_bytes);
        assert_eq!(
            fs::read(step_two::original_path(&self.state)).unwrap(),
            self.root_bytes
        );
        let store = reacquire_lease(self.state.clone());
        let state = store.load().unwrap().unwrap();
        assert_eq!(state.step(), BootstrapStep::GenerateOfflineRoot);
        assert_eq!(
            state.production_state(),
            ProductionState::BlockedRecoveryTest
        );
        let log = calls(self.directory.path());
        assert!(!log.contains("root-signing"));
        assert!(
            !log.lines()
                .any(|l| l.starts_with("delete ") || l.starts_with("wrap-secret "))
        );
    }
}

#[test]
fn participant_generates_nonreplacing_keys_and_reopens_exactly_with_nfc_profile() {
    let mut fixture = ParticipantFixture::new();
    let first = fixture.prepare("A\u{308}nne").unwrap();
    assert_eq!(fixture.generate_count(), 2);
    assert!(first.admin_public_key().thumbprint() != first.operator_public_key().thumbprint());
    assert_eq!(
        first.protection_profile(),
        KeyProtectionProfileV1::OsWrapped
    );
    let prior_signatures = calls(fixture.directory.path())
        .lines()
        .filter(|l| *l == "sign operator-instance")
        .count();
    fixture.native = NativeOperatorProvider::open_test_fixture(
        fixture.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let repeated = fixture.prepare("Änne").unwrap();
    assert_eq!(first, repeated);
    assert_eq!(fixture.generate_count(), 2);
    assert!(
        calls(fixture.directory.path())
            .lines()
            .filter(|l| *l == "sign operator-instance")
            .count()
            > prior_signatures
    );
    assert!(!format!("{repeated:?}").contains("Änne"));
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_invalid_lease_state_and_root_refuse_before_further_native_io() {
    let fixture = ParticipantFixture::new();
    let before = calls(fixture.directory.path());
    let mut unleased = FileBootstrapStore::new(fixture.state.clone());
    assert!(
        prepare_native_bootstrap_admin_participant(
            &mut unleased,
            &fixture.database,
            &fixture.native,
            fixture.identity("Änne")
        )
        .is_err()
    );
    assert_eq!(calls(fixture.directory.path()), before);
    let mut corrupt = fixture.state_bytes.clone();
    let index = corrupt.len() - 9;
    assert_eq!(&corrupt[index..], &[0; 9]);
    corrupt[index] = 1;
    BootstrapStateV1::from_persisted_image(&corrupt).unwrap();
    fs::write(&fixture.state, &corrupt).unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(calls(fixture.directory.path()), before);
    fs::write(&fixture.state, &fixture.state_bytes).unwrap();
    let original = step_two::original_path(&fixture.state);
    let mut broken = fixture.root_bytes.clone();
    *broken.last_mut().unwrap() ^= 1;
    fs::write(&original, &broken).unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(calls(fixture.directory.path()), before);
    assert_eq!(fixture.generate_count(), 0);
}

#[test]
fn participant_wrong_native_database_key_is_rejected_without_generation_or_replacement() {
    let fixture = ParticipantFixture::new();
    let database_bytes = fs::read(&fixture.database).unwrap();
    fs::write(
        fixture.directory.path().join("participant-db-other-key"),
        b"",
    )
    .unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(fixture.generate_count(), 0);
    assert_eq!(fs::read(&fixture.database).unwrap(), database_bytes);
    fs::remove_file(fixture.directory.path().join("participant-db-other-key")).unwrap();
    fixture.prepare("Änne").unwrap();
    assert_eq!(fixture.generate_count(), 2);
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_missing_empty_corrupt_and_symlink_databases_never_get_replaced() {
    use std::os::unix::fs::symlink;
    let fixture = ParticipantFixture::new();
    let original = fs::read(&fixture.database).unwrap();
    fs::remove_file(&fixture.database).unwrap();
    let before = calls(fixture.directory.path());
    assert!(fixture.prepare("Änne").is_err());
    assert!(!fixture.database.try_exists().unwrap());
    assert_eq!(
        calls(fixture.directory.path())
            .matches("unwrap-secret database-key")
            .count(),
        before.matches("unwrap-secret database-key").count(),
        "missing shape precedes key unwrap"
    );
    fs::write(&fixture.database, b"").unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert!(fs::read(&fixture.database).unwrap().is_empty());
    assert_eq!(
        calls(fixture.directory.path())
            .matches("unwrap-secret database-key")
            .count(),
        before.matches("unwrap-secret database-key").count()
    );
    fs::write(&fixture.database, b"not a SQLCipher database").unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(
        fs::read(&fixture.database).unwrap(),
        b"not a SQLCipher database"
    );
    fs::remove_file(&fixture.database).unwrap();
    let target = fixture.directory.path().join("other.sqlcipher");
    fs::write(&target, &original).unwrap();
    symlink(&target, &fixture.database).unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(fs::read(&target).unwrap(), original);
    assert_eq!(fixture.generate_count(), 0);
}

#[test]
fn participant_missing_database_key_never_generates_a_replacement() {
    let fixture = ParticipantFixture::new();
    fs::write(
        fixture.directory.path().join("participant-db-key-missing"),
        b"",
    )
    .unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(fixture.generate_count(), 0);
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_occupied_unassigned_slot_and_ambiguous_generation_are_not_adopted() {
    let fixture = ParticipantFixture::new();
    let marker = fixture
        .directory
        .path()
        .join("participant-key-admin-signing");
    fs::write(&marker, b"").unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(fixture.generate_count(), 0);
    fs::remove_file(&marker).unwrap();
    fs::write(
        fixture
            .directory
            .path()
            .join("participant-lost-generation-response"),
        b"",
    )
    .unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert!(marker.try_exists().unwrap());
    assert_eq!(fixture.generate_count(), 1);
    fs::remove_file(
        fixture
            .directory
            .path()
            .join("participant-lost-generation-response"),
    )
    .unwrap();
    assert!(
        fixture.prepare("Änne").is_err(),
        "uncertain generated key must remain pending"
    );
    assert_eq!(fixture.generate_count(), 1);
    assert!(
        !fixture
            .directory
            .path()
            .join("participant-key-operator-instance")
            .try_exists()
            .unwrap()
    );
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_lost_confirmed_key_and_foreign_readback_never_regenerate() {
    let fixture = ParticipantFixture::new();
    fixture.prepare("Änne").unwrap();
    fs::write(
        fixture.directory.path().join("participant-foreign-key"),
        b"",
    )
    .unwrap();
    assert!(fixture.prepare("Änne").is_err());
    fs::remove_file(fixture.directory.path().join("participant-foreign-key")).unwrap();
    fs::remove_file(
        fixture
            .directory
            .path()
            .join("participant-key-admin-signing"),
    )
    .unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(fixture.generate_count(), 2);
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_equal_signing_and_instance_keys_are_refused() {
    let fixture = ParticipantFixture::new();
    fs::write(fixture.directory.path().join("participant-equal-keys"), b"").unwrap();
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(fixture.generate_count(), 2);
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(fixture.generate_count(), 2);
    fixture.assert_unchanged_ceremony();
}

fn journal_bytes(fixture: &ParticipantFixture) -> Vec<u8> {
    let provider = fixture
        .native
        .signing_provider(ea_admin::native_provider::NativeSigningSlot::Admin);
    let key = provider.handle(SecretPurpose::LocalDatabaseKey);
    let database = EncryptedDatabase::open_existing(&fixture.database, &provider, &key).unwrap();
    database
        .query_row(
            "SELECT exact_journal FROM native_bootstrap_participant WHERE singleton=1",
            &[],
        )
        .unwrap()
        .unwrap()
        .blob(0)
        .unwrap()
        .to_vec()
}

#[test]
fn participant_changed_profile_and_noncanonical_retained_journal_are_not_repaired() {
    use ea_local_store::StoreValue;
    let fixture = ParticipantFixture::new();
    fixture.prepare("Änne").unwrap();
    let original = journal_bytes(&fixture);
    assert!(
        original
            .windows("Änne".len())
            .any(|w| w == "Änne".as_bytes())
    );
    assert!(fixture.prepare("Other").is_err());
    assert_eq!(journal_bytes(&fixture), original);
    let mut changed = original.clone();
    let at = changed
        .windows("Änne".len())
        .position(|w| w == "Änne".as_bytes())
        .unwrap();
    assert_eq!(changed[at - 1], 0x65);
    changed.splice(
        at - 1..at + "Änne".len(),
        [&[0x66][..], "A\u{308}nne".as_bytes()].concat(),
    );
    let provider = fixture
        .native
        .signing_provider(ea_admin::native_provider::NativeSigningSlot::Admin);
    let key = provider.handle(SecretPurpose::LocalDatabaseKey);
    let database = EncryptedDatabase::open_existing(&fixture.database, &provider, &key).unwrap();
    database
        .execute(
            "UPDATE native_bootstrap_participant SET exact_journal=?1 WHERE singleton=1",
            &[StoreValue::Blob(changed.clone())],
        )
        .unwrap();
    drop(database);
    assert!(fixture.prepare("Änne").is_err());
    assert_eq!(journal_bytes(&fixture), changed);
    assert_eq!(fixture.generate_count(), 2);
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_different_identity_and_salt_preserve_exact_journal() {
    let fixture = ParticipantFixture::new();
    fixture.prepare("Änne").unwrap();
    let original = journal_bytes(&fixture);
    let mut store = reacquire_lease(fixture.state.clone());
    for (device, subject, salt) in [(0x37, 0x35, 0x36), (0x34, 0x38, 0x36), (0x34, 0x35, 0x39)] {
        let identity = BootstrapAdminParticipantIdentity::new(
            DeviceId::try_from(&[device; 16][..]).unwrap(),
            OperatorSubjectId::try_from(&[subject; 16][..]).unwrap(),
            "Änne",
            "Führung",
            [salt; 32],
        );
        assert!(
            prepare_native_bootstrap_admin_participant(
                &mut store,
                &fixture.database,
                &fixture.native,
                identity
            )
            .is_err()
        );
        assert_eq!(journal_bytes(&fixture), original);
    }
    assert_eq!(fixture.generate_count(), 2);
}

fn paused_operation(
    fixture: &ParticipantFixture,
) -> (
    std::thread::JoinHandle<
        Result<PreparedNativeBootstrapAdminParticipant, OperatorLifecycleError>,
    >,
    PathBuf,
) {
    let barrier = fixture.directory.path().join("hold-operator-signature");
    fs::write(&barrier, b"").unwrap();
    let native = Arc::clone(&fixture.native);
    let state = fixture.state.clone();
    let database = fixture.database.clone();
    let identity = fixture.identity("Änne");
    let operation = std::thread::spawn(move || {
        let mut store = reacquire_lease(state);
        prepare_native_bootstrap_admin_participant(&mut store, &database, &native, identity)
    });
    let paused = fixture.directory.path().join("operator-signature-paused");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while !paused.try_exists().unwrap() {
        assert!(
            std::time::Instant::now() < deadline,
            "actual native signature must reach barrier"
        );
        std::thread::yield_now();
    }
    (operation, barrier)
}

#[test]
fn participant_observed_watch_invalidation_during_presence_refuses_result() {
    let fixture = ParticipantFixture::new();
    let (operation, barrier) = paused_operation(&fixture);
    fs::write(
        fixture.directory.path().join("watch-action"),
        b"watch-event",
    )
    .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while fixture.native.ensure_session_active().is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "watch must observe invalidation before release"
        );
        std::thread::yield_now();
    }
    assert!(barrier.try_exists().unwrap());
    fs::remove_file(barrier).unwrap();
    assert!(operation.join().unwrap().is_err());
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_current_database_key_must_still_open_the_exact_file_at_return() {
    let fixture = ParticipantFixture::new();
    let (operation, barrier) = paused_operation(&fixture);
    let baseline_unwraps = calls(fixture.directory.path())
        .matches("unwrap-secret database-key")
        .count();
    fs::write(
        fixture.directory.path().join("participant-db-other-key"),
        b"",
    )
    .unwrap();
    fs::remove_file(barrier).unwrap();
    let error = operation.join().unwrap().unwrap_err();
    assert_eq!(error.code(), "EA-STORE-DATABASE");
    assert!(
        fixture
            .directory
            .path()
            .join("participant-signature-created")
            .try_exists()
            .unwrap()
    );
    assert!(
        calls(fixture.directory.path())
            .matches("unwrap-secret database-key")
            .count()
            > baseline_unwraps,
        "native signature passed verification before the final actual key unwrap/Cipher open"
    );
    assert_eq!(fixture.generate_count(), 2);
    fs::remove_file(fixture.directory.path().join("participant-db-other-key")).unwrap();
    fixture.prepare("Änne").unwrap();
    assert_eq!(fixture.generate_count(), 2);
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_ceremony_lease_refuses_a_second_consumer_during_presence() {
    let fixture = ParticipantFixture::new();
    let (operation, barrier) = paused_operation(&fixture);
    assert!(
        FileBootstrapStore::new(fixture.state.clone())
            .acquire_lease()
            .is_err()
    );
    fs::remove_file(barrier).unwrap();
    let first = operation.join().unwrap().unwrap();
    assert_eq!(fixture.prepare("Änne").unwrap(), first);
    assert_eq!(fixture.generate_count(), 2);
    fixture.assert_unchanged_ceremony();
}

#[test]
fn participant_changed_current_native_account_cannot_reuse_the_journal() {
    use ea_operator::OsAccountProvider as _;
    let fixture = ParticipantFixture::new();
    let first = fixture.prepare("Änne").unwrap();
    let retained = journal_bytes(&fixture);
    fs::write(
        fixture.directory.path().join("participant-other-account"),
        b"",
    )
    .unwrap();
    let actual = fixture
        .native
        .os_account_binding_hash(first.organization_id(), first.device_id())
        .unwrap();
    assert!(
        actual != first.os_account_binding_hash(),
        "fixture supplies a valid different measured account"
    );
    let error = fixture.prepare("Änne").unwrap_err();
    assert_eq!(error.code(), "EA-OPERATOR-JOURNAL-CONFLICT");
    assert_eq!(journal_bytes(&fixture), retained);
    assert_eq!(fixture.generate_count(), 2);
    fixture.assert_unchanged_ceremony();
}

pub(super) mod signing_backup;
