//! Real durable Step-2 host witnesses.
use super::*;
use ea_admin::{BootstrapStore, complete_native_root_step};
use std::os::unix::fs::MetadataExt as _;

pub(super) fn original_path(state: &Path) -> PathBuf {
    let mut path = state.as_os_str().to_os_string();
    path.push(".root-certificate.etb");
    path.into()
}

pub(super) fn sign_count(directory: &Path) -> usize {
    calls(directory)
        .lines()
        .filter(|line| *line == "sign root-signing")
        .count()
}

fn file_identity(path: &Path) -> (u64, u64, i64, i64, i64, i64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn begin_store(path: &Path) -> FileBootstrapStore {
    let mut store = FileBootstrapStore::new(path.into())
        .acquire_lease()
        .unwrap();
    let machine = Some(Hash32::try_from(&[0x45; 32][..]).unwrap());
    let coordinator =
        BootstrapCoordinator::begin(&mut store, &mut SystemRandomSource, machine).unwrap();
    assert_eq!(coordinator.step(), BootstrapStep::GenerateIds);
    drop(coordinator);
    store
}

#[test]
fn native_root_step_two_retains_original_and_reopens_without_signing_or_rewriting() {
    let (directory, native) = installation(true);
    let path = directory.path().join("completed.bootstrap-state");
    let mut store = begin_store(&path);
    let before = store.load().unwrap().unwrap();
    let prior_signs = sign_count(directory.path());
    let output = complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).unwrap();
    let original = original_path(&path);
    let exact = fs::read(&original).unwrap();
    assert_eq!(exact, output.exact_certificate().as_bytes());
    assert_eq!(fs::metadata(&original).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(sign_count(directory.path()), prior_signs + 1);
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.step(), BootstrapStep::GenerateOfflineRoot);
    assert_eq!(
        state.production_state(),
        ProductionState::BlockedRecoveryTest
    );
    assert!(state.organization_id() == before.organization_id());
    assert!(state.chain_id() == before.chain_id());
    assert!(state.ceremony_machine() == before.ceremony_machine());
    let state_bytes = state.persisted_image();
    let state_identity = file_identity(&path);
    let original_identity = file_identity(&original);
    drop(store);

    let mut reopened = FileBootstrapStore::new(path.clone())
        .acquire_lease()
        .unwrap();
    let repeated =
        complete_native_root_step(&mut reopened, &native, RegistryVersion::new(7)).unwrap();
    assert_eq!(repeated.exact_certificate().as_bytes(), exact);
    assert_eq!(
        reopened.load().unwrap().unwrap().persisted_image(),
        state_bytes
    );
    assert_eq!(
        file_identity(&path),
        state_identity,
        "no state rewrite on resume"
    );
    assert_eq!(
        file_identity(&original),
        original_identity,
        "no original rewrite on resume"
    );
    assert_eq!(sign_count(directory.path()), prior_signs + 1);
    assert_no_key_mutation(&calls(directory.path()));
}

#[test]
fn native_root_step_two_reuses_actual_original_left_before_state_commit() {
    let (directory, native) = installation(true);
    let path = directory.path().join("interrupted.bootstrap-state");
    let mut store = begin_store(&path);
    let coordinator = BootstrapCoordinator::resume(&mut store).unwrap().unwrap();
    let output =
        prepare_native_root_for_ceremony(&coordinator, &native, RegistryVersion::new(7)).unwrap();
    drop(coordinator);
    let original = original_path(&path);
    // Construct the actual durable pre-commit boundary, not a claimed process crash.
    fs::write(&original, output.exact_certificate().as_bytes()).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    fs::File::open(&original).unwrap().sync_all().unwrap();
    fs::File::open(directory.path())
        .unwrap()
        .sync_all()
        .unwrap();
    assert_eq!(
        store.load().unwrap().unwrap().step(),
        BootstrapStep::GenerateIds
    );
    let prior_signs = sign_count(directory.path());
    drop(store);

    let mut reopened = FileBootstrapStore::new(path.clone())
        .acquire_lease()
        .unwrap();
    let result =
        complete_native_root_step(&mut reopened, &native, RegistryVersion::new(7)).unwrap();
    assert_eq!(
        result.exact_certificate().as_bytes(),
        output.exact_certificate().as_bytes()
    );
    assert_eq!(
        sign_count(directory.path()),
        prior_signs,
        "reuse the retained original"
    );
    assert_eq!(
        reopened.load().unwrap().unwrap().step(),
        BootstrapStep::GenerateOfflineRoot
    );
    assert_no_key_mutation(&calls(directory.path()));
}

#[test]
fn native_root_step_two_refuses_unleased_store_before_native_io() {
    let (directory, native) = installation(true);
    let path = directory.path().join("unleased.bootstrap-state");
    drop(begin_store(&path));
    let before = fs::read(&path).unwrap();
    let prior_calls = calls(directory.path());
    let mut store = FileBootstrapStore::new(path.clone());
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(calls(directory.path()), prior_calls);
    assert!(
        !original_path(&path)
            .try_exists()
            .expect("read original absence")
    );
}

#[test]
fn native_root_step_two_never_replaces_missing_or_corrupt_committed_original() {
    let (directory, native) = installation(true);
    let path = directory.path().join("damaged.bootstrap-state");
    let mut store = begin_store(&path);
    complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).unwrap();
    let original = original_path(&path);
    let state_bytes = fs::read(&path).unwrap();
    let prior_signs = sign_count(directory.path());
    let damaged = b"synthetic truncated public certificate";
    fs::write(&original, damaged).unwrap();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert_eq!(fs::read(&original).unwrap(), damaged);
    assert_eq!(fs::read(&path).unwrap(), state_bytes);
    assert_eq!(sign_count(directory.path()), prior_signs);
    fs::remove_file(&original).unwrap();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert!(!original.try_exists().expect("read missing original"));
    assert_eq!(fs::read(&path).unwrap(), state_bytes);
    assert_eq!(sign_count(directory.path()), prior_signs);
}

#[test]
fn native_root_step_two_refuses_changed_explicit_version_without_rewriting_original() {
    let (directory, native) = installation(true);
    let path = directory.path().join("version.bootstrap-state");
    let mut store = begin_store(&path);
    complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).unwrap();
    let original = original_path(&path);
    let before = fs::read(&original).unwrap();
    let state_before = fs::read(&path).unwrap();
    let prior_signs = sign_count(directory.path());
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(8)).is_err());
    assert_eq!(fs::read(&original).unwrap(), before);
    assert_eq!(fs::read(&path).unwrap(), state_before);
    assert_eq!(sign_count(directory.path()), prior_signs);
}

#[test]
fn native_root_step_two_rejects_bad_predecessors_before_helper_io() {
    let (directory, native) = installation(true);
    let path = directory.path().join("predecessor.bootstrap-state");
    let mut store = begin_store(&path);
    let fresh = fs::read(&path).unwrap();
    complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).unwrap();
    let committed = fs::read(&path).unwrap();
    let prefix = b"EINSATZARCHIV-BOOTSTRAP-STATE-v1".len();
    let mut aborted = fresh;
    aborted[prefix + 1] = 1;
    let mut hidden = committed.clone();
    hidden[prefix] = BootstrapStep::GenerateIds.number();
    let mut later = committed;
    later[prefix] = 3;
    let prior_calls = calls(directory.path());
    for bytes in [aborted, hidden, later] {
        BootstrapStateV1::from_persisted_image(&bytes).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
        assert_eq!(calls(directory.path()), prior_calls);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn native_root_step_two_refuses_unsafe_original_files_without_helper_io() {
    use std::os::unix::fs::symlink;
    let (directory, native) = installation(true);
    let path = directory.path().join("unsafe.bootstrap-state");
    let mut store = begin_store(&path);
    let before = fs::read(&path).unwrap();
    let original = original_path(&path);
    let target = directory.path().join("unrelated");
    fs::write(&target, b"unrelated original").unwrap();
    let prior_calls = calls(directory.path());
    symlink(&target, &original).unwrap();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"unrelated original");
    fs::remove_file(&original).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&original)
            .status()
            .unwrap()
            .success()
    );
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    fs::remove_file(&original).unwrap();
    let file = fs::File::create(&original).unwrap();
    file.set_len(ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1 as u64 + 1)
        .unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert_eq!(
        fs::metadata(&original).unwrap().len(),
        ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1 as u64 + 1
    );
    fs::write(&original, b"public but wrong permissions").unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&original, directory.path().join("alias")).unwrap();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert_eq!(calls(directory.path()), prior_calls);
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn native_root_step_two_rejects_a_valid_foreign_original_without_resigning() {
    let (directory, native) = installation(true);
    let path = directory.path().join("foreign.bootstrap-state");
    let mut store = begin_store(&path);
    let before = fs::read(&path).unwrap();
    let foreign = sign_native_initial_root(&native, fields()).unwrap();
    let original = original_path(&path);
    fs::write(&original, foreign.exact_certificate().as_bytes()).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    let prior_calls = calls(directory.path());
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert_eq!(calls(directory.path()), prior_calls);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        fs::read(&original).unwrap(),
        foreign.exact_certificate().as_bytes()
    );
}

#[test]
fn native_root_step_two_retains_original_on_real_state_write_failure_and_reuses_it() {
    let (directory, native) = installation(true);
    let path = directory.path().join("write-failure.bootstrap-state");
    let mut store = begin_store(&path);
    let before = fs::read(&path).unwrap();
    let mut writing = path.as_os_str().to_os_string();
    writing.push(".writing");
    let writing = PathBuf::from(writing);
    fs::create_dir(&writing).unwrap();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    let original = original_path(&path);
    let retained = fs::read(&original).unwrap();
    assert!(matches!(
        decode_exact_object(&retained).unwrap(),
        ParsedArchiveObject::Trust(_)
    ));
    let prior_signs = sign_count(directory.path());
    fs::remove_dir(&writing).unwrap();
    drop(store);
    let mut store = FileBootstrapStore::new(path).acquire_lease().unwrap();
    let output = complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).unwrap();
    assert_eq!(output.exact_certificate().as_bytes(), retained);
    assert_eq!(sign_count(directory.path()), prior_signs);
    assert_eq!(
        store.load().unwrap().unwrap().step(),
        BootstrapStep::GenerateOfflineRoot
    );
}

#[test]
fn native_root_step_two_refuses_observed_native_invalidation_during_signature() {
    let (directory, native) = installation(true);
    let path = directory.path().join("invalidated.bootstrap-state");
    let mut store = begin_store(&path);
    let before = fs::read(&path).unwrap();
    let barrier = directory.path().join("hold-root-signature");
    fs::write(&barrier, b"").unwrap();
    let operation_native = native.clone();
    let operation = std::thread::spawn(move || {
        complete_native_root_step(&mut store, &operation_native, RegistryVersion::new(7))
    });
    let paused = directory.path().join("root-signature-paused");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !paused.try_exists().unwrap() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    fs::write(directory.path().join("watch-action"), b"watch-event").unwrap();
    while native.ensure_session_active().is_ok() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    fs::remove_file(barrier).unwrap();
    assert!(operation.join().unwrap().is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!original_path(&path).try_exists().unwrap());
}

#[test]
fn native_root_step_two_keeps_state_when_original_publication_fails_after_signing() {
    let (directory, native) = installation(true);
    let path = directory.path().join("publication-failure.bootstrap-state");
    let mut store = begin_store(&path);
    let before = fs::read(&path).unwrap();
    let barrier = directory.path().join("hold-root-signature");
    fs::write(&barrier, b"").unwrap();
    let operation_native = native.clone();
    let operation = std::thread::spawn(move || {
        complete_native_root_step(&mut store, &operation_native, RegistryVersion::new(7))
    });
    let paused = directory.path().join("root-signature-paused");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !paused.try_exists().unwrap() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    // A deliberate test-only obstacle after admission, before create_new.
    let original = original_path(&path);
    fs::create_dir(&original).unwrap();
    fs::remove_file(barrier).unwrap();
    assert!(operation.join().unwrap().is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(fs::symlink_metadata(&original).unwrap().is_dir());
    assert_eq!(sign_count(directory.path()), 1);
}

#[test]
fn native_root_step_two_rejects_valid_pop_from_another_root_without_replacing_it() {
    let (directory, native) = installation(true);
    let path = directory.path().join("foreign-root.bootstrap-state");
    let mut store = begin_store(&path);
    let state = store.load().unwrap().unwrap();
    let secret = [0x67; 32];
    let signer = CoseSigner::from_secret(SecretBytes::new(secret));
    let public =
        CanonicalPublicCoseKey::ed25519(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
            .unwrap();
    let payload = TrustPayloadV1::initial_root_certificate(RootCertificateFieldsV1 {
        organization_id: state.organization_id(),
        root_public_cose_key: public.to_deterministic_cbor(),
        root_key_thumbprint: public.thumbprint(),
        previous_root_certificate_object_hash: None,
        effective_from_registry_version: RegistryVersion::new(7),
    })
    .unwrap();
    let digest = trust_digest(payload.exact_digest_input());
    let certificate = encode_trust(
        &TrustObjectV1::new(
            payload,
            vec![signer.sign_initial_root(digest.as_bytes()).unwrap()],
        )
        .unwrap(),
    )
    .unwrap();
    let original = original_path(&path);
    fs::write(&original, certificate.as_bytes()).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    assert_eq!(fs::read(&original).unwrap(), certificate.as_bytes());
    assert_eq!(fs::read(&path).unwrap(), state.persisted_image());
    assert_eq!(sign_count(directory.path()), 0);
}

#[test]
fn native_root_step_two_reconfirms_parent_flush_after_injected_post_rename_error() {
    use std::os::unix::fs::symlink;
    let (directory, native) = installation(true);
    let ceremony = directory.path().join("ceremony");
    fs::create_dir(&ceremony).unwrap();
    let path = ceremony.join("late-flush.bootstrap-state");
    let mut store = begin_store(&path);
    store.fail_next_parent_flush_after_rename_for_test();
    assert!(complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err());
    // The rename actually happened; only the following parentflush was
    // deliberately refused by the per-store test-only injection.
    assert_eq!(
        store.load().unwrap().unwrap().step(),
        BootstrapStep::GenerateOfflineRoot
    );
    let state_bytes = fs::read(&path).unwrap();
    let original = original_path(&path);
    let original_bytes = fs::read(&original).unwrap();
    let state_identity = file_identity(&path);
    let original_identity = file_identity(&original);
    let prior_signs = sign_count(directory.path());
    drop(store);

    // Same real files and lock inode via a stable alias. The secure parent
    // flush must reject the symlink; this observes that Resume actually takes
    // that path, not an invented hardware fsync failure or process crash.
    let alias = directory.path().join("ceremony-alias");
    symlink(&ceremony, &alias).unwrap();
    let alias_path = alias.join("late-flush.bootstrap-state");
    let mut alias_store = FileBootstrapStore::new(alias_path).acquire_lease().unwrap();
    assert!(
        complete_native_root_step(&mut alias_store, &native, RegistryVersion::new(7)).is_err(),
        "step 2 must reconfirm the same parentflush instead of only rereading bytes"
    );
    drop(alias_store);
    let mut store = FileBootstrapStore::new(path.clone())
        .acquire_lease()
        .unwrap();
    let result = complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).unwrap();
    assert_eq!(result.exact_certificate().as_bytes(), original_bytes);
    assert_eq!(fs::read(&path).unwrap(), state_bytes);
    assert_eq!(file_identity(&path), state_identity);
    assert_eq!(file_identity(&original), original_identity);
    assert_eq!(sign_count(directory.path()), prior_signs);
}

#[test]
fn native_root_step_two_rejects_later_flags_hidden_in_early_state_before_native_io() {
    let (directory, native) = installation(true);
    let path = directory.path().join("hidden-fingerprints.bootstrap-state");
    let mut store = begin_store(&path);
    let fresh = fs::read(&path).unwrap();
    complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).unwrap();
    let committed = fs::read(&path).unwrap();
    let original = fs::read(original_path(&path)).unwrap();
    let prior_calls = calls(directory.path());
    for mut bytes in [fresh, committed] {
        // Existing persisted grammar tail: fingerprints bool, u32 target
        // count, then four absent optional fields. Change only the bool.
        let index = bytes.len() - 9;
        assert_eq!(&bytes[index..], &[0; 9]);
        bytes[index] = 1;
        BootstrapStateV1::from_persisted_image(&bytes).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(
            complete_native_root_step(&mut store, &native, RegistryVersion::new(7)).is_err(),
            "early persisted state cannot contain a later fingerprints confirmation"
        );
        let coordinator = BootstrapCoordinator::resume(&mut store).unwrap().unwrap();
        assert!(
            prepare_native_root_for_ceremony(&coordinator, &native, RegistryVersion::new(7))
                .is_err()
        );
        drop(coordinator);
        assert_eq!(
            calls(directory.path()),
            prior_calls,
            "reject before native helper IO"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read(original_path(&path)).unwrap(), original);
    }
}
