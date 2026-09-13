//! Real helper-process host composition; private synthetic fixture keys only.
use super::*;
use ea_admin::{
    complete_native_root_step, seal_native_bootstrap_admin_backup,
    seal_native_bootstrap_root_backup,
};
use ea_crypto::SecretVec;
use ea_recovery::ContainedKeyKind;

pub(in crate::process_native) fn binary_fixture_response(
    directory: &Path,
    request: &Value,
    installation: &str,
    fallback_secret: [u8; 32],
    allowed: bool,
) -> bool {
    let operation = request["op"].as_str().unwrap_or("");
    if operation == "unwrap-secret"
        && request["slot"] == "database-key"
        && directory.join("backup-export-returned").exists()
        && directory.join("hold-final-backup-unwrap").exists()
    {
        fs::write(directory.join("backup-final-unwrap-paused"), b"").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while directory.join("hold-final-backup-unwrap").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "bounded final unwrap barrier"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    if operation == "public-key"
        && request["slot"] == "root-signing"
        && directory.join("backup-export-returned").exists()
        && directory.join("hold-final-backup-binding").exists()
    {
        let counter = directory.join("backup-root-check-count");
        let count = fs::read_to_string(&counter)
            .ok()
            .and_then(|text| text.parse::<u8>().ok())
            .unwrap_or(0)
            + 1;
        fs::write(counter, count.to_string()).unwrap();
        if count == 2 {
            fs::write(directory.join("backup-final-binding-paused"), b"").unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while directory.join("hold-final-backup-binding").exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "bounded final binding barrier"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }
    if operation != "backup-signing-seed" {
        return false;
    }
    assert_eq!(request.as_object().unwrap().len(), 5);
    assert_eq!(request["presence"], true);
    assert_eq!(request["installation_id"], installation);
    let slot = request["slot"].as_str().unwrap();
    let role = match slot {
        "admin-signing" => 1,
        "root-signing" => 2,
        _ => panic!("closed backup fixture slot"),
    };
    let secret = if directory.join("bootstrap-participant-fixture").exists() {
        assert_eq!(slot, "admin-signing");
        assert!(directory.join("participant-key-admin-signing").exists());
        super::participant::signing_backup::fixture_admin_seed()
    } else {
        assert!(allowed);
        fallback_secret
    };
    let public = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
    assert_eq!(request["expected_public_key"], hex::encode(public));
    let mut frame = zeroize::Zeroizing::new([0u8; 106]);
    frame[..8].copy_from_slice(b"EABKSEED");
    frame[8] = 1;
    frame[9] = role;
    frame[10..42].copy_from_slice(&hex::decode(installation).unwrap());
    frame[42..74].copy_from_slice(&public);
    frame[74..].copy_from_slice(&secret);
    let mut pipe = fs::OpenOptions::new()
        .write(true)
        .open("/dev/fd/3")
        .unwrap();
    pipe.write_all(&*frame).unwrap();
    pipe.flush().unwrap();
    fs::write(directory.join("backup-export-returned"), b"").unwrap();
    true
}

#[test]
fn root_backup_seals_existing_native_key_without_advancing_ceremony() {
    let (directory, native) = installation(true);
    let state_path = directory.path().join("backup.bootstrap-state");
    let mut ceremony = FileBootstrapStore::new(state_path.clone())
        .acquire_lease()
        .unwrap();
    drop(
        BootstrapCoordinator::begin(
            &mut ceremony,
            &mut SystemRandomSource,
            Some(Hash32::try_from(&[0x45; 32][..]).unwrap()),
        )
        .unwrap(),
    );
    let root = complete_native_root_step(&mut ceremony, &native, RegistryVersion::new(7)).unwrap();
    let state = fs::read(&state_path).unwrap();
    let original = fs::read(step_two::original_path(&state_path)).unwrap();
    let offset = calls(directory.path()).len();
    let passphrase = SecretVec::new(b"synthetic root backup passphrase".to_vec());
    let container = seal_native_bootstrap_root_backup(&mut ceremony, &native, &passphrase)
        .expect("retained Root seed seals through the private native process");
    let secret = container
        .open(ContainedKeyKind::Signing, &passphrase)
        .unwrap();
    let public = CoseSigner::from_secret(secret).public_key().unwrap();
    assert_eq!(
        public.to_deterministic_cbor(),
        root.material().exact_public_cose_key
    );
    assert_eq!(fs::read(&state_path).unwrap(), state);
    assert_eq!(
        fs::read(step_two::original_path(&state_path)).unwrap(),
        original
    );
    let log = calls(directory.path());
    let after = &log[offset..];
    assert!(
        after
            .lines()
            .any(|line| line == "backup-signing-seed root-signing")
    );
    for forbidden in ["generate ", "delete ", "initialize ", "wrap-secret "] {
        assert!(!after.lines().any(|line| line.starts_with(forbidden)));
    }
}

#[test]
fn backup_hosts_refuse_unheld_ceremony_before_export_or_database_key_io() {
    let (directory, native) = installation(true);
    let mut ceremony = FileBootstrapStore::new(directory.path().join("absent.bootstrap-state"));
    let offset = calls(directory.path()).len();
    let passphrase = SecretVec::new(b"synthetic passphrase".to_vec());
    assert!(seal_native_bootstrap_root_backup(&mut ceremony, &native, &passphrase).is_err());
    assert!(
        seal_native_bootstrap_admin_backup(
            &mut ceremony,
            &directory.path().join("absent.sqlcipher"),
            &native,
            &passphrase
        )
        .is_err()
    );
    assert_eq!(calls(directory.path()).len(), offset);
}

pub(in crate::process_native) fn fixture_response_returned(directory: &Path, request: &Value) {
    if request["op"] == "unwrap-secret"
        && request["slot"] == "database-key"
        && directory.join("backup-final-unwrap-paused").exists()
    {
        fs::write(directory.join("backup-final-unwrap-returned"), b"").unwrap();
    }
    if request["op"] == "public-key"
        && request["slot"] == "root-signing"
        && directory.join("backup-final-binding-paused").exists()
    {
        fs::write(directory.join("backup-final-binding-returned"), b"").unwrap();
    }
}
pub(super) fn wait_marker(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "bounded fixture stage"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
#[test]
fn root_backup_refuses_replaced_lease_during_last_native_recheck() {
    let (directory, native) = installation(true);
    let state_path = directory.path().join("last-lease.bootstrap-state");
    let mut ceremony = FileBootstrapStore::new(state_path.clone())
        .acquire_lease()
        .unwrap();
    drop(
        BootstrapCoordinator::begin(
            &mut ceremony,
            &mut SystemRandomSource,
            Some(Hash32::try_from(&[0x45; 32][..]).unwrap()),
        )
        .unwrap(),
    );
    complete_native_root_step(&mut ceremony, &native, RegistryVersion::new(7)).unwrap();
    let before = fs::read(&state_path).unwrap();
    let barrier = directory.path().join("hold-final-backup-binding");
    fs::write(&barrier, b"").unwrap();
    let result = std::thread::scope(|scope| {
        let action = scope.spawn(|| {
            seal_native_bootstrap_root_backup(
                &mut ceremony,
                &native,
                &SecretVec::new(b"synthetic lease passphrase".to_vec()),
            )
        });
        wait_marker(&directory.path().join("backup-final-binding-paused"));
        let mut lock_path = state_path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        fs::rename(&lock_path, directory.path().join("old-held-lock")).unwrap();
        fs::write(&lock_path, b"").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&barrier).unwrap();
        let result = action.join().unwrap();
        wait_marker(&directory.path().join("backup-final-binding-returned"));
        result
    });
    assert_eq!(fs::read(state_path).unwrap(), before);
    assert!(
        result.is_err(),
        "lost final lease must refuse the encrypted container"
    );
}
