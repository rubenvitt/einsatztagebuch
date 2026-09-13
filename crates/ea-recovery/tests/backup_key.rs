use ea_crypto::SecretVec;
use ea_recovery::RecoveryBackupKdf;

#[test]
fn backup_kdf_is_fixed_fresh_and_passphrase_bound() {
    let first = RecoveryBackupKdf::fresh().unwrap();
    let second = RecoveryBackupKdf::fresh().unwrap();
    assert_ne!(first.salt(), second.salt());
    let password = SecretVec::new(b"fixture-only recovery backup phrase".to_vec());
    let a = first.derive(&password).unwrap();
    let b = RecoveryBackupKdf::from_exact(first.exact_bytes())
        .unwrap()
        .derive(&password)
        .unwrap();
    a.with_exposed(|a| b.with_exposed(|b| assert_eq!(a, b)));
    let wrong = first
        .derive(&SecretVec::new(b"wrong fixture phrase".to_vec()))
        .unwrap();
    a.with_exposed(|a| wrong.with_exposed(|b| assert_ne!(a, b)));
    assert!(first.derive(&SecretVec::new(Vec::new())).is_err());
    let mut changed = first.exact_bytes().to_vec();
    let position = changed
        .windows(3)
        .position(|bytes| bytes == [0x1a, 0, 1])
        .unwrap();
    changed[position + 2] = 0;
    assert!(RecoveryBackupKdf::from_exact(&changed).is_err());
    let mut changed = first.exact_bytes().to_vec();
    changed.push(0);
    assert!(RecoveryBackupKdf::from_exact(&changed).is_err());
}
