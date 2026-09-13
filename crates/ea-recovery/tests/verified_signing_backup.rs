//! Pure codec composition only; synthetic seeds are not a native-export witness.
use ea_crypto::{CanonicalPublicCoseKey, CoseSigner, SecretBytes, SecretVec};
use ea_recovery::{
    ContainedKeyKind, EncryptedKeyContainer, RecoveryError, seal_verified_signing,
    verify_signing_container_key,
};

fn public(seed: u8) -> CanonicalPublicCoseKey {
    CoseSigner::from_secret(SecretBytes::new([seed; 32]))
        .public_key()
        .unwrap()
}

#[test]
fn verified_signing_seal_retains_existing_v1_codec_and_exact_key() {
    let passphrase = SecretVec::new(b"synthetic backup passphrase".to_vec());
    let expected = public(0x71);
    let container = seal_verified_signing(SecretBytes::new([0x71; 32]), &expected, &passphrase)
        .expect("matching signing seed seals");
    let decoded = EncryptedKeyContainer::from_bytes(&container.to_bytes()).unwrap();
    let opened = decoded
        .open(ContainedKeyKind::Signing, &passphrase)
        .unwrap();
    assert!(CoseSigner::from_secret(opened).public_key().unwrap() == expected);
    assert!(
        decoded
            .open(ContainedKeyKind::RecipientKem, &passphrase)
            .is_err()
    );
    assert!(
        decoded
            .open(
                ContainedKeyKind::Signing,
                &SecretVec::new(b"wrong".to_vec())
            )
            .is_err()
    );
}

#[test]
fn verified_signing_seal_refuses_wrong_seed_and_invalid_passphrase() {
    let expected = public(0x71);
    let passphrase = SecretVec::new(b"synthetic backup passphrase".to_vec());
    assert!(seal_verified_signing(SecretBytes::new([0x72; 32]), &expected, &passphrase).is_err());
    assert!(
        seal_verified_signing(
            SecretBytes::new([0x71; 32]),
            &CanonicalPublicCoseKey::X25519([0x71; 32]),
            &passphrase
        )
        .is_err()
    );
    for bytes in [
        vec![],
        vec![b'x'; ea_recovery::MAX_SECRET_FILE_BYTES_V1 + 1],
    ] {
        assert!(
            seal_verified_signing(
                SecretBytes::new([0x71; 32]),
                &expected,
                &SecretVec::new(bytes)
            )
            .is_err()
        );
    }
}

#[test]
fn verified_signing_container_checks_actual_key_without_changing_bytes() {
    let passphrase = SecretVec::new(b"synthetic readback passphrase".to_vec());
    let expected = public(0x73);
    let container = EncryptedKeyContainer::seal(
        ContainedKeyKind::Signing,
        SecretBytes::new([0x73; 32]),
        &passphrase,
    )
    .unwrap();
    let original = container.to_bytes();
    let reopened = EncryptedKeyContainer::from_bytes(&original).unwrap();
    assert_eq!(
        verify_signing_container_key(&reopened, &expected, &passphrase),
        Ok(())
    );
    assert_eq!(reopened.to_bytes(), original);
    assert_eq!(
        verify_signing_container_key(&reopened, &public(0x74), &passphrase),
        Err(RecoveryError::KeySource)
    );
    assert_eq!(
        verify_signing_container_key(&reopened, &expected, &SecretVec::new(b"wrong".to_vec())),
        Err(RecoveryError::ContainerOpen)
    );
    let mut changed = original;
    *changed.last_mut().unwrap() ^= 1;
    let changed = EncryptedKeyContainer::from_bytes(&changed).unwrap();
    assert_eq!(
        verify_signing_container_key(&changed, &expected, &passphrase),
        Err(RecoveryError::ContainerOpen)
    );
}

#[test]
fn verified_signing_container_checks_kind_and_bounds_before_open() {
    let passphrase = SecretVec::new(vec![b'p'; ea_recovery::MAX_SECRET_FILE_BYTES_V1]);
    let expected = public(0x75);
    let signing = EncryptedKeyContainer::seal(
        ContainedKeyKind::Signing,
        SecretBytes::new([0x75; 32]),
        &passphrase,
    )
    .unwrap();
    let recipient = EncryptedKeyContainer::seal(
        ContainedKeyKind::RecipientKem,
        SecretBytes::new([0x75; 32]),
        &passphrase,
    )
    .unwrap();
    let empty = SecretVec::new(Vec::new());
    assert_eq!(
        verify_signing_container_key(&recipient, &expected, &empty),
        Err(RecoveryError::KeySource)
    );
    assert_eq!(
        verify_signing_container_key(
            &signing,
            &CanonicalPublicCoseKey::X25519([0x75; 32]),
            &empty
        ),
        Err(RecoveryError::KeySource)
    );
    assert_eq!(
        verify_signing_container_key(&signing, &expected, &empty),
        Err(RecoveryError::SecretEmpty)
    );
    assert_eq!(
        verify_signing_container_key(
            &signing,
            &expected,
            &SecretVec::new(vec![b'p'; ea_recovery::MAX_SECRET_FILE_BYTES_V1 + 1])
        ),
        Err(RecoveryError::KeySource)
    );
    assert_eq!(
        verify_signing_container_key(&signing, &expected, &passphrase),
        Ok(())
    );
}
