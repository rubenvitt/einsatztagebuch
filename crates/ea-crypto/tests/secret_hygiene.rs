use ea_crypto::{
    CoseSigner, CryptoError, HpkeRecipientPrivateKey, SecretBytes, SecretVec, aead_open, aead_seal,
    hpke_open, hpke_seal, trust_digest,
};
use zeroize::Zeroize;

fn panic_payload_text(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(text) => *text,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(text) => (*text).to_owned(),
            Err(_) => "non-text panic payload".to_owned(),
        },
    }
}

fn captured_error_panic(error: CryptoError) -> String {
    let panic = std::panic::catch_unwind(move || panic!("{error:?}"))
        .expect_err("the real error must reach the panic payload capture");
    panic_payload_text(panic)
}

#[test]
fn secrets_do_not_implement_formatting_or_leak_through_errors() {
    let key_canary = "PRIVATE-KEY-CANARY";
    let cek_canary = "CEK-CANARY";
    let plaintext_canary = "PLAINTEXT-CANARY";
    let challenge_canary = "RECOVERY-CHALLENGE-CANARY";
    let rendered = format!("{:?} {}", CryptoError::AeadOpen, CryptoError::HpkeOpen);
    for canary in [key_canary, cek_canary, plaintext_canary, challenge_canary] {
        assert!(!rendered.contains(canary));
    }

    let secret = SecretBytes::<32>::new([0x55; 32]);
    let plaintext = SecretVec::new(plaintext_canary.as_bytes().to_vec());
    assert_eq!(secret.len(), 32);
    assert_eq!(plaintext.len(), plaintext_canary.len());
}

#[test]
fn stable_errors_never_include_upstream_details() {
    assert_eq!(
        format!("{:?}", CryptoError::InvalidCose),
        "EA-CRYPTO-INVALID-COSE"
    );
    assert_eq!(
        format!("{}", CryptoError::SignerMismatch),
        "EA-TRUST-SIGNER-MISMATCH"
    );
}

#[test]
fn owned_secret_backing_is_observably_zeroized_where_safe_access_permits() {
    let mut fixed = SecretBytes::new([0x5a; 32]);
    fixed.zeroize();
    assert!(fixed.matches(&[0; 32]));

    let mut variable = SecretVec::new(b"PLAINTEXT-ZEROIZE-CANARY".to_vec());
    variable.zeroize();
    assert!(variable.matches(&[0; 24]));
}

#[test]
fn cryptographic_failure_paths_return_only_stable_codes_and_no_secret_buffers() {
    let key = SecretBytes::new([0x4b; 32]);
    let nonce = SecretBytes::new([0x4e; 12]);
    let plaintext_canary = b"PLAINTEXT-FAILURE-CANARY";
    let ciphertext = aead_seal(
        &key,
        &nonce,
        SecretVec::new(plaintext_canary.to_vec()),
        b"bound aad",
    )
    .unwrap();
    assert!(
        !ciphertext
            .windows(plaintext_canary.len())
            .any(|window| window == plaintext_canary)
    );
    let aead_error = aead_open(&key, &nonce, &ciphertext, b"wrong aad")
        .err()
        .unwrap();

    let recipient = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x42; 32])).unwrap();
    let sealed = hpke_seal(
        &recipient.public_key(),
        &SecretBytes::new([0x43; 32]),
        b"info",
        b"aad",
    )
    .unwrap();
    let hpke_error = hpke_open(&recipient, &sealed, b"wrong info", b"aad")
        .err()
        .unwrap();

    let signer = CoseSigner::from_secret(SecretBytes::new([0x53; 32]));
    let productive = trust_digest(b"PRODUCTIVE-TRUST-CANARY");
    let recovery_error = signer.sign_enrollment(productive.as_bytes()).unwrap_err();

    let rendered = format!("{aead_error:?}|{hpke_error}|{recovery_error:?}");
    assert_eq!(
        rendered,
        "EA-CRYPTO-AEAD-OPEN|EA-CRYPTO-HPKE-OPEN|EA-CRYPTO-INVALID-PROTOCOL-CORE"
    );
    for canary in [
        "PLAINTEXT-FAILURE-CANARY",
        "PRODUCTIVE-TRUST-CANARY",
        "KKKKKKKK",
        "CCCCCCCC",
        "SSSSSSSS",
    ] {
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn real_failure_snapshots_and_panic_payloads_never_contain_secret_canaries() {
    let key = SecretBytes::new([b'K'; 32]);
    let nonce = SecretBytes::new([b'N'; 12]);
    let ciphertext = aead_seal(
        &key,
        &nonce,
        SecretVec::new(b"PLAINTEXT-FAILURE-CANARY".to_vec()),
        b"bound aad",
    )
    .unwrap();
    let aead_error = aead_open(&key, &nonce, &ciphertext, b"wrong aad")
        .err()
        .unwrap();

    let hpke_private = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([b'H'; 32])).unwrap();
    let hpke_wire = hpke_seal(
        &hpke_private.public_key(),
        &SecretBytes::new([b'C'; 32]),
        b"bound info",
        b"bound aad",
    )
    .unwrap();
    let hpke_error = hpke_open(&hpke_private, &hpke_wire, b"wrong info", b"bound aad")
        .err()
        .unwrap();

    let recovery_signer = CoseSigner::from_secret(SecretBytes::new([b'S'; 32]));
    let certificate = ea_types::CertificateHash::try_from([0x51; 32].as_slice()).unwrap();
    let recovery = recovery_signer
        .sign_recovery_test(certificate, SecretBytes::new([b'R'; 32]))
        .unwrap();
    let recovery_error = recovery_signer.sign_enrollment(&recovery).err().unwrap();

    let snapshot = format!("{aead_error:?}|{hpke_error:?}|{recovery_error:?}");
    assert_eq!(
        snapshot,
        "EA-CRYPTO-AEAD-OPEN|EA-CRYPTO-HPKE-OPEN|EA-CRYPTO-INVALID-COSE"
    );
    let panic_snapshot = [aead_error, hpke_error, recovery_error]
        .map(captured_error_panic)
        .join("|");
    assert_eq!(panic_snapshot, snapshot);

    for canary in [
        "KKKKKKKK",
        "NNNNNNNN",
        "PLAINTEXT-FAILURE-CANARY",
        "HHHHHHHH",
        "CCCCCCCC",
        "SSSSSSSS",
        "RRRRRRRR",
    ] {
        assert!(!snapshot.contains(canary));
        assert!(!panic_snapshot.contains(canary));
    }
}

#[test]
fn production_crypto_sources_have_no_logging_or_console_emitters() {
    let sources = [
        include_str!("../src/aead.rs"),
        include_str!("../src/cose.rs"),
        include_str!("../src/digest.rs"),
        include_str!("../src/hpke.rs"),
        include_str!("../src/os_account.rs"),
        include_str!("../src/secret.rs"),
        include_str!("../src/thumbprint.rs"),
    ];
    for source in sources {
        for emitter in ["println!(", "eprintln!(", "dbg!(", "log::", "tracing::"] {
            assert!(
                !source.contains(emitter),
                "production crypto source contains forbidden emitter {emitter}"
            );
        }
    }
}

/// Schluesselmaterial fester Groesse MUSS die Crate verlassen koennen, sonst
/// ist der Schluesselport der Stufe 2 nicht baubar: ein Provider uebergibt den
/// `draftDEK` an den Schluesselspeicher des Betriebssystems und liegt damit
/// ausserhalb dieser Crate. Der Weg ist derselbe bereichsgebundene wie bei
/// [`ea_crypto::SecretVec::with_exposed`]: die Bytes sind nur innerhalb des
/// Rueckrufs sichtbar, gehen nie in den Besitz des Aufrufers ueber, und der
/// Zeroize-on-Drop-Vertrag bleibt unberuehrt.
#[test]
fn a_fixed_size_secret_exposes_its_bytes_only_inside_a_scoped_callback() {
    let secret = SecretBytes::<32>::new([0x5a; 32]);

    let length = secret.with_exposed(|bytes| {
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|byte| *byte == 0x5a));
        bytes.len()
    });
    assert_eq!(length, 32);

    // Der Rueckruf darf beliebig oft laufen und veraendert nichts.
    assert!(secret.with_exposed(|bytes| bytes == &[0x5a; 32]));
    assert_eq!(secret.len(), 32);
    assert!(secret.matches(&[0x5a; 32]));
}

/// Der Klartext eines entschluesselten Payloads MUSS die Crate verlassen
/// koennen, sonst ist `einsatzarchiv decrypt --output` nicht baubar
/// (`design.md` §16, Stage-1-Plan Task 10). Der Weg ist bereichsgebunden: die
/// Bytes sind nur innerhalb des Rueckrufs sichtbar, gehen nie in den Besitz des
/// Aufrufers ueber, und der Zeroize-on-Drop-Vertrag bleibt unberuehrt.
#[test]
fn a_variable_secret_exposes_its_bytes_only_inside_a_scoped_callback() {
    let secret = ea_crypto::SecretVec::new(vec![0x5a; 48]);

    let length = secret.with_exposed(|bytes| {
        assert_eq!(bytes.len(), 48);
        assert!(bytes.iter().all(|byte| *byte == 0x5a));
        bytes.len()
    });
    assert_eq!(length, 48);

    // Der Rueckruf darf beliebig oft laufen und veraendert nichts.
    assert!(secret.with_exposed(|bytes| bytes == [0x5a; 48]));
    assert_eq!(secret.len(), 48);
    assert!(secret.matches(&[0x5a; 48]));
}
