//! Explicit real-module fixture. The Stage-5 gate must provide its isolated module.
use ea_crypto::{SecretBytes, hpke_seal, parse_cose_sign1};
use ea_recovery::{Pkcs11KeyReference, Pkcs11RecipientKey, Pkcs11SigningKey};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};
mod support;
static TEST_MODULE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_fixture_session<R>(
    module: &Path,
    operation: impl FnOnce(&cryptoki::session::Session) -> R,
) -> R {
    use cryptoki::{
        context::{CInitializeArgs, CInitializeFlags, Pkcs11},
        session::UserType,
        types::AuthPin,
    };
    let context = Pkcs11::new(module).unwrap();
    context
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slots: Vec<_> = context
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .filter(|slot| context.get_token_info(*slot).unwrap().label() == "drk250-fixture")
        .collect();
    assert_eq!(slots.len(), 1);
    let session = context.open_rw_session(slots[0]).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new("12345678".into())))
        .unwrap();
    let result = operation(&session);
    session.logout().unwrap();
    drop(session);
    context.finalize().unwrap();
    result
}

#[test]
fn token_selection_is_unique_fresh_and_keeps_long_term_values_nonexportable() {
    use cryptoki::object::{Attribute as A, AttributeType as T, KeyType, ObjectClass};
    let _guard = TEST_MODULE.lock().unwrap();
    let module =
        PathBuf::from(std::env::var_os("EA_TEST_PKCS11_MODULE").expect("real fixture required"));
    let pin = PinFile::new(b"12345678");
    let key = Pkcs11RecipientKey::open(reference(&module, "a1"), &pin.0).unwrap();
    // An already authenticated module cannot stand in for a fresh PIN check.
    // The refused provider must not finalize or log out the owner session.
    with_fixture_session(&module, |session| {
        let result = Pkcs11RecipientKey::open(reference(&module, "a1"), &pin.0);
        assert!(matches!(
            result,
            Err(ea_recovery::RecoveryError::Pkcs11Provider(
                ea_recovery::Pkcs11ProviderError::Unavailable
            ))
        ));
        for id in [0xa1, 0xb1, 0xc1, 0xd1] {
            let private = session
                .find_objects(&[A::Class(ObjectClass::PRIVATE_KEY), A::Id(vec![id])])
                .unwrap();
            assert_eq!(private.len(), 1);
            let attrs = session
                .get_attributes(private[0], &[T::Sensitive, T::Extractable, T::Value])
                .unwrap();
            assert!(attrs.contains(&A::Sensitive(true)) && attrs.contains(&A::Extractable(false)));
            assert!(
                !attrs.iter().any(|attr| matches!(attr, A::Value(_))),
                "private value must remain inaccessible"
            );
        }
        session
            .create_object(&[
                A::Class(ObjectClass::PUBLIC_KEY),
                A::Token(true),
                A::KeyType(KeyType::EC_EDWARDS),
                A::Id(vec![0xa1]),
                A::Label(b"drk250-duplicate-canary".to_vec()),
                A::EcParams(vec![6, 3, 0x2b, 0x65, 0x6e]),
                A::EcPoint(key.public_key().as_bytes().to_vec()),
            ])
            .unwrap();
    });
    let ambiguous = Pkcs11RecipientKey::open(reference(&module, "a1"), &pin.0);
    with_fixture_session(&module, |session| {
        let duplicates = session
            .find_objects(&[A::Label(b"drk250-duplicate-canary".to_vec())])
            .unwrap();
        assert_eq!(duplicates.len(), 1);
        session.destroy_object(duplicates[0]).unwrap();
    });
    assert!(matches!(
        ambiguous,
        Err(ea_recovery::RecoveryError::Pkcs11Provider(
            ea_recovery::Pkcs11ProviderError::KeySelection
        ))
    ));
    // Native errors cannot leak the selected module/token/PIN through output.
    let wrong_pin = PinFile::new(b"diagnostic-secret-canary");
    let Err(error) = Pkcs11RecipientKey::open(reference(&module, "a1"), &wrong_pin.0) else {
        panic!("incorrect PIN accepted")
    };
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("diagnostic-secret-canary"));
    assert!(!diagnostic.contains("drk250-fixture"));
    assert!(!diagnostic.contains(module.to_str().unwrap()));
    assert!(Pkcs11RecipientKey::open(reference(&module, "a1"), &pin.0).is_ok());
}

#[test]
fn a_replaced_public_mapping_cannot_reuse_an_opened_key_authority() {
    use cryptoki::object::{Attribute as A, AttributeType as T, ObjectClass};
    let _guard = TEST_MODULE.lock().unwrap();
    let module =
        PathBuf::from(std::env::var_os("EA_TEST_PKCS11_MODULE").expect("real fixture required"));
    let pin = PinFile::new(b"12345678");
    let key = Pkcs11RecipientKey::open(reference(&module, "a1"), &pin.0).unwrap();
    let envelope = hpke_seal(
        &key.public_key(),
        &SecretBytes::new([0x34; 32]),
        b"replace",
        b"mapping",
    )
    .unwrap();
    let replacement = ea_crypto::HpkeRecipientPrivateKey::from_bytes(SecretBytes::new([0x35; 32]))
        .unwrap()
        .public_key();
    let original = with_fixture_session(&module, |session| {
        let public = session
            .find_objects(&[A::Class(ObjectClass::PUBLIC_KEY), A::Id(vec![0xa1])])
            .unwrap();
        assert_eq!(public.len(), 1);
        let mut original = session
            .get_attributes(
                public[0],
                &[
                    T::Token,
                    T::Private,
                    T::KeyType,
                    T::Id,
                    T::Label,
                    T::EcParams,
                    T::EcPoint,
                ],
            )
            .unwrap();
        original.push(A::Class(ObjectClass::PUBLIC_KEY));
        let mut changed = original.clone();
        for attribute in &mut changed {
            if let A::EcPoint(bytes) = attribute {
                *bytes = replacement.as_bytes().to_vec();
            }
        }
        session.destroy_object(public[0]).unwrap();
        session.create_object(&changed).unwrap();
        original
    });
    let result = key.open_envelope(&envelope, b"replace", b"mapping");
    with_fixture_session(&module, |session| {
        let public = session
            .find_objects(&[A::Class(ObjectClass::PUBLIC_KEY), A::Id(vec![0xa1])])
            .unwrap();
        assert_eq!(public.len(), 1);
        session.destroy_object(public[0]).unwrap();
        session.create_object(&original).unwrap();
    });
    assert!(matches!(
        result,
        Err(ea_recovery::RecoveryError::Pkcs11Provider(
            ea_recovery::Pkcs11ProviderError::KeySelection
        ))
    ));
    assert!(
        key.open_envelope(&envelope, b"replace", b"mapping")
            .unwrap()
            .matches(&[0x34; 32])
    );
}

struct PinFile(PathBuf);
impl PinFile {
    fn new(value: &[u8]) -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("ea-pkcs11-fixture-{}", hex::encode(random)));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path).unwrap().write_all(value).unwrap();
        Self(path)
    }
}
impl Drop for PinFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn reference(module: &Path, id: &str) -> Pkcs11KeyReference {
    Pkcs11KeyReference::new(module.to_path_buf(), "drk250-fixture".into(), id).unwrap()
}

#[test]
fn explicit_nonexporting_module_opens_hpke_and_signs_with_separate_keys() {
    let _guard = TEST_MODULE.lock().unwrap();
    let module = PathBuf::from(
        std::env::var_os("EA_TEST_PKCS11_MODULE").expect("real isolated PKCS11 fixture required"),
    );
    let pin = PinFile::new(b"12345678");
    let resolved = ea_recovery::resolve_recipient_key(&ea_recovery::KeySourceSpec::Pkcs11 {
        reference: reference(&module, "a1"),
        pin_file: pin.0.clone(),
    })
    .expect("the product resolver must return a non-exporting operation handle");
    let resolved_signer = ea_recovery::resolve_signing_key(&ea_recovery::KeySourceSpec::Pkcs11 {
        reference: reference(&module, "b1"),
        pin_file: pin.0.clone(),
    })
    .expect("the product resolver must support the separate HGA key");
    let key = Pkcs11RecipientKey::open(reference(&module, "a1"), &pin.0).unwrap();
    assert!(resolved.public_key() == key.public_key());
    let sealed = hpke_seal(
        &key.public_key(),
        &SecretBytes::new([0x61; 32]),
        b"fixture-info",
        b"fixture-aad",
    )
    .unwrap();
    assert!(
        key.open_envelope(&sealed, b"fixture-info", b"fixture-aad")
            .unwrap()
            .matches(&[0x61; 32])
    );
    assert!(
        key.open_envelope(&sealed, b"changed", b"fixture-aad")
            .is_err()
    );
    let signer = Pkcs11SigningKey::open(reference(&module, "b1"), &pin.0).unwrap();
    assert!(resolved_signer.public_key().unwrap() == *signer.public_key());
    let certificate = ea_types::CertificateHash::try_from(&[0x62; 32][..]).unwrap();
    let signed = signer
        .sign_recovery_test(certificate, SecretBytes::new([0x63; 32]))
        .unwrap();
    let parsed = parse_cose_sign1(&signed, &[]).unwrap();
    assert!(parsed.key_thumbprint() == signer.public_key().thumbprint());
    assert!(parsed.certificate_hash() == Some(certificate));
    // Repeated, interleaved sources must perform fresh sessions, not reuse
    // a previous token-wide authenticated state or invalidate another key.
    assert!(
        key.open_envelope(&sealed, b"fixture-info", b"fixture-aad")
            .unwrap()
            .matches(&[0x61; 32])
    );
    assert!(Pkcs11RecipientKey::open(reference(&module, "b1"), &pin.0).is_err());
    assert!(Pkcs11SigningKey::open(reference(&module, "a1"), &pin.0).is_err());
    assert!(Pkcs11RecipientKey::open(reference(&module, "ff"), &pin.0).is_err());
    let wrong_pin = PinFile::new(b"wrong-fixture-pin");
    assert!(Pkcs11RecipientKey::open(reference(&module, "a1"), &wrong_pin.0).is_err());
    // A failed login must not leave the provider poisoned or authenticated.
    assert!(
        key.open_envelope(&sealed, b"fixture-info", b"fixture-aad")
            .unwrap()
            .matches(&[0x61; 32])
    );
}

#[test]
fn verified_archive_decrypts_through_the_nonexporting_product_resolver() {
    let _guard = TEST_MODULE.lock().unwrap();
    let module =
        PathBuf::from(std::env::var_os("EA_TEST_PKCS11_MODULE").expect("real fixture required"));
    let pin = PinFile::new(b"12345678");
    let root = support::temp_dir("token-archive-decrypt");
    let fixture = support::verify_support::historical::fixture(
        support::verify_support::COMPLETE_PLAINTEXT_V1,
    );
    let archive = root.path().join("archive");
    support::materialize(&fixture.fixture, &archive);
    let key = ea_recovery::resolve_recipient_key(&ea_recovery::KeySourceSpec::Pkcs11 {
        reference: reference(&module, "c1"),
        pin_file: pin.0.clone(),
    })
    .unwrap();
    let thumbprint = ea_recovery::recipient_key_thumbprint(&key).unwrap();
    assert!(thumbprint == support::verify_support::complete_recipient_key_thumbprint());
    let report = ea_recovery::verify_directory(
        &archive,
        &fixture.anchor,
        ea_types::UnixMillis::new(800),
        Some((thumbprint, &key)),
    )
    .unwrap();
    assert_eq!(
        ea_recovery::exit_code_for(&report),
        ea_recovery::ExitCode::Success
    );
    let output = root.path().join("plaintext");
    let result = ea_recovery::decrypt_directory(
        &archive,
        &fixture.anchor,
        ea_types::UnixMillis::new(800),
        &key,
        &output,
    )
    .unwrap();
    assert_eq!(
        ea_recovery::exit_code_for(&result.report),
        ea_recovery::ExitCode::Success
    );
    let files: Vec<_> = fs::read_dir(&output)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(
        fs::read(&files[0]).unwrap(),
        support::verify_support::COMPLETE_PLAINTEXT_V1
    );
}
