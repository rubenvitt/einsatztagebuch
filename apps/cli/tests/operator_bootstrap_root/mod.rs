use super::*;
mod step_two;
pub(super) mod signing_backup;
mod cli;
pub(super) mod participant;
use ea_admin::{
    BootstrapCoordinator, BootstrapStateV1, BootstrapStep, FileBootstrapStore, ProductionState,
    SystemRandomSource, native_provider::NativeOperatorProvider, prepare_native_root_for_ceremony,
    sign_native_initial_root,
};
use ea_crypto::{CoseSigner, SecretBytes, object_hash, parse_cose_sign1, trust_digest};
use ea_format::{
    DecodedTrustPayloadV1, ParsedArchiveObject, RootCertificateFieldsV1, TrustObjectV1,
    TrustPayloadV1, decode_exact_object, encode_trust,
};
use ea_types::RegistryVersion;

fn installation(authority: bool) -> (support::TempDir, Arc<NativeOperatorProvider>) {
    let directory = support::temp_dir("native-bootstrap-root");
    install_fixture_helper(directory.path());
    if authority {
        fs::write(directory.path().join("authority-fixture"), b"").unwrap();
    }
    let native = NativeOperatorProvider::open_test_fixture(
        directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    (directory, native)
}

fn fields() -> RootCertificateFieldsV1 {
    let key = CanonicalPublicCoseKey::ed25519(
        SigningKey::from_bytes(&trust_support::root_signing_secret())
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    RootCertificateFieldsV1 {
        organization_id: trust_support::organization(),
        root_public_cose_key: key.to_deterministic_cbor(),
        root_key_thumbprint: key.thumbprint(),
        previous_root_certificate_object_hash: None,
        effective_from_registry_version: RegistryVersion::new(0),
    }
}

fn calls(directory: &Path) -> String {
    fs::read_to_string(directory.join("helper-calls")).unwrap()
}

fn assert_no_key_mutation(log: &str) {
    for forbidden in [
        "initialize",
        "generate",
        "delete",
        "wrap-secret",
        "unwrap-secret",
    ] {
        assert!(!log.lines().any(|line| line.starts_with(forbidden)));
    }
}

#[test]
fn native_initial_root_matches_existing_software_fixture_bytes_and_material_hash() {
    let (directory, native) = installation(true);
    let fields = fields();
    let payload = TrustPayloadV1::initial_root_certificate(fields.clone()).unwrap();
    let digest = trust_digest(payload.exact_digest_input());
    let signer = CoseSigner::from_secret(SecretBytes::new(trust_support::root_signing_secret()));
    let expected = encode_trust(
        &TrustObjectV1::new(
            payload,
            vec![signer.sign_initial_root(digest.as_bytes()).unwrap()],
        )
        .unwrap(),
    )
    .unwrap();
    let result = sign_native_initial_root(&native, fields.clone()).unwrap();
    assert_eq!(result.exact_certificate().as_bytes(), expected.as_bytes());
    let material = result.material();
    assert!(material.certificate_object_hash == object_hash(expected.as_bytes()));
    assert_eq!(material.exact_public_cose_key, fields.root_public_cose_key);
    assert!(material.key_thumbprint == fields.root_key_thumbprint);
    assert!(material.signing_handle.account_instance() == native.installation_id());
    assert_eq!(
        material.signing_handle.purpose(),
        SecretPurpose::WriterSigningKey
    );
    let ParsedArchiveObject::Trust(object) =
        decode_exact_object(result.exact_certificate().as_bytes()).unwrap()
    else {
        panic!("initial certificate must retain its Trust container");
    };
    assert!(
        matches!(object.value().decoded_payload().unwrap(), DecodedTrustPayloadV1::InitialRoot(actual) if actual == fields)
    );
    assert_eq!(object.value().signatures().len(), 1);
    let signature = parse_cose_sign1(&object.value().signatures()[0], &[]).unwrap();
    assert!(signature.certificate_hash().is_none());
    assert_eq!(signature.payload(), digest.as_bytes());
    let public =
        CanonicalPublicCoseKey::from_deterministic_cbor(&fields.root_public_cose_key).unwrap();
    ea_crypto::verify_initial_root_pop(&object.value().signatures()[0], &public, digest.as_bytes())
        .unwrap();
    let log = calls(directory.path());
    assert_eq!(
        log.lines()
            .filter(|line| *line == "sign root-signing")
            .count(),
        1
    );
    assert_no_key_mutation(&log);
}

#[test]
fn native_initial_root_rejects_foreign_key_thumbprint_and_rotation_before_signing() {
    let (directory, native) = installation(true);
    let mut foreign = fields();
    let other = CanonicalPublicCoseKey::ed25519(
        SigningKey::from_bytes(&[0x79; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    foreign.root_public_cose_key = other.to_deterministic_cbor();
    foreign.root_key_thumbprint = other.thumbprint();
    let mut wrong_thumbprint = fields();
    wrong_thumbprint.root_key_thumbprint = other.thumbprint();
    let mut rotation = fields();
    rotation.previous_root_certificate_object_hash =
        Some(ObjectHash::try_from(&[0x31; 32][..]).unwrap());
    for fields in [foreign, wrong_thumbprint, rotation] {
        assert!(sign_native_initial_root(&native, fields).is_err());
    }
    let log = calls(directory.path());
    assert!(!log.contains("sign root-signing"));
    assert_no_key_mutation(&log);
}

#[test]
fn missing_native_root_is_not_generated_or_replaced_by_a_writer_key() {
    let (directory, native) = installation(false);
    assert!(sign_native_initial_root(&native, fields()).is_err());
    let log = calls(directory.path());
    assert!(!log.lines().any(|line| line.starts_with("sign ")));
    assert_no_key_mutation(&log);
}

#[test]
fn native_initial_root_does_not_return_a_certificate_after_watch_invalidation() {
    let (directory, native) = installation(true);
    let barrier = directory.path().join("hold-root-signature");
    fs::write(&barrier, b"").unwrap();
    let operation_native = native.clone();
    let operation =
        std::thread::spawn(move || sign_native_initial_root(&operation_native, fields()));
    let paused = directory.path().join("root-signature-paused");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !paused.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "native Root signature reaches existing fixture barrier"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    fs::write(directory.path().join("watch-action"), b"watch-event").unwrap();
    let invalidation_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while native.ensure_session_active().is_ok() {
        assert!(
            std::time::Instant::now() < invalidation_deadline,
            "native watcher observes invalidation before signature release"
        );
        std::thread::yield_now();
    }
    assert!(barrier.exists());
    fs::remove_file(barrier).unwrap();
    assert!(operation.join().unwrap().is_err());
    assert_no_key_mutation(&calls(directory.path()));
}

#[test]
fn prepared_native_root_binds_resumed_file_ceremony_without_advancing_or_rewriting_it() {
    let (directory, native) = installation(true);
    let path = directory.path().join("ceremony.bootstrap-state");
    let machine = Some(Hash32::try_from(&[0x43; 32][..]).unwrap());
    let (organization, chain) = {
        let mut store = FileBootstrapStore::new(path.clone());
        let coordinator =
            BootstrapCoordinator::begin(&mut store, &mut SystemRandomSource, machine).unwrap();
        (coordinator.organization_id(), coordinator.chain_id())
    };
    let before = fs::read(&path).unwrap();
    let mut store = FileBootstrapStore::new(path.clone());
    let coordinator = BootstrapCoordinator::resume(&mut store).unwrap().unwrap();
    let version = RegistryVersion::new(7); // Explicit syntax input, no 0/1 host convention.
    let prepared = prepare_native_root_for_ceremony(&coordinator, &native, version).unwrap();
    let ParsedArchiveObject::Trust(object) =
        decode_exact_object(prepared.exact_certificate().as_bytes()).unwrap()
    else {
        panic!("prepared output must remain an initial Root Trust object");
    };
    let DecodedTrustPayloadV1::InitialRoot(actual) = object.value().decoded_payload().unwrap()
    else {
        panic!("preparation cannot produce a rotation");
    };
    assert!(actual.organization_id == organization);
    assert!(actual.effective_from_registry_version == version);
    assert_eq!(actual.root_public_cose_key, fields().root_public_cose_key);
    assert!(actual.previous_root_certificate_object_hash.is_none());
    assert!(
        prepared.material().certificate_object_hash
            == object_hash(prepared.exact_certificate().as_bytes())
    );
    assert_eq!(coordinator.step(), BootstrapStep::GenerateIds);
    assert_eq!(
        coordinator.production_state(),
        ProductionState::BlockedRecoveryTest
    );
    assert!(coordinator.organization_id() == organization && coordinator.chain_id() == chain);
    assert!(coordinator.state().ceremony_machine() == machine);
    assert_eq!(coordinator.state().persisted_image(), before);
    assert_eq!(fs::read(&path).unwrap(), before);
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".writing");
    assert!(
        !PathBuf::from(temporary)
            .try_exists()
            .expect("temporary state-file absence must be observable")
    );
    drop(coordinator);
    drop(store);
    let mut reopened_store = FileBootstrapStore::new(path);
    let reopened = BootstrapCoordinator::resume(&mut reopened_store)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.state().persisted_image(), before);
    assert_no_key_mutation(&calls(directory.path()));
}

#[test]
fn prepare_rejects_later_aborted_and_hidden_root_file_states_before_any_helper_io() {
    let (directory, native) = installation(true);
    let path = directory.path().join("refused.bootstrap-state");
    let (fresh, later) = {
        let mut store = FileBootstrapStore::new(path.clone());
        let mut coordinator =
            BootstrapCoordinator::begin(&mut store, &mut SystemRandomSource, None).unwrap();
        let fresh = coordinator.state().persisted_image();
        let mut initial_fields = fields();
        initial_fields.organization_id = coordinator.organization_id();
        let root = sign_native_initial_root(&native, initial_fields).unwrap();
        coordinator
            .generate_offline_root(root.material().clone())
            .unwrap();
        (fresh, coordinator.state().persisted_image())
    };
    // Negative persisted-state inputs: the existing decoder accepts these
    // flags/step bytes. They grant no authority and must not reach a signer.
    let prefix = b"EINSATZARCHIV-BOOTSTRAP-STATE-v1";
    assert!(fresh.starts_with(prefix) && later.starts_with(prefix));
    let mut aborted = fresh.clone();
    aborted[prefix.len() + 1] = 1;
    let mut hidden_root = later.clone();
    hidden_root[prefix.len()] = BootstrapStep::GenerateIds.number();
    for image in [later, aborted, hidden_root] {
        BootstrapStateV1::from_persisted_image(&image).unwrap();
        fs::write(&path, &image).unwrap();
        let mut store = FileBootstrapStore::new(path.clone());
        let coordinator = BootstrapCoordinator::resume(&mut store).unwrap().unwrap();
        let before_calls = calls(directory.path());
        assert!(
            prepare_native_root_for_ceremony(&coordinator, &native, RegistryVersion::new(7))
                .is_err()
        );
        assert_eq!(
            calls(directory.path()),
            before_calls,
            "no native helper operation is allowed before state admission"
        );
        assert_eq!(fs::read(&path).unwrap(), image);
        assert_eq!(coordinator.state().persisted_image(), image);
    }
    assert_no_key_mutation(&calls(directory.path()));
}
