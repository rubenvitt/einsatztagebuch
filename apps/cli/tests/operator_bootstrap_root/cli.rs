//! Separate CLI fixture; never the installed CLI/OS keystore.
use super::*;
use ea_admin::complete_installed_native_root_step;

#[test]
fn certify_root_installed_entry_rejects_missing_state_before_provider_open() {
    let directory = support::temp_dir("certify-root-no-state");
    let mut store = FileBootstrapStore::new(directory.path().join("missing.state"))
        .acquire_lease()
        .unwrap();
    assert!(matches!(
        complete_installed_native_root_step(&mut store, RegistryVersion::new(7)),
        Err(ea_admin::AdminError::BootstrapContextMismatch)
    ));
}

#[allow(dead_code)]
#[path = "../../src/commands/organization.rs"]
mod organization_command;
use ea_admin::{BootstrapStore as _, complete_native_root_step_with_test_opener};
use std::os::unix::fs::MetadataExt as _;

#[test]
#[ignore = "separate fixture process; never production main"]
fn fixture_cli() {
    let directory = PathBuf::from(std::env::var_os("EA_BOOTSTRAP_CLI_FIXTURE_DIRECTORY").unwrap());
    let arguments: Vec<String> =
        serde_json::from_str(&std::env::var("EA_BOOTSTRAP_CLI_FIXTURE_ARGS").unwrap()).unwrap();
    println!("EA_BOOTSTRAP_CLI_OUTPUT");
    std::io::stdout().flush().unwrap();
    let invocation = match args::parse(arguments.into_iter().map(std::ffi::OsString::from)) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let code = match invocation.command {
        args::Command::OrganizationInit => organization_command::run(&invocation),
        args::Command::OrganizationCertifyRoot {
            initial_registry_version,
        } => organization_command::run_certify_root_with_host(
            &invocation,
            initial_registry_version,
            |store, version| {
                complete_native_root_step_with_test_opener(store, version, || {
                    fs::write(directory.join("cli-native-opened"), b"opened").unwrap();
                    NativeOperatorProvider::open_test_fixture(
                        directory.join("ea-native-operator"),
                        false,
                    )
                })
            },
        ),
        _ => panic!("only organization commands in this fixture"),
    };
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
    std::process::exit(code.as_i32());
}

fn cli(directory: &Path, anchor: &Path, tail: &[&str]) -> std::process::Output {
    let mut arguments = vec![
        "--trust-anchor".to_owned(),
        anchor.to_str().unwrap().to_owned(),
        "organization".to_owned(),
    ];
    arguments.extend(tail.iter().map(|s| s.to_string()));
    let mut result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "process_native::bootstrap_root::cli::fixture_cli",
            "--nocapture",
        ])
        .env("EA_BOOTSTRAP_CLI_FIXTURE_DIRECTORY", directory)
        .env(
            "EA_BOOTSTRAP_CLI_FIXTURE_ARGS",
            serde_json::to_string(&arguments).unwrap(),
        )
        .output()
        .unwrap();
    let marker = b"EA_BOOTSTRAP_CLI_OUTPUT\n";
    let start = result
        .stdout
        .windows(marker.len())
        .position(|b| b == marker)
        .unwrap_or_else(|| {
            panic!(
                "fixture did not start: {}",
                String::from_utf8_lossy(&result.stderr)
            )
        });
    result.stdout.drain(..start + marker.len());
    result
}

fn state_path(anchor: &Path) -> PathBuf {
    let mut path = anchor.as_os_str().to_os_string();
    path.push(".bootstrap-state");
    path.into()
}

fn certify(directory: &Path, anchor: &Path, version: &str) -> std::process::Output {
    cli(
        directory,
        anchor,
        &["certify-root", "--initial-registry-version", version],
    )
}

fn snapshot(path: &Path) -> (Vec<u8>, u64, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (fs::read(path).unwrap(), metadata.dev(), metadata.ino())
}

#[test]
fn certify_root_fixture_process_commits_and_reopens_exact_original_without_resigning() {
    let (directory, native) = installation(true);
    drop(native);
    let anchor = directory.path().join("future.anchor.etb");
    let init = cli(directory.path(), &anchor, &["init"]);
    assert_eq!(
        init.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let path = state_path(&anchor);
    let before = FileBootstrapStore::new(path.clone())
        .load()
        .unwrap()
        .unwrap();
    let result = certify(directory.path(), &anchor, "7");
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    let expected = format!(
        "bootstrapStep.number 2\nbootstrapStep.name GenerateOfflineRoot\nbootstrapStep.count 12\norganizationId {}\nchainId {}\nproductionState BlockedRecoveryTest\n",
        hex::encode(before.organization_id().as_bytes()),
        hex::encode(before.chain_id().as_bytes())
    );
    assert_eq!(result.stdout, expected.as_bytes());
    let committed = FileBootstrapStore::new(path.clone())
        .load()
        .unwrap()
        .unwrap();
    assert!(committed.ceremony_machine() == before.ceremony_machine());
    let original = super::step_two::original_path(&path);
    let original_snapshot = snapshot(&original);
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&original_snapshot.0).unwrap()
    else {
        panic!("trust original")
    };
    let DecodedTrustPayloadV1::InitialRoot(fields) = parsed.value().decoded_payload().unwrap()
    else {
        panic!("initial root")
    };
    assert!(fields.organization_id == before.organization_id());
    assert_eq!(
        fields.effective_from_registry_version,
        RegistryVersion::new(7)
    );
    let public =
        CanonicalPublicCoseKey::from_deterministic_cbor(&fields.root_public_cose_key).unwrap();
    let digest = trust_digest(parsed.value().exact_digest_input());
    ea_crypto::verify_initial_root_pop(&parsed.value().signatures()[0], &public, digest.as_bytes())
        .unwrap();
    let state_snapshot = snapshot(&path);
    let signs = super::step_two::sign_count(directory.path());
    assert_eq!(signs, 1);
    let repeated = certify(directory.path(), &anchor, "7");
    assert_eq!(
        repeated.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&repeated.stderr)
    );
    assert_eq!(repeated.stdout, result.stdout);
    assert_eq!(snapshot(&path), state_snapshot);
    assert_eq!(snapshot(&original), original_snapshot);
    assert_eq!(super::step_two::sign_count(directory.path()), signs);
    fs::remove_file(directory.path().join("cli-native-opened")).unwrap();
    let wrong_version = certify(directory.path(), &anchor, "8");
    assert_eq!(wrong_version.status.code(), Some(12));
    assert!(
        !directory
            .path()
            .join("cli-native-opened")
            .try_exists()
            .unwrap()
    );
    assert!(wrong_version.stdout.is_empty());
    assert_eq!(snapshot(&path), state_snapshot);
    assert_eq!(snapshot(&original), original_snapshot);
    assert_no_key_mutation(&calls(directory.path()));
    assert!(!anchor.try_exists().unwrap());
}

#[test]
fn certify_root_fixture_rejects_bad_states_and_files_before_native_construction() {
    let (directory, native) = installation(true);
    drop(native);
    let anchor = directory.path().join("future.etb");
    let path = state_path(&anchor);
    let marker = directory.path().join("cli-native-opened");
    let before_calls = calls(directory.path());
    assert_eq!(
        certify(directory.path(), &anchor, "7").status.code(),
        Some(12)
    );
    assert!(!marker.try_exists().unwrap());
    assert_eq!(
        cli(directory.path(), &anchor, &["init"]).status.code(),
        Some(0)
    );
    let initial = fs::read(&path).unwrap();
    let mut hidden = initial.clone();
    let flag = hidden.len() - 9;
    assert_eq!(&hidden[flag..], &[0; 9]);
    hidden[flag] = 1;
    BootstrapStateV1::from_persisted_image(&hidden).unwrap();
    fs::write(&path, &hidden).unwrap();
    assert_eq!(
        certify(directory.path(), &anchor, "7").status.code(),
        Some(12)
    );
    assert_eq!(fs::read(&path).unwrap(), hidden);
    assert!(!marker.try_exists().unwrap());
    fs::write(&path, &initial).unwrap();
    let original = super::step_two::original_path(&path);
    fs::write(&original, b"corrupt original").unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    let corrupt = snapshot(&original);
    let result = certify(directory.path(), &anchor, "7");
    assert_eq!(result.status.code(), Some(10));
    assert!(result.stdout.is_empty());
    assert!(!marker.try_exists().unwrap());
    assert_eq!(snapshot(&original), corrupt);
    assert_eq!(fs::read(&path).unwrap(), initial);
    assert_eq!(calls(directory.path()), before_calls);
    let lease = FileBootstrapStore::new(path).acquire_lease().unwrap();
    assert_eq!(
        certify(directory.path(), &anchor, "7").status.code(),
        Some(20)
    );
    assert!(!marker.try_exists().unwrap());
    drop(lease);
}

#[test]
fn certify_root_fixture_missing_native_root_never_generates_or_replaces_it() {
    let (directory, native) = installation(false);
    drop(native);
    let anchor = directory.path().join("future.etb");
    assert_eq!(
        cli(directory.path(), &anchor, &["init"]).status.code(),
        Some(0)
    );
    let path = state_path(&anchor);
    let before = snapshot(&path);
    let result = certify(directory.path(), &anchor, "7");
    assert_eq!(result.status.code(), Some(14));
    assert!(result.stdout.is_empty());
    assert_eq!(snapshot(&path), before);
    assert!(!super::step_two::original_path(&path).try_exists().unwrap());
    assert_no_key_mutation(&calls(directory.path()));
}
