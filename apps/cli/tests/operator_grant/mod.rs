use super::*;
use std::os::unix::fs::OpenOptionsExt as _;
use support::verify_support as fixture;
#[test]
fn actual_grant_command_uses_native_admin_and_publishes_only_audited_grant_bytes() {
    actual_grant_command(false);
}
#[cfg(feature = "pkcs11-fixture")]
#[test]
fn actual_grant_command_uses_nonexporting_pkcs11_recovery_and_hga_keys() {
    actual_grant_command(true);
}
fn actual_grant_command(use_token: bool) {
    let directory = support::temp_dir("historical-native-cli");
    install_fixture_helper(directory.path());
    fs::write(directory.path().join("authority-fixture"), b"").unwrap();
    let subject = OperatorSubjectId::try_from(&[0x42; 16][..]).unwrap();
    let material = fixture::historical::fixture_with_host_options(
        |_, _| fixture::COMPLETE_PLAINTEXT_V1.to_vec(),
        Some(fixture::historical::HostOptions {
            not_after: support::LIVE_WRITER_NOT_AFTER_V1,
            max_age: support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
            instance: ADMIN_INSTANCE_SECRET,
            account_hash: native_account_hash_for(
                true,
                DeviceId::try_from(&[0x52; 16][..]).unwrap(),
            ),
            commitment: ea_crypto::operator_profile_commitment(
                trust_support::organization(),
                subject,
                TEST_NAME,
                TEST_FUNCTION,
                &PROFILE_SALT,
            ),
        }),
    );
    let archive = directory.path().join("archive");
    support::materialize(&material.fixture, &archive);
    let anchor = directory.path().join("independent-anchor.etb");
    fs::write(&anchor, material.line.exact_anchor_bytes()).unwrap();
    let auth = directory.path().join("authorization.etb");
    let auth_bytes = material.authorization(support::live_clock().get() + 60_000);
    fs::write(&auth, &auth_bytes).unwrap();
    let recipient = directory.path().join("reader.etb");
    fs::write(&recipient, &material.recipient_certificate).unwrap();
    let (recovery, authority) = if use_token {
        let module =
            std::env::var("EA_TEST_PKCS11_MODULE").expect("explicit isolated module required");
        let pin = directory.path().join("pin.txt");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        std::io::Write::write_all(&mut options.open(&pin).unwrap(), b"12345678").unwrap();
        let source = |id: &str| {
            format!(
                "pkcs11:module={module};token=drk250-fixture;id={id};pin-file={}",
                pin.display()
            )
        };
        (source("c1"), source("d1"))
    } else {
        let recovery = directory.path().join("recovery.key");
        fs::write(&recovery, fixture::complete_recipient_secret_bytes()).unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o600)).unwrap();
        let authority = directory.path().join("hga.key");
        fs::write(&authority, trust_support::device_signing_secret()).unwrap();
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o600)).unwrap();
        (
            recovery.to_str().unwrap().to_owned(),
            authority.to_str().unwrap().to_owned(),
        )
    };
    let database = directory.path().join("operator.sqlite");
    let (provider, key) = database_provider_for(true);
    let db = EncryptedDatabase::open(&database, &provider, &key).unwrap();
    db.execute(
        "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
        &[
            StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
            StoreValue::Blob(subject.as_bytes().to_vec()),
            StoreValue::Text(TEST_NAME.into()),
            StoreValue::Text(TEST_FUNCTION.into()),
            StoreValue::Blob(PROFILE_SALT.to_vec()),
            StoreValue::Blob(material.operator_binding.as_bytes().to_vec()),
        ],
    )
    .unwrap();
    drop(db);
    let config = directory.path().join("operator.json");
    fs::write(&config,serde_json::to_vec(&json!({
        "archive_directory":"archive","database_path":"operator.sqlite","device_certificate_hash":hex::encode(material.line.second_bootstrap_admin_hash().as_bytes()),"binding_object_hash":hex::encode(material.operator_binding.as_bytes()),"role":"organization-admin","purpose":"historical-regrant"
    })).unwrap()).unwrap();
    let arguments: Vec<String> = [
        "--trust-anchor",
        anchor.to_str().unwrap(),
        "grant",
        archive.to_str().unwrap(),
        "--recovery-key",
        recovery.as_str(),
        "--authority-key",
        authority.as_str(),
        "--authorization",
        auth.to_str().unwrap(),
        "--recipient-cert",
        recipient.to_str().unwrap(),
        "--operator-config",
        config.to_str().unwrap(),
    ]
    .map(str::to_owned)
    .to_vec();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "process_native::fixture_cli",
            "--nocapture",
        ])
        .env("EA_OPERATOR_FIXTURE_DIRECTORY", directory.path())
        .env(
            "EA_OPERATOR_FIXTURE_ARGS",
            serde_json::to_string(&arguments).unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(archive.join("entries/000000000000_entry.eip")).unwrap(),
        material.entry_bytes
    );
    let db = EncryptedDatabase::open_existing(&database, &provider, &key).unwrap();
    let row = db
        .query_row(
            "SELECT exact_bytes FROM local_audit_event ORDER BY rowid DESC LIMIT 1",
            &[],
        )
        .unwrap()
        .expect("durable audit");
    let event = ea_format::decode_local_audit_event(row.blob(0).unwrap()).unwrap();
    let LocalAuditActionV1::HistoricalRegrant(context) = event.action() else {
        panic!()
    };
    let grant_path = archive.join("grants").join(format!(
        "{}.eag",
        hex::encode(context.new_grant_object_hash().as_bytes())
    ));
    let grant = fs::read(grant_path).unwrap();
    assert_eq!(
        ea_crypto::object_hash(&grant).as_bytes(),
        context.new_grant_object_hash().as_bytes()
    );
    assert_eq!(
        fs::read(archive.join("grants").join(format!(
            "{}.etb",
            hex::encode(ea_crypto::object_hash(&auth_bytes).as_bytes())
        )))
        .unwrap(),
        auth_bytes
    );
    let source = ea_recovery::FsArchiveSource::open(&archive).unwrap();
    let reader = fixture::other_recipient_private_key();
    let report = ea_verify::verify_archive(
        &source,
        &material.anchor,
        ea_verify::VerifyOptions::new(support::live_clock())
            .with_recipient(fixture::other_recipient_key_thumbprint(), &reader),
    )
    .unwrap();
    assert!(report.is_fully_verified(), "{report:?}");
    assert_eq!(report.recipient_grants().count(), 1);
    let calls = fs::read_to_string(directory.path().join("helper-calls")).unwrap();
    assert!(calls.contains("sign operator-instance"));
    assert!(calls.contains("sign admin-signing"));
}
