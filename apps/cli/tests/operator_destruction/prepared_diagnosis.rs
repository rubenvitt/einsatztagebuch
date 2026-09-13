//! Actual Prepared commit followed by the CurrentAdmin diagnostic Rust entry.
use super::*;
use ea_desktop::{
    runtime::{DesktopLaunchConfig, NativeDesktopRuntime},
    state::{ReauthPort, RuntimeSessionPort},
};

fn open(f: &NativeDestructionFixture, admin: bool) -> OperatorRuntime {
    let (directory, config) = if admin {
        (&f.admin_directory, &f.admin_config)
    } else {
        (&f.writer_directory, &f.writer_config)
    };
    OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        NativeOperatorProvider::open_test_fixture(directory.join("ea-native-operator"), false)
            .unwrap(),
    )
    .unwrap()
}
fn settings(f: &NativeDestructionFixture) -> serde_json::Value {
    let ArchiveBackendProfileV1::LocalPath(p) = &f.profile else {
        panic!("local fixture")
    };
    json!({"kind":"local-path","filesystem_row_id":p.filesystem_row_id,"capability_test_vector_id":p.capability_test_vector_id})
}
fn launch(f: &NativeDestructionFixture, admin: bool) -> DesktopLaunchConfig {
    DesktopLaunchConfig {
        operator_config: if admin {
            f.admin_config.clone()
        } else {
            f.writer_config.clone()
        },
        trust_anchor: f.anchor.clone(),
        writer_config: None,
        destruction_config: None,
        recovery_config: None,
        administration_config: None,
    }
}
fn admin_host(f: &NativeDestructionFixture, with_writer: bool) -> Arc<NativeDesktopRuntime> {
    let config = f.admin_directory.join("administration.json");
    fs::write(&config, serde_json::to_vec(&json!({"version":1,"registration_inbox":f.admin_directory,"archive_profile":settings(f)})).unwrap()).unwrap();
    let mut public: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.admin_config).unwrap()).unwrap();
    public["admin_certificate_hash"] = public["device_certificate_hash"].clone();
    public["admin_binding_object_hash"] = public["binding_object_hash"].clone();
    public["ceremony_exchange_directory"] = json!(f.admin_directory);
    fs::write(&f.admin_config, serde_json::to_vec(&public).unwrap()).unwrap();
    let mut launch = launch(f, true);
    launch.administration_config = Some(config);
    if with_writer {
        NativeDesktopRuntime::open_with_test_destruction_runtime(launch, open(f, true), f.runtime())
            .unwrap()
    } else {
        NativeDesktopRuntime::open_with_test_runtime(launch, open(f, true)).unwrap()
    }
}
fn marker(db: &EncryptedDatabase) -> Option<Vec<u8>> {
    db.query_row(
        "SELECT marker FROM draft_transition WHERE singleton=0 AND kind=1",
        &[],
    )
    .unwrap()
    .map(|r| r.blob(0).unwrap().to_vec())
}
fn commit_prepared(f: &NativeDestructionFixture) -> Vec<u8> {
    let config = f.writer_directory.join("writer-settings.json");
    fs::write(
        &config,
        serde_json::to_vec(
            &json!({"version":1,"timezone":"Europe/Berlin","archive_profile":settings(f)}),
        )
        .unwrap(),
    )
    .unwrap();
    let mut launch = launch(f, false);
    launch.writer_config = Some(config);
    let host = NativeDesktopRuntime::open_with_test_runtime(launch, open(f, false)).unwrap();
    assert_eq!(
        host.diagnose_prepared_writer().err().unwrap().code,
        "EA-DESKTOP-ADMINISTRATION-FORBIDDEN"
    );
    host.login().unwrap();
    let state = host.desktop_state();
    state
        .drafts()
        .unwrap()
        .save_payload("prepared diagnosis original incident".into())
        .unwrap();
    let input = ea_ui_contracts::IncidentInputView {
        human_incident_number: "PREPARED-DIAG-1".into(),
        occurred_at: ea_ui_contracts::OccurredAtView {
            start: support::live_clock(),
            end: None,
        },
        keyword: ea_ui_contracts::KeywordView {
            reference_id: Some("N1".into()),
            display_text: "Hilfeleistung".into(),
        },
        location: ea_ui_contracts::LocationView {
            free_text: Some("Testort".into()),
            address: None,
            coordinates: None,
        },
        personnel: vec![],
        personnel_empty_reason: Some("Keine weiteren Kräfte".into()),
        vehicles: vec![],
        vehicles_empty_reason: Some("Kein Fahrzeug".into()),
        patient_count: ea_ui_contracts::PatientCountView::Known(0),
        notes: None,
        external_organizations: vec![],
    };
    let writer = state.writer().unwrap();
    let preview = writer.preview(&input).unwrap();
    host.reauthenticate(ea_operator::ReauthPurpose::Finalize)
        .unwrap();
    fs::write(
        f.writer_directory.join("helper-mode"),
        "draft-delete-refused",
    )
    .unwrap();
    let failure = writer
        .finalize(&input, &preview)
        .expect_err("actual stop after Prepared commit");
    eprintln!("Prepared fixture finalization refused: {}", failure.code);
    fs::remove_file(f.writer_directory.join("helper-mode")).unwrap();
    let (p, k) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &p, &k).unwrap();
    let exact = marker(&db).expect("actual Writer persisted Prepared bytes");
    assert_eq!(
        ea_writer::diagnose_prepared_marker(&exact),
        ea_writer::PreparedMarkerDiagnosisV1::StructurallyConsistent
    );
    exact
}
#[test]
fn native_prepared_diagnosis_reads_actual_writer_commit_under_current_admin() {
    let f = NativeDestructionFixture::without_server();
    let exact = commit_prepared(&f);
    let host = admin_host(&f, true);
    assert_eq!(
        host.diagnose_prepared_writer().err().unwrap().code,
        "EA-DESKTOP-SESSION-LOCKED"
    );
    host.login().unwrap();
    let calls_before = fs::read_to_string(f.writer_directory.join("helper-calls")).unwrap();
    let key_before = fs::read(f.writer_directory.join("fixture-draft-key.sealed")).unwrap();
    let archive_before = archive_files(&f.archive);
    assert_eq!(
        host.diagnose_prepared_writer().unwrap(),
        Some(ea_writer::PreparedMarkerDiagnosisV1::StructurallyConsistent)
    );
    let calls_after = fs::read_to_string(f.writer_directory.join("helper-calls")).unwrap();
    for call in calls_after.strip_prefix(&calls_before).unwrap().lines() {
        assert!(
            call.starts_with("account ") || call.starts_with("public-key "),
            "diagnostic Writer helper operation: {call}"
        );
    }
    assert_eq!(
        fs::read(f.writer_directory.join("fixture-draft-key.sealed")).unwrap(),
        key_before
    );
    assert_eq!(archive_files(&f.archive), archive_before);
    let (p, k) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &p, &k).unwrap();
    assert_eq!(marker(&db), Some(exact));
    let (p, k) = database_provider_for(true);
    let admin =
        EncryptedDatabase::open_existing(&f.admin_directory.join("local.sqlite"), &p, &k).unwrap();
    assert!(marker(&admin).is_none());
    let reached = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        host.diagnose_prepared_writer_with_test_after_profile(|| {
            reached.store(true, std::sync::atomic::Ordering::SeqCst);
            host.invalidate();
        })
        .err()
        .unwrap()
        .code,
        "EA-DESKTOP-SESSION-LOCKED"
    );
    assert!(reached.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        host.diagnose_prepared_writer().err().unwrap().code,
        "EA-DESKTOP-SESSION-LOCKED"
    );
}
#[test]
fn native_prepared_diagnosis_missing_writer_never_falls_back_to_admin_database() {
    let f = NativeDestructionFixture::without_server();
    let host = admin_host(&f, false);
    assert_eq!(
        host.diagnose_prepared_writer().err().unwrap().code,
        "EA-DESKTOP-ADMINISTRATION-UNAVAILABLE"
    );
}

fn archive_files(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for item in fs::read_dir(path).unwrap() {
        let path = item.unwrap().path();
        if path.is_dir() {
            out.extend(archive_files(&path));
        } else {
            out.push((path.clone(), fs::read(path).unwrap()));
        }
    }
    out.sort();
    out
}
#[test]
fn native_prepared_diagnosis_profile_and_marker_share_the_sqlite_reservation() {
    let f = NativeDestructionFixture::without_server();
    let owner = f.runtime();
    let admin = open(&f, true);
    let (p, k) = database_provider_for(false);
    let other =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &p, &k).unwrap();
    other.query_row("PRAGMA busy_timeout=0", &[]).unwrap();
    let change = || {
        other.transaction::<_,ea_local_store::StoreError>(|tx| {
        tx.execute("UPDATE operator_profile SET display_name='concurrent different profile' WHERE singleton=0",&[])?;
        tx.execute("INSERT INTO draft_transition(singleton,kind,draft_id,save_revision,marker,recorded_at_ms) VALUES(0,1,zeroblob(16),0,X'FF',0)",&[])?;
        Ok(())
    })
    };
    let changed = std::cell::Cell::new(false);
    let result = owner
        .writer_prepared_diagnosis()
        .diagnose_with_test_after_profile(&admin, &f.profile, || {
            changed.set(change().is_ok());
        })
        .unwrap();
    assert_eq!(
        result, None,
        "a new marker after the old admitted profile must not be returned"
    );
    assert!(
        !changed.get(),
        "the real second SQLite BEGIN was refused during the reserved snapshot"
    );
    change().expect("identical transaction succeeds after diagnosis releases its reservation");
    assert!(
        owner
            .writer_prepared_diagnosis()
            .diagnose(&admin, &f.profile)
            .is_err(),
        "new mismatched profile cannot expose its marker"
    );
}
#[test]
fn native_prepared_diagnosis_checks_its_own_writer_identity_and_profile() {
    let f = NativeDestructionFixture::without_server();
    let owner = f.runtime();
    let admin = open(&f, true);
    assert_eq!(
        owner
            .writer_prepared_diagnosis()
            .diagnose(&admin, &f.profile)
            .unwrap(),
        None
    );
    fs::write(f.writer_directory.join("helper-mode"), "foreign-instance").unwrap();
    assert!(
        owner
            .writer_prepared_diagnosis()
            .diagnose(&admin, &f.profile)
            .is_err()
    );
    fs::write(f.writer_directory.join("helper-mode"), "foreign-writer").unwrap();
    assert!(
        owner
            .writer_prepared_diagnosis()
            .diagnose(&admin, &f.profile)
            .is_err()
    );
    fs::remove_file(f.writer_directory.join("helper-mode")).unwrap();
    let (p, k) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &p, &k).unwrap();
    db.execute(
        "UPDATE operator_profile SET display_name='foreign local profile'",
        &[],
    )
    .unwrap();
    assert_eq!(
        owner
            .writer_prepared_diagnosis()
            .diagnose(&admin, &f.profile)
            .err()
            .unwrap()
            .code(),
        "EA-OPERATOR-PROFILE-COMMITMENT"
    );
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.writer_config).unwrap()).unwrap();
    config["binding_object_hash"] = json!("ef".repeat(32));
    fs::write(&f.writer_config, serde_json::to_vec(&config).unwrap()).unwrap();
    let wrong = f.runtime();
    assert!(
        wrong
            .writer_prepared_diagnosis()
            .diagnose(&admin, &f.profile)
            .is_err(),
        "native certificate alone does not admit configured Writer binding"
    );
}

struct DiagnosisPosture(std::sync::atomic::AtomicU8);
impl ea_key_provider::DevicePostureProvider for DiagnosisPosture {
    fn report(&self) -> Result<ea_key_provider::DevicePostureReport, ea_key_provider::KeyError> {
        use ea_key_provider::{DevicePostureProviderFake as Fake, PostureRequirement as R};
        let fake = match self.0.load(std::sync::atomic::Ordering::SeqCst) {
            0 => Fake::all_passing(),
            1 => Fake::unknown(R::LockedNonSharedAccount),
            _ => Fake::failing(R::LockedNonSharedAccount),
        };
        ea_key_provider::DevicePostureProvider::report(&fake)
    }
    fn os_build_identity(&self) -> Result<ea_key_provider::HostOsBuild, ea_key_provider::KeyError> {
        Ok(ea_key_provider::HostOsBuild::test_fixture(1, 1))
    }
}
#[test]
fn native_prepared_diagnosis_documented_unknown_does_not_write_clock_bounds() {
    let f = NativeDestructionFixture::without_server();
    let measured = Arc::new(DiagnosisPosture(std::sync::atomic::AtomicU8::new(1)));
    let writer = OperatorRuntime::open_with_test_native_and_posture(
        OperatorRuntimeConfig::load(&f.writer_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        NativeOperatorProvider::open_test_fixture(
            f.writer_directory.join("ea-native-operator"),
            false,
        )
        .unwrap(),
        measured.clone(),
    )
    .unwrap();
    let admin = open(&f, true);
    assert!(
        writer.posture_admission().is_err(),
        "Unknown needs actual signed documentation"
    );
    let doc = admin
        .issue_posture_document(
            &writer.posture_target_context().unwrap(),
            ea_crypto::object_hash(b"explicit Writer operational evidence"),
            60_000,
        )
        .unwrap();
    writer.import_posture_document(&doc).unwrap();
    let db = writer.database().clone();
    let holder = NativeLocalHolder::open(
        &writer,
        f.archive.clone(),
        f.profile.clone(),
        f.writer_certificate,
    )
    .unwrap();
    let owner = DestructionRuntime::new(
        open(&f, true),
        writer,
        vec![holder],
        f.component,
        f.key_source.clone(),
    )
    .unwrap();
    let before = db
        .query_row(
            "SELECT installation_id,last_observed_wall FROM go_live_posture_clock",
            &[],
        )
        .unwrap()
        .unwrap();
    let evidence = db
        .query_row("SELECT * FROM go_live_posture_evidence", &[])
        .unwrap()
        .unwrap();
    assert_eq!(
        owner
            .writer_prepared_diagnosis()
            .diagnose(&admin, &f.profile)
            .unwrap(),
        None
    );
    assert_eq!(
        db.query_row(
            "SELECT installation_id,last_observed_wall FROM go_live_posture_clock",
            &[]
        )
        .unwrap()
        .unwrap(),
        before
    );
    assert_eq!(
        db.query_row("SELECT * FROM go_live_posture_evidence", &[])
            .unwrap()
            .unwrap(),
        evidence
    );
    measured.0.store(2, std::sync::atomic::Ordering::SeqCst);
    assert!(
        owner
            .writer_prepared_diagnosis()
            .diagnose(&admin, &f.profile)
            .is_err(),
        "documentation never overrides an actual Fail"
    );
    assert_eq!(
        db.query_row(
            "SELECT installation_id,last_observed_wall FROM go_live_posture_clock",
            &[]
        )
        .unwrap()
        .unwrap(),
        before
    );
}
#[test]
fn native_prepared_diagnosis_writer_watch_loss_after_snapshot_refuses_result() {
    let f = NativeDestructionFixture::without_server();
    let owner = f.runtime();
    let admin = open(&f, true);
    let error = owner
        .writer_prepared_diagnosis()
        .diagnose_with_test_after_profile(&admin, &f.profile, || {
            fs::write(f.writer_directory.join("watch-action"), "watch-event").unwrap();
            let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !f
                .writer_directory
                .join("watch-delivered")
                .try_exists()
                .unwrap()
            {
                assert!(
                    std::time::Instant::now() < end,
                    "bounded actual Watch delivery"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })
        .expect_err("delivered Writer lock event closes diagnosis");
    assert_eq!(error.code(), "EA-OPERATOR-NATIVE-LOCKED");
}
