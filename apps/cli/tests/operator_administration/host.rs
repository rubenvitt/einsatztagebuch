use super::*;
use ea_desktop::{
    runtime::{DesktopLaunchConfig, NativeDesktopRuntime},
    state::{ReauthPort, RuntimeSessionPort},
};
fn launch(stations: &SeparateAdministrationStations, configuration: &Path) -> DesktopLaunchConfig {
    DesktopLaunchConfig::parse([
        std::ffi::OsString::from("--operator-config"),
        stations.source.config.as_os_str().to_owned(),
        std::ffi::OsString::from("--trust-anchor"),
        stations.source.anchor.as_os_str().to_owned(),
        std::ffi::OsString::from("--administration-config"),
        configuration.as_os_str().to_owned(),
    ])
    .unwrap()
    .unwrap()
}
#[test]
fn native_administration_resources_bind_real_inbox_and_current_proofs() {
    let stations = SeparateAdministrationStations::new();
    let runtime = stations.source.open();
    // SeparateAdministrationStations binds a shared archive outside the
    // source installation. Diagnose exactly the admitted runtime path.
    let archive_root = runtime.config().archive_directory.clone();
    let (request, target) = actual_registration_intent(&runtime);
    let directory = stations.source.directory.path().join("requests");
    fs::create_dir(&directory).unwrap();
    let stem = hex::encode(ea_crypto::object_hash(&request).as_bytes());
    fs::write(
        directory.join(format!("{stem}.registration.cbor")),
        &request,
    )
    .unwrap();
    fs::write(
        directory.join(format!("{stem}.certificate-intent.cbor")),
        &target,
    )
    .unwrap();
    let config = stations.source.directory.path().join("administration.json");
    fs::write(&config,serde_json::to_vec(&json!({
        "version":1,"registration_inbox":"requests",
        "archive_profile":{"kind":"local-path","filesystem_row_id":"fixture-native-administration-fs",
            "capability_test_vector_id":"native-administration-v1"}
    })).unwrap()).unwrap();
    let native =
        NativeDesktopRuntime::open_with_test_runtime(launch(&stations, &config), runtime).unwrap();
    let state = native.desktop_state();
    let port = state
        .administration_port()
        .expect("configured actual native administration port");
    assert!(
        port.pending_device_requests().is_err(),
        "native login is mandatory even for direct port access"
    );
    assert!(port.diagnose_writer_lock().is_err());
    native.login().unwrap();
    let lock_path = archive_root.join(ea_archive_fs::CONTROL_FILES_V1[0]);
    assert!(!lock_path.exists());
    assert_eq!(port.diagnose_writer_lock().unwrap(), ea_archive_fs::LocalWriterLockDiagnosis::Missing);
    assert!(!lock_path.exists(), "diagnosis never creates a lock file");
    fs::write(&lock_path, b"opaque lock contents remain unchanged").unwrap();
    assert_eq!(port.diagnose_writer_lock().unwrap(), ea_archive_fs::LocalWriterLockDiagnosis::AbandonedInert);
    let held = fs::OpenOptions::new().read(true).write(true).open(&lock_path).unwrap();
    held.try_lock().unwrap();
    assert_eq!(port.diagnose_writer_lock().unwrap(), ea_archive_fs::LocalWriterLockDiagnosis::LiveOwner);
    assert_eq!(fs::read(&lock_path).unwrap(), b"opaque lock contents remain unchanged");
    drop(held);
    assert_eq!(port.diagnose_writer_lock().unwrap(), ea_archive_fs::LocalWriterLockDiagnosis::AbandonedInert);
    let requests = port.pending_device_requests().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].request_id, stem);
    let policy = port.policy_profile().unwrap();
    assert_eq!(policy.operating_profile, 0);
    assert_eq!(port.registry_health().unwrap().next_sequence.get(), 1);
    let checklist = port.go_live_checklist().unwrap();
    assert!(
        !checklist.production_ready(),
        "missing independent key backup/recovery evidence stays unresolved"
    );
    assert!(
        !port
            .revocation_effect(&stations.source.reader)
            .unwrap()
            .recalls_issued_grants
    );
    assert_eq!(
        port.writer_transition_state().unwrap().phase,
        ea_admin::writer_transition::WriterTransitionPhase::NoTransition
    );
    assert_ne!(
        port.clock_release_offer().unwrap().availability,
        ea_admin::clock_release::ClockReleaseAvailability::Offered
    );
    assert!(
        port.clock_release_issue(ea_format::ClockReleaseJustificationV1::OperatorVerifiedWallClock)
            .is_err(),
        "an unblocked clock never emits a release success"
    );
    let pending = port
        .begin_ceremony(
            &requests[0].request_id,
            ea_admin::TrustCeremonyKind::DeviceApprove,
        )
        .unwrap();
    let id = pending.ceremony_id;
    assert!(port.ceremony("00").is_err());
    assert!(
        port.confirm_fingerprint(&id, &ea_crypto::object_hash(b"wrong"))
            .is_err()
    );
    port.confirm_fingerprint(&id, &ea_crypto::object_hash(&request))
        .unwrap();
    native
        .reauthenticate(ea_operator::ReauthPurpose::AdminRootCeremony)
        .unwrap();
    assert_eq!(
        port.authorize(&id).unwrap().step,
        ea_admin::TrustCeremonyStep::AdminAuthorized
    );
    let opened = port.open_ceremonies().unwrap();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].ceremony_id, id);
    assert_eq!(opened[0].step, ea_admin::TrustCeremonyStep::AdminAuthorized);
    native.invalidate();
    assert!(port.diagnose_writer_lock().is_err());
    assert!(port.open_ceremonies().is_err());
    assert!(port.pending_device_requests().is_err());
    assert!(port.export_request(&id).is_err());
    drop(port);
    drop(state);
    drop(native);
    for profile in [
        json!({"kind":"local-path", "filesystem_row_id":"unapproved-row", "capability_test_vector_id":"native-administration-v1"}),
        json!({"kind":"controlled-network-path", "filesystem_row_id":"network-row", "protocol_id":"smb", "server_product":"fixture", "server_version":"1", "mount_options":[], "failover_config_id":"none", "capability_test_vector_id":"fixture", "queue_max_objects":10, "queue_max_bytes":1024, "resume_backoff_initial_ms":1, "resume_backoff_max_ms":2, "resume_max_attempts":1}),
    ] {
        fs::write(&config, serde_json::to_vec(&json!({"version":1, "registration_inbox":"requests", "archive_profile":profile})).unwrap()).unwrap();
        let rejected = NativeDesktopRuntime::open_with_test_runtime(launch(&stations, &config), stations.source.open()).unwrap();
        rejected.login().unwrap();
        let port = rejected.desktop_state().administration_port().unwrap();
        assert!(port.diagnose_writer_lock().is_err(), "unapproved exact profiles and network profiles are not diagnosed");
        assert_eq!(fs::read(&lock_path).unwrap(), b"opaque lock contents remain unchanged");
    }
}

#[test]
fn native_administration_host_publishes_both_exact_rounds_and_reopens_them() {
    use ea_admin::{
        TrustCeremonyKind, TrustCeremonyStep, administration_runtime::TrustCeremonyRoundV1,
    };
    let stations = SeparateAdministrationStations::new();
    let runtime = stations.source.open();
    let (request, target) = actual_registration_intent(&runtime);
    let directory = stations.source.directory.path().join("host-round-requests");
    fs::create_dir(&directory).unwrap();
    let stem = hex::encode(ea_crypto::object_hash(&request).as_bytes());
    fs::write(
        directory.join(format!("{stem}.registration.cbor")),
        &request,
    )
    .unwrap();
    fs::write(
        directory.join(format!("{stem}.certificate-intent.cbor")),
        &target,
    )
    .unwrap();
    let config = stations
        .source
        .directory
        .path()
        .join("host-round-administration.json");
    fs::write(&config,serde_json::to_vec(&json!({
        "version":1,"registration_inbox":"host-round-requests",
        "archive_profile":{"kind":"local-path","filesystem_row_id":"fixture-native-administration-fs",
            "capability_test_vector_id":"native-administration-v1"}
    })).unwrap()).unwrap();
    let native =
        NativeDesktopRuntime::open_with_test_runtime(launch(&stations, &config), runtime).unwrap();
    native.login().unwrap();
    let state = native.desktop_state();
    let port = state.administration_port().unwrap();
    let requests = port.pending_device_requests().unwrap();
    let first = port
        .begin_ceremony(&requests[0].request_id, TrustCeremonyKind::DeviceApprove)
        .unwrap();
    assert!(
        port.authorize(&first.ceremony_id).is_err(),
        "no fingerprint bypass"
    );
    port.confirm_fingerprint(&first.ceremony_id, &ea_crypto::object_hash(&request))
        .unwrap();
    fn round(
        native: &NativeDesktopRuntime,
        port: &dyn ea_desktop::state::AdministrationPort,
        stations: &SeparateAdministrationStations,
        id: &str,
    ) -> ea_ui_contracts::TrustCeremonyView {
        native
            .reauthenticate(ea_operator::ReauthPurpose::AdminRootCeremony)
            .unwrap();
        port.authorize(id).unwrap();
        let exported = port.export_request(id).unwrap();
        let reply = stations.exchange.path().join(
            exported
                .exchange_file_name
                .unwrap()
                .replacen("request-", "reply-", 1),
        );
        let mut service = stations.service();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
        while !reply.exists() {
            assert!(service.0.try_wait().unwrap().is_none());
            assert!(std::time::Instant::now() < deadline, "actual Root response");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        port.import_reply(id).unwrap();
        drop(service);
        native
            .reauthenticate(ea_operator::ReauthPurpose::AdminRootCeremony)
            .unwrap();
        port.publish(id).unwrap()
    }
    let issued = round(&native, port.as_ref(), &stations, &first.ceremony_id);
    assert_eq!(issued.round, TrustCeremonyRoundV1::IssueTarget);
    assert_eq!(issued.step, TrustCeremonyStep::TargetPublished);
    let child = port
        .ceremony(issued.linked_ceremony_id.as_deref().unwrap())
        .unwrap();
    assert_eq!(child.round, TrustCeremonyRoundV1::ActivateRegistry);
    let open = port.open_ceremonies().unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].ceremony_id, child.ceremony_id);
    assert!(
        port.confirm_fingerprint(&child.ceremony_id, &ea_crypto::object_hash(&request))
            .is_err()
    );
    let cert =
        ea_admin::parse_human_readable_fingerprint(child.target_fingerprint.as_deref().unwrap())
            .unwrap();
    port.confirm_fingerprint(&child.ceremony_id, &cert).unwrap();
    let activated = round(&native, port.as_ref(), &stations, &child.ceremony_id);
    assert_eq!(activated.step, TrustCeremonyStep::RegistryPublished);
    assert!(port.pending_device_requests().unwrap().is_empty());
    assert!(port.open_ceremonies().unwrap().is_empty());
    drop(port);
    drop(state);
    drop(native);
    let reopened = NativeDesktopRuntime::open_with_test_runtime(
        launch(&stations, &config),
        stations.source.open(),
    )
    .unwrap();
    reopened.login().unwrap();
    let reopened_state = reopened.desktop_state();
    let reopened_port = reopened_state.administration_port().unwrap();
    assert_eq!(
        reopened_port.ceremony(&first.ceremony_id).unwrap().step,
        TrustCeremonyStep::TargetPublished
    );
    assert_eq!(
        reopened_port.ceremony(&child.ceremony_id).unwrap().step,
        TrustCeremonyStep::RegistryPublished
    );
    assert!(
        stations
            .source
            .open()
            .head()
            .active_certificate_fields(ea_types::CertificateHash::from(cert))
            .is_some()
    );
}
