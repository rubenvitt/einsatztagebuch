use super::*;
use ea_admin::{
    native_provider::NativeOperatorProvider,
    operator_runtime::{OperatorRuntimeConfig, writer::InteractiveOperatorRuntime},
};
use ea_desktop::{
    runtime::{DesktopLaunchConfig, NativeDesktopRuntime},
    state::{ReauthPort, RuntimeSessionPort},
};
use ea_operator::ReauthPurpose;

fn host(installed: &Installation) -> Arc<NativeDesktopRuntime> {
    host_with_writer(installed, None)
}

fn host_with_writer(
    installed: &Installation,
    writer_config: Option<PathBuf>,
) -> Arc<NativeDesktopRuntime> {
    let native = NativeOperatorProvider::open_test_fixture(
        installed.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let runtime = InteractiveOperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&installed.config).unwrap(),
        &installed.anchor,
        support::live_clock(),
        native,
    )
    .unwrap();
    NativeDesktopRuntime::open_with_test_runtime(
        DesktopLaunchConfig {
            operator_config: installed.config.clone(),
            trust_anchor: installed.anchor.clone(),
            writer_config,
            destruction_config: None,
            recovery_config: None,
            administration_config: None,
        },
        runtime,
    )
    .unwrap()
}

fn configure_writer(installed: &mut Installation) -> PathBuf {
    configure_writer_expiring_at(
        installed,
        UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
    )
}
fn configure_writer_expiring_at(installed: &mut Installation, not_after: UnixMillis) -> PathBuf {
    configure_writer_with_policy(installed, not_after, 0, 0)
}
fn configure_writer_with_policy(
    installed: &mut Installation,
    not_after: UnixMillis,
    profile_code: u8,
    expiry_behavior: u8,
) -> PathBuf {
    use ea_trust::TrustObjectSource as _;
    let profile = ea_archive::ArchiveBackendProfileV1::LocalPath(ea_archive::LocalPathProfileV1 {
        filesystem_row_id: "fixture-native-writer-fs".into(),
        capability_test_vector_id: "native-desktop-cap-v1".into(),
    });
    let previous = installed.line.current_policy_hash();
    let mut previous_hashes = Vec::new();
    installed
        .line
        .source()
        .visit_trust_object_hashes(&mut |hash| {
            previous_hashes.push(hash);
            Ok(())
        })
        .unwrap();
    installed.line.push(
        ActionSpec::Policy {
            policy_version: Some(2),
            previous_policy_hash: Some(previous),
            effective_from: Some(1),
        },
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
            not_after,
            policy_operating_profile_override: Some(profile_code),
            policy_registry_expiry_behavior_override: Some(expiry_behavior),
            policy_max_registry_age_ms_override: Some(support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1),
            policy_allowed_archive_profile_hashes_override: Some(vec![
                profile.profile_hash().unwrap(),
            ]),
            ..HeadOptions::default()
        },
    );
    installed.line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::RecoveryRecipient,
            marker: 0x62,
            effective_from: Some(1),
        },
        HeadOptions {
            effective_from: Some(1),
            valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
            not_after,
            ..HeadOptions::default()
        },
    );
    let source = installed.line.source();
    source
        .visit_trust_object_hashes(&mut |hash| {
            if previous_hashes.contains(&hash) {
                return Ok(());
            }
            let target = installed
                .archive
                .join(format!("{}.etb", hex::encode(hash.as_bytes())));
            if !target.exists() {
                fs::write(target, source.read_exact_trust_object(hash)?.unwrap()).unwrap();
            }
            Ok(())
        })
        .unwrap();
    let report = ea_recovery::verify_directory(
        &installed.archive,
        &ea_recovery::load_trust_anchor(&installed.anchor).unwrap(),
        support::live_clock(),
        None,
    )
    .unwrap();
    assert!(
        report.is_fully_verified(),
        "{}",
        report.to_canonical_json().unwrap()
    );
    let config = installed.directory.path().join("writer.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "version":1, "timezone":"Europe/Berlin", "archive_profile": {
                "kind":"local-path", "filesystem_row_id":"fixture-native-writer-fs",
                "capability_test_vector_id":"native-desktop-cap-v1"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    config
}

fn native_incident() -> ea_ui_contracts::IncidentInputView {
    ea_ui_contracts::IncidentInputView {
        human_incident_number: "DESKTOP-NATIVE-914".into(),
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
    }
}

#[test]
fn native_desktop_writer_publishes_exact_confirmed_incident_and_refuses_changed_preview() {
    let mut installed = Installation::new();
    let config = configure_writer(&mut installed);
    let native = host_with_writer(&installed, Some(config));
    native.login().unwrap();
    let state = native.desktop_state();
    state
        .drafts()
        .unwrap()
        .save_payload("active native incident".into())
        .unwrap();
    let writer = state.writer().expect("native Writer service");
    let input = native_incident();
    let preview = writer.preview(&input).unwrap();
    let mut changed = input.clone();
    changed.human_incident_number = "DIFFERENT-INPUT".into();
    assert!(writer.finalize(&changed, &preview).is_err());
    let preview = writer.preview(&input).unwrap();
    native
        .reauthenticate(ea_operator::ReauthPurpose::Finalize)
        .unwrap();
    let outcome = writer.finalize(&input, &preview).unwrap();
    assert_eq!(outcome.sequence.get(), 1);
    assert_eq!(state.drafts().unwrap().load_payload().unwrap(), "");
    let snapshot = ea_admin::operator_runtime::OperatorArchiveSnapshot::open(
        &installed.archive,
        &installed.anchor,
        support::live_clock(),
    )
    .unwrap();
    assert_eq!(snapshot.next_sequence().get(), 2);
    let row = open_database(&installed.database).query_row(
        "SELECT record_id,entry_hash,object_hash FROM writer_original_identity WHERE sequence=1", &[],
    ).unwrap().unwrap();
    let original_hash = ObjectHash::try_from(row.blob(2).unwrap()).unwrap();
    let original = snapshot
        .inventory()
        .entries()
        .iter()
        .find(|entry| entry.object_hash() == original_hash)
        .unwrap()
        .exact_bytes()
        .as_bytes()
        .to_vec();
    let amendment = ea_ui_contracts::AmendmentInputView {
        reference: ea_ui_contracts::CorrectionReferenceView {
            original_record_id: hex::encode(row.blob(0).unwrap()),
            original_entry_hash: hex::encode(row.blob(1).unwrap()),
            original_sequence: 1,
        },
        reason: "Ergänzung nach Rückmeldung".into(),
        changes: vec![ea_ui_contracts::AmendmentChangeView {
            field_path: "notes".into(),
            change_text: "Rückmeldung dokumentiert".into(),
        }],
    };
    state
        .drafts()
        .unwrap()
        .save_payload("native amendment draft".into())
        .unwrap();
    writer
        .validate_amendment_reference(&amendment.reference)
        .unwrap();
    let preview = writer.preview_amendment(&amendment).unwrap();
    native
        .reauthenticate(ea_operator::ReauthPurpose::Finalize)
        .unwrap();
    let appended = writer.finalize_amendment(&amendment, &preview).unwrap();
    assert_eq!(appended.sequence.get(), 2);
    let after = ea_admin::operator_runtime::OperatorArchiveSnapshot::open(
        &installed.archive,
        &installed.anchor,
        support::live_clock(),
    )
    .unwrap();
    assert_eq!(after.next_sequence().get(), 3);
    assert_eq!(
        after
            .inventory()
            .entries()
            .iter()
            .find(|entry| entry.object_hash() == original_hash)
            .unwrap()
            .exact_bytes()
            .as_bytes(),
        original
    );
    native.invalidate();
    assert!(writer.preview(&input).is_err());
}

#[test]
fn native_desktop_startup_preserves_unknown_key_state_and_resumes_exact_prepared_bytes() {
    for mode in ["draft-delete-refused", "draft-delete-response-lost"] {
        let mut installed = Installation::new();
        let config = configure_writer(&mut installed);
        let native = host_with_writer(&installed, Some(config.clone()));
        native.login().unwrap();
        let state = native.desktop_state();
        let canary = "original draft remains recoverable";
        state.drafts().unwrap().save_payload(canary.into()).unwrap();
        let key_path = installed.directory.path().join("fixture-draft-key.sealed");
        let original_sealed_key = fs::read(&key_path).unwrap();
        let writer = state.writer().unwrap();
        let input = native_incident();
        let preview = writer.preview(&input).unwrap();
        native
            .reauthenticate(ea_operator::ReauthPurpose::Finalize)
            .unwrap();
        fs::write(installed.directory.path().join("helper-mode"), mode).unwrap();
        assert!(writer.finalize(&input, &preview).is_err());
        if mode == "draft-delete-refused" {
            assert!(
                fs::read(&key_path).unwrap() == original_sealed_key,
                "refused delete preserves the original native key"
            );
        } else {
            assert!(
                !key_path.exists(),
                "lost response follows actual key removal"
            );
        }
        let db = open_database(&installed.database);
        let marker = db
            .query_row("SELECT marker FROM draft_transition WHERE singleton=0", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap()
            .to_vec();
        // Read exact EIP bytes from the existing marker format for comparison;
        // only the production recovery service can authorize their publication.
        let mut decoder = minicbor::Decoder::new(&marker);
        assert_eq!(decoder.array().unwrap(), Some(7));
        assert_eq!(decoder.u64().unwrap(), 1);
        assert_eq!(decoder.u64().unwrap(), 1);
        for _ in 0..3 {
            decoder.bytes().unwrap();
        }
        let exact_entry = decoder.bytes().unwrap().to_vec();
        drop(state);
        drop(native);
        fs::remove_file(installed.directory.path().join("helper-mode")).unwrap();
        let reopened = host_with_writer(&installed, Some(config));
        let resumed = reopened.desktop_state();
        assert!(
            resumed
                .startup()
                .unwrap()
                .resolve_pending_finalization()
                .is_err(),
            "native login precedes recovery"
        );
        reopened.login().unwrap();
        if mode == "draft-delete-refused" {
            fs::write(
                installed.directory.path().join("helper-mode"),
                "draft-unwrap-unavailable",
            )
            .unwrap();
            assert!(
                resumed
                    .startup()
                    .unwrap()
                    .resolve_pending_finalization()
                    .is_err(),
                "provider outage cannot prove key absence"
            );
            assert_eq!(
                db.query_row("SELECT marker FROM draft_transition WHERE singleton=0", &[])
                    .unwrap()
                    .unwrap()
                    .blob(0)
                    .unwrap(),
                marker
            );
            fs::remove_file(installed.directory.path().join("helper-mode")).unwrap();
            assert!(
                fs::read(&key_path).unwrap() == original_sealed_key,
                "an unwrap outage must not change the original native key"
            );
            assert_eq!(
                resumed.drafts().unwrap().load_payload().unwrap(),
                canary,
                "after the outage the original draft decrypts"
            );
        }
        resumed
            .startup()
            .unwrap()
            .resolve_pending_finalization()
            .unwrap();
        let snapshot = ea_admin::operator_runtime::OperatorArchiveSnapshot::open(
            &installed.archive,
            &installed.anchor,
            support::live_clock(),
        )
        .unwrap();
        if mode == "draft-delete-refused" {
            assert_eq!(snapshot.next_sequence().get(), 1);
            assert_eq!(resumed.drafts().unwrap().load_payload().unwrap(), canary);
        } else {
            assert_eq!(snapshot.next_sequence().get(), 2);
            assert!(
                snapshot
                    .inventory()
                    .entries()
                    .iter()
                    .any(|entry| entry.exact_bytes().as_bytes() == exact_entry)
            );
            assert_eq!(resumed.drafts().unwrap().load_payload().unwrap(), "");
        }
        assert!(
            db.query_row("SELECT marker FROM draft_transition WHERE singleton=0", &[])
                .unwrap()
                .is_none()
        );
        resumed
            .startup()
            .unwrap()
            .resolve_pending_finalization()
            .unwrap();
    }
}

#[test]
fn native_desktop_login_verifies_current_authority_and_lock_clears_before_ui() {
    let installed = Installation::new();
    let native = host(&installed);
    let state = native.desktop_state();
    assert_eq!(state.verified_role().unwrap(), None);
    state.login().unwrap();
    assert_eq!(state.verified_role().unwrap(), Some(OperatorRoleV1::Writer));
    assert_eq!(installed.latest_audit(LocalAuditOutcomeV1::Completed).1, 1);
    fs::write(
        installed.directory.path().join("watch-action"),
        "watch-event",
    )
    .unwrap();
    assert!(native.check_native_session().is_err());
    ea_desktop::honor_session_lock(&state, || {
        assert_eq!(state.verified_role().unwrap(), None);
        assert_eq!(state.session().lock().unwrap().fresh_reauth(), None);
    });
    fs::remove_file(installed.directory.path().join("watch-action")).unwrap();
    assert!(
        native.check_native_session().is_err(),
        "unlock must not revive the old watcher"
    );
    assert_eq!(state.verified_role().unwrap(), None);
    // Explicitly construct a new native login after unlock; identity and the
    // encrypted acquisition/profile/audit database remain the existing ones.
    let renewed = host(&installed);
    renewed.login().unwrap();
    assert_eq!(
        renewed.verified_role().unwrap(),
        Some(OperatorRoleV1::Writer)
    );
    assert_eq!(installed.latest_audit(LocalAuditOutcomeV1::Completed).1, 2);
}

#[test]
fn native_desktop_existing_session_rechecks_a_newly_published_revocation() {
    let mut installed = Installation::new();
    let native = host(&installed);
    native.login().unwrap();
    assert_eq!(
        native.verified_role().unwrap(),
        Some(OperatorRoleV1::Writer)
    );
    installed.publish_fixture_revocation();
    assert_eq!(native.verified_role().unwrap(), None);
    assert_eq!(native.verified_role().unwrap(), None);
}

#[test]
fn native_desktop_lock_during_presence_does_not_wait_for_the_dialog_mutex() {
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };
    let installed = Installation::new();
    let native = host(&installed);
    native.login().unwrap();
    let barrier = installed.directory.path().join("hold-operator-signature");
    fs::write(&barrier, b"").unwrap();
    let login_host = native.clone();
    let login = std::thread::spawn(move || login_host.login());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !installed
        .directory
        .path()
        .join("operator-signature-paused")
        .exists()
    {
        assert!(
            Instant::now() < deadline,
            "actual native presence must reach barrier"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    fs::write(
        installed.directory.path().join("watch-action"),
        "watch-event",
    )
    .unwrap();
    let monitor_host = native.clone();
    let (send, receive) = mpsc::channel();
    let monitor = std::thread::spawn(move || {
        let blocked = monitor_host.check_native_session().is_err();
        let role_cleared = monitor_host.verified_role().ok().flatten().is_none();
        send.send(blocked && role_cleared).unwrap();
    });
    let before_dialog_returns = receive.recv_timeout(Duration::from_secs(2));
    fs::remove_file(barrier).unwrap();
    assert!(login.join().unwrap().is_err());
    monitor.join().unwrap();
    assert_eq!(
        before_dialog_returns,
        Ok(true),
        "lock must close authority while presence is still pending"
    );
    assert_eq!(native.verified_role().unwrap(), None);
}

#[test]
fn native_desktop_manual_lock_discards_a_late_successful_presence_proof() {
    use std::time::{Duration, Instant};
    let installed = Installation::new();
    let native = host(&installed);
    native.login().unwrap();
    let barrier = installed.directory.path().join("hold-operator-signature");
    fs::write(&barrier, b"").unwrap();
    let login_host = native.clone();
    let login = std::thread::spawn(move || login_host.login());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !installed
        .directory
        .path()
        .join("operator-signature-paused")
        .exists()
    {
        assert!(
            Instant::now() < deadline,
            "actual native presence must reach barrier"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    native.invalidate();
    assert_eq!(native.verified_role().unwrap(), None);
    // The OS is still unlocked and the helper will return a valid signature.
    // Closing the desktop session nevertheless invalidates this pending proof.
    assert!(native.check_native_session().is_ok());
    fs::remove_file(barrier).unwrap();
    assert!(login.join().unwrap().is_err());
    assert_eq!(native.verified_role().unwrap(), None);
}

#[test]
fn native_desktop_draft_reopens_and_discard_consumes_native_purpose_proof() {
    let installed = Installation::new();
    let native = host(&installed);
    let state = native.desktop_state();
    let drafts = state.drafts().expect("configured native draft port");
    assert!(drafts.load_payload().is_err());
    native.login().unwrap();
    assert_eq!(drafts.load_payload().unwrap(), "");
    let canary = "desktop-private-draft-58271";
    drafts.save_payload(canary.to_owned()).unwrap();
    assert_eq!(drafts.load_payload().unwrap(), canary);
    let reopened = host(&installed);
    reopened.login().unwrap();
    let reopened_state = reopened.desktop_state();
    assert_eq!(
        reopened_state.drafts().unwrap().load_payload().unwrap(),
        canary
    );
    let discard = reopened_state.discard().expect("native discard port");
    assert!(discard.begin().is_err(), "Finalize proof cannot discard");
    reopened
        .reauthenticate(ea_operator::ReauthPurpose::DiscardDraft)
        .unwrap();
    assert!(discard.begin().is_ok());
    assert!(discard.begin().is_err(), "single-use discard proof");
    assert_eq!(reopened_state.drafts().unwrap().load_payload().unwrap(), "");
    for path in [
        &installed.database,
        &installed.directory.path().join("fixture-draft-key.sealed"),
    ] {
        assert!(
            !fs::read(path)
                .unwrap()
                .windows(canary.len())
                .any(|bytes| bytes == canary.as_bytes())
        );
    }
    reopened.invalidate();
    assert!(reopened_state.drafts().unwrap().load_payload().is_err());
    assert!(
        reopened_state
            .drafts()
            .unwrap()
            .save_payload("blocked".into())
            .is_err()
    );
}

#[test]
fn native_key_provider_distinguishes_unavailable_or_malformed_from_confirmed_absence() {
    use ea_key_provider::KeyProvider as _;
    let installed = Installation::new();
    let native = host(&installed);
    native.login().unwrap();
    native
        .desktop_state()
        .drafts()
        .unwrap()
        .save_payload("retained draft".into())
        .unwrap();
    let provider = NativeOperatorProvider::open_test_fixture(
        installed.directory.path().join("ea-native-operator"),
        false,
    )
    .unwrap();
    let keys = provider.signing_provider(ea_admin::native_provider::NativeSigningSlot::Writer);
    let handle = keys.handle(ea_key_provider::SecretPurpose::DraftDek);
    for mode in [
        "draft-unwrap-unavailable",
        "draft-contains-malformed",
        "draft-unwrap-malformed",
    ] {
        fs::write(installed.directory.path().join("helper-mode"), mode).unwrap();
        let error = keys
            .unwrap_secret(&handle)
            .err()
            .expect("unavailable key operation");
        assert_ne!(
            error,
            ea_key_provider::KeyError::NotFound,
            "{mode} must not prove irreversible key absence"
        );
    }
    fs::remove_file(installed.directory.path().join("helper-mode")).unwrap();
    assert!(keys.unwrap_secret(&handle).is_ok());
    keys.delete(&handle).unwrap();
    assert_eq!(
        keys.unwrap_secret(&handle).err(),
        Some(ea_key_provider::KeyError::NotFound)
    );
}

#[test]
fn native_desktop_restarts_after_registry_expiry_and_requires_signed_ack() {
    let mut installed = Installation::new();
    let expired = UnixMillis::new(support::live_clock().get() - 1000);
    let config = configure_writer_expiring_at(&mut installed, expired);
    let native = host_with_writer(&installed, Some(config));
    native.login().unwrap();
    let state = native.desktop_state();
    state
        .drafts()
        .unwrap()
        .save_payload("expired native writer draft".into())
        .unwrap();
    let writer = state.writer().unwrap();
    let input = native_incident();
    let preview = writer.preview(&input).unwrap();
    assert_eq!(
        preview.stale_decision,
        ea_ui_contracts::StaleDecision::StaleAcknowledgeable
    );
    assert!(writer.finalize(&input, &preview).is_err());
    let preview = writer.preview(&input).unwrap();
    native
        .reauthenticate(ReauthPurpose::RegistryStaleFinalize)
        .unwrap();
    writer
        .acknowledge_stale_registry(&input, &preview, true)
        .unwrap();
    native.reauthenticate(ReauthPurpose::Finalize).unwrap();
    let result = writer.finalize(&input, &preview).unwrap();
    assert_eq!(result.sequence.get(), 1);
    assert_eq!(state.drafts().unwrap().load_payload().unwrap(), "");
    let row = open_database(&installed.database)
        .query_row(
            "SELECT record_id,entry_hash FROM writer_original_identity WHERE sequence=1",
            &[],
        )
        .unwrap()
        .unwrap();
    let amendment = ea_ui_contracts::AmendmentInputView {
        reference: ea_ui_contracts::CorrectionReferenceView {
            original_record_id: hex::encode(row.blob(0).unwrap()),
            original_entry_hash: hex::encode(row.blob(1).unwrap()),
            original_sequence: 1,
        },
        reason: "Nachmeldung bei abgelaufener Registry".into(),
        changes: vec![ea_ui_contracts::AmendmentChangeView {
            field_path: "notes".into(),
            change_text: "Ergänzt".into(),
        }],
    };
    state
        .drafts()
        .unwrap()
        .save_payload("expired native amendment".into())
        .unwrap();
    let preview = writer.preview_amendment(&amendment).unwrap();
    assert_eq!(
        preview.stale_decision,
        ea_ui_contracts::StaleDecision::StaleAcknowledgeable
    );
    native
        .reauthenticate(ReauthPurpose::RegistryStaleFinalize)
        .unwrap();
    writer
        .acknowledge_stale_amendment(&amendment, &preview, true)
        .unwrap();
    native.reauthenticate(ReauthPurpose::Finalize).unwrap();
    assert_eq!(
        writer
            .finalize_amendment(&amendment, &preview)
            .unwrap()
            .sequence
            .get(),
        2
    );
    assert_eq!(state.drafts().unwrap().load_payload().unwrap(), "");
    assert!(native.reauthenticate(ReauthPurpose::Destruction).is_err());
}

/// DRK-282, Posture-Ruling „Plan wörtlich": die Stale-Writer-Ausnahme verlangt
/// STRIKT gemessenes Pass in allen vier Anforderungen (`writer.rs`,
/// `ensure_writer_ready`). Ein Unknown — das eine gewöhnliche Sitzung mit
/// signierter Dokumentation zulassen darf — und jedes Fail öffnen sie nicht.
///
/// Ein gültiges signiertes Posture-Dokument lässt sich hier nicht beilegen:
/// Dokumentation läuft spätestens mit `Registry.notAfter` ab, und genau dieses
/// `notAfter` liegt für die abgelaufene Registry in der Vergangenheit. Der
/// Stale-Pfad liest `go_live_posture_evidence` zudem gar nicht.
#[test]
fn stale_writer_opens_only_on_measured_pass_never_on_unknown_or_fail() {
    use ea_key_provider::{DevicePostureProvider, DevicePostureProviderFake, PostureRequirement};
    let mut installed = Installation::new();
    configure_writer_expiring_at(
        &mut installed,
        UnixMillis::new(support::live_clock().get() - 1000),
    );
    let open = |posture: DevicePostureProviderFake| {
        let native = NativeOperatorProvider::open_test_fixture(
            installed.directory.path().join("ea-native-operator"),
            false,
        )
        .unwrap();
        let posture: Arc<dyn DevicePostureProvider> = Arc::new(posture);
        InteractiveOperatorRuntime::open_with_test_native_and_posture(
            OperatorRuntimeConfig::load(&installed.config).unwrap(),
            &installed.anchor,
            support::live_clock(),
            native,
            posture,
        )
    };
    // Gegenprobe: gemessenes Pass öffnet genau die Stale-Writer-Ausnahme.
    match open(DevicePostureProviderFake::all_passing()) {
        Ok(InteractiveOperatorRuntime::StaleWriter(_)) => {}
        Ok(InteractiveOperatorRuntime::Current(_)) => {
            panic!("the expired Registry must route through the stale-writer exception")
        }
        Err(error) => panic!("measured Pass must open the stale writer: {}", error.code()),
    }
    for requirement in PostureRequirement::ALL {
        for (label, posture) in [
            ("unknown", DevicePostureProviderFake::unknown(requirement)),
            ("fail", DevicePostureProviderFake::failing(requirement)),
        ] {
            match open(posture) {
                Ok(_) => panic!("{label} {requirement:?} must not open the stale writer"),
                Err(error) => assert_eq!(
                    error.code(),
                    "EA-OPERATOR-POSTURE",
                    "{label} {requirement:?}"
                ),
            }
        }
    }
}

#[test]
fn native_presence_cannot_survive_a_registry_revocation_during_the_dialog() {
    for stale in [false, true] {
        let mut installed = Installation::new();
        let config = if stale {
            configure_writer_expiring_at(
                &mut installed,
                UnixMillis::new(support::live_clock().get() - 1000),
            )
        } else {
            configure_writer(&mut installed)
        };
        let native = host_with_writer(&installed, Some(config));
        native.login().unwrap();
        let barrier = installed.directory.path().join("hold-operator-signature");
        fs::write(&barrier, b"").unwrap();
        let host = native.clone();
        let login = std::thread::spawn(move || host.login());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !installed
            .directory
            .path()
            .join("operator-signature-paused")
            .exists()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "native presence barrier"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        installed.publish_fixture_revocation();
        fs::remove_file(barrier).unwrap();
        assert!(
            login.join().unwrap().is_err(),
            "revocation during presence must reject before success; stale={stale}"
        );
        assert_eq!(native.verified_role().unwrap(), None);
    }
}

#[test]
fn native_expired_writer_cannot_bypass_block_or_evidence_grade_policy() {
    for (profile, behavior) in [(0, 1), (1, 0)] {
        let mut installed = Installation::new();
        configure_writer_with_policy(
            &mut installed,
            UnixMillis::new(support::live_clock().get() - 1000),
            profile,
            behavior,
        );
        let native = NativeOperatorProvider::open_test_fixture(
            installed.directory.path().join("ea-native-operator"),
            false,
        )
        .unwrap();
        assert!(
            InteractiveOperatorRuntime::open_with_test_native(
                OperatorRuntimeConfig::load(&installed.config).unwrap(),
                &installed.anchor,
                support::live_clock(),
                native
            )
            .is_err()
        );
    }
}

mod time_authority;
