//! Actual native configured Host through the public evidence IPC cores.
use super::*;
use ea_desktop::commands::{
    destruction_evidence::{destruction_evidence_finalize_core, destruction_evidence_preview_core},
    writer::FinalizationPreviewDto,
};

fn configured_files(f: &NativeDestructionFixture) -> (PathBuf, PathBuf, Vec<u8>) {
    let (path, exact) = custodian::configuration(f);
    let settings = f._directory.path().join("evidence-writer.json");
    let ArchiveBackendProfileV1::LocalPath(profile) = &f.profile else {
        panic!("local native fixture")
    };
    let settings_exact = serde_json::to_vec(&serde_json::json!({
        "version": 1, "timezone": "Europe/Berlin", "archive_profile": {
            "kind": "local-path", "filesystem_row_id": profile.filesystem_row_id,
            "capability_test_vector_id": profile.capability_test_vector_id
        }
    }))
    .unwrap();
    fs::write(&settings, &settings_exact).unwrap();
    let mut config: serde_json::Value = serde_json::from_slice(&exact).unwrap();
    config["evidence_writer_config"] = serde_json::to_value(&settings).unwrap();
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    (path, settings, settings_exact)
}
#[test]
fn configured_evidence_host_finalizes_only_after_explicit_preview_and_reopens_exact_status() {
    let f = NativeDestructionFixture::without_server();
    let (config, _, _) = configured_files(&f);
    let host = custodian::configured(&f, &config);
    let state = host.desktop_state();
    assert!(destruction_evidence_preview_core(&state, &"11".repeat(16), &"22".repeat(32)).is_err());
    host.login().unwrap();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let id = prepared["process"]["destructionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let hash = prepared["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap()
        .to_owned();
    destruction_start_core(&state, &id, &hash).unwrap();
    destruction_resume_core(&state, &id).unwrap();
    let review =
        serde_json::to_value(destruction_evidence_preview_core(&state, &id, &hash).unwrap())
            .unwrap();
    assert_eq!(review["process"]["destructionId"], id);
    assert_eq!(review["process"]["preflight"]["jobHash"], hash);
    assert_eq!(
        review["writerDeviceId"],
        review["process"]["custodianDeviceId"]
    );
    assert!(review["process"]["evidenceEntryHash"].is_null());
    let confirmed: FinalizationPreviewDto =
        serde_json::from_value(review["preview"].clone()).unwrap();
    let completed = serde_json::to_value(
        destruction_evidence_finalize_core(&state, &id, &hash, &confirmed).unwrap(),
    )
    .unwrap();
    assert!(
        completed["entryHash"]
            .as_str()
            .is_some_and(|h| h.len() == 64)
    );
    assert!(destruction_evidence_finalize_core(&state, &id, &hash, &confirmed).is_err());
    drop(state);
    drop(host);
    let reopened = custodian::configured(&f, &config);
    reopened.login().unwrap();
    let status =
        serde_json::to_value(destruction_read_core(&reopened.desktop_state(), Some(&id)).unwrap())
            .unwrap();
    assert_eq!(
        status["process"]["evidenceEntryHash"],
        completed["entryHash"]
    );
    assert_ne!(
        status["process"]["state"], "completeManagedScope",
        "missing Reader is still an obligation"
    );
}

#[test]
fn configured_evidence_settings_cannot_change_silently_before_writer_presence() {
    let f = NativeDestructionFixture::without_server();
    let (config, settings, exact) = configured_files(&f);
    let host = custodian::configured(&f, &config);
    host.login().unwrap();
    let state = host.desktop_state();
    let before = fs::read(f.writer_directory.join("helper-calls")).unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&exact).unwrap();
    changed["timezone"] = "UTC".into();
    fs::write(&settings, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert_eq!(
        destruction_evidence_preview_core(&state, &"11".repeat(16), &"22".repeat(32))
            .err()
            .unwrap()
            .code,
        "EA-DESKTOP-LAUNCH-CONFIG"
    );
    assert_eq!(
        fs::read(f.writer_directory.join("helper-calls")).unwrap(),
        before,
        "changed settings fail before independent Writer presence or effects"
    );
    fs::write(&settings, exact).unwrap();
}

#[test]
fn configured_evidence_rejected_finalize_allows_fresh_preview_in_same_session() {
    let f = NativeDestructionFixture::without_server();
    let (config, _, _) = configured_files(&f);
    let host = custodian::configured(&f, &config);
    host.login().unwrap();
    let state = host.desktop_state();
    let prepared =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let id = prepared["process"]["destructionId"].as_str().unwrap();
    let hash = prepared["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap();
    destruction_start_core(&state, id, hash).unwrap();
    destruction_resume_core(&state, id).unwrap();
    let review =
        serde_json::to_value(destruction_evidence_preview_core(&state, id, hash).unwrap()).unwrap();
    let confirmed: FinalizationPreviewDto =
        serde_json::from_value(review["preview"].clone()).unwrap();
    assert_eq!(
        destruction_evidence_finalize_core(&state, id, &"00".repeat(32), &confirmed)
            .err()
            .unwrap()
            .code,
        "EA-DRAFT-EVIDENCE-BINDING"
    );
    assert!(
        destruction_evidence_finalize_core(&state, id, hash, &confirmed).is_err(),
        "a rejected operation must invalidate the old preview"
    );
    // No login, host replacement, or draft discard between the rejection and retry.
    let fresh =
        serde_json::to_value(destruction_evidence_preview_core(&state, id, hash).unwrap()).unwrap();
    let confirmed: FinalizationPreviewDto =
        serde_json::from_value(fresh["preview"].clone()).unwrap();
    let completed = serde_json::to_value(
        destruction_evidence_finalize_core(&state, id, hash, &confirmed).unwrap(),
    )
    .unwrap();
    assert!(
        completed["entryHash"]
            .as_str()
            .is_some_and(|h| h.len() == 64)
    );
}
