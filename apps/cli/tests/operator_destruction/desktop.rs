//! Real native helpers, signed authorization, SQLCipher and the actual Desktop IPC core.
mod completion;
mod failure;
mod pending;
mod custodian;
mod evidence;
mod reader_delivery;
use super::*;
use ea_desktop::{
    commands::destruction::{
        destruction_import_progress_core, destruction_mark_incomplete_core,
        destruction_prepare_core, destruction_read_core, destruction_resume_core,
        destruction_start_core,
    },
    runtime::{DesktopLaunchConfig, NativeDesktopRuntime},
    state::RuntimeSessionPort,
};

/// Local test runtime without any server transport: the NoServer Desktop host.
pub(super) fn desktop(f: &NativeDestructionFixture) -> std::sync::Arc<NativeDesktopRuntime> {
    let native = NativeOperatorProvider::open_test_fixture(
        f.admin_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let controller = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.admin_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    NativeDesktopRuntime::open_with_test_destruction_runtime(
        DesktopLaunchConfig {
            operator_config: f.admin_config.clone(),
            trust_anchor: f.anchor.clone(),
            writer_config: None,
            destruction_config: None,
            recovery_config: None,
            administration_config: None,
        },
        controller,
        f.runtime(),
    )
    .unwrap()
}

#[test]
fn native_desktop_destruction_import_start_resume_reconstructs_exact_persisted_job() {
    let f = NativeDestructionFixture::without_server();
    let host = desktop(&f);
    assert!(destruction_read_core(&host.desktop_state(), None).is_err());
    host.login().unwrap();
    let state = host.desktop_state();
    let initial = serde_json::to_value(destruction_read_core(&state, None).unwrap()).unwrap();
    assert!(
        initial["knownDestructionIds"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let requested =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let id = requested["process"]["destructionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let job = requested["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(requested["process"]["state"], "requested");
    assert_eq!(
        requested["process"]["approverCertificateHashes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        !requested["process"]["replicas"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(requested["process"]["evidenceEntryHash"].is_null());
    assert!(
        requested["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|target| target.get("stubObjectHash") == Some(&serde_json::Value::Null))
    );
    let started = serde_json::to_value(destruction_start_core(&state, &id, &job).unwrap()).unwrap();
    assert_eq!(started["process"]["state"], "inProgress");
    drop(state);
    drop(host);
    let reopened = desktop(&f);
    reopened.login().unwrap();
    let resumed =
        serde_json::to_value(destruction_resume_core(&reopened.desktop_state(), &id).unwrap())
            .unwrap();
    assert_eq!(resumed["process"]["destructionId"], id);
    assert_eq!(resumed["process"]["preflight"]["jobHash"], job);
    assert_ne!(resumed["process"]["state"], "completeManagedScope");
    let replicas = resumed["process"]["replicas"].as_array().unwrap();
    assert!(
        replicas
            .iter()
            .any(|r| r["resultCode"] == 0 && r["attestationHash"].is_string())
    );
    assert!(replicas.iter().any(|r| r["resultCode"].is_null()));
    assert!(resumed["process"]["evidenceEntryHash"].is_null());
    assert!(
        resumed["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|target| target["stubObjectHash"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64))
    );
    reopened.invalidate();
    assert!(destruction_read_core(&reopened.desktop_state(), Some(&id)).is_err());
}

#[test]
fn native_desktop_signed_replica_import_persists_the_verified_state_and_refuses_tampering() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let host = desktop(&f);
    host.login().unwrap();
    let state = host.desktop_state();
    let requested =
        serde_json::to_value(destruction_prepare_core(&state, &f.authorization).unwrap()).unwrap();
    let id = requested["process"]["destructionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let job = requested["process"]["preflight"]["jobHash"]
        .as_str()
        .unwrap()
        .to_owned();
    destruction_start_core(&state, &id, &job).unwrap();
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let objects = super::import::complete_pending_objects(&f, &db);
    let imported = serde_json::to_value(
        destruction_import_progress_core(&state, &id, &job, &objects).unwrap(),
    )
    .unwrap();
    assert_eq!(imported["process"]["state"], "pendingBackupExpiry");
    // Optional public DTO witness consumed by the real TypeScript boundary.
    // It contains no private key, payload or local provider path.
    if let Some(output) = std::env::var_os("EA_T13_NATIVE_VIEW_OUTPUT") {
        fs::write(output, serde_json::to_vec_pretty(&imported).unwrap()).unwrap();
    }

    assert_eq!(imported["process"]["preflight"]["jobHash"], job);
    assert!(
        imported["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["resultCode"] == 1
                && replica["attestationHash"].is_string()
                && replica["backupExpiryAt"].is_number())
    );
    assert!(imported["process"]["evidenceEntryHash"].is_null());
    drop(state);
    drop(host);
    let reopened = desktop(&f);
    reopened.login().unwrap();
    let state = reopened.desktop_state();
    let durable = serde_json::to_value(destruction_read_core(&state, Some(&id)).unwrap()).unwrap();
    assert_eq!(durable["process"], imported["process"]);
    let mut corrupted = objects;
    let last = corrupted[0].len() - 1;
    corrupted[0][last] ^= 1;
    assert!(destruction_import_progress_core(&state, &id, &job, &corrupted).is_err());
    let after = serde_json::to_value(destruction_read_core(&state, Some(&id)).unwrap()).unwrap();
    assert_eq!(after["process"], durable["process"]);
    reopened.invalidate();
    assert!(destruction_import_progress_core(&state, &id, &job, &corrupted).is_err());
}
