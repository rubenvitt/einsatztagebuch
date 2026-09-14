//! Actual native Desktop configuration and commands over authenticated TLS/PG/S3.
mod reader_opfs;
mod pending;
mod failure;
use super::*;
use ea_desktop::commands::{
    destruction_evidence::{destruction_evidence_finalize_core, destruction_evidence_preview_core},
    writer::FinalizationPreviewDto,
};
use ea_desktop::{
    commands::destruction::{
        destruction_prepare_core, destruction_read_core, destruction_resume_core,
        destruction_start_core, destruction_synchronize_core,
    },
    runtime::{DesktopLaunchConfig, NativeDesktopRuntime},
    state::RuntimeSessionPort,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn configured_host(
    f: &NativeDestructionFixture,
    server: &ServerFixture,
) -> Arc<NativeDesktopRuntime> {
    configured_host_with(f, server, "desktop-server-destruction.json", Vec::new())
}

/// Same exact configuration grammar under its own file; `extra_servers` are
/// appended after the registered server (e.g. an unbound server identity).
fn configured_host_with(
    f: &NativeDestructionFixture,
    server: &ServerFixture,
    config_name: &str,
    extra_servers: Vec<serde_json::Value>,
) -> Arc<NativeDesktopRuntime> {
    let open = |directory: &Path| {
        NativeOperatorProvider::open_test_fixture(directory.join("ea-native-operator"), false)
            .unwrap()
    };
    let controller = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.admin_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        open(&f.admin_directory),
    )
    .unwrap();
    let ea_archive::ArchiveBackendProfileV1::LocalPath(profile) = &f.profile else {
        panic!("explicit local fixture holder");
    };
    let KeySourceSpec::Container {
        path,
        passphrase_file,
    } = &f.key_source
    else {
        panic!("explicit protected component container");
    };
    let config_path = f._directory.path().join(config_name);
    let mut servers = vec![serde_json::json!({
        "device_id": hex(server.config.device_id.as_bytes()),
        "address": server.config.address.to_string(),
        "server_name": server.config.server_name,
        "authority": server.config.authority,
        "ca_file": server.config.ca_file,
        "server_certificate_hash": hex(server.config.server_certificate.as_bytes())
    })];
    servers.extend(extra_servers);
    let evidence_settings_path = f
        ._directory
        .path()
        .join("desktop-server-evidence-writer.json");
    let evidence_settings = serde_json::to_vec(&serde_json::json!({
        "version": 1, "timezone": "Europe/Berlin", "archive_profile": {
            "kind": "local-path", "filesystem_row_id": profile.filesystem_row_id,
            "capability_test_vector_id": profile.capability_test_vector_id
        }
    }))
    .unwrap();
    if evidence_settings_path.exists() {
        assert_eq!(
            fs::read(&evidence_settings_path).unwrap(),
            evidence_settings
        );
    } else {
        fs::write(&evidence_settings_path, evidence_settings).unwrap();
    }
    let exact = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "writer_operator_config": f.writer_config,
        "evidence_writer_config": evidence_settings_path,
        "component_certificate_hash": hex(f.component.as_bytes()),
        "component_key_source": format!("container:{};passphrase-file={}", path.display(), passphrase_file.display()),
        "delivery": "authenticated-server",
        "servers": servers,
        "holders": [{
            "archive_directory": f.archive,
            "filesystem_row_id": profile.filesystem_row_id,
            "capability_test_vector_id": profile.capability_test_vector_id,
            "custody_certificate_hash": hex(f.writer_certificate.as_bytes())
        }]
    })).unwrap();
    if config_path.exists() {
        assert_eq!(
            fs::read(&config_path).unwrap(),
            exact,
            "reopen preserves exact native configuration"
        );
    } else {
        fs::write(&config_path, exact).unwrap();
    }
    let launch = DesktopLaunchConfig::parse([
        std::ffi::OsString::from("--operator-config"),
        f.admin_config.clone().into_os_string(),
        std::ffi::OsString::from("--trust-anchor"),
        f.anchor.clone().into_os_string(),
        std::ffi::OsString::from("--destruction-config"),
        config_path.into_os_string(),
    ])
    .unwrap()
    .unwrap();
    let host = NativeDesktopRuntime::open_with_test_destruction_configuration(
        launch,
        controller,
        open(&f.writer_directory),
    )
    .unwrap();
    host.login().unwrap();
    host
}

fn job_count(services: &tokio::runtime::Runtime, server: &ServerFixture) -> i64 {
    services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
                .fetch_one(server.database.pool()),
        )
        .unwrap()
}

type EventCoreRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type EventTransitionRow = (Vec<u8>, Vec<u8>, Vec<u8>, i16, i64, i64);

#[derive(Debug, PartialEq, Eq)]
struct EventStorageSnapshot {
    cores: Vec<EventCoreRow>,
    transitions: Vec<EventTransitionRow>,
}

fn event_storage_snapshot(
    services: &tokio::runtime::Runtime,
    server: &ServerFixture,
) -> EventStorageSnapshot {
    // Read both complete tables independently so even an unmatched added row
    // would be visible. BYTEA, SMALLINT and BIGINT retain their exact values.
    services.block_on(async {
        let cores = sqlx::query_as::<_, EventCoreRow>(
            "SELECT object_hash, organization_id, destruction_id, event_id, exact_bytes \
             FROM destruction_event_cores ORDER BY object_hash",
        )
        .fetch_all(server.database.pool())
        .await
        .unwrap();
        let transitions = sqlx::query_as::<_, EventTransitionRow>(
            "SELECT object_hash, organization_id, destruction_id, to_state_code, \
             recorded_at_millis, technical_index \
             FROM destruction_transitions ORDER BY object_hash",
        )
        .fetch_all(server.database.pool())
        .await
        .unwrap();
        EventStorageSnapshot { cores, transitions }
    })
}

#[test]
fn native_desktop_configured_server_start_sync_and_resume_preserve_durable_progress() {
    let f = NativeDestructionFixture::with_server_state(true, 4);
    // The fixture helper otherwise ends its Controller OS subscription after
    // an absolute 300 seconds, independently of actual verified presence.
    // This control changes only that helper lifetime; core inactivity stays
    // 300 seconds and the separate Custodian receives no extra login here.
    fs::write(f.admin_directory.join("long-recovery-run"), b"").unwrap();
    let inventory =
        ArchiveInventory::build(&ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap())
            .unwrap();
    assert!(inventory.trust().iter().any(|object| matches!(
        object.value().decoded_payload(),
        Ok(DecodedTrustPayloadV1::Policy(ref policy)) if policy.fields().max_future_clock_skew_ms == 1_800_000
    )), "explicit signed test horizon; no default-policy long-run claim");
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let host = configured_host(&f, &server);
    let state = host.desktop_state();
    let initial = serde_json::to_value(destruction_read_core(&state, None).unwrap()).unwrap();
    assert!(
        initial["knownDestructionIds"]
            .as_array()
            .unwrap()
            .is_empty()
    );
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
    assert_eq!(
        job_count(&services, &server),
        0,
        "configuration/read/prepare do not send server jobs"
    );
    assert!(destruction_synchronize_core(&state, &id, &"ff".repeat(32)).is_err());
    assert_eq!(job_count(&services, &server), 0);
    let started =
        serde_json::to_value(destruction_start_core(&state, &id, &hash).unwrap()).unwrap();
    assert_eq!(started["process"]["state"], "inProgress");
    assert_eq!(job_count(&services, &server), 1);
    let attestations: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_attestations")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(
        attestations, 1,
        "actual server effect and signed attestation"
    );
    host.invalidate();
    assert!(destruction_read_core(&state, Some(&id)).is_err());
    drop(state);
    drop(host);

    let reopened = configured_host(&f, &server);
    let state = reopened.desktop_state();
    let synchronized =
        serde_json::to_value(destruction_synchronize_core(&state, &id, &hash).unwrap()).unwrap();
    assert_eq!(synchronized["process"]["destructionId"], id);
    assert_eq!(synchronized["process"]["preflight"]["jobHash"], hash);
    assert_eq!(
        job_count(&services, &server),
        1,
        "explicit synchronize creates no remote job"
    );
    assert_eq!(synchronized["process"]["state"], "inProgress");
    drop(state);
    drop(reopened);

    let resumed = configured_host(&f, &server);
    let state = resumed.desktop_state();
    let view = serde_json::to_value(destruction_resume_core(&state, &id).unwrap()).unwrap();
    assert_eq!(view["process"]["destructionId"], id);
    assert_eq!(view["process"]["preflight"]["jobHash"], hash);
    assert!(
        view["process"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|target| target["stubObjectHash"].is_string())
    );
    assert!(
        view["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["kindCode"] == 0 && replica["resultCode"] == 0)
    );
    assert!(
        view["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["kindCode"] == 1 && replica["resultCode"].is_null())
    );
    assert_eq!(view["process"]["state"], "inProgress");
    assert!(view["process"]["evidenceEntryHash"].is_null());
    drop(state);
    drop(resumed);
    let final_host = configured_host(&f, &server);
    let final_view = serde_json::to_value(
        destruction_read_core(&final_host.desktop_state(), Some(&id)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        final_view, view,
        "new host reconstructs exact durable public status"
    );
    let final_state = final_host.desktop_state();
    // Resume/synchronization intentionally relay later component attestations.
    // Compare the projection with its immediate pre-state, not the Start count.
    let before_projection: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_attestations")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    let events_before_projection = event_storage_snapshot(&services, &server);
    assert!(
        !events_before_projection.cores.is_empty()
            && !events_before_projection.transitions.is_empty(),
        "actual Start/Resume server events make the projection baseline nonempty"
    );
    let review =
        serde_json::to_value(destruction_evidence_preview_core(&final_state, &id, &hash).unwrap())
            .unwrap();
    assert_eq!(review["process"]["destructionId"], id);
    assert_eq!(review["process"]["preflight"]["jobHash"], hash);
    assert_eq!(
        job_count(&services, &server),
        1,
        "evidence projection adds no stored server job"
    );
    let after_projection: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_attestations")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(
        after_projection, before_projection,
        "read-only projection adds no server attestation"
    );
    assert_eq!(
        event_storage_snapshot(&services, &server),
        events_before_projection,
        "evidence projection preserves all stored server event hashes, cores and transitions"
    );
    let confirmed: FinalizationPreviewDto =
        serde_json::from_value(review["preview"].clone()).unwrap();
    let completed = serde_json::to_value(
        destruction_evidence_finalize_core(&final_state, &id, &hash, &confirmed).unwrap(),
    )
    .unwrap();
    drop(final_state);
    drop(final_host);
    let evidence_host = configured_host(&f, &server);
    let persisted = serde_json::to_value(
        destruction_read_core(&evidence_host.desktop_state(), Some(&id)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        persisted["process"]["evidenceEntryHash"],
        completed["entryHash"]
    );
    assert!(
        persisted["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|replica| replica["kindCode"] == 1 && replica["resultCode"].is_null()),
        "the persisted Reader replica remains open after Evidence and host reopen"
    );
    assert_ne!(
        persisted["process"]["state"], "completeManagedScope",
        "Reader remains an explicit obligation"
    );
}
