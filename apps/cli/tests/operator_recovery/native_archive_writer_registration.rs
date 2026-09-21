//! Ein Writer registriert die lokale Komponente in seiner eigenen Datenbank
//! (EA-CNA-REG-1): eigene frische Präsenz, eigenes signiertes Audit, Profil
//! exakt in der signierten Policy. Das Temp-Verzeichnis ist kein Beleg für
//! ein gemountetes Netzdateisystem.
use super::native_archive_registration::run_operator_fixture;
use super::*;
use ea_admin::native_archive::{
    NativeArchiveConfig, NativeArchiveRegistrationOutcome, register_network_component,
};
use ea_archive::ArchiveBackendProfileV1;

pub(crate) fn network_profile(queue_max_objects: u64) -> ArchiveBackendProfileV1 {
    ArchiveBackendProfileV1::ControlledNetworkPath(ea_archive::ControlledNetworkProfileV1 {
        filesystem_row_id: "fixture-network-writer-no-mount".into(),
        protocol_id: "SMB3".into(),
        server_product: "native-network-writer-fixture".into(),
        server_version: "1".into(),
        mount_options: vec!["writer-only".into()],
        failover_config_id: "none".into(),
        capability_test_vector_id: "native-network-writer-v1".into(),
        queue_max_objects,
        queue_max_bytes: 64 * 1024 * 1024,
        resume_backoff_initial_ms: 1000,
        resume_backoff_max_ms: 5000,
        resume_max_attempts: 3,
    })
}

/// Das Profil in der camelCase-Grammatik des CLI-Verbs.
fn cli_profile_json(profile: &ArchiveBackendProfileV1) -> Value {
    let ArchiveBackendProfileV1::ControlledNetworkPath(p) = profile else {
        panic!("network profile fixture");
    };
    json!({
        "kind":"controlledNetworkPath",
        "filesystemRowId":p.filesystem_row_id,"protocolId":p.protocol_id,
        "serverProduct":p.server_product,"serverVersion":p.server_version,
        "mountOptions":p.mount_options,"failoverConfigId":p.failover_config_id,
        "capabilityTestVectorId":p.capability_test_vector_id,
        "queueMaxObjects":p.queue_max_objects,"queueMaxBytes":p.queue_max_bytes,
        "resumeBackoffInitialMs":p.resume_backoff_initial_ms,
        "resumeBackoffMaxMs":p.resume_backoff_max_ms,
        "resumeMaxAttempts":p.resume_max_attempts
    })
}

/// Die native Writer-`Installation` mit einer Policy, die genau das
/// Netzprofil zulässt, und einem Wiederherstellungsempfänger für die Grants.
pub(crate) struct NetworkWriterInstallation {
    pub(crate) installed: Installation,
    pub(crate) profile: ArchiveBackendProfileV1,
}
impl NetworkWriterInstallation {
    pub(crate) fn new() -> Self {
        Self::with_profile(network_profile(10_000))
    }
    pub(crate) fn with_profile(profile: ArchiveBackendProfileV1) -> Self {
        use ea_trust::TrustObjectSource as _;
        let mut installed = Installation::new();
        let mut previous_hashes = Vec::new();
        installed
            .line
            .source()
            .visit_trust_object_hashes(&mut |hash| {
                previous_hashes.push(hash);
                Ok(())
            })
            .unwrap();
        let options = || HeadOptions {
            effective_from: Some(1),
            valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
            ..HeadOptions::default()
        };
        let previous = installed.line.current_policy_hash();
        installed.line.push(
            ActionSpec::Policy {
                policy_version: Some(2),
                previous_policy_hash: Some(previous),
                effective_from: Some(1),
            },
            HeadOptions {
                policy_max_registry_age_ms_override: Some(
                    support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                ),
                policy_allowed_archive_profile_hashes_override: Some(vec![
                    profile.profile_hash().unwrap(),
                ]),
                ..options()
            },
        );
        installed.line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::RecoveryRecipient,
                marker: 0x62,
                effective_from: Some(1),
            },
            options(),
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
        drop(source);
        Self { installed, profile }
    }

    /// Die Current-`OperatorRuntime` der Writer-Konfiguration.
    pub(crate) fn open_writer_runtime(&self) -> OperatorRuntime {
        let native = NativeOperatorProvider::open_test_fixture(
            self.installed.directory.path().join("ea-native-operator"),
            false,
        )
        .unwrap();
        OperatorRuntime::open_with_test_native(
            OperatorRuntimeConfig::load(&self.installed.config).unwrap(),
            &self.installed.anchor,
            support::live_clock(),
            false,
            native,
        )
        .unwrap()
    }
}

fn component_rows(runtime: &OperatorRuntime) -> i64 {
    runtime
        .database()
        .query_row("SELECT count(*) FROM native_archive_component", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}

#[test]
fn writer_registers_its_own_database_with_its_own_presence_and_audit() {
    let installed = NetworkWriterInstallation::new();
    let runtime = installed.open_writer_runtime();
    assert_eq!(runtime.config().role, OperatorRoleV1::Writer);
    let audit_before = runtime
        .database()
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    let (outcome, component) = register_network_component(
        &runtime,
        NativeArchiveConfig::for_runtime_database(
            installed.profile.clone(),
            runtime.database().path(),
        ),
    )
    .unwrap();
    assert_eq!(outcome, NativeArchiveRegistrationOutcome::Registered);
    assert!(component.profile_hash() == installed.profile.profile_hash().unwrap());
    assert!(component.is_network());
    drop(component);
    assert_eq!(component_rows(&runtime), 1);
    // Genau eine Registrierungszeile, signiert mit der eigenen Sitzung.
    let db = runtime.database();
    let mut migrations = 0;
    let count = db
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap();
    for index in audit_before..count {
        let row = db
            .query_row(
                "SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence LIMIT 1 OFFSET ?1",
                &[StoreValue::Integer(index)],
            )
            .unwrap()
            .unwrap();
        let event = ea_format::decode_local_audit_event(row.blob(0).unwrap()).unwrap();
        if let ea_format::LocalAuditActionV1::ArchiveProfileMigration(context) = event.action() {
            migrations += 1;
            assert!(context.source_profile_hash() == installed.profile.profile_hash().unwrap());
            assert!(context.target_profile_hash() == context.source_profile_hash());
        }
    }
    assert_eq!(migrations, 1, "exactly one registration audit row");
    // Wiederholung: identische Zeile, ohne Präsenz und Audit.
    let (again, component) = register_network_component(
        &runtime,
        NativeArchiveConfig::for_runtime_database(
            installed.profile.clone(),
            runtime.database().path(),
        ),
    )
    .unwrap();
    assert_eq!(again, NativeArchiveRegistrationOutcome::AlreadyRegistered);
    drop(component);
    assert_eq!(component_rows(&runtime), 1);
}

#[test]
fn writer_registration_refuses_a_profile_outside_the_signed_policy() {
    let installed = NetworkWriterInstallation::new();
    let runtime = installed.open_writer_runtime();
    let mut other = installed.profile.clone();
    if let ArchiveBackendProfileV1::ControlledNetworkPath(p) = &mut other {
        p.server_version = "not-in-policy".into();
    }
    let refused = register_network_component(
        &runtime,
        NativeArchiveConfig::for_runtime_database(other, runtime.database().path()),
    );
    assert_eq!(
        refused.err().unwrap().code(),
        "EA-ARCHIVE-PROFILE-NOT-ALLOWED"
    );
    assert_eq!(component_rows(&runtime), 0);
}

#[test]
fn cli_registers_the_writer_database_and_refuses_an_authority_config() {
    let installed = NetworkWriterInstallation::new();
    let directory = installed.installed.directory.path();
    let profile_path = directory.join("archive-profile.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&cli_profile_json(&installed.profile)).unwrap(),
    )
    .unwrap();
    let arguments = |config: &Path| -> Vec<String> {
        [
            "--trust-anchor",
            installed.installed.anchor.to_str().unwrap(),
            "operator",
            "register-network-archive",
            "--operator-config",
            config.to_str().unwrap(),
            "--network-archive-profile",
            profile_path.to_str().unwrap(),
            "--format",
            "json",
        ]
        .map(str::to_owned)
        .to_vec()
    };
    // Eine Authority-Konfiguration (einzige Konfigurationsform außerhalb von
    // Admin/Writer) wird vor dem Öffnen abgelehnt und schreibt nichts.
    let mut authority: Value =
        serde_json::from_slice(&fs::read(&installed.installed.config).unwrap()).unwrap();
    authority["role"] = json!("organization-admin");
    authority["authority"] = json!(true);
    authority["target_certificate_hash"] = json!("ab".repeat(32));
    let authority_config = directory.join("authority.json");
    fs::write(&authority_config, serde_json::to_vec(&authority).unwrap()).unwrap();
    let refused = run_operator_fixture(directory, &arguments(&authority_config));
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("EA-NATIVE-ARCHIVE-ROLE"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let output = run_operator_fixture(directory, &arguments(&installed.installed.config));
    assert!(
        output.status.success(),
        "writer registration must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "{\"registration\":\"registered\"}"
    );
    let runtime = installed.open_writer_runtime();
    assert_eq!(component_rows(&runtime), 1);
}
