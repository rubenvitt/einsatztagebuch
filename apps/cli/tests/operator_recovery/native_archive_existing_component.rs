//! Native signed-policy/SQLCipher component evidence, not a mounted network
//! or complete Recovery-source witness. Setup SQL explicitly seeds an existing
//! registration; it is not a production bootstrap API.
use super::*;
use ea_admin::native_archive::{
    NativeArchiveConfig, NativeArchiveExistingComponent, NativeArchiveOpenError,
};
use ea_archive::{ArchiveBackendError, ArchivePath};
use sha2::{Digest, Sha256};

fn profile() -> ea_archive::ArchiveBackendProfileV1 {
    ea_archive::ArchiveBackendProfileV1::ControlledNetworkPath(
        ea_archive::ControlledNetworkProfileV1 {
            filesystem_row_id: "existing-component-only-no-mount".into(),
            protocol_id: "SMB3".into(),
            server_product: "native-component-fixture".into(),
            server_version: "1".into(),
            mount_options: vec!["component-only".into()],
            failover_config_id: "none".into(),
            capability_test_vector_id: "native-existing-component-v1".into(),
            queue_max_objects: 10000,
            queue_max_bytes: 64 * 1024 * 1024,
            resume_backoff_initial_ms: 1000,
            resume_backoff_max_ms: 5000,
            resume_max_attempts: 3,
        },
    )
}
fn config(
    runtime: &OperatorRuntime,
    profile: ea_archive::ArchiveBackendProfileV1,
) -> NativeArchiveConfig {
    NativeArchiveConfig {
        profile,
        local_commit_database_path: Some(runtime.database().path().to_owned()),
    }
}
fn namespace(runtime: &OperatorRuntime, profile: &ea_archive::ArchiveBackendProfileV1) -> Hash32 {
    let mut digest = Sha256::new();
    digest.update(b"EINSATZARCHIV-NATIVE-ARCHIVE-COMPONENT-v1\0");
    digest.update(runtime.anchor().trust_anchor_hash().as_bytes());
    digest.update(profile.profile_hash().unwrap().as_bytes());
    Hash32::try_from(digest.finalize().as_slice()).unwrap()
}
fn seed(runtime: &OperatorRuntime, profile: &ea_archive::ArchiveBackendProfileV1, mutation: &str) {
    let database = runtime.database();
    let mut ns = namespace(runtime, profile);
    if mutation == "namespace" {
        ns = Hash32::try_from([0x77; 32].as_slice()).unwrap();
    }
    if mutation != "scope" {
        database.execute("INSERT INTO local_commit_scope(namespace,object_limit,byte_limit) VALUES(?1,?2,?3)", &[
            StoreValue::Blob(ns.as_bytes().to_vec()),StoreValue::Integer(if mutation=="limits" {9999}else{10000}),
            StoreValue::Integer(64*1024*1024),
        ]).unwrap();
    } else {
        // Deliberately corrupt test fixture, impossible via normal immutable
        // registration with foreign keys enabled. Admission must still refuse.
        database.execute("PRAGMA foreign_keys=OFF", &[]).unwrap();
    }
    if mutation != "binding" {
        let mut exact =
            ea_format::encode_archive_backend_profile_core(&profile.core().unwrap()).unwrap();
        if mutation == "exact" {
            exact.push(0);
        }
        let hash = if mutation == "hash" {
            Hash32::try_from([0x78; 32].as_slice()).unwrap()
        } else {
            profile.profile_hash().unwrap()
        };
        database.execute("INSERT INTO native_archive_component(anchor_hash,profile_hash,namespace,exact_profile) VALUES(?1,?2,?3,?4)", &[
            StoreValue::Blob(runtime.anchor().trust_anchor_hash().as_bytes().to_vec()),StoreValue::Blob(hash.as_bytes().to_vec()),
            StoreValue::Blob(ns.as_bytes().to_vec()),StoreValue::Blob(exact),
        ]).unwrap();
    }
    if mutation == "scope" {
        database.execute("PRAGMA foreign_keys=ON", &[]).unwrap();
    }
}
fn observe_archive_writes(runtime: &OperatorRuntime) {
    let db = runtime.database();
    db.execute(
        "CREATE TEMP TABLE native_archive_write_witness(event INTEGER)",
        &[],
    )
    .unwrap();
    // Existing ensure_current may update go_live_posture_clock. Observe only
    // archive storage writes, including a probe inserted and then deleted.
    for table in [
        "native_archive_component",
        "local_commit_scope",
        "local_commit_probe",
        "local_commit_object",
        "local_commit_directory",
    ] {
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            db.execute(&format!("CREATE TEMP TRIGGER witness_{table}_{operation} AFTER {operation} ON main.{table} BEGIN INSERT INTO native_archive_write_witness(event) VALUES(1); END"), &[]).unwrap();
        }
    }
}
fn state(runtime: &OperatorRuntime) -> Vec<String> {
    let db = runtime.database();
    let mut state = Vec::new();
    for (table, projection, order) in [
        (
            "native_archive_component",
            "hex(anchor_hash)||hex(profile_hash)||hex(namespace)||hex(exact_profile)",
            "anchor_hash",
        ),
        (
            "local_commit_scope",
            "hex(namespace)||':'||object_limit||':'||byte_limit",
            "namespace",
        ),
        (
            "local_commit_probe",
            "hex(namespace)||hex(probe_bytes)",
            "namespace",
        ),
        (
            "local_commit_object",
            "hex(namespace)||hex(relative_path)||hex(exact_bytes)",
            "namespace,relative_path",
        ),
        (
            "local_commit_directory",
            "hex(namespace)||hex(directory)",
            "namespace,directory",
        ),
        ("native_archive_write_witness", "event", "rowid"),
    ] {
        let sql = format!(
            "SELECT count(*),coalesce(group_concat(exact,';'),'') FROM (SELECT {projection} AS exact FROM {table} ORDER BY {order})"
        );
        let row = db.query_row(&sql, &[]).unwrap().unwrap();
        state.push(format!(
            "{}:{}",
            row.integer(0).unwrap(),
            row.text(1).unwrap()
        ));
    }
    state
}
#[test]
fn native_existing_component_opens_offline_and_preserves_exact_local_bytes_across_reopen() {
    let installed = RecoveryInstallation::with_profile(None, false, Some(profile()));
    let runtime = installed.open();
    seed(&runtime, &installed.profile, "");
    let detached = installed.archive.with_extension("detached");
    fs::rename(&installed.archive, &detached).unwrap();
    let component = NativeArchiveExistingComponent::open_current(
        &runtime,
        config(&runtime, installed.profile.clone()),
    )
    .unwrap();
    assert!(component.profile_hash() == installed.profile.profile_hash().unwrap());
    let writer_lock = component.local_backend().acquire_writer_lock().unwrap();
    let path = ArchivePath::in_dir("entries/", "native-exact.eip").unwrap();
    let bytes = b"NATIVE-EXISTING-COMPONENT-PRIVATE-EXACT-BYTES";
    component
        .local_backend()
        .create_non_object_if_absent(&path, bytes)
        .unwrap();
    component.local_backend().sync_file(&path).unwrap();
    assert!(fs::read(installed.archive.join(path.as_str())).is_err());
    assert!(
        !installed.archive.exists(),
        "local open never materializes the missing remote root"
    );
    drop(writer_lock);
    drop(component);
    drop(runtime);
    fs::rename(&detached, &installed.archive).unwrap();
    let runtime = installed.open();
    fs::rename(&installed.archive, &detached).unwrap();
    let component = NativeArchiveExistingComponent::open_current(
        &runtime,
        config(&runtime, installed.profile.clone()),
    )
    .unwrap();
    let _writer_lock = component.local_backend().acquire_writer_lock().unwrap();
    let mut found = None;
    component
        .local_backend()
        .visit_managed_blobs(&mut |blob| {
            if blob.path_hint() == path.as_str() {
                found = Some(blob.bytes().to_vec());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(found.as_deref(), Some(bytes.as_slice()));
    assert!(!installed.archive.exists());
}
#[test]
fn native_existing_component_rejects_invalid_admission_without_sql_or_probe_writes() {
    for case in [
        "absent",
        "binding",
        "scope",
        "exact",
        "hash",
        "namespace",
        "limits",
        "database",
        "missing_database",
        "policy",
        "shape",
        "malformed",
        "probe_conflict",
        "migration",
    ] {
        let installed = RecoveryInstallation::with_profile(None, false, Some(profile()));
        let runtime = installed.open();
        if case != "absent" {
            seed(&runtime, &installed.profile, case);
        }
        if case == "probe_conflict" {
            runtime
                .database()
                .execute(
                    "INSERT INTO local_commit_probe(namespace,probe_bytes) VALUES(?1,?2)",
                    &[
                        StoreValue::Blob(
                            namespace(&runtime, &installed.profile).as_bytes().to_vec(),
                        ),
                        StoreValue::Blob(b"preexisting different probe bytes".to_vec()),
                    ],
                )
                .unwrap();
        }
        if case == "migration" {
            runtime
                .database()
                .execute("DELETE FROM schema_migration WHERE version=26", &[])
                .unwrap();
        }
        let mut cfg = config(&runtime, installed.profile.clone());
        if case == "database" {
            let alternate = installed.directory.path().join("other-existing.sqlite");
            let (provider, key) = database_provider_for(true);
            drop(EncryptedDatabase::open(&alternate, &provider, &key).unwrap());
            cfg.local_commit_database_path = Some(alternate);
        }
        let missing = installed.directory.path().join("must-not-create.sqlite");
        if case == "missing_database" {
            cfg.local_commit_database_path = Some(missing.clone());
        }
        if case == "shape" {
            cfg.local_commit_database_path = None;
        }
        if let ea_archive::ArchiveBackendProfileV1::ControlledNetworkPath(p) = &mut cfg.profile {
            if case == "policy" {
                p.server_version = "different".into();
            }
            if case == "malformed" {
                p.queue_max_objects = 0;
            }
        }
        observe_archive_writes(&runtime);
        let before = state(&runtime);
        let result = NativeArchiveExistingComponent::open_current(&runtime, cfg);
        assert!(result.is_err(), "{case}");
        if case == "policy" {
            assert!(matches!(
                result,
                Err(NativeArchiveOpenError::Backend(
                    ArchiveBackendError::ProfileNotAllowed
                ))
            ));
        }
        if ["absent", "binding", "scope"].contains(&case) {
            assert!(matches!(
                result,
                Err(NativeArchiveOpenError::Backend(
                    ArchiveBackendError::MissingLocalCommitComponent
                ))
            ));
        }
        assert_eq!(
            state(&runtime),
            before,
            "{case}: admission must not write, even a transient probe"
        );
        assert!(!missing.exists());
    }
}
#[test]
fn native_existing_component_current_writer_entry_is_storage_only_and_local_config_stays_compatible()
 {
    let installed = RecoveryInstallation::with_profile(None, false, Some(profile()));
    let runtime = installed.open();
    seed(&runtime, &installed.profile, "");
    let cfg = config(&runtime, installed.profile.clone());
    let runtime = ea_admin::operator_runtime::writer::InteractiveOperatorRuntime::from(runtime);
    let component = NativeArchiveExistingComponent::open_writer(&runtime, cfg).unwrap();
    assert!(component.profile_hash() == installed.profile.profile_hash().unwrap());
    let local = RecoveryInstallation::new();
    let runtime = local.open();
    observe_archive_writes(&runtime);
    let before = state(&runtime);
    assert!(matches!(
        NativeArchiveExistingComponent::open_current(
            &runtime,
            config(&runtime, local.profile.clone())
        ),
        Err(NativeArchiveOpenError::Config)
    ));
    assert_eq!(state(&runtime), before);
    assert!(
        NativeArchiveExistingComponent::open_current(
            &runtime,
            NativeArchiveConfig {
                profile: local.profile.clone(),
                local_commit_database_path: None
            }
        )
        .is_ok()
    );
}
