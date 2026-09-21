//! Erstregistrierung der Netzkomponente (EA-CNA-REG-1 … REG-10) gegen die
//! echte native Autorität und SQLCipher-Datei. Das Temp-Verzeichnis ist kein
//! Beleg für ein gemountetes Netzdateisystem.
use super::native_archive_existing_component::{config, observe_archive_writes, profile, state};
use super::*;
use ea_admin::native_archive::{
    NativeArchiveConfig, NativeArchiveExistingComponent, NativeArchiveOpenError,
    NativeArchiveRegistrationOutcome, register_network_component,
};
use ea_archive::{ArchiveBackendError, BoundArchiveProfilePolicyV1};
use ea_archive_fs::LocalPathBackend;

fn audit_count(runtime: &OperatorRuntime) -> i64 {
    runtime
        .database()
        .query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}

/// Die neuen Auditzeilen ab `offset` in Einfügereihenfolge, dekodiert.
fn audit_events_after(runtime: &OperatorRuntime, offset: i64) -> Vec<ea_format::LocalAuditEventV1> {
    let db = runtime.database();
    let count = audit_count(runtime);
    (offset..count)
        .map(|index| {
            let row = db
                .query_row(
                    "SELECT exact_bytes FROM local_audit_event ORDER BY insertion_sequence LIMIT 1 OFFSET ?1",
                    &[StoreValue::Integer(index)],
                )
                .unwrap()
                .unwrap();
            ea_format::decode_local_audit_event(row.blob(0).unwrap()).unwrap()
        })
        .collect()
}

/// Projektion der Archivtabellen ohne Zeugentabelle: der Idempotenztest darf
/// keinen Zeugen installieren, weil `open_current` die Ruheort-Probe
/// rechtmäßig einfügt und wieder löscht.
fn storage_rows(runtime: &OperatorRuntime) -> Vec<String> {
    let db = runtime.database();
    [
        "SELECT count(*),coalesce(group_concat(hex(anchor_hash)||hex(profile_hash)||hex(namespace)||hex(exact_profile),';'),'') FROM native_archive_component",
        "SELECT count(*),coalesce(group_concat(hex(namespace)||':'||object_limit||':'||byte_limit,';'),'') FROM local_commit_scope",
        "SELECT count(*),coalesce(group_concat(hex(namespace)||hex(relative_path)||hex(exact_bytes),';'),'') FROM local_commit_object",
        "SELECT count(*),coalesce(group_concat(hex(namespace)||hex(directory),';'),'') FROM local_commit_directory",
    ]
    .iter()
    .map(|sql| {
        let row = db.query_row(sql, &[]).unwrap().unwrap();
        format!("{}:{}", row.integer(0).unwrap(), row.text(1).unwrap())
    })
    .collect()
}

fn local_path_profile() -> ea_archive::ArchiveBackendProfileV1 {
    ea_archive::ArchiveBackendProfileV1::LocalPath(ea_archive::LocalPathProfileV1 {
        filesystem_row_id: "fixture-recovery-fs".into(),
        capability_test_vector_id: "native-recovery-cap-v1".into(),
    })
}

#[test]
fn registration_inserts_scope_component_and_one_audit_row_atomically() {
    let installed = RecoveryInstallation::with_profile(None, false, Some(profile()));
    let runtime = installed.open();
    let profile_hash = installed.profile.profile_hash().unwrap();
    let anchor = runtime.anchor().trust_anchor_hash();
    let namespace = ea_crypto::native_archive_component_namespace(anchor, profile_hash);
    let exact =
        ea_format::encode_archive_backend_profile_core(&installed.profile.core().unwrap()).unwrap();
    let policy = BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
    let inventory = LocalPathBackend::open_existing(
        installed.archive.clone(),
        installed.profile.clone(),
        &policy,
    )
    .unwrap()
    .inventory()
    .unwrap();
    let inventory_hash = ea_crypto::archive_inventory_digest(
        &ea_format::encode_archive_inventory_list(&inventory).unwrap(),
    );
    let audit_before = audit_count(&runtime);

    let (outcome, component) =
        register_network_component(&runtime, config(&runtime, installed.profile.clone())).unwrap();
    assert_eq!(outcome, NativeArchiveRegistrationOutcome::Registered);
    assert!(component.profile_hash() == profile_hash);
    drop(component);

    let db = runtime.database();
    let row = db
        .query_row(
            "SELECT count(*),anchor_hash,profile_hash,namespace,exact_profile FROM native_archive_component",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.integer(0).unwrap(), 1);
    assert_eq!(row.blob(1).unwrap(), anchor.as_bytes());
    assert_eq!(row.blob(2).unwrap(), profile_hash.as_bytes());
    assert_eq!(row.blob(3).unwrap(), namespace.as_bytes());
    assert_eq!(row.blob(4).unwrap(), exact.as_slice());
    let scope = db
        .query_row(
            "SELECT count(*),namespace,object_limit,byte_limit FROM local_commit_scope",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(scope.integer(0).unwrap(), 1);
    assert_eq!(scope.blob(1).unwrap(), namespace.as_bytes());
    assert_eq!(scope.integer(2).unwrap(), 10000);
    assert_eq!(scope.integer(3).unwrap(), 64 * 1024 * 1024);

    // Genau eine Registrierungszeile. Die frische Präsenz bucht zusätzlich
    // ihre bestehende Login-Zeile; eine weitere Zeile gibt es nicht.
    let events = audit_events_after(&runtime, audit_before);
    let migrations: Vec<_> = events
        .iter()
        .filter_map(|event| match event.action() {
            ea_format::LocalAuditActionV1::ArchiveProfileMigration(context) => {
                Some((context, event.outcome()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(migrations.len(), 1, "exactly one registration audit row");
    let (context, outcome) = migrations[0];
    assert_eq!(outcome, ea_format::LocalAuditOutcomeV1::Accepted);
    assert!(context.source_profile_hash() == profile_hash);
    assert!(context.target_profile_hash() == profile_hash);
    assert!(context.inventory_hash() == inventory_hash);
    assert!(context.active_pointer_hash() == Hash32::try_from([0; 32].as_slice()).unwrap());
    assert!(
        events.iter().all(|event| matches!(
            event.action(),
            ea_format::LocalAuditActionV1::ArchiveProfileMigration(_)
                | ea_format::LocalAuditActionV1::Login(_)
        )),
        "only the presence login and the registration row are booked"
    );

    assert!(
        NativeArchiveExistingComponent::open_current(
            &runtime,
            config(&runtime, installed.profile.clone())
        )
        .is_ok()
    );
}

#[test]
fn registration_is_idempotent_for_the_identical_row_without_presence_or_audit() {
    let installed = RecoveryInstallation::with_profile(None, false, Some(profile()));
    let runtime = installed.open();
    let (first, component) =
        register_network_component(&runtime, config(&runtime, installed.profile.clone())).unwrap();
    assert_eq!(first, NativeArchiveRegistrationOutcome::Registered);
    drop(component);
    let rows = storage_rows(&runtime);
    let audit = audit_count(&runtime);
    let (second, component) =
        register_network_component(&runtime, config(&runtime, installed.profile.clone())).unwrap();
    assert_eq!(second, NativeArchiveRegistrationOutcome::AlreadyRegistered);
    assert!(component.profile_hash() == installed.profile.profile_hash().unwrap());
    drop(component);
    assert_eq!(storage_rows(&runtime), rows);
    assert_eq!(audit_count(&runtime), audit, "no presence and no audit");
}

#[test]
fn registration_refuses_every_precondition_without_writes() {
    for case in [
        "local_path",
        "missing_database",
        "other_database",
        "policy",
        "migration",
        "remote_missing",
        "pointer",
        "component_conflict",
        "scope_conflict",
    ] {
        let installed = RecoveryInstallation::with_profile(None, false, Some(profile()));
        let runtime = installed.open();
        let profile_hash = installed.profile.profile_hash().unwrap();
        let namespace = ea_crypto::native_archive_component_namespace(
            runtime.anchor().trust_anchor_hash(),
            profile_hash,
        );
        let mut cfg = config(&runtime, installed.profile.clone());
        match case {
            "local_path" => cfg.profile = local_path_profile(),
            "missing_database" => cfg.local_commit_database_path = None,
            "other_database" => {
                let alternate = installed.directory.path().join("other-existing.sqlite");
                let (provider, key) = database_provider_for(true);
                drop(EncryptedDatabase::open(&alternate, &provider, &key).unwrap());
                cfg.local_commit_database_path = Some(alternate);
            }
            "policy" => {
                if let ea_archive::ArchiveBackendProfileV1::ControlledNetworkPath(p) =
                    &mut cfg.profile
                {
                    p.server_version = "different".into();
                }
            }
            "migration" => {
                runtime
                    .database()
                    .execute("DELETE FROM schema_migration WHERE version=26", &[])
                    .unwrap();
            }
            "remote_missing" => {
                fs::rename(&installed.archive, installed.archive.with_extension("away")).unwrap();
            }
            "pointer" => {
                let policy =
                    BoundArchiveProfilePolicyV1::from_policy(runtime.head().policy_fields());
                LocalPathBackend::open_existing(
                    installed.archive.clone(),
                    installed.profile.clone(),
                    &policy,
                )
                .unwrap()
                .write_active_profile_pointer(&ea_format::ActiveProfilePointerCoreV1::new(
                    Hash32::try_from([0x5a; 32].as_slice()).unwrap(),
                    1,
                ))
                .unwrap();
            }
            "component_conflict" => {
                let db = runtime.database();
                db.execute(
                    "INSERT INTO local_commit_scope(namespace,object_limit,byte_limit) VALUES(?1,?2,?3)",
                    &[
                        StoreValue::Blob(namespace.as_bytes().to_vec()),
                        StoreValue::Integer(10000),
                        StoreValue::Integer(64 * 1024 * 1024),
                    ],
                )
                .unwrap();
                let mut exact = ea_format::encode_archive_backend_profile_core(
                    &installed.profile.core().unwrap(),
                )
                .unwrap();
                exact.push(0);
                db.execute(
                    "INSERT INTO native_archive_component(anchor_hash,profile_hash,namespace,exact_profile) VALUES(?1,?2,?3,?4)",
                    &[
                        StoreValue::Blob(runtime.anchor().trust_anchor_hash().as_bytes().to_vec()),
                        StoreValue::Blob(profile_hash.as_bytes().to_vec()),
                        StoreValue::Blob(namespace.as_bytes().to_vec()),
                        StoreValue::Blob(exact),
                    ],
                )
                .unwrap();
            }
            "scope_conflict" => {
                runtime
                    .database()
                    .execute(
                        "INSERT INTO local_commit_scope(namespace,object_limit,byte_limit) VALUES(?1,?2,?3)",
                        &[
                            StoreValue::Blob(namespace.as_bytes().to_vec()),
                            StoreValue::Integer(9999),
                            StoreValue::Integer(64 * 1024 * 1024),
                        ],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        observe_archive_writes(&runtime);
        let before = state(&runtime);
        let audit = audit_count(&runtime);
        let result = register_network_component(&runtime, cfg);
        let error = match result {
            Ok(_) => panic!("{case}: registration must refuse"),
            Err(error) => error,
        };
        let expected = match case {
            "local_path" | "missing_database" | "other_database" => {
                matches!(error, NativeArchiveOpenError::Config)
            }
            "policy" => matches!(
                error,
                NativeArchiveOpenError::Backend(ArchiveBackendError::ProfileNotAllowed)
            ),
            "migration" => matches!(
                error,
                NativeArchiveOpenError::Backend(ArchiveBackendError::MissingLocalCommitComponent)
            ),
            "remote_missing" => {
                matches!(error, NativeArchiveOpenError::Backend(ArchiveBackendError::Io))
            }
            "pointer" => matches!(error, NativeArchiveOpenError::PointerConflict),
            _ => matches!(error, NativeArchiveOpenError::RegistrationConflict),
        };
        assert!(expected, "{case}: unexpected {error:?}");
        assert_eq!(state(&runtime), before, "{case}: no database write");
        assert_eq!(audit_count(&runtime), audit, "{case}: no audit row");
    }
}

#[test]
fn registered_anchor_refuses_local_path_configuration() {
    let installed = RecoveryInstallation::with_profile(None, false, Some(profile()));
    let runtime = installed.open();
    drop(
        register_network_component(&runtime, config(&runtime, installed.profile.clone())).unwrap(),
    );
    let result = NativeArchiveExistingComponent::open_current(
        &runtime,
        NativeArchiveConfig {
            profile: local_path_profile(),
            local_commit_database_path: None,
        },
    );
    assert!(matches!(
        result,
        Err(NativeArchiveOpenError::ProfileMismatch)
    ));
    assert_eq!(
        result.err().unwrap().code(),
        "EA-NATIVE-ARCHIVE-PROFILE-MISMATCH"
    );
}
