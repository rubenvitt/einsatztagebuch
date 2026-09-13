//! Actual native Failure-only service; missing confirmation is not a measured
//! network cause, and signed state4 is never a physical removal claim.
use super::*;
use ea_admin::destruction_runtime::NativeDestructionDelivery;

#[test]
fn native_failure_records_missing_confirmation_before_cleanup_and_replays_exactly() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let id = requested.destruction_id;
    let job = requested.preflight_hash.unwrap();
    let started = runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let entries_before = actual_entries(&f);
    assert!(
        !entries_before.is_empty(),
        "actual originals still retained"
    );
    let db = completion::writer_database(&f);
    let audits_before = count(&db, "local_audit_event");
    let failed = runtime.mark_incomplete_progress(id, job).unwrap();
    assert_eq!(failed.state.code(), 4);
    assert!(failed.preflight_hash == started.preflight_hash);
    assert_eq!(failed.replicas.len(), started.replicas.len());
    assert!(failed.replicas.iter().any(|replica| {
        replica.result == ea_destruction::EvidenceReplicaStatus::Unreachable
            && replica.attestation_hash.is_none()
    }));
    assert_eq!(count(&db, "destruction_import_batch"), 1);
    assert_eq!(count(&db, "local_audit_event"), audits_before + 2);
    assert_eq!(actual_entries(&f), entries_before);
    let exact = context(&db);
    let started_hash = ObjectHash::try_from(
        db.query_row("SELECT event_hash FROM destruction_job_event", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
    )
    .unwrap();
    let original = exact_failure_event(&f, &exact, 1, started_hash);
    drop(runtime);
    let mut reopened = f.runtime();
    let replay = reopened.mark_incomplete_progress(id, job).unwrap();
    assert_eq!(replay.state.code(), 4);
    assert!(replay.preflight_hash == failed.preflight_hash);
    assert_eq!(context(&db), exact);
    assert_eq!(
        exact_failure_event(&f, &context(&db), 1, started_hash),
        original
    );
    assert_eq!(count(&db, "destruction_import_batch"), 1);
    assert_eq!(count(&db, "local_audit_event"), audits_before + 2);
    assert_eq!(actual_entries(&f), entries_before);
    // The exact historical failure survives later genuine local removal and
    // certified synthetic Reader confirmation, but cannot be reissued today.
    reopened
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let reader = completion::fixture_reader_claim(&f, &db);
    let confirmed = reopened.import_signed_progress(id, job, &[reader]).unwrap();
    assert_eq!(confirmed.state.code(), 4);
    assert!(confirmed.replicas.iter().all(|replica| matches!(
        replica.result,
        ea_destruction::EvidenceReplicaStatus::Successful(_)
    )));
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        reopened.mark_incomplete_progress(id, job)
    });
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        reopened.complete_verified_progress(id, job, NativeDestructionDelivery::NoRegisteredServer)
    });
    assert_eq!(reopened.status(id).unwrap().state.code(), 4);
}

#[test]
fn native_failure_refuses_requested_wrong_job_and_running_backup_but_records_overdue() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let id = requested.destruction_id;
    let job = requested.preflight_hash.unwrap();
    let db = completion::writer_database(&f);
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_incomplete_progress(id, job)
    });
    runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-SECURITY-CONFLICT", || {
        runtime.mark_incomplete_progress(id, ObjectHash::try_from(&[0xef; 32][..]).unwrap())
    });
    let original = import::changed_objects(
        &f,
        &db,
        |claim| {
            claim.backup_expiry_at = Some(UnixMillis::new(claim.executed_at.get() + 300_000));
        },
        |_| {},
    );
    let pending = import::with_reader_pending_original(&f, original);
    assert_eq!(
        runtime
            .import_signed_progress(id, job, &pending)
            .unwrap()
            .state
            .code(),
        2
    );
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_incomplete_progress(id, job)
    });

    // Separate original operation: a valid historical state2 while its signed
    // +1ms bound ran; today's actual freshly selected time is already later.
    let expired = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = expired.runtime();
    let requested = runtime.prepare(&expired.authorization).unwrap();
    let (id, job) = (requested.destruction_id, requested.preflight_hash.unwrap());
    runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = completion::writer_database(&expired);
    let original = import::changed_objects(
        &expired,
        &db,
        |claim| {
            claim.backup_expiry_at = Some(UnixMillis::new(claim.executed_at.get() + 1));
        },
        |_| {},
    );
    let objects = import::with_reader_pending_original(&expired, original);
    assert_eq!(
        runtime
            .import_signed_progress(id, job, &objects)
            .unwrap()
            .state
            .code(),
        2
    );
    let failed = runtime.mark_incomplete_progress(id, job).unwrap();
    assert_eq!(failed.state.code(), 4);
    assert!(
        failed
            .replicas
            .iter()
            .all(|replica| replica.result == ea_destruction::EvidenceReplicaStatus::PendingBackup)
    );
    assert_eq!(count(&db, "destruction_import_batch"), 2);
    let exact = context(&db);
    let previous = ea_crypto::object_hash(&objects[0]);
    let event = exact_failure_event(&expired, &exact, 2, previous);
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&event).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DestructionTransition(failure) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&objects[1]).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(claim) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert!(
        failure.executed_at >= claim.backup_expiry_at.unwrap(),
        "the signed event itself is after the historical maximum"
    );
    let audits = count(&db, "local_audit_event");
    drop(runtime);
    let mut reopened = expired.runtime();
    assert_eq!(
        reopened
            .mark_incomplete_progress(id, job)
            .unwrap()
            .state
            .code(),
        4
    );
    assert_eq!(context(&db), exact);
    assert_eq!(
        exact_failure_event(&expired, &context(&db), 2, previous),
        event
    );
    assert_eq!(count(&db, "local_audit_event"), audits);
    assert_eq!(count(&db, "destruction_import_batch"), 2);
}

fn refuses_without_append(
    db: &EncryptedDatabase,
    expected: &str,
    operation: impl FnOnce() -> Result<
        ea_admin::destruction_runtime::NativeDestructionStatus,
        ea_admin::destruction_runtime::NativeDestructionError,
    >,
) {
    let audits = count(db, "local_audit_event");
    let imports = count(db, "destruction_import_batch");
    assert_eq!(
        operation()
            .err()
            .expect("specific conservative Failure refusal")
            .code(),
        expected
    );
    assert_eq!(count(db, "local_audit_event"), audits);
    assert_eq!(count(db, "destruction_import_batch"), imports);
}

fn actual_entries(f: &NativeDestructionFixture) -> Vec<Vec<u8>> {
    // FsArchiveSource owns a frozen blob vector: reopen for EVERY observation.
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    ea_archive::ArchiveInventory::build(&source)
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.exact_bytes().as_bytes().to_vec())
        .collect()
}

fn count(db: &EncryptedDatabase, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}
fn context(db: &EncryptedDatabase) -> Vec<u8> {
    db.query_row("SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1", &[])
        .unwrap().unwrap().blob(0).unwrap().to_vec()
}
fn exact_failure_event(
    f: &NativeDestructionFixture,
    context: &[u8],
    from: u8,
    previous: ObjectHash,
) -> Vec<u8> {
    let mut decoder = minicbor::Decoder::new(context);
    assert_eq!(decoder.array().unwrap(), Some(8));
    decoder.str().unwrap();
    assert_eq!(decoder.u8().unwrap(), 1);
    let mut set = minicbor::Decoder::new(decoder.bytes().unwrap());
    assert_eq!(set.array().unwrap(), Some(8));
    for _ in 0..7 {
        set.skip().unwrap();
    }
    assert_eq!(set.array().unwrap(), Some(1));
    assert_eq!(set.array().unwrap(), Some(2));
    let hash = set.bytes().unwrap();
    let exact = set.bytes().unwrap().to_vec();
    assert_eq!(ea_crypto::object_hash(&exact).as_bytes(), hash);
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&exact).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DestructionTransition(fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert_eq!(fields.from_state, Some(from));
    assert_eq!(fields.to_state, 4);
    assert_eq!(fields.trigger_code, 4);
    assert!(
        fields.destruction_authorization_object_hash == ea_crypto::object_hash(&f.authorization)
    );
    let operator = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.admin_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        NativeOperatorProvider::open_test_fixture(
            f.admin_directory.join("ea-native-operator"),
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let ea_format::ParsedArchiveObject::Trust(auth) =
        ea_format::decode_exact_object(&f.authorization).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DestructionAuthorization(route) =
        auth.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let historical = ea_trust::verify_historical_registry_authority(
        operator.trust(),
        route.registry_version,
        ObjectHash::try_from(route.registry_head_hash.as_bytes().as_slice()).unwrap(),
        ea_types::ChainSequence::new(route.authorization_sequence),
    )
    .unwrap();
    let auth =
        ea_destruction::verify_authorization_historical(&f.authorization, &historical).unwrap();
    let verified =
        ea_destruction::verify_event_historical(&exact, &auth, &historical, support::live_clock())
            .unwrap();
    assert!(verified.fields().previous_event_object_hash == Some(previous));
    let stored = fs::read(
        f.archive
            .join(ea_archive::DESTRUCTIONS_DIR_V1)
            .join(format!("{}.etb", hex::encode(hash))),
    )
    .unwrap();
    assert_eq!(stored, exact);
    exact
}

fn clean(
    f: &NativeDestructionFixture,
    mut runtime: DestructionRuntime,
) -> (
    DestructionRuntime,
    DestructionId,
    ObjectHash,
    EncryptedDatabase,
) {
    let requested = runtime.prepare(&f.authorization).unwrap();
    let (id, hash) = (requested.destruction_id, requested.preflight_hash.unwrap());
    runtime
        .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    runtime
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    (runtime, id, hash, completion::writer_database(f))
}
fn expired_reader(f: &NativeDestructionFixture, db: &EncryptedDatabase) -> Vec<u8> {
    pending::changed_reader_claim(f, db, |claim| {
        claim.result = 1;
        claim.backup_expiry_at = Some(UnixMillis::new(claim.executed_at.get() + 1));
    })
}
#[test]
fn native_failure_pre_sign_snapshot_refuses_real_competing_original_import() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (mut runtime, id, hash, db) = clean(&f, f.runtime());
    let mut other = f.runtime();
    let claim = expired_reader(&f, &db);
    let audits = count(&db, "local_audit_event");
    let result = runtime.mark_incomplete_progress_with_test_before_sign(id, hash, || {
        other.import_signed_progress(id, hash, &[claim]).unwrap();
        assert_eq!(count(&db, "destruction_import_batch"), 1);
    });
    assert_eq!(
        result.err().unwrap().code(),
        "EA-DESTRUCTION-SECURITY-CONFLICT"
    );
    assert_eq!(count(&db, "destruction_import_batch"), 1);
    assert_eq!(count(&db, "local_audit_event"), audits + 2);
    assert_eq!(other.status(id).unwrap().state.code(), 1);
}
#[test]
fn native_failure_known_event_in_larger_batch_replays_without_audit_growth() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (mut runtime, id, hash, db) = clean(&f, f.runtime());
    let event = import::changed_objects(
        &f,
        &db,
        |_| {},
        |event| {
            event.to_state = 4;
            event.trigger_code = 4;
            event.executed_at = support::live_clock();
        },
    )
    .remove(0);
    let batch = vec![expired_reader(&f, &db), event.clone()];
    runtime.import_signed_progress(id, hash, &batch).unwrap();
    let audits = count(&db, "local_audit_event");
    let original_context = context(&db);
    runtime.import_signed_progress(id, hash, &batch).unwrap();
    let replay = runtime.mark_incomplete_progress(id, hash).unwrap();
    assert_eq!(replay.state.code(), 4);
    assert_eq!(count(&db, "destruction_import_batch"), 1);
    assert_eq!(count(&db, "local_audit_event"), audits);
    assert_eq!(context(&db), original_context);
    assert_eq!(
        fs::read(
            f.archive
                .join(ea_archive::DESTRUCTIONS_DIR_V1)
                .join(format!(
                    "{}.etb",
                    hex::encode(ea_crypto::object_hash(&event).as_bytes())
                ))
        )
        .unwrap(),
        event
    );
}
fn wait_marker(path: &Path) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(25);
    while !path.try_exists().unwrap() {
        assert!(
            std::time::Instant::now() < until,
            "actual native audit marker was not reached"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
#[test]
fn native_failure_held_audit_refuses_changed_history_holder_stub_watch_and_storage() {
    for fault in [
        "history",
        "holdings",
        "secondary",
        "stub",
        "watch",
        "storage",
    ] {
        let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
        let original = actual_entries(&f).remove(0);
        let secondary = f.archive.parent().unwrap().join("failure-secondary-holder");
        let runtime = if fault == "secondary" {
            pending::with_secondary_holder(&f, &secondary)
        } else {
            f.runtime()
        };
        let (mut runtime, id, hash, db) = clean(&f, runtime);
        let mut other = (fault == "history").then(|| f.runtime());
        let claim = expired_reader(&f, &db);
        let barrier = f.admin_directory.join("hold-completion-audit");
        fs::write(&barrier, b"").unwrap();
        let result = std::thread::scope(|scope| {
            let task = scope.spawn(|| runtime.mark_incomplete_progress(id, hash));
            wait_marker(&f.admin_directory.join("completion-audit-paused"));
            let audits = count(&db, "local_audit_event");
            match fault {
                "history" => {
                    other
                        .as_mut()
                        .unwrap()
                        .import_signed_progress(id, hash, &[claim])
                        .unwrap();
                }
                "holdings" => fs::write(
                    f.archive.join("entries/failure-reintroduced.eip.staging"),
                    original,
                )
                .unwrap(),
                "secondary" => fs::write(
                    secondary.join("entries/failure-reintroduced.eip.staging"),
                    original,
                )
                .unwrap(),
                "stub" => {
                    let stub = fs::read_dir(f.archive.join(ea_archive::DESTROYED_ENTRIES_DIR_V1))
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .find(|path| path.extension().is_some_and(|extension| extension == "eds"))
                        .unwrap();
                    fs::remove_file(stub).unwrap();
                }
                "watch" => {
                    fs::write(f.writer_directory.join("watch-action"), b"watch-event").unwrap();
                    wait_marker(&f.writer_directory.join("watch-delivered"));
                }
                "storage" => {
                    db.execute("CREATE TRIGGER failure_fixture_refusal BEFORE INSERT ON destruction_import_batch BEGIN SELECT RAISE(ABORT,'fixture refusal'); END", &[]).unwrap();
                }
                _ => unreachable!(),
            }
            fs::remove_file(&barrier).unwrap();
            let result = task.join().unwrap();
            if fault != "watch" {
                assert!(
                    f.admin_directory
                        .join("completion-audit-returned")
                        .try_exists()
                        .unwrap(),
                    "actual held helper returned; timeout is not an accepted refusal"
                );
            }
            assert_eq!(
                count(&db, "local_audit_event"),
                audits + if fault == "history" { 2 } else { 0 }
            );
            result
        });
        let error = result.err().expect("late Failure commit must be refused");
        let expected = match fault {
            "history" => "EA-DESTRUCTION-SECURITY-CONFLICT",
            "holdings" | "secondary" => "EA-DESTRUCTION-TARGET",
            // Missing primary stub is observed already by native archive admission;
            // only the secondary staged bytes are a final all-holder witness.
            "stub" | "watch" => "EA-DESTRUCTION-NATIVE-SESSION",
            "storage" => "EA-DESTRUCTION-STORAGE",
            _ => unreachable!(),
        };
        assert_eq!(
            error.code(),
            expected,
            "actual Failure audit barrier: {fault}"
        );
        assert_eq!(
            count(&db, "destruction_import_batch"),
            if fault == "history" { 1 } else { 0 }
        );
        eprintln!("native failure held audit: {fault} {}", error.code());
    }
}
#[test]
fn native_failure_refuses_all_successful_complete_and_missing_native_presence() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (mut runtime, id, hash, db) = clean(&f, f.runtime());
    runtime
        .import_signed_progress(id, hash, &[completion::fixture_reader_claim(&f, &db)])
        .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_incomplete_progress(id, hash)
    });
    assert_eq!(
        runtime
            .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
            .unwrap()
            .state
            .code(),
        3
    );
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_incomplete_progress(id, hash)
    });
    let missing = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = missing.runtime();
    let requested = runtime.prepare(&missing.authorization).unwrap();
    let (id, hash) = (requested.destruction_id, requested.preflight_hash.unwrap());
    runtime
        .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = completion::writer_database(&missing);
    fs::rename(
        missing.admin_directory.join("ea-native-operator"),
        missing.admin_directory.join("withheld-native-helper"),
    )
    .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-NATIVE-SESSION", || {
        runtime.mark_incomplete_progress(id, hash)
    });
}

#[test]
fn native_failure_early_success_and_second_later_deadline_do_not_hide_expired_duty() {
    let f = NativeDestructionFixture::with_optional_readers(false, 0, true, true);
    let (mut runtime, id, hash, db) = clean(&f, f.runtime());
    let pending = pending::changed_reader_claim(&f, &db, |claim| {
        claim.result = 1;
        claim.backup_expiry_at = Some(UnixMillis::new(claim.executed_at.get() + 2));
    });
    let early = pending::changed_reader_claim(&f, &db, |claim| {
        claim.executed_at = UnixMillis::new(claim.executed_at.get() + 1);
        claim.backup_expiry_at = None;
    });
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&pending).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(mut fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    fields.replica_id = [0xe2; 16];
    fields.backup_expiry_at = Some(UnixMillis::new(support::live_clock().get() + 300_000));
    let payload = ea_format::TrustPayloadV1::deletion_attestation(fields).unwrap();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        pending::SECOND_READER_COMPONENT_SECRET,
    ));
    let signature = signer
        .sign_deletion_attestation_digest(
            f.second_reader_component.unwrap(),
            payload.exact_digest_input(),
            &f.authorization,
        )
        .unwrap();
    let second =
        ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
    // Real original verification, including reverse input ordering and history
    // max: the early success cannot become a successful removal projection.
    runtime
        .import_signed_progress(id, hash, &[second, early, pending])
        .unwrap();
    let failed = runtime.mark_incomplete_progress(id, hash).unwrap();
    assert_eq!(failed.state.code(), 4);
    assert_eq!(failed.replicas.len(), 3);
    assert_eq!(failed.replicas.iter().filter(|replica| replica.result == ea_destruction::EvidenceReplicaStatus::PendingBackup).count(), 2);
    let removed_after_expiry = pending::changed_reader_claim(&f, &db, |claim| {
        claim.executed_at = UnixMillis::new(claim.executed_at.get() + 2);
        claim.backup_expiry_at = None;
    });
    runtime
        .import_signed_progress(id, hash, &[removed_after_expiry])
        .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_incomplete_progress(id, hash)
    });
    assert_eq!(
        runtime.status(id).unwrap().state.code(),
        4,
        "old failure remains readable, running second backup alone does not reissue it"
    );
}
