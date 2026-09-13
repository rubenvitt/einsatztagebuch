//! Native Pending producer. Remote backup claims are signed synthetic fixture
//! inputs; these tests do not claim actual WORM or remote backup destruction.
use super::*;
use ea_admin::destruction_runtime::NativeDestructionDelivery;
pub(super) const SECOND_READER_COMPONENT_SECRET: [u8; 32] = [0xe2; 32];

pub(super) fn changed_reader_claim(
    f: &NativeDestructionFixture,
    db: &EncryptedDatabase,
    change: impl FnOnce(&mut ea_format::DeletionAttestationFieldsV1),
) -> Vec<u8> {
    let exact = completion::fixture_reader_claim(f, db);
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&exact).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(mut fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    change(&mut fields);
    let payload = ea_format::TrustPayloadV1::deletion_attestation(fields).unwrap();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        READER_OPFS_COMPONENT_SECRET,
    ));
    let signature = signer
        .sign_deletion_attestation_digest(
            f.reader_opfs_component.unwrap(),
            payload.exact_digest_input(),
            &f.authorization,
        )
        .unwrap();
    ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, vec![signature]).unwrap())
        .unwrap()
        .as_bytes()
        .to_vec()
}
fn count(db: &EncryptedDatabase, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}
#[test]
fn native_pending_persists_certified_original_and_replays_after_real_reopen() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let id = requested.destruction_id;
    let hash = requested.preflight_hash.unwrap();
    runtime
        .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let cleaned = runtime
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = completion::writer_database(&f);
    let pending = changed_reader_claim(&f, &db, |fields| {
        fields.result = 1;
        fields.backup_expiry_at = Some(UnixMillis::new(support::live_clock().get() + 300_000));
    });
    runtime
        .import_signed_progress(id, hash, &[pending])
        .unwrap();
    let before_audits = count(&db, "local_audit_event");
    let result = runtime
        .mark_pending_backup_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert_eq!(result.state.code(), 2);
    assert_eq!(result.replicas.len(), cleaned.replicas.len());
    assert!(
        result
            .replicas
            .iter()
            .any(|r| r.result == ea_destruction::EvidenceReplicaStatus::PendingBackup)
    );
    assert_eq!(count(&db, "destruction_import_batch"), 2);
    assert_eq!(count(&db, "local_audit_event"), before_audits + 2);
    let exact = db.query_row("SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1", &[]).unwrap().unwrap().blob(0).unwrap().to_vec();
    verify_certified_pending(&f, &db, &exact);
    drop(runtime);
    let mut reopened = f.runtime();
    let replay = reopened
        .mark_pending_backup_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert_eq!(replay.state.code(), 2);
    assert_eq!(count(&db, "destruction_import_batch"), 2);
    assert_eq!(count(&db, "local_audit_event"), before_audits + 2);
    assert_eq!(db.query_row("SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1", &[]).unwrap().unwrap().blob(0).unwrap(), exact);
}

fn clean(
    f: &NativeDestructionFixture,
) -> (
    DestructionRuntime,
    DestructionId,
    ObjectHash,
    EncryptedDatabase,
) {
    clean_with_runtime(f, f.runtime())
}
fn clean_with_runtime(
    f: &NativeDestructionFixture,
    mut runtime: DestructionRuntime,
) -> (
    DestructionRuntime,
    DestructionId,
    ObjectHash,
    EncryptedDatabase,
) {
    let requested = runtime.prepare(&f.authorization).unwrap();
    let id = requested.destruction_id;
    let hash = requested.preflight_hash.unwrap();
    runtime
        .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    runtime
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = completion::writer_database(f);
    (runtime, id, hash, db)
}
fn future_claim(f: &NativeDestructionFixture, db: &EncryptedDatabase) -> Vec<u8> {
    changed_reader_claim(f, db, |a| {
        a.result = 1;
        a.backup_expiry_at = Some(UnixMillis::new(support::live_clock().get() + 300_000));
    })
}
fn event_from_start(f: &NativeDestructionFixture, db: &EncryptedDatabase, to: u8) -> Vec<u8> {
    import::changed_objects(
        f,
        db,
        |_| {},
        |event| {
            event.to_state = to;
            event.trigger_code = u64::from(to);
            event.executed_at = support::live_clock();
        },
    )
    .remove(0)
}
fn refuses_without_append(
    db: &EncryptedDatabase,
    expected: &str,
    action: impl FnOnce() -> Result<
        ea_admin::destruction_runtime::NativeDestructionStatus,
        ea_admin::destruction_runtime::NativeDestructionError,
    >,
) {
    let audits = count(db, "local_audit_event");
    let imports = count(db, "destruction_import_batch");
    assert_eq!(
        action()
            .err()
            .expect("specific Pending admission refusal")
            .code(),
        expected
    );
    assert_eq!(count(db, "local_audit_event"), audits);
    assert_eq!(count(db, "destruction_import_batch"), imports);
}
#[test]
fn native_pending_refuses_missing_local_remote_expired_wrong_job_and_failure_state() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let (id, hash) = (requested.destruction_id, requested.preflight_hash.unwrap());
    let db = completion::writer_database(&f);
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    runtime
        .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-TARGET", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    runtime
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    // Missing expiry is rejected by the unchanged original-claim verifier,
    // before such a Pending claim can even reach the producer's Saved state.
    let missing = changed_reader_claim(&f, &db, |a| {
        a.result = 1;
        a.backup_expiry_at = None;
    });
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.import_signed_progress(id, hash, &[missing])
    });
    let expired = changed_reader_claim(&f, &db, |a| {
        a.result = 1;
        a.backup_expiry_at = Some(UnixMillis::new(a.executed_at.get() + 1));
    });
    runtime
        .import_signed_progress(id, hash, &[expired])
        .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    let future = changed_reader_claim(&f, &db, |a| {
        a.executed_at = UnixMillis::new(a.executed_at.get() + 1);
        a.result = 1;
        a.backup_expiry_at = Some(UnixMillis::new(support::live_clock().get() + 300_000));
    });
    runtime.import_signed_progress(id, hash, &[future]).unwrap();
    let wrong = ObjectHash::try_from(&[0xee; 32][..]).unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-SECURITY-CONFLICT", || {
        runtime.mark_pending_backup_progress(
            id,
            wrong,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    // An actually called refusal port cannot be replaced by NoRegisteredServer.
    struct RefusingReservation(bool);
    impl ea_destruction::ServerReservationPort for RefusingReservation {
        fn read_current_status(
            &mut self,
            _: ea_types::OrganizationId,
            _: DestructionId,
        ) -> Result<Vec<u8>, ea_destruction::DestructionError> {
            self.0 = true;
            Err(ea_destruction::DestructionError::Storage)
        }
    }
    let mut refused = RefusingReservation(false);
    refuses_without_append(&db, "EA-DESTRUCTION-STORAGE", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::AuthenticatedServer(&mut refused),
        )
    });
    assert!(
        refused.0,
        "actual requested reservation read failed; no success was simulated"
    );
    let failed = event_from_start(&f, &db, 4);
    runtime.import_signed_progress(id, hash, &[failed]).unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
}
#[test]
fn native_pending_known_event_in_larger_batch_replays_without_audit_growth() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (mut runtime, id, hash, db) = clean(&f);
    let reader = future_claim(&f, &db);
    let event = event_from_start(&f, &db, 2);
    let original = event.clone();
    let batch = vec![reader, event];
    runtime.import_signed_progress(id, hash, &batch).unwrap();
    let audits = count(&db, "local_audit_event");
    // The ordinary duplicate-batch branch also keeps its original semantics.
    runtime.import_signed_progress(id, hash, &batch).unwrap();
    let result = runtime
        .mark_pending_backup_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert_eq!(result.state.code(), 2);
    assert_eq!(count(&db, "destruction_import_batch"), 1);
    assert_eq!(count(&db, "local_audit_event"), audits);
    assert_eq!(
        fs::read(
            f.archive
                .join(ea_archive::DESTRUCTIONS_DIR_V1)
                .join(format!(
                    "{}.etb",
                    hex::encode(ea_crypto::object_hash(&original).as_bytes())
                ))
        )
        .unwrap(),
        original
    );
}
#[test]
fn native_pending_pre_sign_snapshot_is_bound_before_real_competing_import() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (mut runtime, id, hash, db) = clean(&f);
    runtime
        .import_signed_progress(id, hash, &[future_claim(&f, &db)])
        .unwrap();
    let mut other = f.runtime();
    let changed = changed_reader_claim(&f, &db, |a| {
        a.executed_at = UnixMillis::new(a.executed_at.get() + 1);
        a.result = 1;
        a.backup_expiry_at = Some(UnixMillis::new(support::live_clock().get() + 400_000));
    });
    let result = runtime.mark_pending_backup_progress_with_test_before_sign(
        id,
        hash,
        NativeDestructionDelivery::NoRegisteredServer,
        || {
            other.import_signed_progress(id, hash, &[changed]).unwrap();
            assert_eq!(count(&db, "destruction_import_batch"), 2);
        },
    );
    assert_eq!(
        result.err().unwrap().code(),
        "EA-DESTRUCTION-SECURITY-CONFLICT"
    );
    assert_eq!(count(&db, "destruction_import_batch"), 2);
    assert_eq!(other.status(id).unwrap().state.code(), 1);
}
#[test]
fn native_pending_one_expired_of_two_remote_duties_is_not_hidden_by_later_deadline() {
    let f = NativeDestructionFixture::with_optional_readers(false, 0, true, true);
    let (mut runtime, id, hash, db) = clean(&f);
    let expired = changed_reader_claim(&f, &db, |a| {
        a.result = 1;
        a.backup_expiry_at = Some(UnixMillis::new(a.executed_at.get() + 1));
    });
    let second = future_claim(&f, &db);
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&second).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(mut fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    fields.replica_id = [0xe2; 16];
    let payload = ea_format::TrustPayloadV1::deletion_attestation(fields).unwrap();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        SECOND_READER_COMPONENT_SECRET,
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
    let before = runtime
        .import_signed_progress(id, hash, &[expired, second])
        .unwrap();
    assert_eq!(before.replicas.len(), 3);
    assert_eq!(
        before
            .replicas
            .iter()
            .filter(|r| r.result == ea_destruction::EvidenceReplicaStatus::PendingBackup)
            .count(),
        2
    );
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    assert_eq!(count(&db, "destruction_import_batch"), 1);
}

fn verify_certified_pending(
    f: &NativeDestructionFixture,
    db: &EncryptedDatabase,
    context: &[u8],
) -> ObjectHash {
    let from = 1;
    let mut c = minicbor::Decoder::new(context);
    assert_eq!(c.array().unwrap(), Some(8));
    c.skip().unwrap();
    c.skip().unwrap();
    let mut set = minicbor::Decoder::new(c.bytes().unwrap());
    assert_eq!(set.array().unwrap(), Some(8));
    for _ in 0..7 {
        set.skip().unwrap();
    }
    assert_eq!(set.array().unwrap(), Some(1));
    assert_eq!(set.array().unwrap(), Some(2));
    let hash = set.bytes().unwrap();
    let exact = set.bytes().unwrap();
    assert_eq!(ea_crypto::object_hash(exact).as_bytes(), hash);
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
    let ea_format::DecodedTrustPayloadV1::DestructionAuthorization(fields) =
        auth.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let historical = ea_trust::verify_historical_registry_authority(
        operator.trust(),
        fields.registry_version,
        ObjectHash::try_from(fields.registry_head_hash.as_bytes().as_slice()).unwrap(),
        ea_types::ChainSequence::new(fields.authorization_sequence),
    )
    .unwrap();
    let auth =
        ea_destruction::verify_authorization_historical(&f.authorization, &historical).unwrap();
    let verified =
        ea_destruction::verify_event_historical(exact, &auth, &historical, support::live_clock())
            .unwrap();
    assert_eq!(
        (verified.fields().from_state, verified.fields().to_state),
        (Some(from), 2)
    );
    if from == 1 {
        let start = db
            .query_row("SELECT event_hash FROM destruction_job_event", &[])
            .unwrap()
            .unwrap();
        assert_eq!(
            verified
                .fields()
                .previous_event_object_hash
                .unwrap()
                .as_bytes(),
            start.blob(0).unwrap()
        );
    }
    let path = f
        .archive
        .join(ea_archive::DESTRUCTIONS_DIR_V1)
        .join(format!("{}.etb", hex::encode(hash)));
    assert_eq!(
        fs::read(path).unwrap(),
        exact,
        "same certified original is durably published"
    );
    verified.fields().previous_event_object_hash.unwrap()
}

fn wait_marker(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    while !path.try_exists().unwrap() {
        assert!(
            std::time::Instant::now() < deadline,
            "actual native audit checkpoint"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
#[test]
fn native_pending_rechecks_snapshot_holdings_watch_and_atomic_audits_after_real_signing() {
    for fault in [
        "history",
        "holdings",
        "secondary",
        "stub",
        "watch",
        "storage",
    ] {
        let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
        let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
        let inventory = ea_archive::ArchiveInventory::build(&source).unwrap();
        let original = inventory.entries()[0].exact_bytes().as_bytes().to_vec();
        drop(inventory);
        drop(source);
        let secondary = f.archive.parent().unwrap().join("secondary-holder");
        let (mut runtime, id, hash, db) = if fault == "secondary" {
            let runtime = with_secondary_holder(&f, &secondary);
            clean_with_runtime(&f, runtime)
        } else {
            clean(&f)
        };
        runtime
            .import_signed_progress(id, hash, &[future_claim(&f, &db)])
            .unwrap();
        let mut other = (fault == "history").then(|| f.runtime());
        let changed = changed_reader_claim(&f, &db, |a| {
            a.executed_at = UnixMillis::new(a.executed_at.get() + 1);
            a.result = 1;
            a.backup_expiry_at = Some(UnixMillis::new(support::live_clock().get() + 400_000));
        });
        let barrier = f.admin_directory.join("hold-completion-audit");
        fs::write(&barrier, b"").unwrap();
        let result = std::thread::scope(|scope| {
            let task = scope.spawn(|| {
                runtime.mark_pending_backup_progress(
                    id,
                    hash,
                    NativeDestructionDelivery::NoRegisteredServer,
                )
            });
            wait_marker(&f.admin_directory.join("completion-audit-paused"));
            let audits = count(&db, "local_audit_event");
            match fault {
                "history" => {
                    other
                        .as_mut()
                        .unwrap()
                        .import_signed_progress(id, hash, &[changed])
                        .unwrap();
                }
                "holdings" => fs::write(
                    f.archive.join("entries/pending-reintroduced.eip.staging"),
                    original,
                )
                .unwrap(),
                "secondary" => fs::write(
                    secondary.join("entries/pending-reintroduced.eip.staging"),
                    original,
                )
                .unwrap(),
                "stub" => {
                    let stub = fs::read_dir(f.archive.join(ea_archive::DESTROYED_ENTRIES_DIR_V1))
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .find(|path| path.extension().is_some_and(|extension| extension == "eds"))
                        .unwrap();
                    fs::remove_file(stub).unwrap();
                }
                "watch" => {
                    fs::write(f.writer_directory.join("watch-action"), b"watch-event").unwrap();
                    wait_marker(&f.writer_directory.join("watch-delivered"));
                }
                "storage" => {
                    db.execute("CREATE TRIGGER pending_fixture_refusal BEFORE INSERT ON destruction_import_batch BEGIN SELECT RAISE(ABORT,'fixture refusal'); END", &[]).unwrap();
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
                    "real held helper returned, not its timeout"
                );
            }
            assert_eq!(
                count(&db, "local_audit_event"),
                audits + if fault == "history" { 2 } else { 0 },
                "only the intentional competing import may append audits"
            );
            result
        });
        let error = result.err().expect("late native Pending refusal");
        let expected = match fault {
            "history" => "EA-DESTRUCTION-SECURITY-CONFLICT",
            "holdings" | "secondary" => "EA-DESTRUCTION-TARGET",
            // Removing the primary stub fails the earlier native archive
            // identity check; this is not a final all-holder guard witness.
            "stub" | "watch" => "EA-DESTRUCTION-NATIVE-SESSION",
            "storage" => "EA-DESTRUCTION-STORAGE",
            _ => unreachable!(),
        };
        assert_eq!(error.code(), expected, "actual barrier refusal {fault}");
        assert_eq!(
            count(&db, "destruction_import_batch"),
            if fault == "history" { 2 } else { 1 }
        );
        eprintln!(
            "native pending: actual held audit refusal {fault} {}",
            error.code()
        );
    }
}
#[test]
fn native_pending_real_deadline_crossing_at_held_audit_and_current_replay_are_refused() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (mut runtime, id, hash, db) = clean(&f);
    // A real future deadline, never a caller time injected into production.
    // The helper barrier below remains held until the actual clock reaches it.
    let cutoff = UnixMillis::new(support::live_clock().get() + 60_000);
    let pending = changed_reader_claim(&f, &db, |a| {
        a.result = 1;
        a.backup_expiry_at = Some(cutoff);
    });
    runtime
        .import_signed_progress(id, hash, &[pending])
        .unwrap();
    let retained = event_from_start(&f, &db, 2);
    fs::write(f.admin_directory.join("pending-cutoff-watchdog"), b"").unwrap();
    let barrier = f.admin_directory.join("hold-completion-audit");
    fs::write(&barrier, b"").unwrap();
    let result = std::thread::scope(|scope| {
        let task = scope.spawn(|| {
            runtime.mark_pending_backup_progress(
                id,
                hash,
                NativeDestructionDelivery::NoRegisteredServer,
            )
        });
        wait_marker(&f.admin_directory.join("completion-audit-paused"));
        assert!(
            support::live_clock() < cutoff,
            "actual audit reached before the signed deadline"
        );
        let audits = count(&db, "local_audit_event");
        let bounded = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while support::live_clock() < cutoff {
            assert!(
                std::time::Instant::now() < bounded,
                "bounded real clock observation"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        fs::remove_file(&barrier).unwrap();
        let result = task.join().unwrap();
        assert!(
            f.admin_directory
                .join("completion-audit-returned")
                .try_exists()
                .unwrap()
        );
        assert_eq!(count(&db, "local_audit_event"), audits);
        result
    });
    let error = result
        .err()
        .expect("cutoff crossed during actual native audit signature");
    assert_eq!(error.code(), "EA-DESTRUCTION-OPERATOR");
    eprintln!(
        "native pending: actual elapsed cutoff refusal {}",
        error.code()
    );
    assert_eq!(count(&db, "destruction_import_batch"), 1);
    // Historical admission uses the retained original time; a current Pending
    // replay must nevertheless refuse after its backup expiry.
    let historical = runtime
        .import_signed_progress(id, hash, &[retained])
        .unwrap();
    assert_eq!(historical.state.code(), 2);
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    assert_eq!(count(&db, "destruction_import_batch"), 2);
}
#[test]
fn native_pending_does_not_reclassify_all_successful_or_complete() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let (mut runtime, id, hash, db) = clean(&f);
    runtime
        .import_signed_progress(id, hash, &[completion::fixture_reader_claim(&f, &db)])
        .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    let complete = runtime
        .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert_eq!(complete.state.code(), 3);
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.mark_pending_backup_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
}

pub(super) fn with_secondary_holder(
    f: &NativeDestructionFixture,
    secondary: &Path,
) -> DestructionRuntime {
    use ea_archive::ArchiveSource;
    fs::create_dir(secondary).unwrap();
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    source
        .visit_blobs(&mut |blob| {
            let path = secondary.join(blob.path_hint());
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, blob.bytes()).unwrap();
            Ok(())
        })
        .unwrap();
    let open = |directory: &Path, config: &Path| {
        OperatorRuntime::open_with_test_native(
            OperatorRuntimeConfig::load(config).unwrap(),
            &f.anchor,
            support::live_clock(),
            false,
            NativeOperatorProvider::open_test_fixture(directory.join("ea-native-operator"), false)
                .unwrap(),
        )
        .unwrap()
    };
    let controller = open(&f.admin_directory, &f.admin_config);
    let custodian = open(&f.writer_directory, &f.writer_config);
    let primary = NativeLocalHolder::open(
        &custodian,
        f.archive.clone(),
        f.profile.clone(),
        f.writer_certificate,
    )
    .unwrap();
    let extra = NativeLocalHolder::open(
        &custodian,
        secondary.to_path_buf(),
        f.profile.clone(),
        f.writer_certificate,
    )
    .unwrap();
    // Reverse input order deliberately: production must use canonical lock order.
    DestructionRuntime::new(
        controller,
        custodian,
        vec![extra, primary],
        f.component,
        f.key_source.clone(),
    )
    .unwrap()
}
