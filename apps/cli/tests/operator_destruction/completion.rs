//! Native completion-service admission/persistence fixture. Reader claims here
//! are explicitly synthetic historical inputs; actual OPFS lives in reader_opfs.
use super::*;
use ea_admin::destruction_runtime::NativeDestructionDelivery;
use ea_format::{DeletionAttestationFieldsV1, TrustPayloadV1};

pub(super) fn writer_database(f: &NativeDestructionFixture) -> EncryptedDatabase {
    let (provider, key) = database_provider_for(false);
    EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
        .unwrap()
}
pub(super) fn fixture_reader_claim(
    f: &NativeDestructionFixture,
    db: &EncryptedDatabase,
) -> Vec<u8> {
    changed_reader_claim(f, db, |_| {})
}
fn changed_reader_claim(
    f: &NativeDestructionFixture,
    db: &EncryptedDatabase,
    change: impl FnOnce(&mut DeletionAttestationFieldsV1),
) -> Vec<u8> {
    let exact = db
        .query_row(
            "SELECT exact_attestation FROM destruction_local_attestation",
            &[],
        )
        .unwrap()
        .unwrap();
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact.blob(0).unwrap()).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(writer) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let certificate = f.reader_opfs_component.unwrap();
    let ea_format::ParsedArchiveObject::Trust(parsed) = ea_format::decode_exact_object(
        f.line
            .exact_object_bytes(ObjectHash::try_from(certificate.as_bytes().as_slice()).unwrap()),
    )
    .unwrap() else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::AuthorizedDevice(reader) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let mut fields = DeletionAttestationFieldsV1 {
        replica_id: *reader.fields().device_id.as_bytes(),
        replica_kind: 1,
        ..writer
    };
    change(&mut fields);
    let payload = TrustPayloadV1::deletion_attestation(fields).unwrap();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        READER_OPFS_COMPONENT_SECRET,
    ));
    let signature = signer
        .sign_deletion_attestation_digest(
            certificate,
            payload.exact_digest_input(),
            &f.authorization,
        )
        .unwrap();
    ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, vec![signature]).unwrap())
        .unwrap()
        .as_bytes()
        .to_vec()
}
fn imports(db: &EncryptedDatabase) -> i64 {
    db.query_row("SELECT count(*) FROM destruction_import_batch", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}
#[test]
fn native_completion_requires_every_duty_then_persists_exact_signed_transition_and_replays() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let prepared = runtime.prepare(&f.authorization).unwrap();
    let id = prepared.destruction_id;
    let hash = prepared.preflight_hash.unwrap();
    runtime
        .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let pending = runtime
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = writer_database(&f);
    assert!(
        runtime
            .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
            .is_err(),
        "missing Reader is still required"
    );
    assert_eq!(imports(&db), 0);
    let wrong_hash = ObjectHash::try_from([0xee; 32].as_slice()).unwrap();
    assert!(
        runtime
            .complete_verified_progress(
                id,
                wrong_hash,
                NativeDestructionDelivery::NoRegisteredServer
            )
            .is_err()
    );
    assert_eq!(imports(&db), 0);
    let reader = fixture_reader_claim(&f, &db);
    runtime.import_signed_progress(id, hash, &[reader]).unwrap();
    let completed = runtime
        .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert_eq!(completed.state.code(), 3);
    assert_eq!(completed.replicas.len(), pending.replicas.len());
    assert!(completed.replicas.iter().all(|r| matches!(
        r.result,
        ea_destruction::EvidenceReplicaStatus::Successful(_)
    )));
    assert_eq!(imports(&db), 2);
    let exact = db.query_row("SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1", &[]).unwrap().unwrap().blob(0).unwrap().to_vec();
    verify_exact_complete(&f, &db, &exact, 1);
    let replay = runtime
        .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert_eq!(replay.state.code(), 3);
    assert_eq!(imports(&db), 2);
    drop(runtime);
    let mut reopened = f.runtime();
    let result = reopened
        .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert_eq!(result.state.code(), 3);
    assert_eq!(imports(&db), 2);
    assert_eq!(db.query_row("SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1", &[]).unwrap().unwrap().blob(0).unwrap(), exact);
}

#[test]
fn native_completion_respects_pending_backup_and_requires_valid_predecessor() {
    for predecessor in [2, 4] {
        let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
        let mut runtime = f.runtime();
        let prepared = runtime.prepare(&f.authorization).unwrap();
        let id = prepared.destruction_id;
        let hash = prepared.preflight_hash.unwrap();
        runtime
            .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
            .unwrap();
        let db = writer_database(&f);
        let objects = import::changed_objects(
            &f,
            &db,
            |a| {
                if predecessor == 4 {
                    a.result = 2;
                    a.backup_expiry_at = None;
                }
            },
            |e| {
                e.to_state = predecessor;
                e.trigger_code = u64::from(predecessor);
            },
        );
        let objects = if predecessor == 2 {
            import::with_reader_pending_original(&f, objects)
        } else {
            objects
        };
        runtime.import_signed_progress(id, hash, &objects).unwrap();
        assert!(
            runtime
                .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
                .is_err()
        );
        assert_eq!(imports(&db), 1);
        runtime
            .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
            .unwrap();
        let pending = changed_reader_claim(&f, &db, |a| {
            a.result = 1;
            a.backup_expiry_at = Some(UnixMillis::new(a.executed_at.get() + 60_000));
        });
        runtime
            .import_signed_progress(id, hash, &[pending])
            .unwrap();
        assert!(
            runtime
                .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
                .is_err()
        );
        assert_eq!(imports(&db), 2);
        let success = changed_reader_claim(&f, &db, |a| {
            a.executed_at = UnixMillis::new(a.executed_at.get() + 1)
        });
        let early = runtime
            .import_signed_progress(id, hash, &[success])
            .unwrap();
        assert!(
            early.replicas.iter().any(|r| r.result
                == ea_destruction::EvidenceReplicaStatus::PendingBackup
                && r.backup_expiry_at.is_some()),
            "earlier deadline remains visible after premature success"
        );
        let result = runtime.complete_verified_progress(
            id,
            hash,
            NativeDestructionDelivery::NoRegisteredServer,
        );
        if predecessor == 2 {
            assert!(
                result.is_err(),
                "early success cannot erase unexpired known backup deadline"
            );
            assert_eq!(imports(&db), 3);
        } else {
            assert!(result.is_err(), "4→3 cannot bypass signed recovery to1");
            assert_eq!(imports(&db), 3);
        }
    }
}

// Exact existing LocalAudit Sig_structure only; a marker never intercepts a
// different signature family. The caller retains all native-provider checks.
pub(crate) fn pause_audit_signature(directory: &Path, data: &[u8]) {
    let barrier = directory.join("hold-completion-audit");
    if !barrier.exists() {
        return;
    }
    let mut d = minicbor::Decoder::new(data);
    if d.array().ok() != Some(Some(4)) || d.str().ok() != Some("Signature1") {
        return;
    }
    let Ok(protected) = d.bytes() else {
        return;
    };
    let mut p = minicbor::Decoder::new(protected);
    let Some(Some(count)) = p.map().ok() else {
        return;
    };
    let mut matches = false;
    for _ in 0..count {
        if p.datatype().ok() == Some(minicbor::data::Type::String) {
            if p.str().is_err() || p.skip().is_err() {
                return;
            }
            continue;
        }
        let Ok(label) = p.i64() else {
            return;
        };
        if label == 3 {
            matches = p.str().ok() == Some("application/vnd.einsatzarchiv.local-audit+cbor");
        } else if p.skip().is_err() {
            return;
        }
    }
    if !matches || p.position() != protected.len() || d.bytes().ok() != Some(&[][..]) {
        return;
    }
    let Ok(core) = d.bytes() else {
        return;
    };
    if d.position() != data.len()
        || ea_crypto::validate_unsigned_protocol_core(ea_crypto::ContentType::LocalAuditCbor, core)
            .is_err()
    {
        return;
    }
    let mut core = minicbor::Decoder::new(core);
    if core.array().ok() != Some(Some(12)) {
        return;
    }
    for _ in 0..6 {
        if core.skip().is_err() {
            return;
        }
    }
    if core.u64().ok() != Some(10) {
        return;
    } // existing Destruction audit
    // Optional deterministic selector: let the first N matching Destruction
    // audits pass (e.g. an earlier import batch within the same action).
    let skip = directory.join("hold-completion-audit-skip");
    if let Ok(text) = fs::read_to_string(&skip) {
        let left: u32 = text.trim().parse().unwrap();
        if left > 0 {
            fs::write(&skip, (left - 1).to_string()).unwrap();
            return;
        }
    }
    // One-shot barrier: a competing real native admission must not wait on the
    // first action's marker. No payload is written to the fixture filesystem.
    let marker = directory.join("completion-audit-paused");
    if fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(marker)
        .is_err()
    {
        return;
    }
    let seconds = if directory.join("pending-cutoff-watchdog").exists() {
        180
    } else {
        30
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while barrier.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "bounded completion audit fixture"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    fs::write(directory.join("completion-audit-returned"), b"").unwrap();
}

fn wait_marker(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "actual bounded fixture checkpoint"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
fn audit_count(db: &EncryptedDatabase) -> i64 {
    db.query_row("SELECT count(*) FROM local_audit_event", &[])
        .unwrap()
        .unwrap()
        .integer(0)
        .unwrap()
}
#[test]
fn native_completion_rechecks_history_holdings_watch_and_durability_after_actual_signing() {
    for fault in ["history", "holdings", "watch", "storage"] {
        let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
        let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
        let inventory = ea_archive::ArchiveInventory::build(&source).unwrap();
        let original = inventory.entries()[0].exact_bytes().as_bytes().to_vec();
        drop(inventory);
        drop(source);
        let mut runtime = f.runtime();
        let prepared = runtime.prepare(&f.authorization).unwrap();
        let id = prepared.destruction_id;
        let hash = prepared.preflight_hash.unwrap();
        runtime
            .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
            .unwrap();
        runtime
            .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
            .unwrap();
        let db = writer_database(&f);
        runtime
            .import_signed_progress(id, hash, &[fixture_reader_claim(&f, &db)])
            .unwrap();
        let mut other = (fault == "history").then(|| f.runtime());
        let pending = changed_reader_claim(&f, &db, |a| {
            a.executed_at = UnixMillis::new(a.executed_at.get() + 1);
            a.result = 1;
            a.backup_expiry_at = Some(UnixMillis::new(a.executed_at.get() + 60_000));
        });
        let ea_format::ParsedArchiveObject::Trust(parsed) =
            ea_format::decode_exact_object(&pending).unwrap()
        else {
            panic!()
        };
        let ea_format::DecodedTrustPayloadV1::DeletionAttestation(fields) =
            parsed.value().decoded_payload().unwrap()
        else {
            panic!()
        };
        let event =
            import::changed_objects(&f, &db, |_| {}, |e| e.executed_at = fields.executed_at)
                .remove(0);
        let barrier = f.admin_directory.join("hold-completion-audit");
        fs::write(&barrier, b"").unwrap();
        let result = std::thread::scope(|scope| {
            let task = scope.spawn(|| {
                runtime.complete_verified_progress(
                    id,
                    hash,
                    NativeDestructionDelivery::NoRegisteredServer,
                )
            });
            wait_marker(&f.admin_directory.join("completion-audit-paused"));
            let audits_before = audit_count(&db);
            match fault {
                "history" => {
                    let concurrent = other
                        .as_mut()
                        .unwrap()
                        .import_signed_progress(id, hash, &[pending, event])
                        .unwrap();
                    assert_eq!(
                        concurrent.state.code(),
                        2,
                        "real competing native predecessor committed while signing held"
                    );
                    assert_eq!(imports(&db), 2);
                }
                "holdings" => fs::write(
                    f.archive
                        .join("entries/completion-reintroduced.eip.staging"),
                    original,
                )
                .unwrap(),
                "watch" => {
                    fs::write(f.writer_directory.join("watch-action"), b"watch-event").unwrap();
                    wait_marker(&f.writer_directory.join("watch-delivered"));
                }
                "storage" => {
                    db.execute("CREATE TRIGGER completion_fixture_refusal BEFORE INSERT ON destruction_import_batch BEGIN SELECT RAISE(ABORT,'fixture refusal'); END", &[]).unwrap();
                }
                _ => unreachable!(),
            }
            fs::remove_file(&barrier).unwrap();
            let result = task.join().unwrap();
            if fault != "watch" {
                assert!(
                    f.admin_directory.join("completion-audit-returned").exists(),
                    "held audit returned after deliberate release, not fixture timeout"
                );
            }
            if fault == "storage" {
                assert_eq!(
                    audit_count(&db),
                    audits_before,
                    "failed import transaction rolls its audit appends back"
                );
            }
            result
        });
        let error = result
            .err()
            .expect("completion refuses after actual signing checkpoint");
        if fault == "history" {
            assert_eq!(error.code(), "EA-DESTRUCTION-SECURITY-CONFLICT");
        }
        eprintln!("native completion: stable refusal {fault} {}", error.code());
        assert_eq!(imports(&db), if fault == "history" { 2 } else { 1 });
        eprintln!("native completion: observed held audit and refused {fault}");
    }
}

fn verify_exact_complete(
    f: &NativeDestructionFixture,
    db: &EncryptedDatabase,
    context: &[u8],
    from: u8,
) -> ObjectHash {
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
        (Some(from), 3)
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

#[test]
fn native_completion_accepts_backup_only_after_expiry_and_attested_removal() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let prepared = runtime.prepare(&f.authorization).unwrap();
    let id = prepared.destruction_id;
    let hash = prepared.preflight_hash.unwrap();
    runtime
        .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = writer_database(&f);
    // Historical fixture claim only. The later real cleanup must actually be
    // after this bound; no clock override, expiry sleep or manufactured removal.
    let objects = import::changed_objects(
        &f,
        &db,
        |a| {
            a.backup_expiry_at = Some(UnixMillis::new(a.executed_at.get() + 1));
        },
        |_| {},
    );
    let objects = import::with_reader_pending_original(&f, objects);
    let previous = ea_crypto::object_hash(&objects[0]);
    let pending = runtime.import_signed_progress(id, hash, &objects).unwrap();
    let expiry = pending
        .replicas
        .iter()
        .filter_map(|r| r.backup_expiry_at)
        .max()
        .unwrap();
    assert_eq!(pending.state.code(), 2);
    runtime
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let reader = fixture_reader_claim(&f, &db);
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&reader).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert!(
        fields.executed_at >= expiry,
        "actual local measurement happened after expiry"
    );
    runtime.import_signed_progress(id, hash, &[reader]).unwrap();
    let complete = runtime
        .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert_eq!(complete.state.code(), 3);
    let context = db.query_row("SELECT exact_context FROM destruction_import_batch ORDER BY insertion_sequence DESC LIMIT 1", &[]).unwrap().unwrap().blob(0).unwrap().to_vec();
    assert!(verify_exact_complete(&f, &db, &context, 2) == previous);
    drop(runtime);
    let mut reopened = f.runtime();
    assert_eq!(
        reopened
            .complete_verified_progress(id, hash, NativeDestructionDelivery::NoRegisteredServer)
            .unwrap()
            .state
            .code(),
        3
    );
    assert_eq!(imports(&db), 3);
}
