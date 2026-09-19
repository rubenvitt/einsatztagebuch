//! Native 4→1 retry for server-bound obligations only (DRK-319 S1).
//!
//! The reservation port here is a local stub returning a self-built exact
//! status frame; it stands for the per-call authenticated GET at the crate
//! boundary. The actual TLS/Postgres/S3 witness is a separate slice (S2).
//! Server and Reader claims are signed synthetic originals of their existing
//! fixture certificates; nothing here claims an actual remote removal.
use super::*;
use ea_admin::destruction_runtime::{
    NativeDestructionDelivery, NativeDestructionError, NativeDestructionStatus,
};
use ea_format::{DeletionAttestationFieldsV1, DestructionTransitionFieldsV1, TrustPayloadV1};

struct StubReservation {
    authorization: ObjectHash,
    calls: usize,
    /// Refuse every read while set; shareable to flip it mid-action.
    refuse: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Refuse from this 1-based call number on (e.g. only the second read).
    refuse_from: Option<usize>,
}
impl StubReservation {
    fn new(f: &NativeDestructionFixture) -> Self {
        Self {
            authorization: ea_crypto::object_hash(&f.authorization),
            calls: 0,
            refuse: Default::default(),
            refuse_from: None,
        }
    }
    fn refusing(f: &NativeDestructionFixture) -> Self {
        let port = Self::new(f);
        port.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
        port
    }
}
impl ea_destruction::ServerReservationPort for StubReservation {
    fn read_current_status(
        &mut self,
        _: ea_types::OrganizationId,
        id: DestructionId,
    ) -> Result<Vec<u8>, ea_destruction::DestructionError> {
        self.calls += 1;
        if self.refuse.load(std::sync::atomic::Ordering::SeqCst)
            || self.refuse_from.is_some_and(|from| self.calls >= from)
        {
            return Err(ea_destruction::DestructionError::Storage);
        }
        Ok(ea_sync_protocol::DestructionStatusResponseV1::new(
            id,
            1,
            self.authorization,
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
        .exact_bytes()
        .to_vec())
    }
}

/// The certified DeletionAttest component of the fixture's registered Server.
fn server_component(f: &NativeDestructionFixture) -> (CertificateHash, DeviceId) {
    use ea_trust::TrustObjectSource as _;
    let source = f.line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .unwrap();
    let thumbprint = public(transport::SERVER_DELETION_SECRET).thumbprint();
    let found = hashes
        .into_iter()
        .filter_map(|hash| {
            let exact = source.read_exact_trust_object(hash).unwrap().unwrap();
            let ea_format::ParsedArchiveObject::Trust(parsed) =
                ea_format::decode_exact_object(&exact).unwrap()
            else {
                return None;
            };
            match parsed.value().decoded_payload().unwrap() {
                ea_format::DecodedTrustPayloadV1::AuthorizedDevice(cert)
                    if cert.fields().certificate_kind == CertificateKindV1::DeletionAttest
                        && cert.fields().signing_key_thumbprint == Some(thumbprint) =>
                {
                    Some((
                        CertificateHash::try_from(hash.as_bytes().as_slice()).unwrap(),
                        cert.fields().device_id,
                    ))
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1, "exactly one certified Server component");
    found[0]
}

/// A Server original built from the own Writer's measured local claim: same
/// removed objects and execution time (i.e. dated before any later state4).
fn server_claim(
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
    let (certificate, device) = server_component(f);
    let mut fields = DeletionAttestationFieldsV1 {
        replica_id: *device.as_bytes(),
        replica_kind: ea_destruction::ManagedReplicaKind::SyncServer.code(),
        ..writer
    };
    change(&mut fields);
    let payload = TrustPayloadV1::deletion_attestation(fields).unwrap();
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(
        transport::SERVER_DELETION_SECRET,
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

fn claim_time(exact: &[u8]) -> UnixMillis {
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(exact).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    fields.executed_at
}

/// The single signed transition of the latest local import batch.
fn latest_batch_event(db: &EncryptedDatabase) -> (ObjectHash, DestructionTransitionFieldsV1) {
    let context = failure::context(db);
    let mut decoder = minicbor::Decoder::new(&context);
    assert_eq!(decoder.array().unwrap(), Some(8));
    decoder.str().unwrap();
    assert_eq!(decoder.u8().unwrap(), 1);
    let mut set = minicbor::Decoder::new(decoder.bytes().unwrap());
    assert_eq!(set.array().unwrap(), Some(8));
    for _ in 0..7 {
        set.skip().unwrap();
    }
    assert_eq!(set.array().unwrap(), Some(1), "one exact event per batch");
    assert_eq!(set.array().unwrap(), Some(2));
    let hash = ObjectHash::try_from(set.bytes().unwrap()).unwrap();
    let exact = set.bytes().unwrap().to_vec();
    assert!(ea_crypto::object_hash(&exact) == hash);
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
    (hash, fields)
}

fn refuses_without_append(
    db: &EncryptedDatabase,
    expected: &str,
    operation: impl FnOnce() -> Result<NativeDestructionStatus, NativeDestructionError>,
) {
    let audits = failure::count(db, "local_audit_event");
    let imports = failure::count(db, "destruction_import_batch");
    assert_eq!(
        operation()
            .err()
            .expect("specific native retry refusal")
            .code(),
        expected
    );
    assert_eq!(failure::count(db, "local_audit_event"), audits);
    assert_eq!(failure::count(db, "destruction_import_batch"), imports);
}

struct Incomplete {
    runtime: DestructionRuntime,
    id: DestructionId,
    job: ObjectHash,
    db: EncryptedDatabase,
    retained: ObjectHash,
    t4: UnixMillis,
}
/// Actual native start and local removal with the stub reservation, then an
/// actual conservative state4 while at least one original duty is missing.
fn incomplete(
    f: &NativeDestructionFixture,
    port: &mut StubReservation,
    before_failure: impl FnOnce(&mut DestructionRuntime, DestructionId, ObjectHash, &EncryptedDatabase),
) -> Incomplete {
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let (id, job) = (requested.destruction_id, requested.preflight_hash.unwrap());
    runtime
        .start(id, job, NativeDestructionDelivery::AuthenticatedServer(port))
        .unwrap();
    runtime
        .resume_local(id, NativeDestructionDelivery::AuthenticatedServer(port))
        .unwrap();
    let db = completion::writer_database(f);
    before_failure(&mut runtime, id, job, &db);
    let failed = runtime.mark_incomplete_progress(id, job).unwrap();
    assert_eq!(failed.state.code(), 4);
    assert!(failed.replicas.iter().any(|replica| {
        replica.kind == ea_destruction::ManagedReplicaKind::SyncServer
    }));
    let (retained, fields) = latest_batch_event(&db);
    assert_eq!((fields.to_state, fields.trigger_code), (4, 4));
    Incomplete {
        runtime,
        id,
        job,
        db,
        retained,
        t4: fields.executed_at,
    }
}

#[test]
fn native_retry_resumes_a_server_bound_incomplete_once_every_duty_is_confirmed() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(true, 3, true);
    let mut port = StubReservation::new(&f);
    // The Reader confirmation is durably imported BEFORE state4; only the
    // Server duty is missing when the conservative state4 is recorded.
    let Incomplete {
        mut runtime,
        id,
        job,
        db,
        retained,
        t4,
    } = incomplete(&f, &mut port, |runtime, id, job, db| {
        let reader = completion::fixture_reader_claim(&f, db);
        runtime.import_signed_progress(id, job, &[reader]).unwrap();
    });
    let failed = runtime.status(id).unwrap();
    assert!(failed.replicas.iter().any(|replica| {
        replica.kind == ea_destruction::ManagedReplicaKind::SyncServer
            && replica.result == ea_destruction::EvidenceReplicaStatus::Unreachable
    }));
    // A late Server original, imported after state4 and dated BEFORE t4.
    let server = server_claim(&f, &db, |_| {});
    let server_time = claim_time(&server);
    assert!(server_time <= t4, "the late original predates the retained state4");
    let confirmed = runtime.import_signed_progress(id, job, &[server]).unwrap();
    assert_eq!(confirmed.state.code(), 4, "an import alone never leaves state4");
    assert!(confirmed.replicas.iter().all(|replica| matches!(
        replica.result,
        ea_destruction::EvidenceReplicaStatus::Successful(_)
    )));
    let audits = failure::count(&db, "local_audit_event");
    let batches = failure::count(&db, "destruction_import_batch");
    let calls = port.calls;
    let resumed = runtime
        .resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
        .unwrap();
    assert_eq!(resumed.state.code(), 1);
    assert!(resumed.preflight_hash == Some(job));
    assert!(
        port.calls >= calls + 2,
        "one actual reservation read before signing and one after blocking work"
    );
    assert_eq!(failure::count(&db, "destruction_import_batch"), batches + 1);
    assert_eq!(failure::count(&db, "local_audit_event"), audits + 2);
    // The retained state4 is bound, never re-signed; the new event carries
    // its own actual effective time, not t4 and not the late claim's time.
    let (retry, fields) = latest_batch_event(&db);
    assert_eq!(fields.from_state, Some(4));
    assert_eq!(fields.to_state, 1);
    assert_eq!(fields.trigger_code, 5);
    assert!(fields.previous_event_object_hash == Some(retained));
    assert!(fields.executed_at >= t4);
    assert!(fields.executed_at >= server_time);
    let exact_context = failure::context(&db);
    // Exact replay after a real reopen: no new event, batch or audit.
    drop(runtime);
    let mut reopened = f.runtime();
    let replay = reopened
        .resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
        .unwrap();
    assert_eq!(replay.state.code(), 1);
    assert_eq!(failure::context(&db), exact_context);
    assert!(latest_batch_event(&db).0 == retry);
    assert_eq!(failure::count(&db, "destruction_import_batch"), batches + 1);
    assert_eq!(failure::count(&db, "local_audit_event"), audits + 2);
    // The retained state4 is consumed once: any other predecessor conflicts.
    let started = ObjectHash::try_from(
        db.query_row("SELECT event_hash FROM destruction_job_event", &[])
            .unwrap()
            .unwrap()
            .blob(0)
            .unwrap(),
    )
    .unwrap();
    refuses_without_append(&db, "EA-DESTRUCTION-SECURITY-CONFLICT", || {
        reopened.resume_incomplete_progress(
            id,
            job,
            started,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    // Nothing is missing any more: no new conservative state4 today.
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        reopened.mark_incomplete_progress(id, job)
    });
    // Unchanged existing follow-up producer: 1→3 with its own reservation.
    let complete = reopened
        .complete_verified_progress(
            id,
            job,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
        .unwrap();
    assert_eq!(complete.state.code(), 3);
    // After 3 the retained state4 can no longer be consumed.
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        reopened.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
}

#[test]
fn native_retry_refuses_an_open_server_duty_missing_server_and_failed_reservation() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(true, 3, true);
    let mut port = StubReservation::new(&f);
    let Incomplete {
        mut runtime,
        id,
        job,
        db,
        retained,
        ..
    } = incomplete(&f, &mut port, |runtime, id, job, db| {
        let reader = completion::fixture_reader_claim(&f, db);
        runtime.import_signed_progress(id, job, &[reader]).unwrap();
    });
    // G4: the Server duty is still unconfirmed now; no 4→1→4 loop. Own code
    // so the host can explain "not yet" instead of a generic event refusal.
    let calls = port.calls;
    refuses_without_append(&db, "EA-DESTRUCTION-RETRY-DUTY-OPEN", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    assert!(port.calls > calls, "the actual reservation was read first");
    // Not a Reader case: the local pre-decision grants nothing and refuses nothing.
    let audits = failure::count(&db, "local_audit_event");
    assert!(runtime.refuse_reader_retry_locally(id, job, retained).is_ok());
    assert_eq!(failure::count(&db, "local_audit_event"), audits);
    // Import the missing Server original; the refusals below are not about it.
    let server = server_claim(&f, &db, |_| {});
    runtime.import_signed_progress(id, job, &[server]).unwrap();
    // No local absence proof may stand in for the per-call reservation.
    refuses_without_append(&db, "EA-DESTRUCTION-RETRY-NO-SERVER-DUTY", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::NoRegisteredServer,
        )
    });
    let mut refused = StubReservation::refusing(&f);
    refuses_without_append(&db, "EA-DESTRUCTION-STORAGE", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut refused),
        )
    });
    assert!(refused.calls > 0, "the actual reservation read failed");
    refuses_without_append(&db, "EA-DESTRUCTION-SECURITY-CONFLICT", || {
        runtime.resume_incomplete_progress(
            id,
            ObjectHash::try_from(&[0xef; 32][..]).unwrap(),
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    refuses_without_append(&db, "EA-DESTRUCTION-SECURITY-CONFLICT", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            ObjectHash::try_from(&[0xee; 32][..]).unwrap(),
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    assert_eq!(runtime.status(id).unwrap().state.code(), 4);
    // E.2: withheld native Admin presence refuses before anything is signed.
    fs::rename(
        f.admin_directory.join("ea-native-operator"),
        f.admin_directory.join("withheld-native-helper"),
    )
    .unwrap();
    let calls = port.calls;
    refuses_without_append(&db, "EA-DESTRUCTION-NATIVE-SESSION", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    assert_eq!(port.calls, calls, "no reservation read without presence");
}

#[test]
fn native_retry_refuses_when_the_open_duty_was_a_reader() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(true, 3, true);
    let mut port = StubReservation::new(&f);
    // The Server confirmed BEFORE state4; the Reader is the missing duty.
    let Incomplete {
        mut runtime,
        id,
        job,
        db,
        retained,
        ..
    } = incomplete(&f, &mut port, |runtime, id, job, db| {
        let server = server_claim(&f, db, |_| {});
        runtime.import_signed_progress(id, job, &[server]).unwrap();
    });
    let open = runtime.status(id).unwrap();
    assert!(open.replicas.iter().any(|replica| {
        replica.kind == ea_destruction::ManagedReplicaKind::Reader
            && replica.result == ea_destruction::EvidenceReplicaStatus::Unreachable
    }));
    // G2: with the server down, the permanent Reader explanation still wins
    // over a transport refusal, because it is decided before any read.
    let mut down = StubReservation::refusing(&f);
    refuses_without_append(&db, "EA-DESTRUCTION-RETRY-READER-DUTY", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut down),
        )
    });
    assert_eq!(down.calls, 0, "refused locally before any server read");
    // The same local pre-decision alone, for a host that re-contacts servers first.
    refuses_without_append(&db, "EA-DESTRUCTION-RETRY-READER-DUTY", || {
        runtime
            .refuse_reader_retry_locally(id, job, retained)
            .map(|()| runtime.status(id).unwrap())
    });
    refuses_without_append(&db, "EA-DESTRUCTION-RETRY-READER-DUTY", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    // G1/G4: a Reader original imported only after t4 does not count as
    // confirmed, even though every duty now looks Successful.
    let reader = completion::fixture_reader_claim(&f, &db);
    let late = runtime.import_signed_progress(id, job, &[reader]).unwrap();
    assert!(late.replicas.iter().all(|replica| matches!(
        replica.result,
        ea_destruction::EvidenceReplicaStatus::Successful(_)
    )));
    let mut down = StubReservation::refusing(&f);
    refuses_without_append(&db, "EA-DESTRUCTION-RETRY-READER-DUTY", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut down),
        )
    });
    assert_eq!(down.calls, 0, "late Reader original: still refused locally");
    refuses_without_append(&db, "EA-DESTRUCTION-RETRY-READER-DUTY", || {
        runtime
            .refuse_reader_retry_locally(id, job, retained)
            .map(|()| runtime.status(id).unwrap())
    });
    refuses_without_append(&db, "EA-DESTRUCTION-RETRY-READER-DUTY", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    assert_eq!(runtime.status(id).unwrap().state.code(), 4);
}

#[test]
fn native_retry_refuses_a_job_without_any_server_duty() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let (id, job) = (requested.destruction_id, requested.preflight_hash.unwrap());
    runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = completion::writer_database(&f);
    assert_eq!(
        runtime.mark_incomplete_progress(id, job).unwrap().state.code(),
        4
    );
    let (retained, _) = latest_batch_event(&db);
    runtime
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    for delivery in [false, true] {
        let mut port = StubReservation::new(&f);
        refuses_without_append(&db, "EA-DESTRUCTION-RETRY-NO-SERVER-DUTY", || {
            runtime.resume_incomplete_progress(
                id,
                job,
                retained,
                if delivery {
                    NativeDestructionDelivery::AuthenticatedServer(&mut port)
                } else {
                    NativeDestructionDelivery::NoRegisteredServer
                },
            )
        });
        assert_eq!(port.calls, 0, "refused locally before any network read");
    }
}

#[test]
fn native_retry_pre_sign_snapshot_refuses_a_real_competing_import() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(true, 3, true);
    let mut port = StubReservation::new(&f);
    let Incomplete {
        mut runtime,
        id,
        job,
        db,
        retained,
        ..
    } = incomplete(&f, &mut port, |runtime, id, job, db| {
        let reader = completion::fixture_reader_claim(&f, db);
        runtime.import_signed_progress(id, job, &[reader]).unwrap();
    });
    let server = server_claim(&f, &db, |_| {});
    runtime.import_signed_progress(id, job, &[server]).unwrap();
    let mut other = f.runtime();
    let competing = server_claim(&f, &db, |fields| {
        fields.executed_at = UnixMillis::new(fields.executed_at.get() + 1);
    });
    let audits = failure::count(&db, "local_audit_event");
    let batches = failure::count(&db, "destruction_import_batch");
    let result = runtime.resume_incomplete_progress_with_test_before_sign(
        id,
        job,
        retained,
        NativeDestructionDelivery::AuthenticatedServer(&mut port),
        || {
            other.import_signed_progress(id, job, &[competing]).unwrap();
        },
    );
    assert_eq!(
        result.err().unwrap().code(),
        "EA-DESTRUCTION-SECURITY-CONFLICT"
    );
    assert_eq!(failure::count(&db, "destruction_import_batch"), batches + 1);
    assert_eq!(failure::count(&db, "local_audit_event"), audits + 2);
    assert_eq!(other.status(id).unwrap().state.code(), 4);
}

fn destruction_files(f: &NativeDestructionFixture) -> usize {
    fs::read_dir(f.archive.join(ea_archive::DESTRUCTIONS_DIR_V1))
        .map(|dir| dir.count())
        .unwrap_or(0)
}
/// Server-bound state4 with every duty confirmed: ready for 4→1.
fn ready(f: &NativeDestructionFixture, port: &mut StubReservation) -> Incomplete {
    let ready = incomplete(f, port, |runtime, id, job, db| {
        let reader = completion::fixture_reader_claim(f, db);
        runtime.import_signed_progress(id, job, &[reader]).unwrap();
    });
    let server = server_claim(f, &ready.db, |_| {});
    let mut runtime = ready.runtime;
    runtime
        .import_signed_progress(ready.id, ready.job, &[server])
        .unwrap();
    Incomplete { runtime, ..ready }
}

#[test]
fn native_retry_refuses_a_failing_second_reservation_read_without_commit() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(true, 3, true);
    let mut port = StubReservation::new(&f);
    let Incomplete {
        mut runtime,
        id,
        job,
        db,
        retained,
        ..
    } = ready(&f, &mut port);
    // The first read (admission) succeeds, the second (after all blocking
    // signing work) fails: nothing is committed, published or replayed.
    port.refuse_from = Some(port.calls + 2);
    let files = destruction_files(&f);
    refuses_without_append(&db, "EA-DESTRUCTION-STORAGE", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    assert_eq!(Some(port.calls), port.refuse_from, "exactly two actual reads");
    assert_eq!(destruction_files(&f), files, "the signed 4→1 was never published");
    assert_eq!(runtime.status(id).unwrap().state.code(), 4);
    // A later healthy attempt signs and commits exactly one new 4→1.
    port.refuse_from = None;
    let resumed = runtime
        .resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
        .unwrap();
    assert_eq!(resumed.state.code(), 1);
    assert_eq!(destruction_files(&f), files + 1);
    let (_, fields) = latest_batch_event(&db);
    assert_eq!((fields.from_state, fields.to_state), (Some(4), 1));
    assert!(fields.previous_event_object_hash == Some(retained));
}

/// E.5: faults while the actual native Destruction audit signature is held.
/// The server fault proves the second read follows the blocking audit work.
#[test]
fn native_retry_held_audit_refuses_changed_history_holder_storage_and_server() {
    for fault in ["history", "holdings", "storage", "server"] {
        let f = NativeDestructionFixture::with_optional_reader_opfs(true, 3, true);
        let mut port = StubReservation::new(&f);
        // The actual original target entry, read before its local removal.
        let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
        let original = ea_archive::ArchiveInventory::build(&source).unwrap().entries()[0]
            .exact_bytes()
            .as_bytes()
            .to_vec();
        let Incomplete {
            mut runtime,
            id,
            job,
            db,
            retained,
            ..
        } = ready(&f, &mut port);
        let mut other = (fault == "history").then(|| f.runtime());
        let competing = server_claim(&f, &db, |fields| {
            fields.executed_at = UnixMillis::new(fields.executed_at.get() + 1);
        });
        let refuse = port.refuse.clone();
        let batches = failure::count(&db, "destruction_import_batch");
        let files = destruction_files(&f);
        let barrier = f.admin_directory.join("hold-completion-audit");
        fs::write(&barrier, b"").unwrap();
        let result = std::thread::scope(|scope| {
            let task = scope.spawn(|| {
                runtime.resume_incomplete_progress(
                    id,
                    job,
                    retained,
                    NativeDestructionDelivery::AuthenticatedServer(&mut port),
                )
            });
            wait_marker(&f.admin_directory.join("completion-audit-paused"));
            let audits = failure::count(&db, "local_audit_event");
            match fault {
                "history" => {
                    other
                        .as_mut()
                        .unwrap()
                        .import_signed_progress(id, job, &[competing])
                        .unwrap();
                }
                "holdings" => fs::write(
                    f.archive.join("entries/retry-reintroduced.eip.staging"),
                    &original,
                )
                .unwrap(),
                "storage" => {
                    db.execute("CREATE TRIGGER retry_fixture_refusal BEFORE INSERT ON destruction_import_batch BEGIN SELECT RAISE(ABORT,'fixture refusal'); END", &[]).unwrap();
                }
                "server" => refuse.store(true, std::sync::atomic::Ordering::SeqCst),
                _ => unreachable!(),
            }
            fs::remove_file(&barrier).unwrap();
            let result = task.join().unwrap();
            assert!(
                f.admin_directory
                    .join("completion-audit-returned")
                    .try_exists()
                    .unwrap(),
                "actual held helper returned; timeout is not an accepted refusal"
            );
            assert_eq!(
                failure::count(&db, "local_audit_event"),
                audits + if fault == "history" { 2 } else { 0 },
                "both retry audits roll back together: {fault}"
            );
            result
        });
        let error = result.err().expect("late retry commit must be refused");
        eprintln!("native retry held audit: {fault} {}", error.code());
        let expected = match fault {
            "history" => "EA-DESTRUCTION-SECURITY-CONFLICT",
            "holdings" => "EA-DESTRUCTION-TARGET",
            "storage" | "server" => "EA-DESTRUCTION-STORAGE",
            _ => unreachable!(),
        };
        assert_eq!(error.code(), expected, "actual retry audit barrier: {fault}");
        assert_eq!(
            failure::count(&db, "destruction_import_batch"),
            batches + if fault == "history" { 1 } else { 0 }
        );
        if fault != "history" {
            assert_eq!(destruction_files(&f), files, "nothing published: {fault}");
        }
        // Reintroduced bytes make even the status read refuse (Target); the
        // unchanged batch count above already shows that state4 remains.
        if fault != "holdings" {
            assert_eq!(runtime.status(id).unwrap().state.code(), 4);
        }
    }
}
fn wait_marker(path: &Path) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !path.try_exists().unwrap() {
        assert!(
            std::time::Instant::now() < until,
            "actual native audit marker was not reached"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// The shared test CA as exact PEM text, without loading the server test
/// harness a second time (it is already a module of `transport::server`).
/// Nothing listens at the witness address, so no handshake ever uses it.
#[cfg(feature = "desktop-fixture")]
fn test_ca_pem() -> &'static str {
    const SOURCE: &str = include_str!("../../../server/tests/common/mod.rs");
    const END: &str = "-----END CERTIFICATE-----";
    let start = SOURCE.find("-----BEGIN CERTIFICATE-----").unwrap();
    let end = start + SOURCE[start..].find(END).unwrap() + END.len();
    &SOURCE[start..end]
}

/// DRK-319 S3 (Review M1): the desktop host transport refuses a Reader case
/// with its permanent explanation BEFORE any network access. With the only
/// registered server unreachable, Resume in state4 answers RETRY-READER-DUTY,
/// not a transport code, and appends nothing.
#[cfg(feature = "desktop-fixture")]
#[test]
fn desktop_resume_refuses_a_reader_case_before_the_unreachable_server() {
    use ea_desktop::runtime::destruction_transport::{
        NativeDestructionServerConfig, NativeDestructionServerTransport,
        NativeDestructionTransportError,
    };
    let f = NativeDestructionFixture::with_optional_reader_opfs(true, 3, true);
    let mut port = StubReservation::new(&f);
    let Incomplete {
        mut runtime, id, db, ..
    } = incomplete(&f, &mut port, |runtime, id, job, db| {
        let server = server_claim(&f, db, |_| {});
        runtime.import_signed_progress(id, job, &[server]).unwrap();
    });
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let inventory = ea_archive::ArchiveInventory::build(&source).unwrap();
    let (certificate, device) = inventory
        .trust()
        .iter()
        .find_map(|p| {
            let ea_format::DecodedTrustPayloadV1::AuthorizedDevice(c) =
                p.value().decoded_payload().ok()?
            else {
                return None;
            };
            (c.fields().signing_key_thumbprint
                == Some(public(transport::SERVER_TRANSPORT_SECRET).thumbprint()))
            .then_some((
                ea_types::CertificateHash::try_from(p.object_hash().as_bytes().as_slice())
                    .unwrap(),
                c.fields().device_id,
            ))
        })
        .unwrap();
    // A port that was bound once and is closed again: nothing listens there.
    let address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let ca_file = f._directory.path().join("unreachable-ca.pem");
    fs::write(&ca_file, test_ca_pem()).unwrap();
    let mut transport = NativeDestructionServerTransport::open(
        vec![NativeDestructionServerConfig {
            device_id: device,
            address,
            server_name: "localhost".into(),
            authority: format!("localhost:{}", address.port()),
            ca_file,
            server_certificate: certificate,
        }],
        &f.key_source,
    )
    .unwrap();
    let audits = failure::count(&db, "local_audit_event");
    let imports = failure::count(&db, "destruction_import_batch");
    let result = transport.resume(&mut runtime, id);
    assert!(
        matches!(
            result,
            Err(NativeDestructionTransportError::Native(
                NativeDestructionError::RetryReaderDuty
            ))
        ),
        "Reader case must be explained before the network: {:?}",
        result.err().map(|error| error.code())
    );
    assert_eq!(failure::count(&db, "local_audit_event"), audits);
    assert_eq!(failure::count(&db, "destruction_import_batch"), imports);
    assert_eq!(runtime.status(id).unwrap().state.code(), 4);
}
