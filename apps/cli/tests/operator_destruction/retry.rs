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
    refuse: bool,
}
impl StubReservation {
    fn new(f: &NativeDestructionFixture) -> Self {
        Self {
            authorization: ea_crypto::object_hash(&f.authorization),
            calls: 0,
            refuse: false,
        }
    }
}
impl ea_destruction::ServerReservationPort for StubReservation {
    fn read_current_status(
        &mut self,
        _: ea_types::OrganizationId,
        id: DestructionId,
    ) -> Result<Vec<u8>, ea_destruction::DestructionError> {
        self.calls += 1;
        if self.refuse {
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
    // G4: the Server duty is still unconfirmed now; no 4→1→4 loop.
    let calls = port.calls;
    refuses_without_append(&db, "EA-DESTRUCTION-EVENT", || {
        runtime.resume_incomplete_progress(
            id,
            job,
            retained,
            NativeDestructionDelivery::AuthenticatedServer(&mut port),
        )
    });
    assert!(port.calls > calls, "the actual reservation was read first");
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
    let mut refused = StubReservation {
        refuse: true,
        ..StubReservation::new(&f)
    };
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
