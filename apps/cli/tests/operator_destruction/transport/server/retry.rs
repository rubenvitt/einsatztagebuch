//! Native 4→1 retry against the actual registered TLS server, PostgreSQL and
//! S3 (DRK-319 S2). The server duty is genuinely open at t4: the server holds
//! only its signed reservation (authenticated GETs, no job POST, so no server
//! execution) when its actual TLS listener stops. The same registered server
//! then restarts at the identical address with the same database and bucket.
//! The Reader confirmation is a certified synthetic original of the fixture's
//! Reader component (no actual OPFS here); it only makes the server the one
//! open duty at t4.
use super::*;
use ea_admin::destruction_runtime::{DestructionRuntime, NativeDestructionDelivery};
use ea_format::DestructionTransitionFieldsV1;

use super::super::super::{completion, failure as local};

const UNAVAILABLE: &str = "EA-DESTRUCTION-TRANSPORT-UNAVAILABLE";
const TLS: &str = "EA-DESTRUCTION-TRANSPORT-TLS";

impl ServerFixture {
    /// Stops exactly the registered TLS listener. PostgreSQL, S3, the
    /// disposable database and the bucket stay up and unchanged.
    pub(super) fn stop_listener(&mut self) {
        self.serving.abort();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            match std::net::TcpStream::connect_timeout(
                &self.config.address,
                std::time::Duration::from_secs(1),
            ) {
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => break,
                _ => {
                    assert!(
                        std::time::Instant::now() < until,
                        "the registered listener must actually stop"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }
    /// Restarts the same registered server identity (transport and deletion
    /// component keys) at the identical address, against the same database
    /// and bucket. The Desktop configuration is never substituted.
    pub(super) fn restart_listener(&mut self, services: &tokio::runtime::Runtime) {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let (server, serving) = loop {
            let spawned = services.block_on(common::spawn_server_with_object_store_at(
                &self.config.address.to_string(),
                self.database.pool().clone(),
                system_now(),
                trust_support::organization(),
                SERVER_TRANSPORT_SECRET,
                self.config.server_certificate,
                &self.bucket,
                common::TestExecutionPorts {
                    deletion: Some((SERVER_DELETION_SECRET, self.deletion_certificate)),
                    objects_override: None,
                    clock_override: Some(Arc::new(
                        einsatzarchiv_server::adapters::clock::SystemClock,
                    )),
                },
            ));
            match spawned {
                Ok(value) => break value,
                Err(error) => {
                    assert!(
                        std::time::Instant::now() < until,
                        "rebinding the identical registered address: {error}"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        };
        assert_eq!(server.address, self.config.address, "identical address");
        assert_eq!(
            server.authority, self.config.authority,
            "identical authority"
        );
        self.server = server;
        self.serving = serving;
    }
}

pub(super) fn server_count(
    services: &tokio::runtime::Runtime,
    server: &ServerFixture,
    table: &str,
) -> i64 {
    services
        .block_on(
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(server.database.pool()),
        )
        .unwrap()
}

/// Every stored server transition in its actual technical order.
pub(super) type ServerTransition = (Vec<u8>, Vec<u8>, i16);
pub(super) fn server_transitions(
    services: &tokio::runtime::Runtime,
    server: &ServerFixture,
) -> Vec<ServerTransition> {
    services
        .block_on(
            sqlx::query_as(
                "SELECT c.object_hash, c.exact_bytes, t.to_state_code \
                 FROM destruction_event_cores c JOIN destruction_transitions t USING(object_hash) \
                 ORDER BY t.technical_index",
            )
            .fetch_all(server.database.pool()),
        )
        .unwrap()
}

pub(super) fn transition(exact: &[u8]) -> DestructionTransitionFieldsV1 {
    let ParsedArchiveObject::Trust(parsed) = decode_exact_object(exact).unwrap() else {
        panic!("exact transition")
    };
    let DecodedTrustPayloadV1::DestructionTransition(fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!("exact transition")
    };
    fields
}

/// The server's exact 4→1 transitions (trigger 5); asserts there is at most one.
pub(super) fn server_retries(
    services: &tokio::runtime::Runtime,
    server: &ServerFixture,
) -> Vec<ServerTransition> {
    server_transitions(services, server)
        .into_iter()
        .filter(|row| transition(&row.1).from_state == Some(4))
        .collect()
}

pub(super) fn destruction_files(f: &NativeDestructionFixture) -> usize {
    fs::read_dir(f.archive.join(ea_archive::DESTRUCTIONS_DIR_V1))
        .map(|dir| dir.count())
        .unwrap_or(0)
}

/// Exact 4→1 originals in the local archive.
pub(super) fn local_retries(f: &NativeDestructionFixture) -> usize {
    fs::read_dir(f.archive.join(ea_archive::DESTRUCTIONS_DIR_V1))
        .unwrap()
        .filter_map(|entry| {
            let exact = fs::read(entry.unwrap().path()).unwrap();
            match decode_exact_object(&exact).ok()? {
                ParsedArchiveObject::Trust(parsed) => {
                    match parsed.value().decoded_payload().ok()? {
                        DecodedTrustPayloadV1::DestructionTransition(fields) => {
                            (fields.from_state == Some(4)).then_some(())
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        })
        .count()
}

/// Local append-only counters of the Custodian database.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct LocalCounts {
    batches: i64,
    audits: i64,
    files: usize,
}
pub(super) fn local_counts(f: &NativeDestructionFixture) -> LocalCounts {
    let db = completion::writer_database(f);
    LocalCounts {
        batches: local::count(&db, "destruction_import_batch"),
        audits: local::count(&db, "local_audit_event"),
        files: destruction_files(f),
    }
}

/// A refused action closes the native session; read the state explicitly.
pub(super) fn state_after_refusal(native: &mut DestructionRuntime, id: DestructionId) -> u8 {
    native.unlock().unwrap();
    native.status(id).unwrap().state.code()
}

/// The last event of the admitted local history.
pub(super) fn last_event(
    native: &mut DestructionRuntime,
    id: DestructionId,
    job: ObjectHash,
) -> (ObjectHash, Vec<u8>) {
    let context = native.prepare_server_exchange(id, job).unwrap();
    let events = context.events().unwrap();
    let last = events.last().unwrap();
    (last.0, last.2.to_vec())
}

pub(super) struct Incomplete {
    pub(super) services: tokio::runtime::Runtime,
    pub(super) server: ServerFixture,
    pub(super) id: DestructionId,
    pub(super) job: ObjectHash,
    /// The exact retained 1→4 original.
    pub(super) retained: ObjectHash,
    pub(super) t4: UnixMillis,
}

/// Actual native Start and local Writer cleanup while the registered server
/// holds only its signed reservation (GET-only port: no job POST, hence no
/// server execution), optionally the Reader confirmation in an earlier import
/// batch, then the actual listener loss and the explicit local state4 with the
/// Server duty genuinely unattested.
pub(super) fn incomplete_with_unexecuted_server(
    f: &NativeDestructionFixture,
    reader_before_state4: bool,
) -> Incomplete {
    // The fixture helper otherwise ends its Controller OS subscription after an
    // absolute 300 seconds; core inactivity stays unchanged.
    fs::write(f.admin_directory.join("long-recovery-run"), b"").unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let mut server = services.block_on(ServerFixture::seed(f));
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    let (id, job) = (requested.destruction_id, requested.preflight_hash.unwrap());
    {
        let mut reservation = ActualReservation {
            services: &services,
            server: &server.server,
        };
        native
            .start(
                id,
                job,
                NativeDestructionDelivery::AuthenticatedServer(&mut reservation),
            )
            .unwrap();
        native
            .resume_local(
                id,
                NativeDestructionDelivery::AuthenticatedServer(&mut reservation),
            )
            .unwrap();
    }
    assert_eq!(
        server_count(&services, &server, "destruction_jobs"),
        0,
        "only the reservation exists: no job was transmitted"
    );
    assert_eq!(
        server_count(&services, &server, "destruction_attestations"),
        0,
        "the server has not executed or attested anything"
    );
    if reader_before_state4 {
        let db = completion::writer_database(f);
        let reader = completion::fixture_reader_claim(f, &db);
        native.import_signed_progress(id, job, &[reader]).unwrap();
    }
    server.stop_listener();
    let failed = native.mark_incomplete_progress(id, job).unwrap();
    assert_eq!(failed.state.code(), 4);
    let server_replica = failed
        .replicas
        .iter()
        .find(|replica| replica.device_id == server.config.device_id)
        .unwrap();
    assert!(
        server_replica.attestation_hash.is_none(),
        "the Server duty is actually open at t4"
    );
    let reader = failed
        .replicas
        .iter()
        .find(|replica| replica.kind == ea_destruction::ManagedReplicaKind::Reader)
        .unwrap();
    assert_eq!(reader.attestation_hash.is_some(), reader_before_state4);
    let (retained, exact) = last_event(&mut native, id, job);
    let fields = transition(&exact);
    assert_eq!(
        (fields.from_state, fields.to_state, fields.trigger_code),
        (Some(1), 4, 4)
    );
    Incomplete {
        services,
        server,
        id,
        job,
        retained,
        t4: fields.executed_at,
    }
}

/// Relays one exact original to the registered server as the configured
/// controller component, outside the Desktop transport.
pub(super) fn post_exact_event(o: &Incomplete, exact: &[u8]) -> u16 {
    let organization = trust_support::organization();
    let signer =
        ea_sync_protocol::RequestSigner::from_secret(ea_crypto::SecretBytes::new(COMPONENT_SECRET));
    let target = format!("/v1/destructions/{}/events", hex::encode(o.id.as_bytes()));
    o.services
        .block_on(async {
            let nonce = common::fresh_challenge(&o.server.server, organization).await;
            let headers = common::signed_headers(&common::SignedCall {
                signer: &signer,
                endpoint: EndpointV1::DestructionEvents,
                authority: &o.server.server.authority,
                target: &target,
                body: Some(exact),
                organization_id: organization,
                request_id: <[u8; 16]>::try_from(&nonce[..16]).unwrap(),
                nonce,
                created: system_now().get().div_euclid(1_000),
            });
            common::https_request(
                o.server.server.address,
                &o.server.server.authority,
                "POST",
                &target,
                &headers,
                exact,
            )
            .await
        })
        .status
}

/// After a completed 4→1→3: the server holds exactly one 4→1 bound to the
/// retained state4, its own measured removal and no original/Grant version.
pub(super) fn assert_server_completed_once(o: &Incomplete, f: &NativeDestructionFixture) {
    let rows = server_transitions(&o.services, &o.server);
    let states = rows.iter().map(|row| row.2).collect::<Vec<_>>();
    assert!(
        states.ends_with(&[4, 1, 3]),
        "actual server order ends with the retained 4, one 4→1 and 1→3: {states:?}"
    );
    let retries = server_retries(&o.services, &o.server);
    assert_eq!(retries.len(), 1, "exactly one 4→1 at the server, no fork");
    let (hash, exact, to) = &retries[0];
    assert_eq!(*to, 1);
    assert_eq!(object_hash(exact).as_bytes(), hash.as_slice());
    let fields = transition(exact);
    assert_eq!(fields.trigger_code, 5);
    assert!(fields.previous_event_object_hash == Some(o.retained));
    assert!(fields.executed_at >= o.t4, "the 4→1 is never backdated");
    assert!(fields.destruction_authorization_object_hash == object_hash(&f.authorization));
    assert_eq!(
        &fs::read(
            f.archive
                .join(ea_archive::DESTRUCTIONS_DIR_V1)
                .join(format!("{}.etb", hex::encode(hash)))
        )
        .unwrap(),
        exact,
        "the server holds the exact local 4→1 original"
    );
    // The server's own measured removal, attested once and relayed exactly.
    let measured: Vec<(i16, Vec<u8>, Vec<u8>)> = o
        .services
        .block_on(
            sqlx::query_as(
                "SELECT result_code, attestation_hash, exact_attestation \
                 FROM destruction_server_measurements",
            )
            .fetch_all(o.server.database.pool()),
        )
        .unwrap();
    // Every job POST re-executes and re-attests the current server state
    // (each Resume re-contact relays the job); every such measurement is a
    // successful removal and is imported exactly.
    assert!(!measured.is_empty(), "an actual server measurement");
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let inventory = ArchiveInventory::build(&source).unwrap();
    for (result, hash, exact) in &measured {
        assert_eq!(*result, 0, "successful server removal");
        let local = inventory
            .trust()
            .iter()
            .find(|object| object.object_hash().as_bytes() == hash.as_slice())
            .expect("the actual server attestation is imported locally");
        assert_eq!(local.exact_bytes().as_bytes(), exact.as_slice());
    }
    assert!(inventory.entries().is_empty() && inventory.grants().is_empty());
    let held = inventory
        .destroyed()
        .iter()
        .map(|stub| stub.value().entry_hash())
        .collect::<Vec<_>>();
    assert_eq!(held.len(), 1, "the local verified stub remains");
    o.services.block_on(async {
        let client = common::object_store_client().await;
        let objects: Vec<(Vec<u8>, i16)> =
            sqlx::query_as("SELECT object_hash, object_type_code FROM destruction_job_objects")
                .fetch_all(o.server.database.pool())
                .await
                .unwrap();
        assert!(
            !objects.is_empty(),
            "the frozen job scope names the originals"
        );
        for (hash, code) in objects {
            let kind = if code == 1 {
                ObjectTypeV1::Entry
            } else {
                ObjectTypeV1::Grant
            };
            let versions = client
                .list_object_versions()
                .bucket(&o.server.bucket)
                .prefix(ea_sync_server::object_key(
                    kind,
                    ObjectHash::try_from(hash.as_slice()).unwrap(),
                ))
                .send()
                .await
                .unwrap();
            assert!(
                versions.versions().is_empty() && versions.delete_markers().is_empty(),
                "every original/Grant version and delete marker is absent"
            );
        }
        let stubs: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT object_hash FROM destruction_job_stubs")
                .fetch_all(o.server.database.pool())
                .await
                .unwrap();
        assert_eq!(stubs.len(), 1);
        let stub = ObjectHash::try_from(stubs[0].as_slice()).unwrap();
        let exact = client
            .get_object()
            .bucket(&o.server.bucket)
            .key(ea_sync_server::object_key(ObjectTypeV1::Destroyed, stub))
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes();
        assert!(object_hash(&exact) == stub);
        let ParsedArchiveObject::Destroyed(stub) = decode_exact_object(&exact).unwrap() else {
            panic!("expected the actual durable server EDS");
        };
        assert!(held.contains(&stub.value().entry_hash()));
    });
}

fn refused_code<T>(
    result: Result<T, ea_desktop::runtime::destruction_transport::NativeDestructionTransportError>,
) -> &'static str {
    match result {
        Ok(_) => panic!("the retry must be refused"),
        Err(error) => error.code(),
    }
}

/// Listener off → no append; restart; the server fails between the retry's
/// first reservation read and its read after the blocking audit signatures →
/// no commit, no publish, no server 4→1; restart again → one Resume call
/// chains 4→1 and 1→3; exact replays after a reopen add nothing anywhere.
#[test]
fn native_retry_survives_a_listener_loss_between_its_reads_and_resumes_once_after_the_same_server_restarts()
 {
    let began = std::time::Instant::now();
    let f = NativeDestructionFixture::with_reader_opfs();
    let mut o = incomplete_with_unexecuted_server(&f, true);
    let (id, job) = (o.id, o.job);
    let mut transport =
        NativeDestructionServerTransport::open(vec![o.server.config.clone()], &f.key_source)
            .unwrap();
    eprintln!(
        "retry transport: state4 with open server duty {:?}",
        began.elapsed()
    );

    // 1. The registered listener stays off: the Desktop Resume fails closed at
    // its first authenticated server contact, before any retry work.
    let before = local_counts(&f);
    let mut native = f.runtime();
    let code = refused_code(transport.resume(&mut native, id));
    assert!([UNAVAILABLE, TLS].contains(&code), "listener off: {code}");
    assert_eq!(
        local_counts(&f),
        before,
        "no local append without the server"
    );
    assert_eq!(state_after_refusal(&mut native, id), 4);
    assert!(last_event(&mut native, id, job).0 == o.retained);
    drop(native);

    // 2. Same registered server, same address, database and bucket. The exact
    // Failure replay relays the durable originals; the server executes now.
    o.server.restart_listener(&o.services);
    assert!(server_transitions(&o.services, &o.server).is_empty());
    let mut native = f.runtime();
    let relayed = transport.mark_incomplete(&mut native, id, job).unwrap();
    assert_eq!(relayed.state.code(), 4, "an exact replay stays state4");
    let server_replica = relayed
        .replicas
        .iter()
        .find(|replica| replica.device_id == o.server.config.device_id)
        .unwrap();
    assert!(
        matches!(
            server_replica.result,
            ea_destruction::EvidenceReplicaStatus::Successful(_)
        ),
        "the restarted server executed and its attestation is imported"
    );
    assert_eq!(server_count(&o.services, &o.server, "destruction_jobs"), 1);
    assert!(
        server_transitions(&o.services, &o.server)
            .iter()
            .map(|row| row.2)
            .collect::<Vec<_>>()
            .ends_with(&[1, 4])
    );
    assert!(server_retries(&o.services, &o.server).is_empty());
    drop(native);
    eprintln!(
        "retry transport: relayed after restart {:?}",
        began.elapsed()
    );

    // 3. Resume chains the retry. Its re-contact POSTs the job again, so the
    // server executes and attests anew and exactly one import batch (one
    // Controller Destruction audit) precedes the retry; that audit passes. The
    // retry's first reservation read succeeds; while its own native
    // Destruction audit signature is held, the registered listener stops; the
    // read after that blocking work fails in the actual Desktop `Reservation`
    // adapter → no commit, no publish.
    let before = local_counts(&f);
    let server_before = server_transitions(&o.services, &o.server);
    let skip = f.admin_directory.join("hold-completion-audit-skip");
    fs::write(&skip, b"1").unwrap();
    let barrier = f.admin_directory.join("hold-completion-audit");
    fs::write(&barrier, b"").unwrap();
    let mut native = f.runtime();
    let result = std::thread::scope(|scope| {
        let task = scope.spawn(|| transport.resume(&mut native, id));
        let paused = f.admin_directory.join("completion-audit-paused");
        let until = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while !paused.try_exists().unwrap() {
            assert!(
                std::time::Instant::now() < until,
                "the actual native audit barrier was not reached"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        o.server.stop_listener();
        fs::remove_file(&barrier).unwrap();
        task.join().unwrap()
    });
    assert!(
        f.admin_directory
            .join("completion-audit-returned")
            .try_exists()
            .unwrap(),
        "the held helper actually returned; a timeout is no refusal"
    );
    let code = refused_code(result);
    assert!([UNAVAILABLE, TLS].contains(&code), "second read: {code}");
    assert_eq!(
        fs::read_to_string(&skip).unwrap(),
        "0",
        "exactly the one import audit passed before the held retry audit"
    );
    // Only the import batch (and its two audits) is durable; the retry's own
    // batch and both audits rolled back together and nothing was published.
    let after = local_counts(&f);
    assert_eq!(after.batches, before.batches + 1, "only the import batch");
    assert_eq!(after.audits, before.audits + 2, "only the import audits");
    assert_eq!(local_retries(&f), 0, "the signed 4→1 was never persisted");
    assert_eq!(state_after_refusal(&mut native, id), 4);
    assert!(last_event(&mut native, id, job).0 == o.retained);
    drop(native);
    o.server.restart_listener(&o.services);
    assert_eq!(
        server_transitions(&o.services, &o.server),
        server_before,
        "the server never saw the discarded signed 4→1"
    );
    eprintln!("retry transport: second read refused {:?}", began.elapsed());

    // 4. One Resume call: 4→1 (new event, previous = retained), publication
    // after the local commit, then 1→3 with its own fresh reservation.
    let mut native = f.runtime();
    let done = transport.resume(&mut native, id).unwrap();
    assert_eq!(done.state.code(), 3, "4→1→3 in one Resume");
    assert!(done.replicas.iter().all(|replica| matches!(
        replica.result,
        ea_destruction::EvidenceReplicaStatus::Successful(_)
    )));
    assert_eq!(local_retries(&f), 1, "exactly one local 4→1");
    assert_server_completed_once(&o, &f);
    drop(native);
    eprintln!("retry transport: 4→1→3 complete {:?}", began.elapsed());

    // 5. Exact replays after a reopen: no growth locally or at the server.
    let completed = local_counts(&f);
    let server_completed = server_transitions(&o.services, &o.server);
    let mut native = f.runtime();
    let synchronized = transport.synchronize(&mut native, id, job).unwrap();
    assert_eq!(synchronized.state.code(), 3);
    let mut reservation = ActualReservation {
        services: &o.services,
        server: &o.server.server,
    };
    assert_eq!(
        native
            .resume_incomplete_progress(
                id,
                job,
                o.retained,
                NativeDestructionDelivery::AuthenticatedServer(&mut reservation),
            )
            .err()
            .expect("the consumed retained state4 cannot be retried after 1→3")
            .code(),
        "EA-DESTRUCTION-EVENT"
    );
    let retry = server_retries(&o.services, &o.server);
    assert_eq!(
        post_exact_event(&o, &retry[0].1),
        EndpointV1::DestructionEvents.success_status(),
        "the exact duplicate POST is an idempotent replay"
    );
    assert_eq!(local_counts(&f), completed);
    assert_eq!(server_transitions(&o.services, &o.server), server_completed);
    drop(native);
    eprintln!(
        "retry transport: replay without growth {:?}",
        began.elapsed()
    );
}

/// G1 end to end: the Reader was the open duty at t4. Resume refuses the
/// retry permanently, with the listener off and after the same server
/// restarted; nothing is appended locally and the server holds no 4→1.
#[test]
fn native_retry_keeps_a_reader_case_in_state4_before_and_after_the_same_server_restarts() {
    let f = NativeDestructionFixture::with_reader_opfs();
    let mut o = incomplete_with_unexecuted_server(&f, false);
    let (id, job) = (o.id, o.job);
    let mut transport =
        NativeDestructionServerTransport::open(vec![o.server.config.clone()], &f.key_source)
            .unwrap();
    let before = local_counts(&f);
    let mut native = f.runtime();
    assert_eq!(
        refused_code(transport.resume(&mut native, id)),
        "EA-DESTRUCTION-RETRY-READER-DUTY",
        "decided locally before any server contact"
    );
    assert_eq!(local_counts(&f), before);
    drop(native);

    o.server.restart_listener(&o.services);
    let mut native = f.runtime();
    assert_eq!(
        refused_code(transport.resume(&mut native, id)),
        "EA-DESTRUCTION-RETRY-READER-DUTY",
        "a reachable server does not re-open a Reader case"
    );
    assert_eq!(local_counts(&f), before, "no local append");
    assert_eq!(state_after_refusal(&mut native, id), 4);
    assert!(last_event(&mut native, id, job).0 == o.retained);
    assert!(
        server_retries(&o.services, &o.server).is_empty(),
        "the server holds no 4→1"
    );
}
