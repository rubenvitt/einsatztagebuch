//! Native public originals only; this does not execute or attest a Reader cache.
use super::*;
use ea_admin::destruction_runtime::{
    DestructionHostGuard, NativeDestructionDelivery, NativeDestructionError,
};
use ea_destruction::{DestructionError, ManagedReplicaKind};
use ea_sync_protocol::DestructionJobUploadV1;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn database(f: &NativeDestructionFixture) -> EncryptedDatabase {
    let (provider, key) = database_provider_for(false);
    EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
        .unwrap()
}

fn snapshot(db: &EncryptedDatabase) -> Vec<Vec<ea_local_store::StoreRow>> {
    [
        "destruction_request",
        "destruction_job",
        "destruction_inventory",
        "managed_custody",
        "destruction_job_event",
        "destruction_local_attestation",
        "destruction_import_batch",
        "draft",
        "draft_transition",
        "writer_evidence_draft",
    ]
    .iter()
    .map(|table| {
        let mut rows = Vec::new();
        for offset in 0..10_000 {
            match db
                .query_row(
                    &format!("SELECT * FROM {table} ORDER BY rowid LIMIT 1 OFFSET {offset}"),
                    &[],
                )
                .unwrap()
            {
                Some(row) => rows.push(row),
                None => return rows,
            }
        }
        panic!("bounded fixture snapshot")
    })
    .collect()
}

fn archive_snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, result: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    visit(root, root, &mut result);
    result
}

struct Host(AtomicBool);
impl DestructionHostGuard for Host {
    fn require_open(&self) -> Result<(), NativeDestructionError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(NativeDestructionError::Session)
        }
    }
}

#[test]
fn native_reader_delivery_exports_exact_started_no_server_job_and_reopens() {
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    assert!(
        !requested
            .replicas
            .iter()
            .any(|r| r.kind == ManagedReplicaKind::SyncServer)
    );
    let reader = requested
        .replicas
        .iter()
        .find(|r| r.kind == ManagedReplicaKind::Reader)
        .unwrap()
        .device_id;
    let id = requested.destruction_id;
    let job_hash = requested.preflight_hash.unwrap();
    assert!(matches!(
        runtime.export_reader_delivery(id, job_hash, reader),
        Err(NativeDestructionError::Core(DestructionError::Event))
    ));
    runtime
        .start(id, job_hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = database(&f);
    let before = snapshot(&db);
    let archive_before = archive_snapshot(&f.archive);
    let delivery = runtime
        .export_reader_delivery(id, job_hash, reader)
        .unwrap();
    assert!(delivery.reader_id() == reader);
    assert!(delivery.job_hash() == job_hash);
    assert_eq!(delivery.exact_authorization(), f.authorization);
    let upload = DestructionJobUploadV1::decode(delivery.exact_job_upload()).unwrap();
    assert!(ea_crypto::object_hash(upload.core_bytes()) == job_hash);
    let saved = db.query_row("SELECT exact_core,exact_signature,exact_inventory,signer_certificate_hash FROM destruction_job", &[]).unwrap().unwrap();
    assert_eq!(upload.core_bytes(), saved.blob(0).unwrap());
    assert_eq!(upload.signature_bytes(), saved.blob(1).unwrap());
    assert_eq!(upload.inventory_bytes(), saved.blob(2).unwrap());
    assert_eq!(upload.certificate_hash().as_bytes(), saved.blob(3).unwrap());
    let ea_format::ParsedArchiveObject::Trust(auth) =
        ea_format::decode_exact_object(delivery.exact_authorization()).unwrap()
    else {
        panic!("authorization ETB")
    };
    let ea_format::DecodedTrustPayloadV1::DestructionAuthorization(auth_fields) =
        auth.value().decoded_payload().unwrap()
    else {
        panic!("authorization type")
    };
    assert!(auth_fields.destruction_id == id);
    let ea_format::ParsedArchiveObject::Trust(event) =
        ea_format::decode_exact_object(delivery.exact_initiating_event()).unwrap()
    else {
        panic!("transition ETB")
    };
    let ea_format::DecodedTrustPayloadV1::DestructionTransition(start) =
        event.value().decoded_payload().unwrap()
    else {
        panic!("transition type")
    };
    assert!(start.destruction_id == id);
    assert!(
        start.destruction_authorization_object_hash
            == ea_crypto::object_hash(delivery.exact_authorization())
    );
    assert_eq!((start.from_state, start.to_state), (Some(0), 1));
    let requested_event = db
        .query_row("SELECT exact_event FROM destruction_request", &[])
        .unwrap()
        .unwrap();
    assert!(
        start.previous_event_object_hash
            == Some(ea_crypto::object_hash(requested_event.blob(0).unwrap()))
    );
    let saved_event = db
        .query_row(
            "SELECT exact_event FROM destruction_job_event ORDER BY insertion_sequence LIMIT 1",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        delivery.exact_initiating_event(),
        saved_event.blob(0).unwrap()
    );
    assert_eq!(snapshot(&db), before);
    assert_eq!(archive_snapshot(&f.archive), archive_before);
    drop(runtime);
    let mut reopened = f.runtime();
    assert!(matches!(
        reopened.export_reader_delivery(id, job_hash, reader),
        Err(NativeDestructionError::Session)
    ));
    reopened.unlock().unwrap();
    let durable = reopened
        .export_reader_delivery(id, job_hash, reader)
        .unwrap();
    assert_eq!(
        durable.exact_authorization(),
        delivery.exact_authorization()
    );
    assert_eq!(
        durable.exact_initiating_event(),
        delivery.exact_initiating_event()
    );
    assert_eq!(durable.exact_job_upload(), delivery.exact_job_upload());
    assert_eq!(snapshot(&db), before);
    assert_eq!(archive_snapshot(&f.archive), archive_before);
    let status = reopened.status(id).unwrap();
    assert!(
        status
            .replicas
            .iter()
            .any(|r| r.device_id == reader && r.attestation_hash.is_none())
    );
    assert!(
        status.state == ea_destruction::DestructionState::InProgress,
        "export creates no Reader completion"
    );
}

#[test]
fn native_reader_delivery_refuses_wrong_selection_and_locked_native_host() {
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let id = requested.destruction_id;
    let job = requested.preflight_hash.unwrap();
    let reader = requested
        .replicas
        .iter()
        .find(|r| r.kind == ManagedReplicaKind::Reader)
        .unwrap()
        .device_id;
    runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let db = database(&f);
    let before = snapshot(&db);
    let archive_before = archive_snapshot(&f.archive);
    let wrong_job = ea_crypto::object_hash(b"different immutable job");
    assert!(matches!(
        runtime.export_reader_delivery(id, wrong_job, reader),
        Err(NativeDestructionError::Core(
            DestructionError::SecurityConflict
        ))
    ));
    for other in [
        requested.custodian_device_id,
        DeviceId::try_from(&[0xee; 16][..]).unwrap(),
    ] {
        assert!(matches!(
            runtime.export_reader_delivery(id, job, other),
            Err(NativeDestructionError::Core(DestructionError::Target))
        ));
    }
    assert!(
        runtime
            .export_reader_delivery(
                DestructionId::try_from(&[0xef; 16][..]).unwrap(),
                job,
                reader
            )
            .is_err()
    );
    let host = Arc::new(Host(AtomicBool::new(true)));
    runtime.set_host_guard(host.clone());
    runtime.export_reader_delivery(id, job, reader).unwrap();
    host.0.store(false, Ordering::SeqCst);
    assert!(matches!(
        runtime.export_reader_delivery(id, job, reader),
        Err(NativeDestructionError::Session)
    ));
    host.0.store(true, Ordering::SeqCst);
    runtime.lock();
    assert!(matches!(
        runtime.export_reader_delivery(id, job, reader),
        Err(NativeDestructionError::Session)
    ));
    assert_eq!(snapshot(&db), before);
    assert_eq!(archive_snapshot(&f.archive), archive_before);
}

#[test]
fn native_reader_delivery_refuses_host_closure_at_final_return_gate() {
    struct ClosingHost {
        calls: AtomicUsize,
        close_at: AtomicUsize,
    }
    impl DestructionHostGuard for ClosingHost {
        fn require_open(&self) -> Result<(), NativeDestructionError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call >= self.close_at.load(Ordering::SeqCst) {
                Err(NativeDestructionError::Session)
            } else {
                Ok(())
            }
        }
    }
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    let id = requested.destruction_id;
    let job = requested.preflight_hash.unwrap();
    let reader = requested
        .replicas
        .iter()
        .find(|r| r.kind == ManagedReplicaKind::Reader)
        .unwrap()
        .device_id;
    runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let host = Arc::new(ClosingHost {
        calls: AtomicUsize::new(0),
        close_at: AtomicUsize::new(usize::MAX),
    });
    runtime.set_host_guard(host.clone());
    runtime.export_reader_delivery(id, job, reader).unwrap();
    let final_gate = host.calls.load(Ordering::SeqCst);
    assert!(final_gate > 1);
    host.calls.store(0, Ordering::SeqCst);
    host.close_at.store(final_gate, Ordering::SeqCst);
    let db = database(&f);
    let before = snapshot(&db);
    let archive_before = archive_snapshot(&f.archive);
    assert!(matches!(
        runtime.export_reader_delivery(id, job, reader),
        Err(NativeDestructionError::Session)
    ));
    assert_eq!(
        host.calls.load(Ordering::SeqCst),
        final_gate,
        "late invalidation was actually reached"
    );
    assert_eq!(snapshot(&db), before);
    assert_eq!(archive_snapshot(&f.archive), archive_before);
}
