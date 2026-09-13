use super::*;
use ea_admin::destruction_runtime::NativeDestructionDelivery;
use ea_format::{DeletionAttestationFieldsV1, DestructionTransitionFieldsV1, TrustPayloadV1};
use ea_types::EventId;
pub(super) fn pending_objects(
    f: &NativeDestructionFixture,
    db: &EncryptedDatabase,
) -> Vec<Vec<u8>> {
    changed_objects(f, db, |_| {}, |_| {})
}
/// Explicit positive historical state-2 fixture with every original duty.
/// The Reader claim is synthetic and signed by its existing fixture certificate.
pub(super) fn complete_pending_objects(
    f: &NativeDestructionFixture,
    db: &EncryptedDatabase,
) -> Vec<Vec<u8>> {
    with_reader_pending_original(f, pending_objects(f, db))
}
pub(super) fn with_reader_pending_original(
    f: &NativeDestructionFixture,
    mut objects: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(&objects[1]).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DeletionAttestation(mut fields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert_eq!(fields.result, 1, "positive Pending fixture only");
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
    fields.replica_id = *reader.fields().device_id.as_bytes();
    fields.replica_kind = 1;
    // Keep the exact historical time and maximum deadline of the positive
    // Writer claim; no invented delivery time or removal is introduced.
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
    objects.push(
        ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .as_bytes()
            .to_vec(),
    );
    objects
}
pub(super) fn changed_objects(
    f: &NativeDestructionFixture,
    db: &EncryptedDatabase,
    attest: impl FnOnce(&mut DeletionAttestationFieldsV1),
    event: impl FnOnce(&mut DestructionTransitionFieldsV1),
) -> Vec<Vec<u8>> {
    let start = db
        .query_row(
            "SELECT exact_event,event_hash FROM destruction_job_event",
            &[],
        )
        .unwrap()
        .unwrap();
    let ea_format::ParsedArchiveObject::Trust(parsed) =
        ea_format::decode_exact_object(start.blob(0).unwrap()).unwrap()
    else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::DestructionTransition(startfields) =
        parsed.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let signer = ea_crypto::CoseSigner::from_secret(ea_crypto::SecretBytes::new(COMPONENT_SECRET));
    let ea_format::ParsedArchiveObject::Trust(component) = ea_format::decode_exact_object(
        f.line
            .exact_object_bytes(ObjectHash::try_from(f.component.as_bytes().as_slice()).unwrap()),
    )
    .unwrap() else {
        panic!()
    };
    let ea_format::DecodedTrustPayloadV1::AuthorizedDevice(component) =
        component.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    let mut fields = DeletionAttestationFieldsV1 {
        destruction_id: startfields.destruction_id,
        destruction_authorization_object_hash: ea_crypto::object_hash(&f.authorization),
        replica_id: *component.fields().device_id.as_bytes(),
        replica_kind: 0,
        removed_object_hashes: vec![],
        result: 1,
        backup_expiry_at: Some(UnixMillis::new(startfields.executed_at.get() + 60_000)),
        executed_at: startfields.executed_at,
    };
    attest(&mut fields);
    let payload = TrustPayloadV1::deletion_attestation(fields).unwrap();
    let signature = signer
        .sign_deletion_attestation_digest(
            f.component,
            payload.exact_digest_input(),
            &f.authorization,
        )
        .unwrap();
    let att =
        ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
    let mut fields = DestructionTransitionFieldsV1 {
        destruction_id: startfields.destruction_id,
        destruction_authorization_object_hash: ea_crypto::object_hash(&f.authorization),
        event_id: EventId::try_from(&[0xba; 16][..]).unwrap(),
        previous_event_object_hash: Some(ea_crypto::object_hash(start.blob(0).unwrap())),
        from_state: Some(1),
        to_state: 2,
        trigger_code: 2,
        executed_at: startfields.executed_at,
    };
    event(&mut fields);
    let payload = TrustPayloadV1::destruction_transition(fields).unwrap();
    let signature = signer
        .sign_destruction_transition_digest(
            f.component,
            payload.exact_digest_input(),
            &f.authorization,
        )
        .unwrap();
    let event =
        ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, vec![signature]).unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
    vec![event, att]
}
#[test]
fn native_destruction_signed_progress_is_durable_replayable_and_bound_to_exact_import_set() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let prepared = runtime.prepare(&f.authorization).unwrap();
    let id = prepared.destruction_id;
    let job = prepared.preflight_hash.unwrap();
    runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let objects = complete_pending_objects(&f, &db);
    let result = runtime.import_signed_progress(id, job, &objects).unwrap();
    assert_eq!(result.state.code(), 2);
    assert!(
        result
            .replicas
            .iter()
            .any(|r| r.backup_expiry_at.is_some() && r.attestation_hash.is_some())
    );
    let row = db
        .query_row(
            "SELECT exact_context,login_audit_id,state_audit_id FROM destruction_import_batch",
            &[],
        )
        .unwrap()
        .unwrap();
    let saved = (
        row.blob(0).unwrap().to_vec(),
        row.blob(1).unwrap().to_vec(),
        row.blob(2).unwrap().to_vec(),
    );
    let mut reversed: Vec<_> = objects.iter().rev().cloned().collect();
    reversed.push(objects[0].clone());
    assert_eq!(
        runtime
            .import_signed_progress(id, job, &reversed)
            .unwrap()
            .state
            .code(),
        2
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_import_batch", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
    let row = db
        .query_row(
            "SELECT exact_context,login_audit_id,state_audit_id FROM destruction_import_batch",
            &[],
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.blob(0).unwrap(), saved.0);
    assert_eq!(row.blob(1).unwrap(), saved.1);
    assert_eq!(row.blob(2).unwrap(), saved.2);
    for object in &objects {
        assert!(
            walk_files(&f.archive)
                .iter()
                .any(|path| fs::read(path).is_ok_and(|bytes| bytes == *object)),
            "exact imported ETB is durable in actual archive"
        );
    }
    drop(runtime);
    let mut reopened = f.runtime();
    reopened.unlock().unwrap();
    assert_eq!(reopened.status(id).unwrap().state.code(), 2);
    // Fixture-only corruption bypasses the append-only trigger. The signed
    // import context still must reject these changed bytes after reopening.
    db.execute("DROP TRIGGER destruction_import_no_update", &[])
        .unwrap();
    let mut changed = saved.0;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    db.execute(
        "UPDATE destruction_import_batch SET exact_context=?1",
        &[ea_local_store::StoreValue::Blob(changed)],
    )
    .unwrap();
    assert!(reopened.status(id).is_err());
}
fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for path in fs::read_dir(root).unwrap().map(|e| e.unwrap().path()) {
        if path.is_dir() {
            result.extend(walk_files(&path))
        } else {
            result.push(path)
        }
    }
    result
}

#[test]
fn native_destruction_import_refuses_false_completion_foreign_replica_future_time_and_wrong_job() {
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let prepared = runtime.prepare(&f.authorization).unwrap();
    let id = prepared.destruction_id;
    let job = prepared.preflight_hash.unwrap();
    runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let pending = pending_objects(&f, &db);
    let candidates = [
        changed_objects(
            &f,
            &db,
            |_| {},
            |e| {
                e.to_state = 3;
                e.trigger_code = 3;
            },
        ),
        changed_objects(&f, &db, |a| a.replica_id = [0xfd; 16], |_| {}),
        changed_objects(
            &f,
            &db,
            |a| a.executed_at = UnixMillis::new(a.executed_at.get() + 1_000_000),
            |_| {},
        ),
    ];
    for input in candidates {
        assert!(runtime.import_signed_progress(id, job, &input).is_err());
    }
    assert!(
        runtime
            .import_signed_progress(id, ObjectHash::try_from(&[0xfa; 32][..]).unwrap(), &pending)
            .is_err()
    );
    assert!(runtime.import_signed_progress(id, job, &[]).is_err());
    assert!(
        runtime
            .import_signed_progress(id, job, &vec![pending[0].clone(); 257])
            .is_err()
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_import_batch", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    assert_eq!(runtime.status(id).unwrap().state.code(), 1);
}
#[test]
fn native_destruction_import_repairs_both_exact_audits_after_cross_database_failure() {
    let f = NativeDestructionFixture::with_optional_reader_opfs(false, 0, true);
    let mut runtime = f.runtime();
    let prepared = runtime.prepare(&f.authorization).unwrap();
    let id = prepared.destruction_id;
    let job = prepared.preflight_hash.unwrap();
    runtime
        .start(id, job, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    let objects = complete_pending_objects(&f, &db);
    let (provider, key) = database_provider_for(true);
    let admin =
        EncryptedDatabase::open_existing(&f.admin_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    admin.execute(&format!("CREATE TRIGGER refuse_import_state_audit BEFORE INSERT ON local_audit_event WHEN instr(NEW.exact_bytes,X'{}')>0 BEGIN SELECT RAISE(ABORT,'fixture mirror unavailable'); END",hex::encode(ea_crypto::object_hash(&objects[0]).as_bytes())),&[]).unwrap();
    assert!(runtime.import_signed_progress(id, job, &objects).is_err());
    let row = db
        .query_row(
            "SELECT login_audit_id,state_audit_id FROM destruction_import_batch",
            &[],
        )
        .unwrap()
        .unwrap();
    let ids = [row.blob(0).unwrap().to_vec(), row.blob(1).unwrap().to_vec()];
    assert!(
        !walk_files(&f.archive)
            .iter()
            .any(|path| fs::read(path).is_ok_and(|b| b == objects[0]))
    );
    drop(runtime);
    admin
        .execute("DROP TRIGGER refuse_import_state_audit", &[])
        .unwrap();
    let mut reopened = f.runtime();
    reopened.unlock().unwrap();
    assert_eq!(reopened.status(id).unwrap().state.code(), 2);
    for id in ids {
        let args = [ea_local_store::StoreValue::Blob(id)];
        let writer = db
            .query_row(
                "SELECT exact_bytes FROM local_audit_event WHERE event_id=?1",
                &args,
            )
            .unwrap()
            .unwrap();
        let reader = admin
            .query_row(
                "SELECT exact_bytes FROM local_audit_event WHERE event_id=?1",
                &args,
            )
            .unwrap()
            .unwrap();
        assert_eq!(writer.blob(0).unwrap(), reader.blob(0).unwrap());
    }
    assert_eq!(
        reopened
            .import_signed_progress(id, job, &objects)
            .unwrap()
            .state
            .code(),
        2
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_import_batch", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}
