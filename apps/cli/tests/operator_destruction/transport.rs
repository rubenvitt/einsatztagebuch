use super::*;
use ea_crypto::object_hash;
pub(super) const SERVER_TRANSPORT_SECRET: [u8; 32] = [0xc1; 32];
pub(super) const SERVER_DELETION_SECRET: [u8; 32] = [0xc2; 32];
pub(super) const HTTP_APPROVER_SECRET: [u8; 32] = [0xc3; 32];
#[test]
fn native_destruction_transport_exports_only_the_exact_durable_job_with_fresh_presence() {
    let f = NativeDestructionFixture::new();
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    let exchange =
        native.prepare_server_exchange(requested.destruction_id, requested.preflight_hash.unwrap());
    assert!(
        exchange.is_ok(),
        "a real persisted signed job and current native presence must yield the opaque exchange context"
    );
    let exchange = exchange.unwrap();
    assert_eq!(exchange.exact_authorization(), f.authorization);
    assert!(exchange.job_hash() == requested.preflight_hash.unwrap());
    assert!(exchange.component_certificate() == f.component);
    assert!(!exchange.required_servers().is_empty());
    let upload = ea_sync_protocol::DestructionJobUploadV1::decode(exchange.exact_job()).unwrap();
    assert!(ea_crypto::object_hash(upload.core_bytes()) == exchange.job_hash());
    exchange
        .verify_component_key(&public(COMPONENT_SECRET))
        .unwrap();
    assert!(exchange.verify_component_key(&public([0x11; 32])).is_err());
    // A server's unsigned state3 cannot invent even one new local event.
    let response = ea_sync_protocol::DestructionStatusResponseV1::new(
        requested.destruction_id,
        3,
        requested.authorization_hash,
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(exchange.progress_batches(&response).unwrap().is_empty());
    assert_eq!(exchange.events().unwrap().len(), 1);
    let wrong_authorization = ea_sync_protocol::DestructionStatusResponseV1::new(
        requested.destruction_id,
        0,
        object_hash(b"another authorization"),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(exchange.progress_batches(&wrong_authorization).is_err());
    let wrong_id = ea_sync_protocol::DestructionStatusResponseV1::new(
        DestructionId::try_from(&[0x44; 16][..]).unwrap(),
        0,
        requested.authorization_hash,
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(exchange.progress_batches(&wrong_id).is_err());
    let events = exchange.events().unwrap();
    let wrong_hash = ea_sync_protocol::DestructionStatusResponseV1::new(
        requested.destruction_id,
        0,
        requested.authorization_hash,
        vec![ea_sync_protocol::ObjectRecordV1::new(
            object_hash(b"another event"),
            events[0].2.to_vec(),
        )],
        Vec::new(),
    )
    .unwrap();
    assert!(exchange.progress_batches(&wrong_hash).is_err());
    let mut tampered = events[0].2.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let invalid_signed_event = ea_sync_protocol::DestructionStatusResponseV1::new(
        requested.destruction_id,
        0,
        requested.authorization_hash,
        vec![ea_sync_protocol::ObjectRecordV1::new(
            object_hash(&tampered),
            tampered,
        )],
        Vec::new(),
    )
    .unwrap();
    assert!(exchange.progress_batches(&invalid_signed_event).is_err());
}

#[cfg(feature = "desktop-fixture")]
mod server;
