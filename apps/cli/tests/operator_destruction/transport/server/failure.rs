//! Actual registered TLS listener loss, not a simulated successful reservation.
use super::*;

#[test]
fn native_failure_persists_locally_after_actual_registered_tls_listener_stops() {
    let f = NativeDestructionFixture::with_reader_opfs();
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    let (id, job) = (requested.destruction_id, requested.preflight_hash.unwrap());
    let mut transport =
        NativeDestructionServerTransport::open(vec![server.config.clone()], &f.key_source).unwrap();
    let started = transport.start(&mut native, id, job).unwrap();
    assert_eq!(started.state.code(), 1);
    let server_replica = started
        .replicas
        .iter()
        .find(|replica| replica.device_id == server.config.device_id)
        .unwrap();
    assert!(matches!(
        server_replica.result,
        ea_destruction::EvidenceReplicaStatus::Successful(_)
    ));
    let server_hash = server_replica.attestation_hash.unwrap();
    let exact_server = server_original(&f, server_hash);
    let retained = entries(&f);
    assert!(
        !retained.is_empty(),
        "actual local originals still retained before cleanup"
    );
    let registered_address = server.config.address;
    drop(native);
    // Only the test-owned runtime and its actual TLS listener stop. Existing
    // PostgreSQL/S3 services remain untouched; no endpoint/config is substituted.
    services.shutdown_timeout(std::time::Duration::from_secs(2));
    assert_eq!(
        std::net::TcpStream::connect_timeout(
            &registered_address,
            std::time::Duration::from_secs(2)
        )
        .unwrap_err()
        .kind(),
        std::io::ErrorKind::ConnectionRefused,
        "the identical registered listener is actually unavailable",
    );
    let mut native = f.runtime();
    let failed = native.mark_incomplete_progress(id, job).unwrap();
    assert_eq!(failed.state.code(), 4);
    assert!(failed.preflight_hash == Some(job));
    assert_eq!(failed.replicas.len(), started.replicas.len());
    let retained_server = failed
        .replicas
        .iter()
        .find(|replica| replica.device_id == server.config.device_id)
        .unwrap();
    assert!(retained_server.attestation_hash == Some(server_hash));
    assert!(matches!(
        retained_server.result,
        ea_destruction::EvidenceReplicaStatus::Successful(_)
    ));
    assert_eq!(server_original(&f, server_hash), exact_server);
    assert_eq!(entries(&f), retained);
    assert!(
        failed
            .replicas
            .iter()
            .any(|replica| replica.attestation_hash.is_none())
    );
    eprintln!(
        "native failure: same registered TLS listener refused connection; local4 retained exact prior serverSuccess and original local entries"
    );
}
fn entries(f: &NativeDestructionFixture) -> Vec<Vec<u8>> {
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    ArchiveInventory::build(&source)
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.exact_bytes().as_bytes().to_vec())
        .collect()
}
fn server_original(f: &NativeDestructionFixture, hash: ObjectHash) -> Vec<u8> {
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let inventory = ArchiveInventory::build(&source).unwrap();
    let claim = inventory
        .trust()
        .iter()
        .find(|object| object.object_hash() == hash)
        .unwrap();
    assert!(
        matches!(claim.value().decoded_payload().unwrap(), DecodedTrustPayloadV1::DeletionAttestation(fields) if fields.result == 0)
    );
    claim.exact_bytes().as_bytes().to_vec()
}
