use super::*;

#[tokio::test]
async fn malformed_transport_and_signed_missing_replica_inventory_are_refused() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-job-invalid");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let mut trailing = fixture.body.clone();
    trailing.push(0);
    for (marker, bytes) in [
        (0x70, vec![0x80]),
        (0x71, trailing),
        (0x72, b"{\"ready\":true}".to_vec()),
    ] {
        assert_eq!(
            common::call(&common::ApiCall {
                ready: &ready,
                signer_seed: COMPONENT_SEED,
                endpoint: EndpointV1::DestructionJobs,
                target: &jobs,
                body: Some(&bytes),
                request_id: [marker; 16]
            })
            .await
            .status,
            400
        );
    }

    // Re-sign a structurally exact job that deliberately omits one registered
    // holder. Valid component crypto never replaces complete managed custody.
    let mut d = minicbor::Decoder::new(&fixture.inventory);
    assert_eq!(d.array().unwrap(), Some(4));
    let domain = d.str().unwrap();
    let custody = d.bytes().unwrap();
    let tail = &fixture.inventory[d.position()..];
    let mut c = minicbor::Decoder::new(custody);
    assert_eq!(c.array().unwrap(), Some(6));
    for _ in 0..5 {
        c.skip().unwrap();
    }
    let prefix = &custody[..c.position()];
    let count = c.array().unwrap().unwrap();
    assert!(count > 1);
    let mut records = Vec::new();
    for _ in 0..count {
        records.push(c.bytes().unwrap().to_vec());
    }
    records.pop();
    let mut reduced = prefix.to_vec();
    let mut e = Encoder::new(&mut reduced);
    e.array(records.len() as u64).unwrap();
    for record in records {
        e.bytes(&record).unwrap();
    }
    let mut inventory = Vec::new();
    Encoder::new(&mut inventory)
        .array(4)
        .unwrap()
        .str(domain)
        .unwrap()
        .bytes(&reduced)
        .unwrap();
    inventory.extend_from_slice(tail);
    let mut core = fixture.core.clone();
    let mut d = minicbor::Decoder::new(&core);
    d.array().unwrap();
    for _ in 0..6 {
        d.skip().unwrap();
    }
    let hash = d.bytes().unwrap();
    assert_eq!(hash, object_hash(&fixture.inventory).as_bytes());
    let end = d.position();
    core[end - 32..end].copy_from_slice(object_hash(&inventory).as_bytes());
    let signature = CoseSigner::from_secret(SecretBytes::new(COMPONENT_SEED))
        .sign_destruction_preflight_report(fixture.component, &core)
        .unwrap();
    let body = ea_sync_protocol::DestructionJobUploadV1::new(
        &core,
        &signature,
        &inventory,
        fixture.component,
    )
    .unwrap();
    let refused = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &jobs,
        body: Some(body.exact_bytes()),
        request_id: [0x73; 16],
    })
    .await;
    assert_eq!(refused.status, 422);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(
        common::object_store_client()
            .await
            .get_object()
            .bucket(&bucket)
            .key(ea_sync_server::object_key(
                ObjectTypeV1::Entry,
                object_hash(&fixture.original.original_bytes)
            ))
            .send()
            .await
            .is_ok()
    );
    cleanup_fixture(database, &bucket).await;
}
