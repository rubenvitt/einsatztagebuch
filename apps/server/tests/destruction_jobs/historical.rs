use super::*;
#[tokio::test]
async fn an_expired_real_historical_grant_and_every_generation_remain_removal_obligations() {
    let fixture = JobFixture::at(800);
    let inventory = ArchiveInventory::build(&fixture.source).unwrap();
    let head = fixture.original.head();
    let historical = ea_verify::historical_registry_head(
        &inventory,
        &fixture.original.anchor,
        head.version,
        head.object_hash,
        ChainSequence::new(1),
        UnixMillis::new(800),
    )
    .unwrap();
    let recipient = historical
        .known_certificate_fields()
        .find(|(_, f)| f.certificate_kind == CertificateKindV1::Reader)
        .unwrap()
        .0;
    let issuer = historical
        .known_certificate_fields()
        .find(|(_, f)| f.certificate_kind == CertificateKindV1::HistoricalGrantAuthority)
        .unwrap()
        .0;
    let approvers = historical
        .known_certificate_fields()
        .filter(|(_, f)| f.capabilities.iter().any(|c| c == "historicalGrantApprove"))
        .map(|(h, _)| h)
        .collect::<Vec<_>>();
    assert_eq!(approvers.len(), 2);
    let key = verify_support::other_recipient_private_key();
    let thumb = verify_support::other_recipient_key_thumbprint();
    let payload = TrustPayloadV1::grant_authorization(GrantAuthorizationFieldsV1 {
        authorization_id: AuthorizationId::try_from(&[0x38; 16][..]).unwrap(),
        organization_id: fixture.original.anchor.organization_id(),
        registry_version: head.version,
        registry_head_hash: Hash32::try_from(head.object_hash.as_bytes().as_slice()).unwrap(),
        authorization_sequence: 1,
        entry_hashes: vec![fixture.original.entry_hash],
        recipient_key_thumbprint: thumb,
        recipient_certificate_hash: recipient,
        expires_at: UnixMillis::new(900),
    })
    .unwrap();
    let signer = trust::authorized_device_signer();
    let signatures = approvers
        .iter()
        .map(|h| {
            signer
                .sign_historical_grant_approval_digest(*h, payload.exact_digest_input())
                .unwrap()
        })
        .collect();
    let authorization = encode_trust(&TrustObjectV1::new(payload, signatures).unwrap())
        .unwrap()
        .into_vec();
    let fields = |encapsulated_key, wrapped_cek| GrantBodyFieldsV1 {
        organization_id: fixture.original.anchor.organization_id(),
        chain_id: fixture.original.anchor.chain_id(),
        entry_hash: fixture.original.entry_hash,
        kind: GrantKindV1::Historical,
        purpose: GrantPurposeV1::Reader,
        recipient_key_thumbprint: thumb,
        recipient_certificate_hash: recipient,
        issuer_key_thumbprint: signer.public_key().unwrap().thumbprint(),
        issuer_certificate_hash: issuer,
        registry_version: head.version,
        registry_head_hash: Hash32::try_from(head.object_hash.as_bytes().as_slice()).unwrap(),
        created_at_device: UnixMillis::new(800),
        original_recovery_grant_object_hash: Some(object_hash(
            &fixture.original.initial_grant_bytes,
        )),
        grant_authorization_object_hash: Some(object_hash(&authorization)),
        encapsulated_key,
        wrapped_cek,
    };
    let draft = GrantBodyV1::new(fields([0; 32], [0; 48])).unwrap();
    let context = draft.exact_grant_context().unwrap();
    let sealed = ea_crypto::hpke_seal(
        &key.public_key(),
        &SecretBytes::new([0x3c; 32]),
        &ea_crypto::hpke_info(context),
        &ea_crypto::hpke_aad(context),
    )
    .unwrap();
    let body = GrantBodyV1::new(fields(*sealed.encapsulated_key(), *sealed.wrapped_cek())).unwrap();
    let signature = signer.sign_historical_grant(body.exact_bytes()).unwrap();
    let grant = encode_grant(&GrantV1::new(body, signature).unwrap())
        .unwrap()
        .into_vec();
    let hash = object_hash(&grant);
    let mut source = fixture.original.source();
    source.push_exact_bytes("receipts/original.esr", fixture.receipt.clone());
    source.push_exact_bytes("trust/regrant.etb", authorization.clone());
    source.push_exact_bytes("grants/regrant.eag", grant.clone());
    let usable = ea_verify::verify_archive(
        &source,
        &fixture.original.anchor,
        ea_verify::VerifyOptions::new(UnixMillis::new(850)).with_recipient(thumb, &key),
    )
    .unwrap();
    assert!(
        usable.is_fully_verified(),
        "actual real HPKE historical grant is valid before expiry: {}",
        usable.to_canonical_json().unwrap()
    );
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-oldgrant");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let client = common::object_store_client().await;
    for (kind, bytes) in [
        (ObjectTypeV1::Trust, &authorization),
        (ObjectTypeV1::Grant, &grant),
    ] {
        client
            .put_object()
            .bucket(&bucket)
            .key(ea_sync_server::object_key(kind, object_hash(bytes)))
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes.clone()))
            .send()
            .await
            .unwrap();
        sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,$3,$4,800)")
            .bind(object_hash(bytes).as_bytes().as_slice()).bind(fixture.original.anchor.organization_id().as_bytes().as_slice())
            .bind(kind.code() as i16).bind(bytes.len() as i64).execute(database.pool()).await.unwrap();
    }
    sqlx::query("INSERT INTO grants(object_hash,organization_id,entry_hash,recipient_key_thumbprint,grant_kind_code,expires_at_millis) VALUES($1,$2,$3,$4,'historical',900)")
        .bind(hash.as_bytes().as_slice()).bind(fixture.original.anchor.organization_id().as_bytes().as_slice())
        .bind(fixture.original.entry_hash.as_bytes().as_slice()).bind(thumb.as_bytes().as_slice()).execute(database.pool()).await.unwrap();
    let keyname = ea_sync_server::object_key(ObjectTypeV1::Grant, hash);
    client
        .put_object()
        .bucket(&bucket)
        .key(&keyname)
        .body(aws_sdk_s3::primitives::ByteStream::from(grant))
        .send()
        .await
        .unwrap();
    client
        .delete_object()
        .bucket(&bucket)
        .key(&keyname)
        .send()
        .await
        .unwrap();
    let host = common::spawn_server_with_deletion_component(
        database.pool().clone(),
        UnixMillis::new(NOW),
        fixture.original.anchor.organization_id(),
        SERVER_SEED,
        fixture.server,
        &bucket,
        Some((COMPONENT_SEED, fixture.component)),
    )
    .await;
    let ready = common::ReadyServer {
        server: host,
        closure: ready.closure,
    };
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    let saved = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &jobs,
        body: Some(&fixture.body),
        request_id: [0x31; 16],
    })
    .await;
    assert_eq!(
        saved.status,
        202,
        "expired-but-verified ciphertext is still a removal obligation: {:?}",
        common::error_code(&saved.body)
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM destruction_job_versions WHERE object_hash=$1")
            .bind(hash.as_bytes().as_slice())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(
        count, 3,
        "both actual historical grant generations and its marker are frozen"
    );
    let request = transition(&fixture, None, 0, None, 0x32);
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&request),
            request_id: [0x32; 16]
        })
        .await
        .status,
        202
    );
    let start = transition(&fixture, Some(0), 1, Some(object_hash(&request)), 0x33);
    let done = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&start),
        request_id: [0x33; 16],
    })
    .await;
    assert_eq!(done.status, 202);
    let status = DestructionStatusResponseV1::decode(&done.body).unwrap();
    let ParsedArchiveObject::Trust(att) =
        decode_exact_object(status.attestations()[0].exact_object_bytes()).unwrap()
    else {
        panic!()
    };
    let DecodedTrustPayloadV1::DeletionAttestation(att) = att.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert_eq!(att.result, 0);
    assert!(att.removed_object_hashes.contains(&hash));
    assert_eq!(att.removed_object_hashes.len(), 3);
    let remaining = client
        .list_object_versions()
        .bucket(&bucket)
        .prefix(&keyname)
        .send()
        .await
        .unwrap();
    assert!(remaining.versions().is_empty() && remaining.delete_markers().is_empty());
    cleanup_fixture(database, &bucket).await;
}
