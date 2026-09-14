//! Prior exact genesis archive is fixture-seeded; job/event/API/PG/S3 execution
//! after that boundary uses the actual TLS server and real versioned storage.
mod common;
#[path = "../../../crates/ea-verify/tests/support/mod.rs"]
mod verify_support;
use ea_archive::ArchiveInventory;
use ea_crypto::{CoseSigner, SecretBytes, object_hash};
use ea_format::*;
use ea_sync_protocol::{DestructionStatusResponseV1, EndpointV1};
use ea_types::*;
use minicbor::Encoder;
use verify_support::archive_support::trust_support as trust;
const COMPONENT_SEED: [u8; 32] = [0xda; 32];
const CONTROLLER_SEED: [u8; 32] = [0xdc; 32];
const SERVER_SEED: [u8; 32] = [0x51; 32];
const NOW: i64 = 1000;

struct JobFixture {
    now: i64,
    original: verify_support::destruction_v12::OriginalFixture,
    source: verify_support::archive_support::ArchiveFixture,
    auth: Vec<u8>,
    core: Vec<u8>,
    signature: Vec<u8>,
    inventory: Vec<u8>,
    body: Vec<u8>,
    component: CertificateHash,
    controller: CertificateHash,
    server: CertificateHash,
    receipt: Vec<u8>,
    stub: Vec<u8>,
    replica_signers: Vec<(CertificateHash, DeviceId, u64, [u8; 32])>,
}
impl JobFixture {
    fn new() -> Self {
        Self::at(NOW)
    }
    fn at(now: i64) -> Self {
        Self::with_replica_signers(now, false)
    }
    fn with_replica_signers(now: i64, all: bool) -> Self {
        Self::with_options(now, all, false)
    }
    fn with_options(now: i64, all: bool, commit_sender: bool) -> Self {
        let mut original = if commit_sender {
            verify_support::destruction_v12::OriginalFixture::new_with_writer_signer(
                verify_support::COMPLETE_PLAINTEXT_V1,
                &CoseSigner::from_secret(SecretBytes::new([0xe3; 32])),
            )
        } else {
            verify_support::destruction_v12::OriginalFixture::new(
                verify_support::COMPLETE_PLAINTEXT_V1,
            )
        };
        let before = ArchiveInventory::build(&original.source()).unwrap();
        let server_device = before
            .trust()
            .iter()
            .find_map(|v| match v.value().decoded_payload().ok()? {
                DecodedTrustPayloadV1::AuthorizedDevice(c)
                    if c.fields().certificate_kind == CertificateKindV1::ServerReceipt =>
                {
                    Some(c.fields().device_id)
                }
                _ => None,
            })
            .unwrap();
        let add = |original: &mut verify_support::destruction_v12::OriginalFixture,
                   kind,
                   marker,
                   seed| {
            let signer = CoseSigner::from_secret(SecretBytes::new(seed));
            CertificateHash::from(
                original
                    .line
                    .push(
                        trust::ActionSpec::Device {
                            kind,
                            marker,
                            effective_from: Some(1),
                        },
                        trust::HeadOptions {
                            effective_from: Some(1),
                            valid_through: Some(100),
                            issued_at: UnixMillis::new(now),
                            not_after: UnixMillis::new(now + 1_000_000),
                            device_id_override: Some(server_device),
                            signing_public_key_override: Some(signer.public_key().unwrap()),
                            ..Default::default()
                        },
                    )
                    .direct_object_hash
                    .unwrap(),
            )
        };
        let server = add(
            &mut original,
            CertificateKindV1::ServerReceipt,
            0x79,
            SERVER_SEED,
        );
        let component = add(
            &mut original,
            CertificateKindV1::DeletionAttest,
            0x78,
            COMPONENT_SEED,
        );
        let controller = add(
            &mut original,
            CertificateKindV1::DeletionAttest,
            0x77,
            CONTROLLER_SEED,
        );

        let mut replica_signers = vec![(component, server_device, 2, COMPONENT_SEED)];
        if all {
            let source = original.source();
            let inventory = ArchiveInventory::build(&source).unwrap();
            let replicas = inventory
                .trust()
                .iter()
                .filter_map(|v| match v.value().decoded_payload().ok()? {
                    DecodedTrustPayloadV1::AuthorizedDevice(c)
                        if matches!(
                            c.fields().certificate_kind,
                            CertificateKindV1::Writer | CertificateKindV1::Reader
                        ) =>
                    {
                        Some((
                            c.fields().device_id,
                            if c.fields().certificate_kind == CertificateKindV1::Writer {
                                0
                            } else {
                                1
                            },
                        ))
                    }
                    _ => None,
                })
                .collect::<std::collections::BTreeSet<_>>();
            for (index, (device, kind)) in replicas.into_iter().enumerate() {
                let marker = 0xb1 + index as u8;
                let seed = [marker; 32];
                let signer = CoseSigner::from_secret(SecretBytes::new(seed));
                let certificate = CertificateHash::from(
                    original
                        .line
                        .push(
                            trust::ActionSpec::Device {
                                kind: CertificateKindV1::DeletionAttest,
                                marker,
                                effective_from: Some(1),
                            },
                            trust::HeadOptions {
                                effective_from: Some(1),
                                valid_through: Some(100),
                                issued_at: UnixMillis::new(now),
                                not_after: UnixMillis::new(now + 1_000_000),
                                device_id_override: Some(device),
                                signing_public_key_override: Some(signer.public_key().unwrap()),
                                ..Default::default()
                            },
                        )
                        .direct_object_hash
                        .unwrap(),
                );
                replica_signers.push((certificate, device, kind, seed));
            }
        }
        let auth = original.authorization();
        let inventory = ArchiveInventory::build(&original.source()).unwrap();
        let entry = &inventory.entries()[0];
        let manifest = entry.value().manifest().fields();
        let historic = ea_verify::historical_registry_head(
            &inventory,
            &original.anchor,
            manifest.registry_version,
            ObjectHash::try_from(manifest.registry_head_hash.as_slice()).unwrap(),
            manifest.chain_sequence,
            UnixMillis::new(now),
        )
        .unwrap();
        let receipt_cert = historic
            .known_certificate_fields()
            .find(|(_, c)| c.certificate_kind == CertificateKindV1::ServerReceipt)
            .unwrap()
            .0;
        let receipt_core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
            organization_id: original.anchor.organization_id(),
            chain_id: original.anchor.chain_id(),
            chain_sequence: ChainSequence::new(0),
            entry_hash: original.entry_hash,
            entry_object_hash: entry.object_hash(),
            previous_entry_hash: None,
            registry_version: manifest.registry_version,
            registry_head_hash: Hash32::try_from(manifest.registry_head_hash.as_slice()).unwrap(),
            policy_object_hash: object_hash_from_policy(&inventory, historic.policy_fields()),
            initial_grant_plan_hash: Hash32::try_from(manifest.initial_grant_plan_hash.as_slice())
                .unwrap(),
            initial_grant_object_hashes: vec![object_hash(&original.initial_grant_bytes)],
            accepted_at_server: UnixMillis::new(200),
            evidence_due_at: None,
            server_key_thumbprint: trust::authorized_device_signer()
                .public_key()
                .unwrap()
                .thumbprint(),
            server_certificate_hash: receipt_cert,
        })
        .unwrap();
        let receipt_signature = trust::authorized_device_signer()
            .sign_receipt(receipt_core.exact_bytes())
            .unwrap();
        let receipt = encode_receipt(&ReceiptV1::new(receipt_core, receipt_signature).unwrap())
            .unwrap()
            .into_vec();
        let mut source = original.source();
        source.push_exact_bytes("receipts/original.ear", receipt.clone());
        let report = ea_verify::verify_archive(
            &source,
            &original.anchor,
            ea_verify::VerifyOptions::new(UnixMillis::new(now)),
        )
        .unwrap();
        assert!(
            report.is_fully_verified(),
            "exact complete pre-state: {}",
            report.to_canonical_json().unwrap()
        );
        let head = original.head();
        let authority = ea_verify::historical_registry_head(
            &inventory,
            &original.anchor,
            head.version,
            head.object_hash,
            ChainSequence::new(1),
            UnixMillis::new(now),
        )
        .unwrap();
        let authorization =
            ea_destruction::verify_authorization_historical(&auth, &authority).unwrap();
        let stub = encode_destroyed_entry_stub(
            &DestroyedEntryStubV1::new(
                entry.value().signed_manifest().clone(),
                entry.value().writer_signature().to_vec(),
                entry.object_hash(),
                authorization.fields().destruction_id,
                authorization.object_hash(),
            )
            .unwrap(),
        )
        .unwrap()
        .into_vec();
        let mut records = Vec::new();
        for (cert, fields) in authority.known_certificate_fields().filter(|(_, f)| {
            matches!(
                f.certificate_kind,
                CertificateKindV1::Writer
                    | CertificateKindV1::Reader
                    | CertificateKindV1::ServerReceipt
            )
        }) {
            let mut bytes = Vec::new();
            Encoder::new(&mut bytes)
                .array(4)
                .unwrap()
                .u8(0)
                .unwrap()
                .bytes(cert.as_bytes())
                .unwrap()
                .bytes(fields.device_id.as_bytes())
                .unwrap()
                .u8(fields.certificate_kind as u8)
                .unwrap();
            records.push(bytes);
        }
        records.sort_by_key(|record| object_hash(record));
        records.dedup();
        let mut custody = Vec::new();
        let mut e = Encoder::new(&mut custody);
        e.array(6)
            .unwrap()
            .str("EINSATZARCHIV-MANAGED-CUSTODY-v1")
            .unwrap()
            .bytes(original.anchor.organization_id().as_bytes())
            .unwrap()
            .bytes(authorization.fields().destruction_id.as_bytes())
            .unwrap()
            .bytes(authorization.object_hash().as_bytes())
            .unwrap()
            .bytes(original.anchor.chain_id().as_bytes())
            .unwrap()
            .array(records.len() as u64)
            .unwrap();
        for record in records {
            e.bytes(&record).unwrap();
        }
        let mut inventory_bytes = Vec::new();
        let mut e = Encoder::new(&mut inventory_bytes);
        e.array(4)
            .unwrap()
            .str("EINSATZARCHIV-DESTRUCTION-JOB-INVENTORY-v1")
            .unwrap()
            .bytes(&custody)
            .unwrap()
            .array(1)
            .unwrap()
            .array(3)
            .unwrap()
            .bytes(original.entry_hash.as_bytes())
            .unwrap()
            .bytes(entry.object_hash().as_bytes())
            .unwrap()
            .bytes(&stub)
            .unwrap();
        let mut removals = vec![
            (entry.object_hash(), "entries/original.eip"),
            (
                object_hash(&original.initial_grant_bytes),
                "grants/original.eag",
            ),
        ];
        removals.sort_by_key(|(hash, _)| *hash);
        e.array(removals.len() as u64).unwrap();
        for (hash, path) in removals {
            e.array(2)
                .unwrap()
                .bytes(hash.as_bytes())
                .unwrap()
                .array(1)
                .unwrap()
                .str(path)
                .unwrap();
        }
        let report = report.to_canonical_json().unwrap();
        let mut core = Vec::new();
        let mut e = Encoder::new(&mut core);
        e.array(16)
            .unwrap()
            .str("EINSATZARCHIV-DESTRUCTION-PREFLIGHT-v1")
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(original.anchor.organization_id().as_bytes())
            .unwrap()
            .bytes(original.anchor.chain_id().as_bytes())
            .unwrap()
            .bytes(authorization.fields().destruction_id.as_bytes())
            .unwrap()
            .bytes(authorization.object_hash().as_bytes())
            .unwrap()
            .bytes(object_hash(&inventory_bytes).as_bytes())
            .unwrap()
            .bytes(object_hash(report.as_bytes()).as_bytes())
            .unwrap()
            .bytes(report.as_bytes())
            .unwrap()
            .u64(head.version.get())
            .unwrap()
            .bytes(head.object_hash.as_bytes())
            .unwrap()
            .u64(1)
            .unwrap()
            .u64(head.version.get())
            .unwrap()
            .bytes(head.object_hash.as_bytes())
            .unwrap()
            .u64(1)
            .unwrap()
            .i64(now)
            .unwrap();
        let signature = CoseSigner::from_secret(SecretBytes::new(COMPONENT_SEED))
            .sign_destruction_preflight_report(component, &core)
            .unwrap();
        let mut body = Vec::new();
        Encoder::new(&mut body)
            .array(4)
            .unwrap()
            .bytes(&core)
            .unwrap()
            .bytes(&signature)
            .unwrap()
            .bytes(&inventory_bytes)
            .unwrap()
            .bytes(component.as_bytes())
            .unwrap();
        Self {
            now,
            original,
            source,
            auth,
            core,
            signature,
            inventory: inventory_bytes,
            body,
            component,
            controller,
            server,
            receipt,
            stub,
            replica_signers,
        }
    }
    async fn seed(&self, database: &common::TestDatabase, bucket: &str) -> common::ReadyServer {
        use ea_archive::ArchiveSource;
        let now = self.now;
        let pool = database.pool();
        let org = self.original.anchor.organization_id();
        sqlx::query("INSERT INTO organizations(organization_id,root_key_thumbprint,trust_anchor_bytes,created_at_millis) VALUES($1,$2,$3,0)")
            .bind(org.as_bytes().as_slice()).bind(self.original.anchor.root_key_thumbprint().as_bytes().as_slice())
            .bind(self.original.line.exact_anchor_bytes()).execute(pool).await.unwrap();
        let mut blobs = Vec::new();
        self.source
            .visit_blobs(&mut |blob| {
                blobs.push(blob.bytes().to_vec());
                Ok(())
            })
            .unwrap();
        blobs.push(self.auth.clone());
        let s3 = common::object_store_client().await;
        for bytes in blobs {
            let parsed = decode_exact_object(&bytes).unwrap();
            let kind = match &parsed {
                ParsedArchiveObject::Trust(_) => ObjectTypeV1::Trust,
                ParsedArchiveObject::Entry(_) => ObjectTypeV1::Entry,
                ParsedArchiveObject::Grant(_) => ObjectTypeV1::Grant,
                ParsedArchiveObject::Receipt(_) => ObjectTypeV1::Receipt,
                _ => panic!(),
            };
            let hash = object_hash(&bytes);
            s3.put_object()
                .bucket(bucket)
                .key(ea_sync_server::object_key(kind, hash))
                .body(aws_sdk_s3::primitives::ByteStream::from(bytes.clone()))
                .send()
                .await
                .unwrap();
            sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,$3,$4,0)")
                .bind(hash.as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(i16::try_from(kind.code()).unwrap()).bind(bytes.len() as i64).execute(pool).await.unwrap();
            if let ParsedArchiveObject::Trust(t) = parsed
                && t.value().subtype() != TrustSubtypeV1::DestructionAuthorization
            {
                sqlx::query("INSERT INTO trust_events(organization_id,event_id,object_hash,event_code,received_at_millis) VALUES($1,$2,$3,$4,0)")
                        .bind(org.as_bytes().as_slice()).bind(&hash.as_bytes()[..16]).bind(hash.as_bytes().as_slice()).bind(t.value().subtype().as_str()).execute(pool).await.unwrap();
            }
        }
        let inventory = ArchiveInventory::build(&self.source).unwrap();
        let entry = &inventory.entries()[0];
        let f = entry.value().manifest().fields();
        let grant = &inventory.grants()[0];
        sqlx::query("INSERT INTO entries(entry_hash,organization_id,chain_id,sequence_number,previous_entry_hash,entry_object_hash,initial_grant_plan_hash,receipt_object_hash,device_id,accepted_at_server_millis,registry_version,registry_head_hash) VALUES($1,$2,$3,0,NULL,$4,$5,$6,$7,200,$8,$9)")
            .bind(self.original.entry_hash.as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(self.original.anchor.chain_id().as_bytes().as_slice())
            .bind(entry.object_hash().as_bytes().as_slice()).bind(f.initial_grant_plan_hash.as_slice()).bind(object_hash(&self.receipt).as_bytes().as_slice())
            .bind(&[0x95u8;16][..]).bind(f.registry_version.get() as i64).bind(f.registry_head_hash.as_slice()).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO grants(object_hash,organization_id,entry_hash,recipient_key_thumbprint,grant_kind_code) VALUES($1,$2,$3,$4,'initial')")
            .bind(grant.object_hash().as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(self.original.entry_hash.as_bytes().as_slice())
            .bind(grant.value().grant_body().fields().recipient_key_thumbprint.as_bytes().as_slice()).execute(pool).await.unwrap();
        common::trust_closure::seed_chain_head(
            pool,
            org,
            self.original.anchor.chain_id(),
            0,
            *self.original.entry_hash.as_bytes(),
            200,
        )
        .await;
        let id = DestructionId::try_from(&[0x74; 16][..]).unwrap();
        sqlx::query("INSERT INTO destructions(organization_id,destruction_id,authorization_object_hash,state_code,requested_at_millis) VALUES($1,$2,$3,0,1000)")
            .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(object_hash(&self.auth).as_bytes().as_slice()).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO destruction_targets(organization_id,destruction_id,entry_hash,chain_sequence) VALUES($1,$2,$3,0)")
            .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(self.original.entry_hash.as_bytes().as_slice()).execute(pool).await.unwrap();
        let server = common::spawn_server_with_deletion_component(
            pool.clone(),
            UnixMillis::new(now),
            org,
            SERVER_SEED,
            self.server,
            bucket,
            Some((COMPONENT_SEED, self.component)),
        )
        .await;
        let head = self.original.head();
        let closure = common::trust_closure::ExtendedClosure {
            organization_id: org,
            chain_id: self.original.anchor.chain_id(),
            writer_certificate_hash: f.writer_certificate_hash,
            reader_certificate_hash: grant
                .value()
                .grant_body()
                .fields()
                .recipient_certificate_hash,
            recovery_certificate_hash: grant
                .value()
                .grant_body()
                .fields()
                .recipient_certificate_hash,
            server_receipt_certificate_hash: self.server,
            second_reader_certificate_hash: None,
            historical_grant_authority_certificate_hash: None,
            approver_certificate_hashes: Some(self.original.approvers),
            deletion_certificate_hash: Some(self.component),
            registry_version: head.version,
            registry_head_hash: head.object_hash,
            objects: Vec::new(),
        };
        common::ReadyServer { server, closure }
    }
}
fn object_hash_from_policy(inventory: &ArchiveInventory, fields: &PolicyFieldsV1) -> ObjectHash {
    inventory
        .trust()
        .iter()
        .find_map(|t| match t.value().decoded_payload().ok()? {
            DecodedTrustPayloadV1::Policy(p) if p.fields() == fields => Some(t.object_hash()),
            _ => None,
        })
        .unwrap()
}
#[tokio::test]
async fn valid_signed_full_preflight_is_accepted_through_tls_and_frozen_in_postgres() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-jobs");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let path = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let upload = ea_sync_protocol::DestructionJobUploadV1::decode(&fixture.body).unwrap();
    assert_eq!(upload.core_bytes(), fixture.core);
    assert_eq!(upload.signature_bytes(), fixture.signature);
    assert_eq!(upload.inventory_bytes(), fixture.inventory);
    let mut tampered = fixture.signature.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let invalid = ea_sync_protocol::DestructionJobUploadV1::new(
        &fixture.core,
        &tampered,
        &fixture.inventory,
        fixture.component,
    )
    .unwrap();
    let bad = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &path,
        body: Some(invalid.exact_bytes()),
        request_id: [0x40; 16],
    })
    .await;
    assert_eq!(bad.status, 422);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    let original_hash = object_hash(&fixture.original.original_bytes);
    let client = common::object_store_client().await;
    let key = ea_sync_server::object_key(ObjectTypeV1::Entry, original_hash);
    for _ in 0..2 {
        client
            .put_object()
            .bucket(&bucket)
            .key(&key)
            .body(aws_sdk_s3::primitives::ByteStream::from(
                fixture.original.original_bytes.clone(),
            ))
            .send()
            .await
            .unwrap();
    }
    client
        .delete_object()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert!(
        client
            .get_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .is_err(),
        "delete marker hides but never removes old versions"
    );
    let response = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: CONTROLLER_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &path,
        body: Some(&fixture.body),
        request_id: [0x42; 16],
    })
    .await;
    assert_eq!(
        response.status,
        202,
        "full exact signed job must persist: {:?}",
        common::error_code(&response.body)
    );
    let status = DestructionStatusResponseV1::decode(&response.body).unwrap();
    assert_eq!(
        status.state(),
        0,
        "a saved preflight is no deletion success"
    );
    let saved: Vec<u8> = sqlx::query_scalar("SELECT exact_upload FROM destruction_jobs")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(saved, fixture.body);

    let actor: Vec<u8> = sqlx::query_scalar("SELECT principal_certificate FROM destruction_jobs")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        actor,
        fixture.controller.as_bytes(),
        "the current action principal is distinct from the historical signer"
    );
    let changed_signature = CoseSigner::from_secret(SecretBytes::new(CONTROLLER_SEED))
        .sign_destruction_preflight_report(fixture.controller, &fixture.core)
        .unwrap();
    let changed = ea_sync_protocol::DestructionJobUploadV1::new(
        &fixture.core,
        &changed_signature,
        &fixture.inventory,
        fixture.controller,
    )
    .unwrap();
    let conflict = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: CONTROLLER_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &path,
        body: Some(changed.exact_bytes()),
        request_id: [0x44; 16],
    })
    .await;
    assert_eq!(
        conflict.status, 409,
        "a different valid exact job cannot replace the immutable saved packet"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_job_versions")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        count, 5,
        "all three EIP generations, its delete marker and one grant generation"
    );
    let markers: i64 =
        sqlx::query_scalar("SELECT count(*) FROM destruction_job_versions WHERE delete_marker")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(markers, 1);
    assert!(fixture.stub.len() > 100);
    assert!(
        sqlx::query("DELETE FROM destruction_jobs")
            .execute(database.pool())
            .await
            .is_err(),
        "durable exact job is immutable"
    );
    let restarted = common::spawn_server_in_bucket(
        database.pool().clone(),
        UnixMillis::new(NOW),
        fixture.original.anchor.organization_id(),
        SERVER_SEED,
        fixture.server,
        &bucket,
    )
    .await;
    let ready = common::ReadyServer {
        server: restarted,
        closure: ready.closure,
    };
    let replay = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &path,
        body: Some(&fixture.body),
        request_id: [0x43; 16],
    })
    .await;
    assert_eq!(replay.status, 202);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_job_versions")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        after, 5,
        "restart exact replay retains the original frozen versions"
    );
    cleanup_fixture(database, &bucket).await;
}

fn transition(
    fixture: &JobFixture,
    from: Option<u8>,
    to: u8,
    previous: Option<ObjectHash>,
    marker: u8,
) -> Vec<u8> {
    let payload = TrustPayloadV1::destruction_transition(DestructionTransitionFieldsV1 {
        destruction_id: DestructionId::try_from(&[0x74; 16][..]).unwrap(),
        destruction_authorization_object_hash: object_hash(&fixture.auth),
        event_id: EventId::try_from(&[marker; 16][..]).unwrap(),
        previous_event_object_hash: previous,
        from_state: from,
        to_state: to,
        trigger_code: u64::from(to),
        executed_at: UnixMillis::new(fixture.now),
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(COMPONENT_SEED))
        .sign_destruction_transition_digest(
            fixture.component,
            payload.exact_digest_input(),
            &fixture.auth,
        )
        .unwrap();
    encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
        .unwrap()
        .into_vec()
}
#[tokio::test]
async fn durable_started_job_removes_every_s3_generation_and_records_only_server_measurement() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-execute");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let s3 = common::object_store_client().await;
    let eip_key = ea_sync_server::object_key(
        ObjectTypeV1::Entry,
        object_hash(&fixture.original.original_bytes),
    );
    for _ in 0..2 {
        s3.put_object()
            .bucket(&bucket)
            .key(&eip_key)
            .body(aws_sdk_s3::primitives::ByteStream::from(
                fixture.original.original_bytes.clone(),
            ))
            .send()
            .await
            .unwrap();
    }
    s3.delete_object()
        .bucket(&bucket)
        .key(&eip_key)
        .send()
        .await
        .unwrap();
    let staged_key = "staging/eip/interrupted-original";
    for _ in 0..2 {
        s3.put_object()
            .bucket(&bucket)
            .key(staged_key)
            .body(aws_sdk_s3::primitives::ByteStream::from(
                fixture.original.original_bytes.clone(),
            ))
            .send()
            .await
            .unwrap();
    }
    s3.delete_object()
        .bucket(&bucket)
        .key(staged_key)
        .send()
        .await
        .unwrap();

    let backup_key = "backups/managed-generation-previous/eip-copy";
    s3.put_object()
        .bucket(&bucket)
        .key(backup_key)
        .body(aws_sdk_s3::primitives::ByteStream::from(
            fixture.original.original_bytes.clone(),
        ))
        .send()
        .await
        .unwrap();
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let accepted = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &jobs,
        body: Some(&fixture.body),
        request_id: [0x61; 16],
    })
    .await;
    assert_eq!(accepted.status, 202);
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    let request = transition(&fixture, None, 0, None, 0x61);
    let accepted = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&request),
        request_id: [0x62; 16],
    })
    .await;
    assert_eq!(accepted.status, 202);
    let start = transition(&fixture, Some(0), 1, Some(object_hash(&request)), 0x62);
    let executed = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&start),
        request_id: [0x63; 16],
    })
    .await;
    assert_eq!(
        executed.status,
        202,
        "valid durable job must execute: {:?}",
        common::error_code(&executed.body)
    );
    let state = DestructionStatusResponseV1::decode(&executed.body).unwrap();
    assert_eq!(state.state(), 1, "Writer and Reader remain outstanding");
    assert_eq!(state.transitions().len(), 2);
    assert_eq!(state.attestations().len(), 1);
    for (kind, hash) in [
        (
            ObjectTypeV1::Entry,
            object_hash(&fixture.original.original_bytes),
        ),
        (
            ObjectTypeV1::Grant,
            object_hash(&fixture.original.initial_grant_bytes),
        ),
    ] {
        let key = ea_sync_server::object_key(kind, hash);
        let list = s3
            .list_object_versions()
            .bucket(&bucket)
            .prefix(&key)
            .send()
            .await
            .unwrap();
        assert!(
            list.versions().is_empty() && list.delete_markers().is_empty(),
            "every actual version removed"
        );
    }
    let staged = s3
        .list_object_versions()
        .bucket(&bucket)
        .prefix(staged_key)
        .send()
        .await
        .unwrap();
    assert!(
        staged.versions().is_empty() && staged.delete_markers().is_empty(),
        "interrupted staging generations are managed holdings too"
    );
    let stub = s3
        .get_object()
        .bucket(&bucket)
        .key(ea_sync_server::object_key(
            ObjectTypeV1::Destroyed,
            object_hash(&fixture.stub),
        ))
        .send()
        .await
        .unwrap()
        .body
        .collect()
        .await
        .unwrap()
        .into_bytes();
    assert_eq!(stub.as_ref(), fixture.stub);
    let exact = s3
        .get_object()
        .bucket(&bucket)
        .key(ea_sync_server::object_key(
            ObjectTypeV1::Trust,
            state.attestations()[0].object_hash(),
        ))
        .send()
        .await
        .unwrap()
        .body
        .collect()
        .await
        .unwrap()
        .into_bytes();
    let inventory = ArchiveInventory::build(&fixture.source).unwrap();
    let head = fixture.original.head();
    let historical = ea_verify::historical_registry_head(
        &inventory,
        &fixture.original.anchor,
        head.version,
        head.object_hash,
        ChainSequence::new(1),
        UnixMillis::new(NOW),
    )
    .unwrap();
    let auth = ea_destruction::verify_authorization_historical(&fixture.auth, &historical).unwrap();
    let attestation = ea_destruction::verify_attestation_historical(
        &exact,
        &auth,
        &historical,
        UnixMillis::new(NOW),
    )
    .unwrap();
    assert_eq!(attestation.fields().replica_kind, 2);
    assert_eq!(attestation.fields().result, 0);
    assert_eq!(attestation.fields().removed_object_hashes.len(), 2);
    let exported = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::ArchiveExports,
        target: EndpointV1::ArchiveExports.path_template(),
        body: None,
        request_id: [0x64; 16],
    })
    .await;
    assert_eq!(
        exported.status,
        200,
        "normal archive export must serve the replacement stub: {:?}",
        common::error_code(&exported.body)
    );
    use ea_sync_server::ArchiveExportDirectory;
    let repository =
        einsatzarchiv_server::adapters::postgres::PostgresRepository::new(database.pool().clone());
    let mut index = repository
        .objects_after(fixture.original.anchor.organization_id(), 0, 500)
        .await
        .unwrap();
    index.sort_by_key(|i| i.object.object_hash);
    assert!(!index.iter().any(|i| {
        attestation
            .fields()
            .removed_object_hashes
            .contains(&i.object.object_hash)
    }));
    assert!(
        index
            .iter()
            .any(|i| i.object.kind == ObjectTypeV1::Destroyed
                && i.object.object_hash == object_hash(&fixture.stub))
    );
    let size: usize = index.iter().map(|i| i.object.size_bytes as usize).sum();
    let manifest =
        ea_sync_protocol::ArchiveExportManifestV1::decode(&exported.body[size..]).unwrap();
    assert_eq!(manifest.sorted_objects().len(), index.len());
    let mut offset = 0;
    let mut archived = verify_support::archive_support::ArchiveFixture::default();
    for record in manifest.sorted_objects() {
        let len = record.byte_length() as usize;
        let bytes = &exported.body[offset..offset + len];
        offset += len;
        assert!(object_hash(bytes) == record.object_hash());
        let kind = decode_exact_object(bytes).unwrap();
        let dir = match kind {
            ParsedArchiveObject::Trust(_) => "trust",
            ParsedArchiveObject::Destroyed(_) => "entries",
            ParsedArchiveObject::Receipt(_) => "receipts",
            _ => panic!("unexpected export object"),
        };
        archived.push_exact_bytes(
            &format!("{dir}/{}", hex::encode(record.object_hash().as_bytes())),
            bytes.to_vec(),
        );
    }
    let verified = ea_verify::verify_archive(
        &archived,
        &fixture.original.anchor,
        ea_verify::VerifyOptions::new(UnixMillis::new(NOW)),
    )
    .unwrap();
    assert!(
        !verified.is_fully_verified(),
        "encrypted WriterEvidence remains required"
    );
    assert!(
        verified.verified_public_chain_head().is_some(),
        "exact signed manifest identity still supplies public chain progress"
    );

    let backups = s3
        .list_object_versions()
        .bucket(&bucket)
        .prefix(backup_key)
        .send()
        .await
        .unwrap();
    assert!(
        backups.versions().is_empty() && backups.delete_markers().is_empty(),
        "actual managed backup copy must be measured and removed"
    );
    cleanup_fixture(database, &bucket).await;
}

#[tokio::test]
async fn reserved_target_cannot_enter_real_s3_staging_again() {
    use ea_sync_server::ObjectStore;
    use einsatzarchiv_server::adapters::{
        clock::FixedClock, postgres::PostgresRepository, s3::S3ObjectStore,
    };
    use std::sync::Arc;
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-barrier");
    common::ensure_bucket(&bucket).await;
    let _ready = fixture.seed(&database, &bucket).await;
    let repo = Arc::new(PostgresRepository::new(database.pool().clone()));
    let store = S3ObjectStore::new(
        common::object_store_client().await,
        bucket.clone(),
        fixture.original.anchor.organization_id(),
        repo.clone(),
        repo,
        Arc::new(FixedClock(UnixMillis::new(NOW))),
    );
    for (kind, bytes) in [
        (ObjectTypeV1::Entry, fixture.original.original_bytes.clone()),
        (
            ObjectTypeV1::Grant,
            fixture.original.initial_grant_bytes.clone(),
        ),
    ] {
        assert!(
            store
                .stage_stream(
                    kind,
                    aws_sdk_s3::primitives::ByteStream::from(bytes),
                    MAX_ARCHIVE_OBJECT_BYTES_V1 as u64
                )
                .await
                .is_err(),
            "reserved target must be blocked before provider staging"
        );
    }
    let list = common::object_store_client()
        .await
        .list_object_versions()
        .bucket(&bucket)
        .prefix("staging/")
        .send()
        .await
        .unwrap();
    assert!(list.versions().is_empty() && list.delete_markers().is_empty());
    cleanup_fixture(database, &bucket).await;
}

fn server_claim(fixture: &JobFixture, replica_kind: u64, hashes: Vec<ObjectHash>) -> Vec<u8> {
    server_claim_at(fixture, replica_kind, hashes, fixture.now)
}
fn server_claim_at(
    fixture: &JobFixture,
    replica_kind: u64,
    hashes: Vec<ObjectHash>,
    at: i64,
) -> Vec<u8> {
    let cert = ArchiveInventory::build(&fixture.source)
        .unwrap()
        .trust()
        .iter()
        .find_map(|t| match t.value().decoded_payload().ok()? {
            DecodedTrustPayloadV1::AuthorizedDevice(c)
                if t.object_hash().as_bytes() == fixture.component.as_bytes() =>
            {
                Some(c.fields().clone())
            }
            _ => None,
        })
        .unwrap();
    let payload = TrustPayloadV1::deletion_attestation(DeletionAttestationFieldsV1 {
        destruction_id: DestructionId::try_from(&[0x74; 16][..]).unwrap(),
        destruction_authorization_object_hash: object_hash(&fixture.auth),
        replica_id: *cert.device_id.as_bytes(),
        replica_kind,
        removed_object_hashes: hashes,
        result: 0,
        backup_expiry_at: None,
        executed_at: UnixMillis::new(at),
    })
    .unwrap();
    let signature = CoseSigner::from_secret(SecretBytes::new(COMPONENT_SEED))
        .sign_deletion_attestation_digest(
            fixture.component,
            payload.exact_digest_input(),
            &fixture.auth,
        )
        .unwrap();
    encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap())
        .unwrap()
        .into_vec()
}
#[tokio::test]
async fn exact_replica_attestation_is_ingested_without_claiming_other_replicas_complete() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-attestation");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let saved = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &jobs,
        body: Some(&fixture.body),
        request_id: [0x81; 16],
    })
    .await;
    assert_eq!(saved.status, 202);
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    let mut hashes = vec![
        object_hash(&fixture.original.original_bytes),
        object_hash(&fixture.original.initial_grant_bytes),
    ];
    hashes.sort();

    let mut foreign = hashes.clone();
    foreign.push(ObjectHash::try_from(&[0xfe; 32][..]).unwrap());
    foreign.sort();
    foreign.dedup();
    for (marker, invalid) in [
        (0x80, server_claim(&fixture, 2, foreign)),
        (0x83, server_claim_at(&fixture, 2, hashes.clone(), NOW - 1)),
    ] {
        let refused = common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&invalid),
            request_id: [marker; 16],
        })
        .await;
        assert_eq!(
            refused.status, 409,
            "unknown removed-object membership or deletion predating complete preflight must remain unresolved"
        );
    }
    let exact = server_claim(&fixture, 2, hashes);
    let result = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&exact),
        request_id: [0x82; 16],
    })
    .await;
    assert_eq!(
        result.status,
        202,
        "existing exact v1 attestation is distinct from a transition: {:?}",
        common::error_code(&result.body)
    );
    let status = DestructionStatusResponseV1::decode(&result.body).unwrap();
    assert_eq!(status.state(), 0);
    assert_eq!(status.attestations().len(), 1);
    assert_eq!(status.attestations()[0].exact_object_bytes(), exact);
    // Uploading a claim is no instruction to remove bytes.
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

#[tokio::test]
async fn pending_backup_resumes_the_same_job_only_after_actual_version_removal() {
    use aws_sdk_s3::types::{
        ObjectLockLegalHold, ObjectLockLegalHoldStatus, ObjectLockRetention,
        ObjectLockRetentionMode,
    };
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let fixture = JobFixture::with_replica_signers(wall, true);
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-retained");
    let s3 = common::object_store_client().await;
    s3.create_bucket()
        .bucket(&bucket)
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let missing_metadata_job = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    assert_eq!(
        common::call_at(
            &common::ApiCall {
                ready: &ready,
                signer_seed: COMPONENT_SEED,
                endpoint: EndpointV1::DestructionJobs,
                target: &missing_metadata_job,
                body: Some(&fixture.body),
                request_id: [0x9f; 16],
            },
            wall
        )
        .await
        .status,
        503,
        "actual ObjectLock provider objects without retention information cannot be frozen as unlocked"
    );
    let stored_jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(stored_jobs, 0);
    let deadline = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 4)
        * 1000;
    for (kind, hash) in [
        (
            ObjectTypeV1::Entry,
            object_hash(&fixture.original.original_bytes),
        ),
        (
            ObjectTypeV1::Grant,
            object_hash(&fixture.original.initial_grant_bytes),
        ),
    ] {
        let key = ea_sync_server::object_key(kind, hash);
        let head = s3
            .head_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .unwrap();
        let version = head.version_id().unwrap();
        s3.put_object_legal_hold()
            .bucket(&bucket)
            .key(&key)
            .version_id(version)
            .legal_hold(
                ObjectLockLegalHold::builder()
                    .status(ObjectLockLegalHoldStatus::Off)
                    .build(),
            )
            .send()
            .await
            .unwrap();
        {
            s3.put_object_retention()
                .bucket(&bucket)
                .key(&key)
                .version_id(version)
                .retention(
                    ObjectLockRetention::builder()
                        .mode(ObjectLockRetentionMode::Governance)
                        .retain_until_date(aws_sdk_s3::primitives::DateTime::from_millis(deadline))
                        .build(),
                )
                .send()
                .await
                .unwrap();
        }
    }
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    let saved = common::call_at(
        &common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0xa1; 16],
        },
        wall,
    )
    .await;
    assert_eq!(
        saved.status,
        202,
        "actual retention preflight {:?}",
        common::error_code(&saved.body)
    );
    let request = transition(&fixture, None, 0, None, 0xa1);
    assert_eq!(
        common::call_at(
            &common::ApiCall {
                ready: &ready,
                signer_seed: COMPONENT_SEED,
                endpoint: EndpointV1::DestructionEvents,
                target: &events,
                body: Some(&request),
                request_id: [0xa2; 16]
            },
            wall
        )
        .await
        .status,
        202
    );
    let start = transition(&fixture, Some(0), 1, Some(object_hash(&request)), 0xa2);
    let attempted = common::call_at(
        &common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&start),
            request_id: [0xa3; 16],
        },
        wall,
    )
    .await;
    assert_eq!(
        attempted.status,
        202,
        "retention becomes measured pending, never removal success: {:?}",
        common::error_code(&attempted.body)
    );
    let pending = DestructionStatusResponseV1::decode(&attempted.body).unwrap();
    let parsed = decode_exact_object(pending.attestations()[0].exact_object_bytes()).unwrap();
    let ParsedArchiveObject::Trust(att) = parsed else {
        panic!()
    };
    let DecodedTrustPayloadV1::DeletionAttestation(att) = att.value().decoded_payload().unwrap()
    else {
        panic!()
    };
    assert_eq!(att.result, 1);
    assert_eq!(att.backup_expiry_at, Some(UnixMillis::new(deadline)));
    let event = transition(&fixture, Some(1), 2, Some(object_hash(&start)), 0xa3);
    // Spec §16.3: inProgress→pendingBackupExpiry only once every immediately
    // removable known replica is attested. The Writer and Reader duties of the
    // frozen denominator have no claim yet, so the server refuses the edge.
    let premature = common::call_at(
        &common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&event),
            request_id: [0xb0; 16],
        },
        wall,
    )
    .await;
    assert_eq!(
        (premature.status, common::error_code(&premature.body)),
        (409, Some("EA-DESTRUCTION-CONFLICT".to_owned())),
        "an unattested immediate replica duty prevents pendingBackupExpiry"
    );
    let mut removed = vec![
        object_hash(&fixture.original.original_bytes),
        object_hash(&fixture.original.initial_grant_bytes),
    ];
    removed.sort();
    let immediate = &fixture.replica_signers[1..];
    assert!(
        !immediate.is_empty(),
        "the frozen denominator has immediate duties"
    );
    for (index, (certificate, device, kind, seed)) in immediate.iter().enumerate() {
        let payload = TrustPayloadV1::deletion_attestation(DeletionAttestationFieldsV1 {
            destruction_id: DestructionId::try_from(&[0x74; 16][..]).unwrap(),
            destruction_authorization_object_hash: object_hash(&fixture.auth),
            replica_id: *device.as_bytes(),
            replica_kind: *kind,
            removed_object_hashes: removed.clone(),
            result: 0,
            backup_expiry_at: None,
            executed_at: UnixMillis::new(wall),
        })
        .unwrap();
        let signature = CoseSigner::from_secret(SecretBytes::new(*seed))
            .sign_deletion_attestation_digest(
                *certificate,
                payload.exact_digest_input(),
                &fixture.auth,
            )
            .unwrap();
        let exact = encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap()).unwrap();
        let accepted = common::call_at(
            &common::ApiCall {
                ready: &ready,
                signer_seed: CONTROLLER_SEED,
                endpoint: EndpointV1::DestructionEvents,
                target: &events,
                body: Some(exact.as_bytes()),
                request_id: [0xb1 + index as u8; 16],
            },
            wall,
        )
        .await;
        assert_eq!(
            accepted.status,
            202,
            "immediate replica removal claim is recorded: {:?}",
            common::error_code(&accepted.body)
        );
    }
    let pending = common::call_at(
        &common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&event),
            request_id: [0xa4; 16],
        },
        wall,
    )
    .await;
    assert_eq!(
        pending.status,
        202,
        "all immediate duties attested, server retention still running: {:?}",
        common::error_code(&pending.body)
    );
    let newer = common::spawn_server_with_deletion_component(
        database.pool().clone(),
        UnixMillis::new(deadline + 1),
        fixture.original.anchor.organization_id(),
        SERVER_SEED,
        fixture.server,
        &bucket,
        Some((COMPONENT_SEED, fixture.component)),
    )
    .await;
    let ready = common::ReadyServer {
        server: newer,
        closure: ready.closure,
    };
    // Simply selecting a later trusted clock has not deleted the object.
    let key = ea_sync_server::object_key(
        ObjectTypeV1::Entry,
        object_hash(&fixture.original.original_bytes),
    );
    assert!(
        s3.get_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .is_ok()
    );
    let resumed = common::call_at(
        &common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0xa5; 16],
        },
        deadline + 1,
    )
    .await;
    assert_eq!(
        resumed.status,
        202,
        "same exact job resumes physical measurement: {:?}",
        common::error_code(&resumed.body)
    );
    let done = DestructionStatusResponseV1::decode(&resumed.body).unwrap();
    assert_eq!(done.state(), 2, "no artificial pending→inProgress edge");
    // Server pending + server removal after the deadline + one claim per
    // immediate Writer/Reader duty.
    assert_eq!(
        done.attestations().len(),
        2 + fixture.replica_signers.len() - 1
    );
    let remaining = s3
        .list_object_versions()
        .bucket(&bucket)
        .prefix(&key)
        .send()
        .await
        .unwrap();
    assert!(
        remaining.versions().is_empty() && remaining.delete_markers().is_empty(),
        "actual provider generations removed after deadline"
    );
    cleanup_fixture(database, &bucket).await;
}

#[tokio::test]
async fn indexed_grant_with_invalid_cose_is_not_a_verified_removal_obligation() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-grant-membership");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let mut forged = fixture.original.initial_grant_bytes.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(matches!(
        decode_exact_object(&forged).unwrap(),
        ParsedArchiveObject::Grant(_)
    ));
    let hash = object_hash(&forged);
    common::object_store_client()
        .await
        .put_object()
        .bucket(&bucket)
        .key(ea_sync_server::object_key(ObjectTypeV1::Grant, hash))
        .body(aws_sdk_s3::primitives::ByteStream::from(forged.clone()))
        .send()
        .await
        .unwrap();
    sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,2,$3,0)")
        .bind(hash.as_bytes().as_slice()).bind(fixture.original.anchor.organization_id().as_bytes().as_slice()).bind(forged.len() as i64)
        .execute(database.pool()).await.unwrap();
    sqlx::query("UPDATE grants SET object_hash=$1")
        .bind(hash.as_bytes().as_slice())
        .execute(database.pool())
        .await
        .unwrap();
    let path = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let rejected = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &path,
        body: Some(&fixture.body),
        request_id: [0xb1; 16],
    })
    .await;
    assert_eq!(
        rejected.status, 422,
        "a DB row and matching plan fields never replace grant COSE verification"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    cleanup_fixture(database, &bucket).await;
}

#[tokio::test]
async fn unsigned_database_state_cannot_claim_completed_destruction() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-state");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    sqlx::query("UPDATE destructions SET state_code=3")
        .execute(database.pool())
        .await
        .unwrap();
    let path = format!("/v1/destructions/{}", hex::encode([0x74; 16]));
    let result = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionStatus,
        target: &path,
        body: None,
        request_id: [0xc1; 16],
    })
    .await;
    assert_eq!(
        result.status, 409,
        "unsigned database code must not replace signed history"
    );
    cleanup_fixture(database, &bucket).await;
}

#[tokio::test]
async fn unindexed_target_holding_prevents_a_complete_provider_freeze() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-orphan");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let mut orphan = fixture.original.initial_grant_bytes.clone();
    *orphan.last_mut().unwrap() ^= 1;
    common::object_store_client()
        .await
        .put_object()
        .bucket(&bucket)
        .key(ea_sync_server::object_key(
            ObjectTypeV1::Grant,
            object_hash(&orphan),
        ))
        .body(aws_sdk_s3::primitives::ByteStream::from(orphan))
        .send()
        .await
        .unwrap();
    let path = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let result = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &path,
        body: Some(&fixture.body),
        request_id: [0xc2; 16],
    })
    .await;
    assert_eq!(
        result.status, 409,
        "an unverified target-owned provider generation must remain unresolved"
    );
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(jobs, 0);
    cleanup_fixture(database, &bucket).await;
}

#[tokio::test]
async fn failed_measurement_flush_preserves_start_and_resumes_after_host_restart() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-failflush");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0xd1; 16]
        })
        .await
        .status,
        202
    );
    let request = transition(&fixture, None, 0, None, 0xd1);
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&request),
            request_id: [0xd2; 16]
        })
        .await
        .status,
        202
    );
    sqlx::raw_sql("CREATE FUNCTION fail_measurement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test durable flush failure'; END; $$; CREATE TRIGGER fail_measurement BEFORE INSERT ON destruction_server_measurements FOR EACH ROW EXECUTE FUNCTION fail_measurement();")
        .execute(database.pool()).await.unwrap();
    let start = transition(&fixture, Some(0), 1, Some(object_hash(&request)), 0xd2);
    let failed = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&start),
        request_id: [0xd3; 16],
    })
    .await;
    assert_eq!(
        failed.status, 503,
        "uncertain durable measurement must not return success"
    );
    let states:(i16,i64,i64)=sqlx::query_as("SELECT state_code,(SELECT count(*) FROM destruction_server_measurements),(SELECT count(*) FROM destruction_attestations) FROM destructions")
        .fetch_one(database.pool()).await.unwrap();
    assert_eq!(
        states,
        (1, 0, 0),
        "valid start remains, no measured success was committed"
    );
    let s3 = common::object_store_client().await;
    let key = ea_sync_server::object_key(
        ObjectTypeV1::Entry,
        object_hash(&fixture.original.original_bytes),
    );
    let before = s3
        .list_object_versions()
        .bucket(&bucket)
        .prefix(&key)
        .send()
        .await
        .unwrap();
    assert!(
        before.versions().is_empty() && before.delete_markers().is_empty(),
        "provider action really happened before the failed PG flush"
    );
    assert!(
        s3.get_object()
            .bucket(&bucket)
            .key(ea_sync_server::object_key(
                ObjectTypeV1::Destroyed,
                object_hash(&fixture.stub)
            ))
            .send()
            .await
            .is_ok()
    );
    sqlx::raw_sql("DROP TRIGGER fail_measurement ON destruction_server_measurements; DROP FUNCTION fail_measurement();").execute(database.pool()).await.unwrap();
    let host = common::spawn_server_with_deletion_component(
        database.pool().clone(),
        UnixMillis::new(NOW + 1),
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
    let resumed = common::call_at(
        &common::ApiCall {
            ready: &ready,
            signer_seed: CONTROLLER_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0xd4; 16],
        },
        NOW + 1,
    )
    .await;
    assert_eq!(
        resumed.status, 202,
        "same exact persisted job must measure actual remaining inventory after restart"
    );
    let status = DestructionStatusResponseV1::decode(&resumed.body).unwrap();
    assert_eq!(status.state(), 1);
    assert_eq!(status.attestations().len(), 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM destruction_server_measurements WHERE result_code=0",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);

    let actor:Option<String>=sqlx::query_scalar("SELECT encode((to_jsonb(m)->>'controller_certificate')::bytea,'hex') FROM destruction_server_measurements m")
        .fetch_one(database.pool()).await.unwrap();
    assert_eq!(
        actor,
        Some(hex::encode(fixture.controller.as_bytes())),
        "physical resume must audit its fresh controller"
    );
    cleanup_fixture(database, &bucket).await;
}

#[tokio::test]
async fn revoked_historical_attester_can_be_transported_only_by_a_current_original_controller() {
    let mut fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-revoked");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0xe1; 16]
        })
        .await
        .status,
        202
    );
    let mut hashes = vec![
        object_hash(&fixture.original.original_bytes),
        object_hash(&fixture.original.initial_grant_bytes),
    ];
    hashes.sort();
    let historical = server_claim(&fixture, 2, hashes.clone());
    fixture.original.line.push(
        trust::ActionSpec::Revoke {
            target_kind: 2,
            object_hash: ObjectHash::try_from(fixture.component.as_bytes().as_slice()).unwrap(),
        },
        trust::HeadOptions {
            effective_from: Some(2),
            valid_through: Some(100),
            issued_at: UnixMillis::new(NOW),
            not_after: UnixMillis::new(NOW + 1_000_000),
            ..Default::default()
        },
    );
    // Only prior trusted catalogue/progress is fixture-seeded. The fresh HTTP
    // authentication, historical COSE intake and storage below are real.
    publish_new_line(&fixture, &database, &bucket).await;
    let s3 = common::object_store_client().await;
    sqlx::query("UPDATE chain_heads SET head_sequence=1,head_entry_hash=$1,head_accepted_at_server_millis=$2").bind(&[0xefu8;32][..]).bind(NOW).execute(database.pool()).await.unwrap();
    let rejected = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&historical),
        request_id: [0xe2; 16],
    })
    .await;
    assert_eq!(
        rejected.status, 401,
        "revoked controller cannot authenticate a fresh HTTP intake"
    );
    let accepted = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: CONTROLLER_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&historical),
        request_id: [0xe3; 16],
    })
    .await;
    assert_eq!(
        accepted.status,
        202,
        "historical valid signer need not remain currently active for pure transport: {:?}",
        common::error_code(&accepted.body)
    );
    let status = DestructionStatusResponseV1::decode(&accepted.body).unwrap();
    assert_eq!(status.state(), 0);
    assert_eq!(status.attestations()[0].exact_object_bytes(), historical);
    let old_transition = transition(&fixture, None, 0, None, 0xe1);
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: CONTROLLER_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&old_transition),
            request_id: [0xe4; 16]
        })
        .await
        .status,
        422,
        "new transition COSE signer must be the current controller"
    );
    for (marker, body) in [
        (0xe5, server_claim(&fixture, 1, hashes)),
        (0xe6, {
            let mut v = historical.clone();
            *v.last_mut().unwrap() ^= 1;
            v
        }),
    ] {
        let rejected = common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: CONTROLLER_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&body),
            request_id: [marker; 16],
        })
        .await;
        assert!(
            matches!(rejected.status, 409 | 422),
            "wrong kind or invalid COSE must not be admitted"
        );
    }
    let audit: Vec<u8> =
        sqlx::query_scalar("SELECT principal_certificate FROM destruction_attestation_intake")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(audit, fixture.controller.as_bytes());
    assert!(
        s3.get_object()
            .bucket(&bucket)
            .key(ea_sync_server::object_key(
                ObjectTypeV1::Entry,
                object_hash(&fixture.original.original_bytes)
            ))
            .send()
            .await
            .is_ok()
    );

    let resign = |exact: Vec<u8>| {
        let ParsedArchiveObject::Trust(t) = decode_exact_object(&exact).unwrap() else {
            panic!()
        };
        let DecodedTrustPayloadV1::DestructionTransition(fields) =
            t.value().decoded_payload().unwrap()
        else {
            panic!()
        };
        let payload = TrustPayloadV1::destruction_transition(fields).unwrap();
        let sig = CoseSigner::from_secret(SecretBytes::new(CONTROLLER_SEED))
            .sign_destruction_transition_digest(
                fixture.controller,
                payload.exact_digest_input(),
                &fixture.auth,
            )
            .unwrap();
        encode_trust(&TrustObjectV1::new(payload, vec![sig]).unwrap())
            .unwrap()
            .into_vec()
    };
    let request = resign(transition(&fixture, None, 0, None, 0xe7));
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: CONTROLLER_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&request),
            request_id: [0xe7; 16]
        })
        .await
        .status,
        202
    );
    let start = resign(transition(
        &fixture,
        Some(0),
        1,
        Some(object_hash(&request)),
        0xe8,
    ));
    let blocked = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: CONTROLLER_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&start),
        request_id: [0xe8; 16],
    })
    .await;
    assert_eq!(
        blocked.status, 422,
        "revoked physical server component cannot execute despite a valid current controller"
    );
    assert!(
        s3.get_object()
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

#[path = "destruction_jobs/race.rs"]
mod race;

#[tokio::test]
async fn signed_replica_claims_cannot_replace_the_servers_durable_physical_measurement() {
    let fixture = JobFixture::with_replica_signers(NOW, true);
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-complete");
    common::ensure_bucket(&bucket).await;
    let seeded = fixture.seed(&database, &bucket).await;
    let host = common::spawn_server_in_bucket(
        database.pool().clone(),
        UnixMillis::new(NOW),
        fixture.original.anchor.organization_id(),
        SERVER_SEED,
        fixture.server,
        &bucket,
    )
    .await;
    let ready = common::ReadyServer {
        server: host,
        closure: seeded.closure,
    };
    let jobs = format!("/v1/destructions/{}/jobs", hex::encode([0x74; 16]));
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionJobs,
            target: &jobs,
            body: Some(&fixture.body),
            request_id: [0x21; 16]
        })
        .await
        .status,
        202
    );
    let request = transition(&fixture, None, 0, None, 0x21);
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&request),
            request_id: [0x22; 16]
        })
        .await
        .status,
        202
    );
    let start = transition(&fixture, Some(0), 1, Some(object_hash(&request)), 0x22);
    assert_eq!(
        common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: COMPONENT_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(&start),
            request_id: [0x23; 16]
        })
        .await
        .status,
        422,
        "without a configured component, no physical action occurs"
    );
    let mut hashes = vec![
        object_hash(&fixture.original.original_bytes),
        object_hash(&fixture.original.initial_grant_bytes),
    ];
    hashes.sort();
    for (index, (certificate, device, kind, seed)) in fixture.replica_signers.iter().enumerate() {
        let payload = TrustPayloadV1::deletion_attestation(DeletionAttestationFieldsV1 {
            destruction_id: DestructionId::try_from(&[0x74; 16][..]).unwrap(),
            destruction_authorization_object_hash: object_hash(&fixture.auth),
            replica_id: *device.as_bytes(),
            replica_kind: *kind,
            removed_object_hashes: hashes.clone(),
            result: 0,
            backup_expiry_at: None,
            executed_at: UnixMillis::new(NOW),
        })
        .unwrap();
        let signature = CoseSigner::from_secret(SecretBytes::new(*seed))
            .sign_deletion_attestation_digest(
                *certificate,
                payload.exact_digest_input(),
                &fixture.auth,
            )
            .unwrap();
        let exact = encode_trust(&TrustObjectV1::new(payload, vec![signature]).unwrap()).unwrap();
        let accepted = common::call(&common::ApiCall {
            ready: &ready,
            signer_seed: CONTROLLER_SEED,
            endpoint: EndpointV1::DestructionEvents,
            target: &events,
            body: Some(exact.as_bytes()),
            request_id: [0x24 + index as u8; 16],
        })
        .await;
        assert_eq!(
            accepted.status,
            202,
            "valid signed replica statement can be recorded: {:?}",
            common::error_code(&accepted.body)
        );
    }
    let complete = transition(&fixture, Some(1), 3, Some(object_hash(&start)), 0x29);
    let rejected = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&complete),
        request_id: [0x2a; 16],
    })
    .await;
    assert_eq!(
        rejected.status, 409,
        "no complete without this server's immutable measured removal"
    );
    let measured: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_server_measurements")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(measured, 0);
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
    let resumed = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionJobs,
        target: &jobs,
        body: Some(&fixture.body),
        request_id: [0x2b; 16],
    })
    .await;
    assert_eq!(
        resumed.status, 202,
        "actual physical removal still uses the original durable start/job"
    );
    let accepted = common::call(&common::ApiCall {
        ready: &ready,
        signer_seed: COMPONENT_SEED,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&complete),
        request_id: [0x2c; 16],
    })
    .await;
    assert_eq!(
        accepted.status, 202,
        "only actual measured removal plus complete historical custody permits signed Complete"
    );
    assert_eq!(
        DestructionStatusResponseV1::decode(&accepted.body)
            .unwrap()
            .state(),
        3
    );
    cleanup_fixture(database, &bucket).await;
}

async fn publish_new_line(fixture: &JobFixture, database: &common::TestDatabase, bucket: &str) {
    let source = fixture.original.source();
    let inventory = ArchiveInventory::build(&source).unwrap();
    let s3 = common::object_store_client().await;
    let org = fixture.original.anchor.organization_id();
    for object in inventory.trust() {
        let hash = object.object_hash();
        let known: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM object_index WHERE object_hash=$1)")
                .bind(hash.as_bytes().as_slice())
                .fetch_one(database.pool())
                .await
                .unwrap();
        if known {
            continue;
        }
        let exact = object.exact_bytes().as_bytes().to_vec();
        s3.put_object()
            .bucket(bucket)
            .key(ea_sync_server::object_key(ObjectTypeV1::Trust, hash))
            .body(aws_sdk_s3::primitives::ByteStream::from(exact.clone()))
            .send()
            .await
            .unwrap();
        sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,5,$3,1000)")
            .bind(hash.as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(exact.len() as i64).execute(database.pool()).await.unwrap();
        sqlx::query("INSERT INTO trust_events(organization_id,event_id,object_hash,event_code,received_at_millis) VALUES($1,$2,$3,$4,1000)")
            .bind(org.as_bytes().as_slice()).bind(&hash.as_bytes()[..16]).bind(hash.as_bytes().as_slice()).bind(object.value().subtype().as_str()).execute(database.pool()).await.unwrap();
    }
}
#[tokio::test]
async fn current_admission_cannot_outlive_a_known_successor_start() {
    use ea_sync_server::RegistryHeadDirectory;
    use einsatzarchiv_server::adapters::{
        clock::FixedClock, postgres::PostgresRepository, s3::S3ObjectStore,
        trust_authority::PostgresTrustAuthority,
    };
    use std::sync::Arc;
    let mut fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-future");
    common::ensure_bucket(&bucket).await;
    let _ready = fixture.seed(&database, &bucket).await;
    fixture.original.line.push(
        trust::ActionSpec::Policy {
            policy_version: None,
            previous_policy_hash: None,
            effective_from: Some(1),
        },
        trust::HeadOptions {
            effective_from: Some(1),
            valid_through: Some(100),
            issued_at: UnixMillis::new(NOW),
            not_before: UnixMillis::new(NOW + 500),
            not_after: UnixMillis::new(NOW + 1_000_000),
            ..Default::default()
        },
    );
    publish_new_line(&fixture, &database, &bucket).await;
    let org = fixture.original.anchor.organization_id();
    let repo = Arc::new(PostgresRepository::new(database.pool().clone()));
    let objects = Arc::new(S3ObjectStore::new(
        common::object_store_client().await,
        bucket.clone(),
        org,
        repo.clone(),
        repo,
        Arc::new(FixedClock(UnixMillis::new(NOW))),
    ));
    let authority = PostgresTrustAuthority::new(database.pool().clone(), objects);
    if let Some(admission) = authority
        .select_current_admission(org, ChainSequence::new(1), UnixMillis::new(NOW))
        .await
        .unwrap()
    {
        assert!(
            admission.fence.not_after < UnixMillis::new(NOW + 500),
            "selected fallback must expire before known successor becomes active"
        );
    }
    cleanup_fixture(database, &bucket).await;
}

async fn cleanup_fixture(database: common::TestDatabase, bucket: &str) {
    assert!(bucket.starts_with("ea-t12-"));
    let client = common::object_store_client().await;
    loop {
        let page = client
            .list_object_versions()
            .bucket(bucket)
            .max_keys(1000)
            .send()
            .await
            .unwrap();
        if page.versions().is_empty() && page.delete_markers().is_empty() {
            break;
        }
        for (key, id) in page
            .versions()
            .iter()
            .map(|v| (v.key(), v.version_id()))
            .chain(
                page.delete_markers()
                    .iter()
                    .map(|v| (v.key(), v.version_id())),
            )
        {
            client
                .delete_object()
                .bucket(bucket)
                .key(key.unwrap())
                .version_id(id.unwrap())
                .send()
                .await
                .unwrap();
        }
    }
    client.delete_bucket().bucket(bucket).send().await.unwrap();
    database.cleanup().await;
}

#[path = "destruction_jobs/historical.rs"]
mod historical_holdings;

#[tokio::test]
async fn exact_transition_replay_still_requires_its_current_original_action_signer() {
    let fixture = JobFixture::new();
    let database = common::fresh_database().await;
    let bucket = common::unique_bucket_name("ea-t12-event-replay");
    common::ensure_bucket(&bucket).await;
    let ready = fixture.seed(&database, &bucket).await;
    let events = format!("/v1/destructions/{}/events", hex::encode([0x74; 16]));
    let exact = transition(&fixture, None, 0, None, 0x91);
    let call = |seed, marker| common::ApiCall {
        ready: &ready,
        signer_seed: seed,
        endpoint: EndpointV1::DestructionEvents,
        target: &events,
        body: Some(&exact),
        request_id: [marker; 16],
    };
    assert_eq!(common::call(&call(COMPONENT_SEED, 0x91)).await.status, 202);
    assert_eq!(common::call(&call(COMPONENT_SEED, 0x92)).await.status, 202);
    assert_eq!(
        common::call(&call(CONTROLLER_SEED, 0x93)).await.status,
        422,
        "an exact transition replay cannot bypass its fresh action signer binding"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM destruction_event_cores")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    cleanup_fixture(database, &bucket).await;
}

#[path = "destruction_jobs/negative.rs"]
mod negative;
