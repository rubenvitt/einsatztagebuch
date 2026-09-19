use super::*;
use ea_archive::{ArchiveInventory, ArchiveSource};
use ea_crypto::object_hash;
use ea_desktop::runtime::destruction_transport::{
    NativeDestructionServerConfig, NativeDestructionServerTransport,
};
use ea_format::{DecodedTrustPayloadV1, ObjectTypeV1, ParsedArchiveObject, decode_exact_object};
use ea_sync_protocol::EndpointV1;

mod host;
mod failure;
mod retry;

#[path = "../../../../server/tests/common/mod.rs"]
mod common;

struct ServerFixture {
    database: common::TestDatabase,
    server: common::TestServer,
    bucket: String,
    config: NativeDestructionServerConfig,
    /// The registered server's own DeletionAttest certificate, kept for an
    /// actual restart of the same identity (`retry.rs`).
    deletion_certificate: CertificateHash,
    /// The actual TLS listener task; aborting it stops only this listener.
    serving: tokio::task::JoinHandle<()>,
}
impl ServerFixture {
    async fn seed(f: &NativeDestructionFixture) -> Self {
        let database = common::fresh_database_with_migrations(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../server/migrations"),
        )
        .await;
        let bucket = common::unique_bucket_name("ea-native-destruction");
        common::ensure_bucket(&bucket).await;
        seed_original_receipt(f);
        let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
        let inventory = ArchiveInventory::build(&source).unwrap();
        let org = trust_support::organization();
        let pool = database.pool();
        let anchor = ea_trust::decode_trust_anchor(&fs::read(&f.anchor).unwrap()).unwrap();
        sqlx::query("INSERT INTO organizations(organization_id,root_key_thumbprint,trust_anchor_bytes,created_at_millis) VALUES($1,$2,$3,0)")
            .bind(org.as_bytes().as_slice()).bind(anchor.root_key_thumbprint().as_bytes().as_slice())
            .bind(fs::read(&f.anchor).unwrap()).execute(pool).await.unwrap();
        let s3 = common::object_store_client().await;
        let mut blobs = Vec::new();
        source
            .visit_blobs(&mut |blob| {
                blobs.push(blob.bytes().to_vec());
                Ok(())
            })
            .unwrap();
        for bytes in blobs {
            let parsed = decode_exact_object(&bytes).unwrap();
            let kind = match &parsed {
                ParsedArchiveObject::Trust(_) => ObjectTypeV1::Trust,
                ParsedArchiveObject::Entry(_) => ObjectTypeV1::Entry,
                ParsedArchiveObject::Grant(_) => ObjectTypeV1::Grant,
                ParsedArchiveObject::Receipt(_) => ObjectTypeV1::Receipt,
                _ => panic!("unexpected native pre-state"),
            };
            let hash = object_hash(&bytes);
            s3.put_object()
                .bucket(&bucket)
                .key(ea_sync_server::object_key(kind, hash))
                .body(aws_sdk_s3::primitives::ByteStream::from(bytes.clone()))
                .send()
                .await
                .unwrap();
            if matches!(kind, ObjectTypeV1::Entry | ObjectTypeV1::Grant) {
                s3.put_object()
                    .bucket(&bucket)
                    .key(ea_sync_server::object_key(kind, hash))
                    .body(aws_sdk_s3::primitives::ByteStream::from(bytes.clone()))
                    .send()
                    .await
                    .unwrap();
            }
            sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,$3,$4,0)")
                .bind(hash.as_bytes().as_slice()).bind(org.as_bytes().as_slice())
                .bind(i16::try_from(kind.code()).unwrap()).bind(bytes.len() as i64).execute(pool).await.unwrap();
            if let ParsedArchiveObject::Trust(t) = parsed {
                sqlx::query("INSERT INTO trust_events(organization_id,event_id,object_hash,event_code,received_at_millis) VALUES($1,$2,$3,$4,0)")
                    .bind(org.as_bytes().as_slice()).bind(&hash.as_bytes()[..16]).bind(hash.as_bytes().as_slice())
                    .bind(t.value().subtype().as_str()).execute(pool).await.unwrap();
            }
        }
        let certificate = |seed| {
            inventory
                .trust()
                .iter()
                .find_map(|p| {
                    let DecodedTrustPayloadV1::AuthorizedDevice(c) =
                        p.value().decoded_payload().ok()?
                    else {
                        return None;
                    };
                    (c.fields().signing_key_thumbprint == Some(public(seed).thumbprint()))
                        .then_some((
                            CertificateHash::try_from(p.object_hash().as_bytes().as_slice())
                                .unwrap(),
                            c.fields().device_id,
                        ))
                })
                .unwrap()
        };
        let (server_cert, device_id) = certificate(SERVER_TRANSPORT_SECRET);
        let (component_cert, _) = certificate(SERVER_DELETION_SECRET);
        let entry = &inventory.entries()[0];
        let fields = entry.value().manifest().fields();
        let writer = inventory
            .trust()
            .iter()
            .find_map(|p| {
                if p.object_hash().as_bytes() != fields.writer_certificate_hash.as_bytes() {
                    return None;
                }
                let DecodedTrustPayloadV1::AuthorizedDevice(c) =
                    p.value().decoded_payload().ok()?
                else {
                    return None;
                };
                Some(c.fields().device_id)
            })
            .unwrap();
        let receipt = inventory
            .receipts()
            .iter()
            .find(|r| {
                r.value().core().fields().entry_object_hash.as_bytes()
                    == entry.object_hash().as_bytes()
            })
            .unwrap();
        sqlx::query("INSERT INTO entries(entry_hash,organization_id,chain_id,sequence_number,previous_entry_hash,entry_object_hash,initial_grant_plan_hash,receipt_object_hash,device_id,accepted_at_server_millis,registry_version,registry_head_hash) VALUES($1,$2,$3,0,NULL,$4,$5,$6,$7,200,$8,$9)")
            .bind(entry.value().entry_hash().as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(anchor.chain_id().as_bytes().as_slice())
            .bind(entry.object_hash().as_bytes().as_slice()).bind(fields.initial_grant_plan_hash.as_slice())
            .bind(receipt.object_hash().as_bytes().as_slice()).bind(writer.as_bytes().as_slice())
            .bind(fields.registry_version.get() as i64).bind(fields.registry_head_hash.as_slice()).execute(pool).await.unwrap();
        for grant in inventory.grants() {
            let fields = grant.value().grant_body().fields();
            sqlx::query("INSERT INTO grants(object_hash,organization_id,entry_hash,recipient_key_thumbprint,grant_kind_code) VALUES($1,$2,$3,$4,'initial')")
                .bind(grant.object_hash().as_bytes().as_slice()).bind(org.as_bytes().as_slice())
                .bind(fields.entry_hash.as_bytes().as_slice()).bind(fields.recipient_key_thumbprint.as_bytes().as_slice())
                .execute(pool).await.unwrap();
        }
        common::trust_closure::seed_chain_head(
            pool,
            org,
            anchor.chain_id(),
            0,
            *entry.value().entry_hash().as_bytes(),
            200,
        )
        .await;
        let (server, serving) = common::spawn_server_with_object_store_at(
            "127.0.0.1:0",
            pool.clone(),
            system_now(),
            org,
            SERVER_TRANSPORT_SECRET,
            server_cert,
            &bucket,
            common::TestExecutionPorts {
                deletion: Some((SERVER_DELETION_SECRET, component_cert)),
                objects_override: None,
                clock_override: Some(Arc::new(einsatzarchiv_server::adapters::clock::SystemClock)),
            },
        )
        .await
        .expect("binding the loopback listener must succeed");
        // The independent approver performs the real reservation. The native Admin host never owns this authority.
        let body = ea_sync_protocol::DestructionRequestV1::new(f.authorization.clone()).unwrap();
        let nonce = common::fresh_challenge(&server, org).await;
        let headers = common::signed_headers(&common::SignedCall {
            signer: &common::request_signer(HTTP_APPROVER_SECRET),
            endpoint: EndpointV1::Destructions,
            authority: &server.authority,
            target: "/v1/destructions",
            body: Some(body.exact_bytes()),
            organization_id: org,
            request_id: [0xc4; 16],
            nonce,
            created: system_now().get().div_euclid(1000),
        });
        let response = common::https_request(
            server.address,
            &server.authority,
            "POST",
            "/v1/destructions",
            &headers,
            body.exact_bytes(),
        )
        .await;
        assert_eq!(
            response.status,
            202,
            "independent real signed reservation: {:?}",
            String::from_utf8_lossy(&response.body)
        );
        let ca_file = f._directory.path().join("transport-ca.pem");
        fs::write(&ca_file, common::TEST_TLS_CA_PEM).unwrap();
        let config = NativeDestructionServerConfig {
            device_id,
            address: server.address,
            server_name: "localhost".into(),
            authority: server.authority.clone(),
            ca_file,
            server_certificate: server_cert,
        };
        Self {
            database,
            server,
            bucket,
            config,
            deletion_certificate: component_cert,
            serving,
        }
    }
}

#[test]
fn native_destruction_transport_start_reopen_resume_with_explicit_signed_clock_horizon() {
    let began = std::time::Instant::now();
    let f = NativeDestructionFixture::with_server_state(true, 4);
    let public =
        ArchiveInventory::build(&ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap())
            .unwrap();
    assert!(
        public.trust().iter().any(|object| matches!(
            object.value().decoded_payload(),
            Ok(DecodedTrustPayloadV1::Policy(ref policy))
                if policy.fields().max_future_clock_skew_ms == 1_800_000
        )),
        "long lifecycle has an explicit Root-signed30-minute policy; no native time guard is relaxed"
    );
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    let mut transport =
        NativeDestructionServerTransport::open(vec![server.config.clone()], &f.key_source)
            .expect("configured TLS transport must load the separately protected component key");
    let started = transport
        .start(
            &mut native,
            requested.destruction_id,
            requested.preflight_hash.unwrap(),
        )
        .unwrap();
    assert_eq!(started.state, ea_destruction::DestructionState::InProgress);
    let rows: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(rows, 1);
    let rows: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_attestations")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(
        rows, 1,
        "actual server measurement must produce its signed component attestation"
    );
    eprintln!(
        "native transport start and import complete at {:?}",
        began.elapsed()
    );
    let original_inventory =
        ArchiveInventory::build(&ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap())
            .unwrap();
    let held = original_inventory
        .entries()
        .iter()
        .map(|v| (ObjectTypeV1::Entry, v.object_hash()))
        .chain(
            original_inventory
                .grants()
                .iter()
                .map(|v| (ObjectTypeV1::Grant, v.object_hash())),
        )
        .collect::<Vec<_>>();
    services.block_on(async {
        let client = common::object_store_client().await;
        for (kind, hash) in held {
            let versions = client
                .list_object_versions()
                .bucket(&server.bucket)
                .prefix(ea_sync_server::object_key(kind, hash))
                .send()
                .await
                .unwrap();
            assert!(
                versions.versions().is_empty() && versions.delete_markers().is_empty(),
                "every real original/Grant version is absent"
            );
        }
        let hashes: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT object_hash FROM destruction_job_stubs")
                .fetch_all(server.database.pool())
                .await
                .unwrap();
        assert_eq!(hashes.len(), 1);
        let hash = ObjectHash::try_from(hashes[0].as_slice()).unwrap();
        let exact = client
            .get_object()
            .bucket(&server.bucket)
            .key(ea_sync_server::object_key(ObjectTypeV1::Destroyed, hash))
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes();
        assert!(object_hash(&exact) == hash);
        let ParsedArchiveObject::Destroyed(stub) = decode_exact_object(&exact).unwrap() else {
            panic!("expected actual durable EDS");
        };
        assert!(stub.value().entry_hash() == requested.targets[0].entry_hash);
    });
    // Separate explicit user operation after the first native action. Reopen
    // both configured identities; never renew a Writer watcher using Admin presence.
    drop(native);
    let mut native = f.runtime();
    eprintln!(
        "native transport fresh resume runtime at {:?}",
        began.elapsed()
    );
    let resumed = transport
        .resume(&mut native, requested.destruction_id)
        .unwrap();
    eprintln!(
        "native transport local resume complete at {:?}",
        began.elapsed()
    );
    assert_eq!(resumed.state, ea_destruction::DestructionState::InProgress);
    assert!(
        resumed
            .replicas
            .iter()
            .any(|r| r.kind == ea_destruction::ManagedReplicaKind::Reader
                && r.attestation_hash.is_none()),
        "unreachable Reader remains unconfirmed, never silently complete"
    );
    drop(native);
    let mut reopened = f.runtime();
    let durable = transport
        .synchronize(
            &mut reopened,
            requested.destruction_id,
            requested.preflight_hash.unwrap(),
        )
        .unwrap();
    assert!(durable.authorization_hash == requested.authorization_hash);
    assert!(durable.preflight_hash == requested.preflight_hash);
    assert_eq!(durable.state, ea_destruction::DestructionState::InProgress);
    let _ = (&server.server, &server.bucket);
}

fn system_now() -> UnixMillis {
    UnixMillis::new(
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap(),
    )
}

fn seed_original_receipt(f: &NativeDestructionFixture) {
    seed_original_receipt_at(f, system_now());
}
fn seed_original_receipt_at(f: &NativeDestructionFixture, accepted_at: UnixMillis) {
    use ea_format::{ReceiptCoreFieldsV1, ReceiptCoreV1, ReceiptV1, encode_receipt};
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let inventory = ArchiveInventory::build(&source).unwrap();
    let anchor = ea_trust::decode_trust_anchor(&fs::read(&f.anchor).unwrap()).unwrap();
    let entry = &inventory.entries()[0];
    let m = entry.value().manifest().fields();
    let historical = ea_verify::historical_registry_head(
        &inventory,
        &anchor,
        m.registry_version,
        ObjectHash::try_from(m.registry_head_hash.as_slice()).unwrap(),
        m.chain_sequence,
        system_now(),
    )
    .unwrap();
    let certificate = historical
        .known_certificate_fields()
        .find(|(_, c)| c.certificate_kind == CertificateKindV1::ServerReceipt)
        .unwrap()
        .0;
    let policy = inventory
        .trust()
        .iter()
        .find_map(|p| match p.value().decoded_payload().ok()? {
            DecodedTrustPayloadV1::Policy(policy)
                if policy.fields() == historical.policy_fields() =>
            {
                Some(p.object_hash())
            }
            _ => None,
        })
        .unwrap();
    let signer = trust_support::authorized_device_signer();
    let core = ReceiptCoreV1::new(ReceiptCoreFieldsV1 {
        organization_id: anchor.organization_id(),
        chain_id: anchor.chain_id(),
        chain_sequence: m.chain_sequence,
        entry_hash: entry.value().entry_hash(),
        entry_object_hash: entry.object_hash(),
        previous_entry_hash: None,
        registry_version: m.registry_version,
        registry_head_hash: Hash32::try_from(m.registry_head_hash.as_slice()).unwrap(),
        policy_object_hash: policy,
        initial_grant_plan_hash: Hash32::try_from(m.initial_grant_plan_hash.as_slice()).unwrap(),
        initial_grant_object_hashes: inventory.grants().iter().map(|g| g.object_hash()).collect(),
        accepted_at_server: accepted_at,
        evidence_due_at: None,
        server_key_thumbprint: signer.public_key().unwrap().thumbprint(),
        server_certificate_hash: certificate,
    })
    .unwrap();
    let signature = signer.sign_receipt(core.exact_bytes()).unwrap();
    let exact = encode_receipt(&ReceiptV1::new(core, signature).unwrap()).unwrap();
    fs::create_dir_all(f.archive.join("receipts")).unwrap();
    fs::write(
        f.archive.join("receipts/native-original.ear"),
        exact.as_bytes(),
    )
    .unwrap();
}

struct ActualReservation<'a> {
    services: &'a tokio::runtime::Runtime,
    server: &'a common::TestServer,
}
impl ea_destruction::ServerReservationPort for ActualReservation<'_> {
    fn read_current_status(
        &mut self,
        organization: ea_types::OrganizationId,
        id: DestructionId,
    ) -> Result<Vec<u8>, ea_destruction::DestructionError> {
        let response = self.services.block_on(async {
            let nonce = common::fresh_challenge(self.server, organization).await;
            let path = format!("/v1/destructions/{}", hex::encode(id.as_bytes()));
            let headers = common::signed_headers(&common::SignedCall {
                signer: &common::request_signer(COMPONENT_SECRET),
                endpoint: EndpointV1::DestructionStatus,
                authority: &self.server.authority,
                target: &path,
                body: None,
                organization_id: organization,
                request_id: nonce[..16].try_into().unwrap(),
                nonce,
                created: system_now().get().div_euclid(1000),
            });
            common::https_request(
                self.server.address,
                &self.server.authority,
                "GET",
                &path,
                &headers,
                &[],
            )
            .await
        });
        assert_eq!(response.status, 200);
        Ok(response.body)
    }
}
#[test]
fn native_destruction_transport_replays_durable_local_progress_when_server_has_only_reservation() {
    let f = NativeDestructionFixture::with_server_state(true, 3);
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    let mut reservation = ActualReservation {
        services: &services,
        server: &server.server,
    };
    native
        .start(
            requested.destruction_id,
            requested.preflight_hash.unwrap(),
            ea_admin::destruction_runtime::NativeDestructionDelivery::AuthenticatedServer(
                &mut reservation,
            ),
        )
        .unwrap();
    native
        .resume_local(
            requested.destruction_id,
            ea_admin::destruction_runtime::NativeDestructionDelivery::AuthenticatedServer(
                &mut reservation,
            ),
        )
        .unwrap();
    let count: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "native crash window: actual reservation exists but no event/job was transmitted"
    );
    drop(native);
    let mut native = f.runtime();
    let mut transport =
        NativeDestructionServerTransport::open(vec![server.config.clone()], &f.key_source).unwrap();
    let result = transport.resume(&mut native, requested.destruction_id);
    assert!(
        result.is_ok(),
        "replay must reconcile the exact already durable local start and attestation: {:?}",
        result.err()
    );
}

#[test]
fn native_destruction_transport_refuses_wrong_tls_identity_key_scope_and_missing_target() {
    use ea_desktop::runtime::destruction_transport::NativeDestructionTransportError as Error;
    let f = NativeDestructionFixture::with_server_state(true, 3);
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    let id = requested.destruction_id;
    let hash = requested.preflight_hash.unwrap();

    let mut config = server.config.clone();
    config.authority = "unrelated.invalid:443".into();
    assert!(matches!(
        NativeDestructionServerTransport::open(vec![config], &f.key_source),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        NativeDestructionServerTransport::open(
            vec![server.config.clone(), server.config.clone()],
            &f.key_source
        ),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        NativeDestructionServerTransport::open(
            vec![server.config.clone()],
            &KeySourceSpec::File(f.anchor.clone())
        ),
        Err(Error::KeySource)
    ));

    let mut config = server.config.clone();
    config.ca_file = f._directory.path().join("untrusted-ca.pem");
    fs::write(&config.ca_file, common::TEST_TLS_CERTIFICATE_PEM).unwrap();
    let mut transport =
        NativeDestructionServerTransport::open(vec![config], &f.key_source).unwrap();
    assert!(matches!(
        transport.synchronize(&mut native, id, hash),
        Err(Error::Tls)
    ));

    let mut config = server.config.clone();
    config.server_certificate = f.component;
    let mut transport =
        NativeDestructionServerTransport::open(vec![config], &f.key_source).unwrap();
    assert!(transport.start(&mut native, id, hash).is_err());

    let mut config = server.config.clone();
    config.device_id = DeviceId::try_from(&[0x77; 16][..]).unwrap();
    let mut transport =
        NativeDestructionServerTransport::open(vec![config], &f.key_source).unwrap();
    assert!(matches!(
        transport.start(&mut native, id, hash),
        Err(Error::Binding)
    ));

    let KeySourceSpec::Container {
        passphrase_file, ..
    } = &f.key_source
    else {
        panic!()
    };
    let wrong_path = f._directory.path().join("other-component.eak");
    EncryptedKeyContainer::seal(
        ContainedKeyKind::Signing,
        ea_crypto::SecretBytes::new([0x33; 32]),
        &ea_recovery::read_secret_file(passphrase_file).unwrap(),
    )
    .unwrap()
    .write_new(&wrong_path)
    .unwrap();
    let wrong_key = KeySourceSpec::Container {
        path: wrong_path,
        passphrase_file: passphrase_file.clone(),
    };
    let mut transport =
        NativeDestructionServerTransport::open(vec![server.config.clone()], &wrong_key).unwrap();
    assert!(transport.start(&mut native, id, hash).is_err());

    // A real HTTP200 is unavailable once even one signed target reservation is absent.
    services
        .block_on(sqlx::query("DELETE FROM destruction_targets").execute(server.database.pool()))
        .unwrap();
    let mut transport =
        NativeDestructionServerTransport::open(vec![server.config.clone()], &f.key_source).unwrap();
    assert!(transport.start(&mut native, id, hash).is_err());
    native.unlock().unwrap();
    assert_eq!(
        native.status(id).unwrap().state,
        ea_destruction::DestructionState::Requested
    );
    let count: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        ArchiveInventory::build(&ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap())
            .unwrap()
            .entries()
            .len(),
        1
    );
}

struct CloseOnActualChallenge {
    runtime: tokio::runtime::Handle,
    pool: sqlx::PgPool,
    baseline: i64,
}
impl ea_admin::destruction_runtime::DestructionHostGuard for CloseOnActualChallenge {
    fn require_open(&self) -> Result<(), ea_admin::destruction_runtime::NativeDestructionError> {
        let count: i64 = self
            .runtime
            .block_on(sqlx::query_scalar("SELECT count(*) FROM challenges").fetch_one(&self.pool))
            .unwrap();
        if count > self.baseline {
            Err(ea_admin::destruction_runtime::NativeDestructionError::Session)
        } else {
            Ok(())
        }
    }
}
#[test]
fn native_destruction_transport_rechecks_host_closure_after_actual_signed_challenge_before_request()
{
    let f = NativeDestructionFixture::with_server_state(true, 3);
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    let baseline: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM challenges").fetch_one(server.database.pool()),
        )
        .unwrap();
    native.set_host_guard(Arc::new(CloseOnActualChallenge {
        runtime: services.handle().clone(),
        pool: server.database.pool().clone(),
        baseline,
    }));
    let mut transport =
        NativeDestructionServerTransport::open(vec![server.config.clone()], &f.key_source).unwrap();
    assert!(
        transport
            .start(
                &mut native,
                requested.destruction_id,
                requested.preflight_hash.unwrap()
            )
            .is_err()
    );
    let issued: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM challenges WHERE challenge_state='issued'")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(
        issued, 1,
        "the new real challenge must remain unconsumed: no authenticated status/job/event request followed closure"
    );
    let jobs: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(jobs, 0);
}

#[test]
fn native_destruction_transport_rejects_oversized_actual_tls_challenge_before_decode() {
    use ea_desktop::runtime::destruction_transport::NativeDestructionTransportError as Error;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let f = NativeDestructionFixture::with_server_state(true, 3);
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let inventory = ArchiveInventory::build(&source).unwrap();
    let (certificate, device) = inventory
        .trust()
        .iter()
        .find_map(|p| {
            let DecodedTrustPayloadV1::AuthorizedDevice(c) = p.value().decoded_payload().ok()?
            else {
                return None;
            };
            (c.fields().signing_key_thumbprint
                == Some(public(SERVER_TRANSPORT_SECRET).thumbprint()))
            .then_some((
                CertificateHash::try_from(p.object_hash().as_bytes().as_slice()).unwrap(),
                c.fields().device_id,
            ))
        })
        .unwrap();
    let services = tokio::runtime::Runtime::new().unwrap();
    let (cert, key) = common::write_test_tls_material();
    let tls = einsatzarchiv_server::config::tls_server_config(&cert, &key).unwrap();
    let listener = services
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address = listener.local_addr().unwrap();
    services.spawn(async move {
        let (socket,_)=listener.accept().await.unwrap();
        let mut stream=tokio_rustls::TlsAcceptor::from(tls).accept(socket).await.unwrap();
        let mut request=[0u8;4096];
        let _=stream.read(&mut request).await.unwrap();
        let body=vec![0u8;ea_sync_protocol::MAX_SMALL_BODY_BYTES_V1+1];
        let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
        stream.write_all(header.as_bytes()).await.unwrap();
        let _=stream.write_all(&body).await;
        let _=stream.shutdown().await;
    });
    let ca_file = f._directory.path().join("oversized-tls-ca.pem");
    fs::write(&ca_file, common::TEST_TLS_CA_PEM).unwrap();
    let config = NativeDestructionServerConfig {
        device_id: device,
        address,
        server_name: "localhost".into(),
        authority: format!("localhost:{}", address.port()),
        ca_file,
        server_certificate: certificate,
    };
    let mut transport =
        NativeDestructionServerTransport::open(vec![config], &f.key_source).unwrap();
    let result = transport.synchronize(
        &mut native,
        requested.destruction_id,
        requested.preflight_hash.unwrap(),
    );
    assert!(
        matches!(result, Err(Error::ResponseLimit)),
        "oversized actual challenge must be stopped at its64KiB transport ceiling: {:?}",
        result.err()
    );
}

struct CloseOnActualJob {
    runtime: tokio::runtime::Handle,
    pool: sqlx::PgPool,
}
impl ea_admin::destruction_runtime::DestructionHostGuard for CloseOnActualJob {
    fn require_open(&self) -> Result<(), ea_admin::destruction_runtime::NativeDestructionError> {
        let count: i64 = self
            .runtime
            .block_on(
                sqlx::query_scalar("SELECT count(*) FROM destruction_jobs").fetch_one(&self.pool),
            )
            .unwrap();
        if count > 0 {
            Err(ea_admin::destruction_runtime::NativeDestructionError::Session)
        } else {
            Ok(())
        }
    }
}
#[test]
fn native_destruction_transport_persists_native_start_before_first_mutating_server_post() {
    let f = NativeDestructionFixture::with_server_state(true, 3);
    let services = tokio::runtime::Runtime::new().unwrap();
    let server = services.block_on(ServerFixture::seed(&f));
    let mut native = f.runtime();
    let requested = native.prepare(&f.authorization).unwrap();
    native.set_host_guard(Arc::new(CloseOnActualJob {
        runtime: services.handle().clone(),
        pool: server.database.pool().clone(),
    }));
    let mut transport =
        NativeDestructionServerTransport::open(vec![server.config.clone()], &f.key_source).unwrap();
    let result = transport.start(
        &mut native,
        requested.destruction_id,
        requested.preflight_hash.unwrap(),
    );
    assert!(
        result.is_err(),
        "closure at the actual durable server job must refuse continuation"
    );
    let jobs: i64 = services
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM destruction_jobs")
                .fetch_one(server.database.pool()),
        )
        .unwrap();
    assert_eq!(
        jobs, 1,
        "the probe must actually reach the mutating TLS/PG job boundary"
    );
    drop(native);
    let mut reopened = f.runtime();
    reopened.unlock().unwrap();
    assert_eq!(
        reopened.status(requested.destruction_id).unwrap().state,
        ea_destruction::DestructionState::InProgress,
        "any mutating server replay may execute physically, so exact native Start and both audit copies must already be durable"
    );
}

#[test]
fn native_destruction_transport_refuses_an_expired_independent_reference_after_reopen() {
    let f = NativeDestructionFixture::with_server_state(true, 3);
    seed_original_receipt_at(&f, UnixMillis::new(system_now().get() - 301_000));
    let provider = NativeOperatorProvider::open_test_fixture(
        f.writer_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let result = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.writer_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        provider,
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("a new provider cannot extend the signed independent-reference ceiling"),
    };
    eprintln!("expired reference exact refusal: {}", error.code());
    assert_eq!(error.code(), "EA-TRUST-FUTURE-SKEW");
}
