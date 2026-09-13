use super::*;
use ea_admin::destruction_runtime::{DestructionRuntime, NativeLocalHolder};
use ea_admin::native_provider::NativeOperatorProvider;
use ea_admin::operator_runtime::{OperatorRuntime, OperatorRuntimeConfig};
use ea_archive::{ArchiveBackendProfileV1, LocalPathProfileV1};
use ea_recovery::{ContainedKeyKind, EncryptedKeyContainer, KeySourceSpec};
use ea_types::DestructionId;
use std::os::unix::fs::OpenOptionsExt as _;
use support::verify_support as fixture;
type FixturePayload = fn(ea_types::RegistryVersion, ea_types::ObjectHash) -> Vec<u8>;
type NativeHistoricalFixtureBuilder = fn(
    FixturePayload,
    Option<fixture::historical::HostOptions>,
) -> fixture::historical::HistoricalFixture;
const COMPONENT_SECRET: [u8; 32] = [0x98; 32];
const READER_OPFS_COMPONENT_SECRET: [u8; 32] = [0xd5; 32];

struct NativeDestructionFixture {
    _directory: support::TempDir,
    admin_directory: PathBuf,
    writer_directory: PathBuf,
    archive: PathBuf,
    anchor: PathBuf,
    admin_config: PathBuf,
    writer_config: PathBuf,
    writer_certificate: CertificateHash,
    component: CertificateHash,
    reader_opfs_component: Option<CertificateHash>,
    second_reader_component: Option<CertificateHash>,
    profile: ArchiveBackendProfileV1,
    key_source: KeySourceSpec,
    authorization: Vec<u8>,
    line: trust_support::RegistryLineBuilder,
}
impl NativeDestructionFixture {
    fn new() -> Self {
        Self::with_server(true)
    }
    fn without_server() -> Self {
        Self::with_server(false)
    }
    fn with_server(include_server: bool) -> Self {
        Self::with_server_state(include_server, 0)
    }
    fn with_server_state(include_server: bool, additional_server: u8) -> Self {
        Self::with_optional_reader_opfs(include_server, additional_server, false)
    }
    fn with_reader_opfs() -> Self {
        Self::with_optional_reader_opfs(true, 4, true)
    }
    fn with_optional_reader_opfs(
        include_server: bool,
        additional_server: u8,
        reader_opfs: bool,
    ) -> Self {
        Self::with_optional_readers(include_server, additional_server, reader_opfs, false)
    }
    fn with_optional_readers(
        include_server: bool,
        additional_server: u8,
        reader_opfs: bool,
        second_reader: bool,
    ) -> Self {
        use ea_trust::TrustObjectSource as _;
        let directory = support::temp_dir("native-destruction");
        let admin_directory = directory.path().join("admin");
        let writer_directory = directory.path().join("writer");
        fs::create_dir(&admin_directory).unwrap();
        fs::create_dir(&writer_directory).unwrap();
        install_fixture_helper(&admin_directory);
        install_fixture_helper(&writer_directory);
        fs::write(admin_directory.join("authority-fixture"), b"").unwrap();
        let admin_subject = OperatorSubjectId::try_from(&[0x42; 16][..]).unwrap();
        let build: NativeHistoricalFixtureBuilder = if include_server {
            fixture::historical::fixture_with_host_options
        } else {
            fixture::historical::fixture_with_host_options_and_no_server
        };
        let mut material = build(
            |_, _| fixture::COMPLETE_PLAINTEXT_V1.to_vec(),
            Some(fixture::historical::HostOptions {
                not_after: support::LIVE_WRITER_NOT_AFTER_V1,
                max_age: support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                instance: ADMIN_INSTANCE_SECRET,
                account_hash: native_account_hash_for(
                    true,
                    DeviceId::try_from(&[0x52; 16][..]).unwrap(),
                ),
                commitment: ea_crypto::operator_profile_commitment(
                    trust_support::organization(),
                    admin_subject,
                    TEST_NAME,
                    TEST_FUNCTION,
                    &PROFILE_SALT,
                ),
            }),
        );
        let inventory = ea_archive::ArchiveInventory::build(&material.fixture).unwrap();
        let writer_certificate = inventory.entries()[0]
            .value()
            .manifest()
            .fields()
            .writer_certificate_hash;
        let writer_device = inventory
            .trust()
            .iter()
            .find_map(|p| {
                if p.object_hash().as_bytes() != writer_certificate.as_bytes() {
                    return None;
                }
                match p.value().decoded_payload().unwrap() {
                    ea_format::DecodedTrustPayloadV1::AuthorizedDevice(f) => {
                        Some(f.fields().device_id)
                    }
                    _ => None,
                }
            })
            .unwrap();
        let profile = ArchiveBackendProfileV1::LocalPath(LocalPathProfileV1 {
            filesystem_row_id: "fixture-native-destruction-fs".into(),
            capability_test_vector_id: "native-destruction-v1".into(),
        });
        let options = || HeadOptions {
            effective_from: Some(1),
            valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
            not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
            ..Default::default()
        };
        material.line.push(
            ActionSpec::Policy {
                policy_version: Some(2),
                previous_policy_hash: Some(material.line.current_policy_hash()),
                effective_from: Some(1),
            },
            HeadOptions {
                policy_destruction_enabled_override: Some(true),
                policy_eds_privacy_decision_document_hash_override: Some(Some(
                    trust_support::hash32(0x91),
                )),
                policy_max_registry_age_ms_override: Some(
                    support::LIVE_POLICY_MAX_REGISTRY_AGE_MS_V1,
                ),
                // Explicit signed policy only for the long actual transport
                // lifecycle. Ordinary fixtures retain the300-second horizon.
                policy_max_future_clock_skew_ms_override: (additional_server == 4)
                    .then_some(1_800_000),
                policy_allowed_archive_profile_hashes_override: Some(vec![
                    profile.profile_hash().unwrap(),
                ]),
                ..options()
            },
        );
        let writer_subject = OperatorSubjectId::try_from(&[0x71; 16][..]).unwrap();
        let binding = material
            .line
            .push(
                ActionSpec::OperatorBinding {
                    certificate_hash: ObjectHash::try_from(
                        writer_certificate.as_bytes().as_slice(),
                    )
                    .unwrap(),
                    role: OperatorRoleV1::Writer,
                    marker: 0x71,
                    effective_from: Some(1),
                },
                HeadOptions {
                    binding_instance_key_thumbprint_override: Some(
                        public(INSTANCE_SECRET).thumbprint(),
                    ),
                    binding_os_account_hash_override: Some(native_account_hash_for(
                        false,
                        writer_device,
                    )),
                    binding_operator_profile_commitment_override: Some(
                        ea_crypto::operator_profile_commitment(
                            trust_support::organization(),
                            writer_subject,
                            TEST_NAME,
                            TEST_FUNCTION,
                            &PROFILE_SALT,
                        ),
                    ),
                    ..options()
                },
            )
            .direct_object_hash
            .unwrap();
        let mut approvers = Vec::new();
        for marker in [0x81, 0x82] {
            approvers.push(CertificateHash::from(
                material
                    .line
                    .push(
                        ActionSpec::Device {
                            kind: CertificateKindV1::KeyApprover,
                            marker,
                            effective_from: Some(1),
                        },
                        HeadOptions {
                            authority_subject_id_override: Some(
                                ea_types::SubjectId::try_from(&[marker; 16][..]).unwrap(),
                            ),
                            certificate_capabilities_override: Some(vec![
                                "destructionApprove".into(),
                            ]),
                            ..options()
                        },
                    )
                    .direct_object_hash
                    .unwrap(),
            ));
        }
        let component = CertificateHash::from(
            material
                .line
                .push(
                    ActionSpec::Device {
                        kind: CertificateKindV1::DeletionAttest,
                        marker: 0x88,
                        effective_from: Some(1),
                    },
                    HeadOptions {
                        signing_public_key_override: Some(public(COMPONENT_SECRET)),
                        device_id_override: Some(writer_device),
                        ..options()
                    },
                )
                .direct_object_hash
                .unwrap(),
        );
        if additional_server == 2 {
            let registered = material
                .line
                .push(
                    ActionSpec::Device {
                        kind: CertificateKindV1::ServerReceipt,
                        marker: 0xa5,
                        effective_from: Some(1),
                    },
                    HeadOptions {
                        device_id_override: Some(DeviceId::try_from(&[0xa5; 16][..]).unwrap()),
                        ..options()
                    },
                )
                .direct_object_hash
                .unwrap();
            material.line.push(
                ActionSpec::Revoke {
                    target_kind: 2,
                    object_hash: registered,
                },
                options(),
            );
        }
        // Opt-in actual transport fixture: server and HTTP Approver keys stay
        // outside both native installations; no production key export is used.
        if matches!(additional_server, 3 | 4) {
            let source_inventory = ea_archive::ArchiveInventory::build(&material.fixture).unwrap();
            let server_device = source_inventory.trust().iter().find_map(|object| {
                match object.value().decoded_payload().ok()? {
                    ea_format::DecodedTrustPayloadV1::AuthorizedDevice(cert)
                        if cert.fields().certificate_kind == CertificateKindV1::ServerReceipt =>
                        Some(cert.fields().device_id),
                    _ => None,
                }
            }).unwrap();
            for (kind,marker,seed,device) in [
                (CertificateKindV1::ServerReceipt,0xc1,transport::SERVER_TRANSPORT_SECRET,server_device),
                (CertificateKindV1::DeletionAttest,0xc2,transport::SERVER_DELETION_SECRET,server_device),
                (CertificateKindV1::KeyApprover,0xc3,transport::HTTP_APPROVER_SECRET,DeviceId::try_from(&[0xc3;16][..]).unwrap()),
            ] {
                material.line.push(ActionSpec::Device { kind, marker, effective_from:Some(1) },
                    HeadOptions {
                        device_id_override:Some(device),
                        signing_public_key_override:Some(public(seed)),
                        certificate_capabilities_override:(kind==CertificateKindV1::KeyApprover).then(||vec!["destructionApprove".into()]),
                        ..options()
                    });
            }
        }
        // Explicit browser fixture only. The Reader's own audit public key is
        // admitted before the original authorization, not retrofitted later.
        let reader_opfs_component = reader_opfs.then(|| {
            let reader_device = inventory.trust().iter().find_map(|object| {
                match object.value().decoded_payload().ok()? {
                    ea_format::DecodedTrustPayloadV1::AuthorizedDevice(cert)
                        if cert.fields().certificate_kind == CertificateKindV1::Reader =>
                        Some(cert.fields().device_id),
                    _ => None,
                }
            }).unwrap();
            CertificateHash::from(material.line.push(
                ActionSpec::Device {
                    kind: CertificateKindV1::DeletionAttest,
                    marker: 0xd5,
                    effective_from: Some(1),
                },
                HeadOptions {
                    device_id_override: Some(reader_device),
                    signing_public_key_override: Some(public(READER_OPFS_COMPONENT_SECRET)),
                    certificate_capabilities_override: Some(vec!["deletionAttest".into()]),
                    ..options()
                },
            ).direct_object_hash.unwrap())
        });
        // Additive Pending-only fixture: an independently certified second
        // Reader duty, present before authorization and never a fake Server.
        let second_reader_component = second_reader.then(|| {
            let device = DeviceId::try_from(&[0xe2; 16][..]).unwrap();
            material.line.push(ActionSpec::Device {
                kind: CertificateKindV1::Reader, marker: 0xe1, effective_from: Some(1),
            }, HeadOptions { device_id_override: Some(device), ..options() });
            CertificateHash::from(material.line.push(ActionSpec::Device {
                kind: CertificateKindV1::DeletionAttest, marker: 0xe2, effective_from: Some(1),
            }, HeadOptions {
                device_id_override: Some(device),
                signing_public_key_override: Some(public(pending::SECOND_READER_COMPONENT_SECRET)),
                certificate_capabilities_override: Some(vec!["deletionAttest".into()]),
                ..options()
            }).direct_object_hash.unwrap())
        });
        let authorization_head = *material.line.heads().last().unwrap();
        if additional_server == 1 {
            material.line.push(
                ActionSpec::Device {
                    kind: CertificateKindV1::ServerReceipt,
                    marker: 0xa6,
                    effective_from: Some(2),
                },
                HeadOptions {
                    device_id_override: Some(DeviceId::try_from(&[0xa6; 16][..]).unwrap()),
                    effective_from: Some(2),
                    ..options()
                },
            );
        }
        {
            let source = material.line.source();
            let mut hashes = Vec::new();
            source
                .visit_trust_object_hashes(&mut |h| {
                    hashes.push(h);
                    Ok(())
                })
                .unwrap();
            for h in hashes {
                let exact = source.read_exact_trust_object(h).unwrap().unwrap().to_vec();
                if !material.fixture.blobs().iter().any(|(_, b)| *b == exact) {
                    material
                        .fixture
                        .push_exact_bytes(&format!("{}.etb", hex::encode(h.as_bytes())), exact);
                }
            }
        }
        let archive = directory.path().join("archive");
        support::materialize(&material.fixture, &archive);
        let anchor = directory.path().join("independent-anchor.etb");
        fs::write(&anchor, material.line.exact_anchor_bytes()).unwrap();
        let make_config = |root: &Path,
                           authority: bool,
                           certificate: CertificateHash,
                           binding: ObjectHash,
                           subject: OperatorSubjectId| {
            let database = root.join("local.sqlite");
            let (p, k) = database_provider_for(authority);
            let db = EncryptedDatabase::open(&database, &p, &k).unwrap();
            db.execute(
                "INSERT INTO operator_profile VALUES(0,?1,?2,?3,?4,?5,?6)",
                &[
                    StoreValue::Blob(trust_support::organization().as_bytes().to_vec()),
                    StoreValue::Blob(subject.as_bytes().to_vec()),
                    StoreValue::Text(TEST_NAME.into()),
                    StoreValue::Text(TEST_FUNCTION.into()),
                    StoreValue::Blob(PROFILE_SALT.to_vec()),
                    StoreValue::Blob(binding.as_bytes().to_vec()),
                ],
            )
            .unwrap();
            let config = root.join("operator.json");
            fs::write(&config,serde_json::to_vec(&json!({
                "archive_directory":archive,"database_path":database,"device_certificate_hash":hex::encode(certificate.as_bytes()),"binding_object_hash":hex::encode(binding.as_bytes()),"role":if authority{"organization-admin"}else{"writer"},"purpose":if authority{"destruction"}else{"finalize"}
            })).unwrap()).unwrap();
            config
        };
        let admin_config = make_config(
            &admin_directory,
            true,
            CertificateHash::from(material.line.second_bootstrap_admin_hash()),
            material.operator_binding,
            admin_subject,
        );
        let writer_config = make_config(
            &writer_directory,
            false,
            writer_certificate,
            binding,
            writer_subject,
        );
        let key = directory.path().join("component.eak");
        let pass = directory.path().join("component-passphrase");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        std::io::Write::write_all(
            &mut options.open(&pass).unwrap(),
            b"fixture independent component passphrase",
        )
        .unwrap();
        EncryptedKeyContainer::seal(
            ContainedKeyKind::Signing,
            ea_crypto::SecretBytes::new(COMPONENT_SECRET),
            &ea_crypto::SecretVec::new(b"fixture independent component passphrase".to_vec()),
        )
        .unwrap()
        .write_new(&key)
        .unwrap();
        let key_source = KeySourceSpec::parse(std::ffi::OsStr::new(&format!(
            "container:{};passphrase-file={}",
            key.display(),
            pass.display()
        )))
        .unwrap();
        let head = &authorization_head;
        let payload = ea_format::TrustPayloadV1::destruction_authorization(
            ea_format::DestructionAuthorizationFieldsV1 {
                destruction_id: DestructionId::try_from(&[0xa8; 16][..]).unwrap(),
                organization_id: trust_support::organization(),
                registry_version: head.version,
                registry_head_hash: Hash32::try_from(head.object_hash.as_bytes().as_slice())
                    .unwrap(),
                authorization_sequence: 1,
                targets: vec![ea_format::DestructionTargetV1::new(
                    *material.entry_hash.as_bytes(),
                    0,
                )],
                scope_code: 0,
                legal_reason_code: 0,
            },
        )
        .unwrap();
        let signatures = approvers
            .iter()
            .map(|cert| {
                trust_support::authorized_device_signer()
                    .sign_destruction_approval_digest(*cert, payload.exact_digest_input())
                    .unwrap()
            })
            .collect();
        let authorization =
            ea_format::encode_trust(&ea_format::TrustObjectV1::new(payload, signatures).unwrap())
                .unwrap()
                .as_bytes()
                .to_vec();
        Self {
            _directory: directory,
            admin_directory,
            writer_directory,
            archive,
            anchor,
            admin_config,
            writer_config,
            writer_certificate,
            component,
            reader_opfs_component,
            second_reader_component,
            profile,
            key_source,
            authorization,
            line: material.line,
        }
    }
    fn advance_unrelated_head(&mut self) {
        use ea_trust::TrustObjectSource as _;
        let source = ea_recovery::FsArchiveSource::open_committed(&self.archive).unwrap();
        let inventory = ea_archive::ArchiveInventory::build(&source).unwrap();
        let original = inventory.entries()[0].value();
        let recovery = inventory.grants()[0].value().grant_body().fields();
        let head = fixture::HeadRefV1::of(self.line.heads().last().unwrap());
        let signer = fixture::writer_device_signer();
        let plan = fixture::complete_grant_plan_hash(
            recovery.recipient_key_thumbprint,
            recovery.recipient_certificate_hash,
        );
        let next = fixture::build_complete_entry_signed_by(
            head,
            self.writer_certificate,
            &signer,
            None,
            original.manifest().fields().chain_id,
            plan,
            1,
            Some(original.entry_hash()),
            fixture::COMPLETE_PLAINTEXT_V1,
        );
        let grant = fixture::complete_grant_bytes_issued_by(
            head,
            self.writer_certificate,
            signer.public_key().unwrap().thumbprint(),
            &signer,
            original.manifest().fields().chain_id,
            next.entry_hash(),
            1,
            ea_format::GrantPurposeV1::Recovery,
            recovery.recipient_key_thumbprint,
            recovery.recipient_certificate_hash,
            &fixture::complete_recipient_private_key().public_key(),
        );
        fs::write(
            self.archive.join("entries/000000000001_progress.eip"),
            ea_format::encode_entry_package(&next).unwrap().as_bytes(),
        )
        .unwrap();
        fs::write(self.archive.join("grants/000000000001_progress.eag"), grant).unwrap();
        let mut previous = std::collections::BTreeSet::new();
        self.line
            .source()
            .visit_trust_object_hashes(&mut |hash| {
                previous.insert(hash);
                Ok(())
            })
            .unwrap();
        self.line.push(
            ActionSpec::Device {
                kind: CertificateKindV1::KeyApprover,
                marker: 0xb1,
                effective_from: Some(2),
            },
            HeadOptions {
                effective_from: Some(2),
                valid_through: Some(support::LIVE_WRITER_LEASE_THROUGH_V1),
                not_after: UnixMillis::new(support::LIVE_WRITER_NOT_AFTER_V1),
                device_id_override: Some(DeviceId::try_from(&[0xb1; 16][..]).unwrap()),
                authority_subject_id_override: Some(
                    ea_types::SubjectId::try_from(&[0xb1; 16][..]).unwrap(),
                ),
                ..Default::default()
            },
        );
        let source = self.line.source();
        source
            .visit_trust_object_hashes(&mut |hash| {
                if previous.contains(&hash) {
                    return Ok(());
                }
                let path = self
                    .archive
                    .join(format!("{}.etb", hex::encode(hash.as_bytes())));
                if !path.exists() {
                    fs::write(path, source.read_exact_trust_object(hash)?.unwrap()).unwrap();
                }
                Ok(())
            })
            .unwrap();
    }
    fn runtime(&self) -> DestructionRuntime {
        let open = |root: &Path, config: &Path| {
            let native =
                NativeOperatorProvider::open_test_fixture(root.join("ea-native-operator"), false)
                    .unwrap();
            OperatorRuntime::open_with_test_native(
                OperatorRuntimeConfig::load(config).unwrap(),
                &self.anchor,
                support::live_clock(),
                false,
                native,
            )
            .unwrap()
        };
        let controller = open(&self.admin_directory, &self.admin_config);
        let custodian = open(&self.writer_directory, &self.writer_config);
        let holder = NativeLocalHolder::open(
            &custodian,
            self.archive.clone(),
            self.profile.clone(),
            self.writer_certificate,
        )
        .unwrap();
        DestructionRuntime::new(
            controller,
            custodian,
            vec![holder],
            self.component,
            self.key_source.clone(),
        )
        .unwrap()
    }
}
#[test]
fn native_destruction_request_uses_distinct_admin_writer_and_protected_component_then_reopens() {
    let f = NativeDestructionFixture::new();
    let mut runtime = f.runtime();
    let status = runtime.prepare(&f.authorization).unwrap();
    assert_eq!(status.state.code(), 0);
    assert!(status.authorization_hash == ea_crypto::object_hash(&f.authorization));
    assert!(status.preflight_hash.is_some());
    let id = status.destruction_id;
    let preflight = status.preflight_hash;
    drop(runtime);
    let mut reopened = f.runtime();
    assert!(
        reopened.status(id).is_err(),
        "closed session cannot read control material"
    );
    reopened.unlock().unwrap();
    let restored = reopened.status(id).unwrap();
    assert!(restored.preflight_hash == preflight);
    assert_eq!(restored.state.code(), 0);
    assert!(
        !restored.replicas.is_empty(),
        "known offline holders remain denominator"
    );
    let (p, k) = database_provider_for(false);
    let writer =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &p, &k).unwrap();
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM destruction_request", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM destruction_job", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}

#[test]
fn native_destruction_start_reopens_exact_job_and_durably_audits_both_roles_before_removal() {
    use ea_admin::destruction_runtime::NativeDestructionDelivery;
    let fixture = NativeDestructionFixture::without_server();
    let mut runtime = fixture.runtime();
    let requested = runtime.prepare(&fixture.authorization).unwrap();
    let id = requested.destruction_id;
    let hash = requested.preflight_hash.unwrap();
    assert!(
        runtime
            .start(
                id,
                ea_crypto::object_hash(b"wrong preview"),
                NativeDestructionDelivery::NoRegisteredServer
            )
            .is_err()
    );
    let status = runtime
        .start(id, hash, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert!(status.state == ea_admin::destruction_runtime::DestructionState::InProgress);
    drop(runtime);
    let mut reopened = fixture.runtime();
    reopened.unlock().unwrap();
    let admin = reopened.administration().unwrap();
    assert_eq!(admin.known_destruction_ids.len(), 1);
    assert!(admin.known_destruction_ids[0] == id);
    assert!(
        reopened.status(id).unwrap().state
            == ea_admin::destruction_runtime::DestructionState::InProgress
    );
    let native = NativeOperatorProvider::open_test_fixture(
        fixture.writer_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let writer = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&fixture.writer_config).unwrap(),
        &fixture.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    let row = writer
        .database()
        .query_row("SELECT count(*) FROM destruction_job_event", &[])
        .unwrap()
        .unwrap();
    assert_eq!(row.integer(0).unwrap(), 1);
    assert!(
        writer.inventory().entries().len() == 1,
        "start records intent without claiming physical removal"
    );
}

#[test]
fn native_destruction_local_resume_removes_real_eip_grants_and_reopens_measured_attestation() {
    use ea_admin::destruction_runtime::{DestructionState, NativeDestructionDelivery};
    let fixture = NativeDestructionFixture::without_server();
    let mut runtime = fixture.runtime();
    let requested = runtime.prepare(&fixture.authorization).unwrap();
    let id = requested.destruction_id;
    assert!(
        requested
            .targets
            .iter()
            .all(|target| target.stub_object_hash.is_none())
    );
    runtime
        .start(
            id,
            requested.preflight_hash.unwrap(),
            NativeDestructionDelivery::NoRegisteredServer,
        )
        .unwrap();
    let result = runtime.resume_local(id, NativeDestructionDelivery::NoRegisteredServer);
    if result.is_err() {
        let source = ea_recovery::FsArchiveSource::open_committed(&fixture.archive).unwrap();
        let inventory = ea_archive::ArchiveInventory::build(&source).unwrap();
        let normal = ea_admin::operator_runtime::OperatorArchiveSnapshot::open(
            &fixture.archive,
            &fixture.anchor,
            support::live_clock(),
        )
        .err()
        .map(|e| e.code());
        eprintln!(
            "physical refusal: original_count={}, stub_count={}, normal_snapshot={normal:?}",
            inventory.entries().len(),
            inventory.destroyed().len()
        );
    }
    let status = result.unwrap();
    assert!(
        status
            .targets
            .iter()
            .all(|target| target.stub_object_hash.is_some()),
        "actual verified local stub must be projected"
    );
    assert!(
        status.evidence_entry_hash.is_none(),
        "no normal Writer Evidence has been committed"
    );
    let evidence = runtime
        .project_writer_evidence(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert!(evidence.destruction_id() == id);
    assert!(
        !evidence.all_managed_replicas_confirmed(),
        "offline Reader remains a real denominator obligation"
    );

    assert!(
        status.state == DestructionState::InProgress,
        "other known Reader remains unconfirmed"
    );
    assert!(
        status
            .replicas
            .iter()
            .any(|r| r.device_id == status.custodian_device_id && r.attestation_hash.is_some())
    );
    drop(runtime);
    let mut reopened = fixture.runtime();
    reopened.unlock().unwrap();
    let replay = reopened.status(id).unwrap();
    assert!(
        replay
            .replicas
            .iter()
            .any(|r| r.device_id == replay.custodian_device_id && r.attestation_hash.is_some())
    );
    let native = NativeOperatorProvider::open_test_fixture(
        fixture.writer_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let writer = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&fixture.writer_config).unwrap(),
        &fixture.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    assert!(writer.inventory().entries().is_empty());
    assert!(writer.inventory().grants().is_empty());
    assert_eq!(writer.inventory().destroyed().len(), 1);
    assert_eq!(
        writer
            .database()
            .query_row("SELECT count(*) FROM destruction_local_attestation", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}

#[test]
fn native_destruction_known_server_cannot_use_local_absence_selection() {
    use ea_admin::destruction_runtime::NativeDestructionDelivery;
    let fixture = NativeDestructionFixture::new();
    let mut runtime = fixture.runtime();
    let requested = runtime.prepare(&fixture.authorization).unwrap();
    assert!(
        runtime
            .start(
                requested.destruction_id,
                requested.preflight_hash.unwrap(),
                NativeDestructionDelivery::NoRegisteredServer
            )
            .is_err()
    );
    assert_eq!(
        runtime
            .status(requested.destruction_id)
            .unwrap()
            .state
            .code(),
        0
    );
}
#[test]
fn native_destruction_cross_database_audit_failure_repairs_exact_request_before_reporting_success()
{
    let fixture = NativeDestructionFixture::without_server();
    let mut runtime = fixture.runtime();
    let (provider, key) = database_provider_for(true);
    let admin = EncryptedDatabase::open_existing(
        &fixture.admin_directory.join("local.sqlite"),
        &provider,
        &key,
    )
    .unwrap();
    let auth = ea_crypto::object_hash(&fixture.authorization);
    admin.execute(&format!("CREATE TRIGGER refuse_destruction_audit BEFORE INSERT ON local_audit_event WHEN instr(NEW.exact_bytes,X'{}')>0 BEGIN SELECT RAISE(ABORT,'fixture audit write unavailable'); END",hex::encode(auth.as_bytes())),&[]).unwrap();
    assert!(runtime.prepare(&fixture.authorization).is_err());
    let (provider, key) = database_provider_for(false);
    let writer = EncryptedDatabase::open_existing(
        &fixture.writer_directory.join("local.sqlite"),
        &provider,
        &key,
    )
    .unwrap();
    let row = writer
        .query_row("SELECT audit_event_id FROM destruction_request", &[])
        .unwrap()
        .unwrap();
    let audit_id = row.blob(0).unwrap().to_vec();
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM destruction_job", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
    admin
        .execute("DROP TRIGGER refuse_destruction_audit", &[])
        .unwrap();
    drop(runtime);
    let mut reopened = fixture.runtime();
    let status = reopened.prepare(&fixture.authorization).unwrap();
    assert_eq!(status.state.code(), 0);
    let params = [ea_local_store::StoreValue::Blob(audit_id)];
    let exact_writer = writer
        .query_row(
            "SELECT exact_bytes FROM local_audit_event WHERE event_id=?1",
            &params,
        )
        .unwrap()
        .unwrap();
    let exact_admin = admin
        .query_row(
            "SELECT exact_bytes FROM local_audit_event WHERE event_id=?1",
            &params,
        )
        .unwrap()
        .unwrap();
    assert_eq!(exact_writer.blob(0).unwrap(), exact_admin.blob(0).unwrap());
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM destruction_request", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        1
    );
}

#[test]
fn native_destruction_holder_requires_measured_filesystem_capabilities() {
    let fixture = NativeDestructionFixture::without_server();
    let native = NativeOperatorProvider::open_test_fixture(
        fixture.writer_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let writer = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&fixture.writer_config).unwrap(),
        &fixture.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    fs::write(
        fixture.archive.join(".ea-capability"),
        b"fixture blocks capability scratch directory",
    )
    .unwrap();
    assert!(
        NativeLocalHolder::open(
            &writer,
            fixture.archive.clone(),
            fixture.profile.clone(),
            fixture.writer_certificate
        )
        .is_err(),
        "profile allowlist alone does not prove actual filesystem semantics"
    );
}

#[cfg(feature = "desktop-fixture")]
mod desktop;

#[test]
fn native_destruction_host_epoch_change_during_presence_refuses_request() {
    use ea_admin::destruction_runtime::{DestructionHostGuard, NativeDestructionError};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    struct Epoch(Arc<AtomicU64>);
    impl DestructionHostGuard for Epoch {
        fn require_open(&self) -> Result<(), NativeDestructionError> {
            if self.0.load(Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(NativeDestructionError::Session)
            }
        }
    }
    let fixture = NativeDestructionFixture::without_server();
    let mut runtime = fixture.runtime();
    let epoch = Arc::new(AtomicU64::new(0));
    runtime.set_host_guard(Arc::new(Epoch(epoch.clone())));
    let barrier = fixture.admin_directory.join("hold-operator-signature");
    fs::write(&barrier, b"").unwrap();
    let exact = fixture.authorization.clone();
    let action = std::thread::spawn(move || runtime.prepare(&exact));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !fixture
        .admin_directory
        .join("operator-signature-paused")
        .exists()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "actual native presence barrier"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    epoch.store(1, Ordering::SeqCst);
    fs::remove_file(barrier).unwrap();
    assert!(
        action.join().unwrap().is_err(),
        "closed host session must refuse after actual native presence"
    );
    let (provider, key) = database_provider_for(false);
    let db = EncryptedDatabase::open_existing(
        &fixture.writer_directory.join("local.sqlite"),
        &provider,
        &key,
    )
    .unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_request", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
}

mod crash;

#[test]
fn native_destruction_host_closure_at_real_stub_refuses_first_remove() {
    use ea_admin::destruction_runtime::{
        DestructionHostGuard, NativeDestructionDelivery, NativeDestructionError,
    };
    use std::sync::Arc;
    struct CloseAtStub(PathBuf);
    impl DestructionHostGuard for CloseAtStub {
        fn require_open(&self) -> Result<(), NativeDestructionError> {
            let contains_stub = fs::read_dir(self.0.join(ea_archive::DESTROYED_ENTRIES_DIR_V1))
                .ok()
                .into_iter()
                .flatten()
                .any(|entry| {
                    entry.ok().is_some_and(|entry| {
                        entry.path().extension().is_some_and(|ext| ext == "eds")
                    })
                });
            if contains_stub {
                Err(NativeDestructionError::Session)
            } else {
                Ok(())
            }
        }
    }
    let f = NativeDestructionFixture::without_server();
    let mut runtime = f.runtime();
    let requested = runtime.prepare(&f.authorization).unwrap();
    runtime
        .start(
            requested.destruction_id,
            requested.preflight_hash.unwrap(),
            NativeDestructionDelivery::NoRegisteredServer,
        )
        .unwrap();
    runtime.set_host_guard(Arc::new(CloseAtStub(f.archive.clone())));
    assert!(
        runtime
            .resume_local(
                requested.destruction_id,
                NativeDestructionDelivery::NoRegisteredServer
            )
            .is_err(),
        "actual stub checkpoint invalidates host before first physical removal"
    );
    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let inventory = ea_archive::ArchiveInventory::build(&source).unwrap();
    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(inventory.destroyed().len(), 1);
    let (provider, key) = database_provider_for(false);
    let db =
        EncryptedDatabase::open_existing(&f.writer_directory.join("local.sqlite"), &provider, &key)
            .unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM destruction_local_attestation", &[])
            .unwrap()
            .unwrap()
            .integer(0)
            .unwrap(),
        0
    );
}

mod audit_repair;

mod no_server;

mod restart;

mod import;

mod transport;

mod writer_evidence;

mod custodian;

mod evidence_writer;

mod reader_delivery;

mod completion;
pub(super) use completion::pause_audit_signature as pause_completion_audit_signature;

#[cfg(feature = "desktop-fixture")]
mod prepared_diagnosis;

mod pending;
mod failure;
