use super::*;
use ea_admin::destruction_runtime::NativeDestructionDelivery;
use ea_archive::{ArchiveInventory, BoundArchiveProfilePolicyV1};
use ea_archive_fs::LocalPathBackend;
use ea_draft::{
    AutosaveDraftRepository, DraftRepository, IncidentNumberRegister, OperatorProfileRepository,
};
use ea_key_provider::SecretPurpose;
use ea_reader::{
    AuthenticatorPrfV1, EntryStatus, ReaderMode, ReaderVault, ReaderVerifier, SilentObserver,
    VaultContentsV1,
};
use ea_writer::{DestructionEvidenceInputV1, WriterBindingV1, WriterService};

fn open_writer(f: &NativeDestructionFixture) -> OperatorRuntime {
    let native = NativeOperatorProvider::open_test_fixture(
        f.writer_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.writer_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap()
}

#[test]
fn native_writer_evidence_reopens_as_real_reader_authorized_destruction() {
    let f = NativeDestructionFixture::without_server();
    let original_source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let original_inventory = ArchiveInventory::build(&original_source).unwrap();
    let original_exact = original_inventory.entries()[0]
        .exact_bytes()
        .as_bytes()
        .to_vec();
    let original_hash = original_inventory.entries()[0].value().entry_hash();
    drop(original_inventory);
    drop(original_source);

    let mut admin = f.runtime();
    let requested = admin.prepare(&f.authorization).unwrap();
    let id = requested.destruction_id;
    admin
        .start(
            id,
            requested.preflight_hash.unwrap(),
            NativeDestructionDelivery::NoRegisteredServer,
        )
        .unwrap();
    let measured = admin
        .resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert!(measured.evidence_entry_hash.is_none());
    refuse_closed_epoch_projection(&f, admin, id);
    let mut admin = f.runtime();
    let evidence = admin
        .project_writer_evidence(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    assert!(
        !evidence.all_managed_replicas_confirmed(),
        "missing Reader stays an obligation"
    );
    drop(admin);

    // Separately bound native Writer; the Admin projection supplies no Writer
    // session, private key, prepared entry, or finalization authority.
    let writer = open_writer(&f);
    let backend = LocalPathBackend::open(
        f.archive.clone(),
        f.profile.clone(),
        &BoundArchiveProfilePolicyV1::from_policy(writer.head().policy_fields()),
    )
    .unwrap();
    let source = backend.as_archive_source();
    let provider = writer.signing_provider().clone();
    let repository = Arc::new(AutosaveDraftRepository::new(
        writer.database().clone(),
        provider.clone(),
    ));
    let draft = repository.load_or_create().unwrap();
    repository.save(draft).unwrap();
    let binding = repository.reserve_evidence_draft(evidence.draft_source().unwrap()).unwrap();
    let repository = Arc::new(repository.for_evidence_draft(binding).unwrap());
    let service = WriterService::new(
        repository.clone(),
        provider.clone(),
        &backend,
        &source,
        writer.head(),
        &[],
        IncidentNumberRegister::new(writer.database().clone()),
        OperatorProfileRepository::new(writer.database().clone()),
        WriterBindingV1 {
            binding_object_hash: writer.config().binding_object_hash,
            writer_certificate_hash: writer.config().device_certificate_hash,
            writer_key_thumbprint: writer
                .head()
                .active_certificate_fields(f.writer_certificate)
                .unwrap()
                .signing_key_thumbprint
                .unwrap(),
            writer_signing_handle: provider.handle(SecretPurpose::WriterSigningKey),
            chain_id: writer.anchor().chain_id(),
            archive_profile_hash: backend.profile_hash().unwrap(),
        },
    );
    let input = || DestructionEvidenceInputV1 {
        timezone: "Europe/Berlin".into(),
        source: ea_schema::NativeSourceV1::new("ea.native", 1).unwrap(),
        evidence: evidence.clone(),
    };
    let admin_native = NativeOperatorProvider::open_test_fixture(
        f.admin_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let controller = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.admin_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        admin_native,
    )
    .unwrap();
    let wrong_role = controller
        .reauthenticate_for(ea_operator::ReauthPurpose::Destruction)
        .unwrap();
    assert!(
        matches!(
            service.preview_destruction_evidence(
                wrong_role.proof(),
                input(),
                support::live_clock()
            ),
            Err(ea_writer::WriterError::ReauthBindingMismatch)
        ),
        "a real Admin destruction proof cannot authorize a Writer finalization"
    );
    drop(controller);
    let preview_proof = writer
        .reauthenticate_for(ea_operator::ReauthPurpose::Finalize)
        .unwrap();
    let staged = f
        .archive
        .join("entries/native-evidence-reinjection.eip.staging");
    fs::write(&staged, original_exact).unwrap();
    assert!(
        matches!(
            service.preview_destruction_evidence(
                preview_proof.proof(),
                input(),
                support::live_clock()
            ),
            Err(ea_writer::WriterError::DestructionEvidenceInvalid)
        ),
        "actual staged original must block the normal native Writer pipeline"
    );
    fs::remove_file(staged).unwrap();
    let preview = service
        .preview_destruction_evidence(preview_proof.proof(), input(), support::live_clock())
        .unwrap();
    // Native presence occurs again for the exact immutable Preview. Its time
    // remains selected; the action proof itself is verified against fresh state.
    let finalize_proof = writer
        .reauthenticate_for(ea_operator::ReauthPurpose::Finalize)
        .unwrap();
    let current = writer.reopened_for_action().unwrap();
    ea_operator::verify_current_session(
        current.head(),
        current.config().device_certificate_hash,
        OperatorRoleV1::Writer,
        finalize_proof.proof(),
        ea_operator::ReauthPurpose::Finalize,
        current.native().as_ref(),
    )
    .unwrap();
    let outcome = service
        .finalize_destruction_evidence(
            finalize_proof.proof(),
            input(),
            &preview,
            preview.effective_now(),
        )
        .unwrap();
    assert_eq!(outcome.sequence.get(), 1);
    let evidence_hash = outcome.entry_hash;
    drop(service);
    drop(repository);
    drop(provider);
    drop(current);
    drop(writer);

    let mut reopened = f.runtime();
    reopened.unlock().unwrap();
    let status = reopened.status(id).unwrap();
    assert!(
        status.evidence_entry_hash == Some(evidence_hash),
        "only the normal committed Evidence is projected after native reopen"
    );
    assert_eq!(
        status.state,
        ea_admin::destruction_runtime::DestructionState::InProgress
    );
    drop(reopened);

    let source = ea_recovery::FsArchiveSource::open_committed(&f.archive).unwrap();
    let inventory = ArchiveInventory::build(&source).unwrap();
    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(inventory.destroyed().len(), 1);
    assert!(
        inventory.entries()[0]
            .value()
            .manifest()
            .fields()
            .previous_entry_hash
            == Some(original_hash)
    );
    assert!(
        inventory.grants().iter().any(|g| {
            let fields = g.value().grant_body().fields();
            fields.purpose == ea_format::GrantPurposeV1::Reader
                && fields.recipient_key_thumbprint == fixture::other_recipient_key_thumbprint()
        }),
        "normal Writer grants must include the separately certified Reader KEM"
    );

    let authenticator = || {
        AuthenticatorPrfV1::new(
            b"native-evidence-reader".to_vec(),
            ea_crypto::SecretBytes::new([0xd1; 32]),
        )
    };
    let sealed = ReaderVault::seal(
        VaultContentsV1::new(
            ea_crypto::SecretBytes::new(fixture::other_recipient_secret_bytes()),
            ea_crypto::SecretBytes::new([0xd2; 32]),
            fs::read(&f.anchor).unwrap(),
            None,
        ),
        &[authenticator()],
    )
    .unwrap();
    let vault = ReaderVault::unlock(&sealed, &authenticator()).unwrap();
    let mut metadata = ea_reader::InMemoryReaderBlobStore::new();
    let classified = ReaderVerifier::new(ReaderMode::File, support::live_clock())
        .classify_with_time_store(&source, &vault, &mut metadata, &mut SilentObserver)
        .unwrap();
    assert_eq!(
        classified.state_of(original_hash).unwrap().entry_state(),
        EntryStatus::AuthorizedDestroyed,
        "the real native Writer output must authorize the exact EDS in the ordinary Reader"
    );
    assert!(
        classified.verified_entry(original_hash).is_none(),
        "destroyed original never receives a decryption witness"
    );
    assert!(
        classified.verified_entry(evidence_hash).is_some(),
        "the normal encrypted Evidence itself has a Reader witness"
    );
}

fn refuse_closed_epoch_projection(
    f: &NativeDestructionFixture,
    mut admin: DestructionRuntime,
    id: DestructionId,
) {
    use ea_admin::destruction_runtime::{DestructionHostGuard, NativeDestructionError};
    use std::sync::atomic::{AtomicU64, Ordering};
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
    let epoch = Arc::new(AtomicU64::new(0));
    admin.set_host_guard(Arc::new(Epoch(epoch.clone())));
    let barrier = f.admin_directory.join("hold-operator-signature");
    let paused = f.admin_directory.join("operator-signature-paused");
    if paused.exists() {
        fs::remove_file(&paused).unwrap();
    }
    fs::write(&barrier, b"").unwrap();
    let action = std::thread::spawn(move || {
        admin.project_writer_evidence(id, NativeDestructionDelivery::NoRegisteredServer)
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !paused.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "actual native Evidence presence barrier"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    epoch.store(1, Ordering::SeqCst);
    fs::remove_file(barrier).unwrap();
    assert!(
        matches!(action.join().unwrap(), Err(NativeDestructionError::Session)),
        "epoch closure during real presence cannot issue an opaque Writer evidence projection"
    );
}
