#[path = "../../ea-destruction/tests/preflight.rs"]
mod local_fixture;
use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_draft::{
    AutosaveDraftRepository, DraftRepository, IncidentNumberRegister, OperatorProfileRepository,
};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{
    CoseSign1Bytes, InMemoryKeyProvider, KeyError, KeyHandle, KeyProvider, SecretPurpose,
};
use ea_types::*;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;

// Real deterministic fixture signing key, with the ordinary measured native
// provider retaining/deleting the independent draft key. No Recovery KEM is
// supplied to the Writer service.
struct FixtureProvider {
    inner: InMemoryKeyProvider,
    deleted_draft: std::sync::atomic::AtomicBool,
}
impl KeyProvider for FixtureProvider {
    fn sign(
        &self,
        handle: &KeyHandle,
        content: ContentType,
        cert: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        handle.require_purpose(&[SecretPurpose::WriterSigningKey])?;
        if !self.inner.contains(handle)? {
            return Err(KeyError::NotFound);
        }
        let key = SigningKey::from_bytes(&local_fixture::support::trust::device_signing_secret());
        let public = CanonicalPublicCoseKey::ed25519(key.verifying_key().to_bytes()).unwrap();
        let protected = ProtectedHeader::normal(content, public.thumbprint(), cert);
        CoseSign1Bytes::compose(
            &protected,
            payload,
            &key.sign(&protected.sig_structure_bytes(payload)).to_bytes(),
        )
    }
    fn generate(&self, p: SecretPurpose, k: KeyProtectionProfileV1) -> Result<KeyHandle, KeyError> {
        self.inner.generate(p, k)
    }
    fn wrap_secret(&self, p: SecretPurpose, s: SecretBytes<32>) -> Result<KeyHandle, KeyError> {
        self.inner.wrap_secret(p, s)
    }
    fn unwrap_secret(&self, h: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        self.inner.unwrap_secret(h)
    }
    fn unwrap_database_key(&self, h: &KeyHandle) -> Result<SecretVec, KeyError> {
        self.inner.unwrap_database_key(h)
    }
    fn delete(&self, h: &KeyHandle) -> Result<(), KeyError> {
        self.inner.delete(h)?;
        if h.purpose() == SecretPurpose::DraftDek {
            self.deleted_draft.store(
                !self.inner.contains(h)?,
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        Ok(())
    }
    fn contains(&self, h: &KeyHandle) -> Result<bool, KeyError> {
        self.inner.contains(h)
    }
    fn reached_protection_profile(
        &self,
        h: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        self.inner.reached_protection_profile(h)
    }
}

#[test]
fn root_probe_staged_original_cannot_bypass_evidence_preview() {
    run(false);
}
#[test]
fn root_probe_staged_original_cannot_bypass_evidence_recovery() {
    run(true);
}
fn run(recover: bool) {
    let fixture = local_fixture::local_evidence_fixture();
    let provider = Arc::new(FixtureProvider {
        inner: InMemoryKeyProvider::new_for_test([0x32; 32]),
        deleted_draft: std::sync::atomic::AtomicBool::new(false),
    });
    let signing = provider
        .generate(
            SecretPurpose::WriterSigningKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .unwrap();
    let repository = Arc::new(AutosaveDraftRepository::new(
        fixture.native.database.clone(),
        provider.clone(),
    ));
    let draft = repository.load_or_create().unwrap();
    assert!(draft.notes().is_empty(), "Evidence starts from an empty draft");
    let binding = repository
        .reserve_evidence_draft(fixture.evidence.draft_source().unwrap())
        .unwrap();
    let repository = Arc::new(repository.for_evidence_draft(binding).unwrap());
    let saved = repository.save(draft).unwrap();
    let draft_key = repository.draft_dek_handle(&saved).unwrap();
    use ea_local_store::StoreValue as V;
    fixture.native.database.execute("INSERT INTO operator_profile(singleton,organization_id,operator_subject_id,display_name,function_label,profile_commitment_salt,operator_binding_object_hash) VALUES(0,?1,?2,?3,?4,?5,?6)",&[V::Blob(fixture.head.active_certificate_fields(fixture.native.certificate).unwrap().organization_id.as_bytes().to_vec()),V::Blob(vec![0x73;16]),V::Text("Destruction Writer".into()),V::Text("Operator".into()),V::Blob(vec![0x74;32]),V::Blob(fixture.native.binding.as_bytes().to_vec())]).unwrap();
    let source = fixture.backend.as_archive_source();
    let service = ea_writer::WriterService::new(
        repository.clone(),
        provider.clone(),
        &fixture.backend,
        &source,
        &fixture.head,
        &[],
        IncidentNumberRegister::new(fixture.native.database.clone()),
        OperatorProfileRepository::new(fixture.native.database.clone()),
        ea_writer::WriterBindingV1 {
            binding_object_hash: fixture.native.binding,
            writer_certificate_hash: fixture.native.certificate,
            writer_key_thumbprint: fixture
                .head
                .active_certificate_fields(fixture.native.certificate)
                .unwrap()
                .signing_key_thumbprint
                .unwrap(),
            writer_signing_handle: signing,
            chain_id: fixture.head.chain_id(),
            archive_profile_hash: fixture.backend.profile_hash().unwrap(),
        },
    );
    let input = || ea_writer::DestructionEvidenceInputV1 {
        timezone: "Europe/Berlin".into(),
        source: ea_schema::NativeSourceV1::new("ea.native", 1).unwrap(),
        evidence: fixture.evidence.clone(),
    };
    let proof = fixture
        .native
        .proof(&fixture.head, ea_operator::ReauthPurpose::Finalize);
    // Identical previously measured bytes must not bypass the source fence.
    let reinjected = fixture.backend.root().join(if recover {
        "entries/reinjected.eip"
    } else {
        "entries/reinjected.eip.staging"
    });
    std::fs::write(&reinjected, &fixture.original.original_bytes).unwrap();
    assert!(matches!(
        service.preview_destruction_evidence(&proof, input(), UnixMillis::new(1001)),
        Err(ea_writer::WriterError::DestructionEvidenceInvalid)
    ));
    assert!(provider.contains(&draft_key).unwrap());
    std::fs::remove_file(reinjected).unwrap();
    let preview = service
        .preview_destruction_evidence(&proof, input(), UnixMillis::new(1001))
        .unwrap();
    let exact_recovered = if recover {
        let state = service
            .finalize_destruction_evidence_interrupted_at(
                &proof,
                input(),
                UnixMillis::new(1001),
                ea_writer::FinalizationFaultPoint::AfterAbsenceConfirmation,
            )
            .unwrap();
        assert!(!provider.contains(&draft_key).unwrap());
        assert_eq!(
            fixture
                .native
                .database
                .query_row("SELECT count(*) FROM writer_destruction_evidence", &[])
                .unwrap()
                .unwrap()
                .integer(0)
                .unwrap(),
            1
        );
        assert!(
            fixture
                .native
                .database
                .execute(
                    "UPDATE writer_destruction_evidence SET exact_binding=x'00'",
                    &[]
                )
                .is_err()
        );
        assert!(
            fixture
                .native
                .database
                .execute("DELETE FROM writer_destruction_evidence", &[])
                .is_err()
        );
        let exact = state.entry_bytes().to_vec();
        drop(service);
        drop(repository);
        let reopened = fixture.native.reopen();
        let repository = Arc::new(AutosaveDraftRepository::new(
            reopened.clone(),
            provider.clone(),
        ));
        let binding = repository.evidence_binding().unwrap().unwrap();
        let repository = Arc::new(repository.for_evidence_draft(binding).unwrap());
        let resume_service = |repository: Arc<AutosaveDraftRepository>| ea_writer::WriterService::new(
            repository,
            provider.clone(),
            &fixture.backend,
            &source,
            &fixture.head,
            &[],
            IncidentNumberRegister::new(reopened.clone()),
            OperatorProfileRepository::new(reopened.clone()),
            ea_writer::WriterBindingV1 {
                binding_object_hash: fixture.native.binding,
                writer_certificate_hash: fixture.native.certificate,
                writer_key_thumbprint: fixture
                    .head
                    .active_certificate_fields(fixture.native.certificate)
                    .unwrap()
                    .signing_key_thumbprint
                    .unwrap(),
                writer_signing_handle: provider
                    .generate(
                        SecretPurpose::WriterSigningKey,
                        KeyProtectionProfileV1::OsWrapped,
                    )
                    .unwrap(),
                chain_id: fixture.head.chain_id(),
                archive_profile_hash: fixture.backend.profile_hash().unwrap(),
            },
        );
        let resumed = resume_service(repository);
        let reinjected = fixture
            .backend
            .root()
            .join("entries/crash-window-reinjected.eip.staging");
        std::fs::write(&reinjected, &fixture.original.original_bytes).unwrap();
        let observed = resumed.recover_pending();
        assert!(
            matches!(observed, Err(ea_writer::WriterError::DestructionEvidenceInvalid)),
            "staged target must prevent Evidence publication: {:?}; staged_original_exists={}",
            observed.as_ref().map(|outcome| outcome.summary()),
            reinjected.exists(),
        );
        assert_eq!(
            ea_archive::ArchiveInventory::build(&source)
                .unwrap()
                .entries()
                .len(),
            0,
            "the re-injected original is staging only; committed source and Evidence remain empty"
        );
        std::fs::remove_file(reinjected).unwrap();
        let grant = fixture
            .backend
            .root()
            .join("grants/crash-window-reinjected.eag");
        std::fs::write(&grant, &fixture.original.initial_grant_bytes).unwrap();
        assert!(matches!(
            resumed.recover_pending(),
            Err(ea_writer::WriterError::DestructionEvidenceInvalid)
        ));
        std::fs::remove_file(grant).unwrap();
        let stub = fixture.backend.root().join(format!(
            "destroyed-entries/{}.eds",
            hex::encode(fixture.original.entry_hash.as_bytes())
        ));
        let original_stub = std::fs::read(&stub).unwrap();
        std::fs::remove_file(&stub).unwrap();
        assert!(matches!(
            resumed.recover_pending(),
            Err(ea_writer::WriterError::DestructionEvidenceInvalid)
        ));
        std::fs::write(stub, original_stub).unwrap();
        assert_eq!(
            resumed.recover_pending().unwrap().summary(),
            ("CommittedFromPreparedBytes", 1)
        );
        assert!(matches!(
            resumed.recover_pending(),
            Err(ea_writer::WriterError::Draft(ea_draft::DraftError::EvidenceBinding))
        ), "the consumed Evidence facade cannot address the new ordinary draft");
        let ordinary = Arc::new(AutosaveDraftRepository::new(
            fixture.native.reopen(),
            provider.clone(),
        ));
        assert_eq!(
            resume_service(ordinary).recover_pending().unwrap().summary(),
            ("NothingPending", 0)
        );
        Some(exact)
    } else {
        let result = service
            .finalize_destruction_evidence(&proof, input(), &preview, UnixMillis::new(1001))
            .unwrap();
        assert_eq!(result.sequence.get(), 1);
        None
    };
    let inventory =
        ea_archive::ArchiveInventory::build(&fixture.backend.as_archive_source()).unwrap();
    assert_eq!(inventory.destroyed().len(), 1);
    assert_eq!(inventory.entries().len(), 1);
    if let Some(exact) = exact_recovered {
        assert_eq!(inventory.entries()[0].exact_bytes().as_bytes(), exact);
    }
    assert!(
        inventory.entries()[0]
            .value()
            .manifest()
            .fields()
            .previous_entry_hash
            == Some(fixture.original.entry_hash)
    );
    assert!(inventory.grants().iter().any(|g|g.value().grant_body().fields().purpose==ea_format::GrantPurposeV1::Recovery));
    assert!(!fixture.backend.root().join("entries/original.eip").exists());
    // Step 13 creates a new draft at the same provider address. The measured
    // absence is the real boundary before that independent replacement.
    assert!(
        provider
            .deleted_draft
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    // Independent Recovery actor: no private recipient key entered Writer.
    let private = local_fixture::archive_support::complete_recipient_private_key();
    let entry = &inventory.entries()[0];
    let grant = inventory
        .grants()
        .iter()
        .find(|g| {
            g.value().grant_body().fields().recipient_key_thumbprint
                == local_fixture::archive_support::complete_recipient_key_thumbprint()
        })
        .unwrap();
    let body = grant.value().grant_body();
    let fields = body.fields();
    let sealed =
        ea_crypto::HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek).unwrap();
    let context = body.exact_grant_context().unwrap();
    let cek = ea_crypto::hpke_open(
        &private,
        &sealed,
        &ea_crypto::hpke_info(context),
        &ea_crypto::hpke_aad(context),
    )
    .unwrap();
    let plaintext = ea_crypto::aead_open(
        &cek,
        &SecretBytes::new(entry.value().manifest().fields().nonce),
        entry.value().ciphertext(),
        &ea_crypto::payload_aad(entry.value().manifest().exact_bytes()),
    )
    .unwrap();
    let validated = plaintext
        .with_exposed(|bytes| {
            ea_schema::SchemaRegistry::v1().validate("ea.destruction-evidence", 1, bytes)
        })
        .unwrap();
    let ea_schema::PayloadV1::DestructionEvidence(evidence) = validated.payload() else {
        panic!("normal encrypted destructionEvidence")
    };
    assert!(evidence.destruction_id() == fixture.evidence.destruction_id());
    assert_eq!(evidence.targets().len(), 1);
    assert_eq!(evidence.stub_bindings().len(), 1);
    assert_eq!(evidence.replica_results().len(), 3);
    let report = ea_verify::verify_archive(
        &fixture.backend.as_archive_source(),
        &fixture.original.anchor,
        ea_verify::VerifyOptions::new(UnixMillis::new(1001)).with_recipient(
            local_fixture::archive_support::complete_recipient_key_thumbprint(),
            &private,
        ),
    )
    .unwrap();
    assert!(
        report
            .object_results()
            .any(|r| r.result() == ea_verify::ObjectResultKindV1::AuthorizedDestroyed),
        "{}",
        report.to_canonical_json().unwrap()
    );
}
