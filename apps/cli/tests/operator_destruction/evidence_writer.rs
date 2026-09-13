use super::*;
use ea_admin::destruction_runtime::NativeDestructionDelivery;
fn prepared() -> (
    NativeDestructionFixture,
    DestructionRuntime,
    ea_destruction::VerifiedDestructionEvidence,
) {
    let f = NativeDestructionFixture::without_server();
    let mut r = f.runtime();
    let p = r.prepare(&f.authorization).unwrap();
    let id = p.destruction_id;
    r.start(
        id,
        p.preflight_hash.unwrap(),
        NativeDestructionDelivery::NoRegisteredServer,
    )
    .unwrap();
    r.resume_local(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    let e = r
        .project_writer_evidence(id, NativeDestructionDelivery::NoRegisteredServer)
        .unwrap();
    (f, r, e)
}
#[test]
fn adapter_native_writer_presence_and_exact_publication() {
    let (f, r, e) = prepared();
    let id = e.draft_source().unwrap().destruction_id();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    let p = w.preview(e).unwrap();
    assert!(w.pending().unwrap().is_some());
    let o = w.finalize(p.preview_hash()).unwrap();
    assert!(w.issued_preview().is_none());
    assert!(w.finalize(p.preview_hash()).is_err());
    let mut reopened = f.runtime();
    reopened.unlock().unwrap();
    assert!(reopened.status(id).unwrap().evidence_entry_hash == Some(o.entry_hash));
}
#[test]
fn adapter_lock_refuses_preview_without_reservation() {
    let (f, r, e) = prepared();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    w.lock();
    assert!(w.preview(e).is_err());
}

fn calls(f: &NativeDestructionFixture) -> usize {
    fs::read_to_string(f.writer_directory.join("helper-calls"))
        .unwrap()
        .lines()
        .filter(|l| *l == "sign operator-instance")
        .count()
}
#[test]
fn adapter_epoch_closes_during_actual_independent_writer_presence() {
    use ea_admin::destruction_runtime::{DestructionHostGuard, NativeDestructionError};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Epoch(Arc<AtomicBool>);
    impl DestructionHostGuard for Epoch {
        fn require_open(&self) -> Result<(), NativeDestructionError> {
            if self.0.load(Ordering::SeqCst) {
                Err(NativeDestructionError::Session)
            } else {
                Ok(())
            }
        }
    }
    let (f, r, e) = prepared();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    let before = calls(&f);
    let epoch = Arc::new(AtomicBool::new(false));
    w.set_host_guard(Arc::new(Epoch(epoch.clone())));
    let barrier = f.writer_directory.join("hold-operator-signature");
    let paused = f.writer_directory.join("operator-signature-paused");
    let _ = fs::remove_file(&paused);
    fs::write(&barrier, b"").unwrap();
    let action = std::thread::spawn(move || w.preview(e));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !paused.exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    epoch.store(true, Ordering::SeqCst);
    fs::remove_file(barrier).unwrap();
    assert!(action.join().unwrap().is_err());
    assert_eq!(calls(&f), before + 1);
    let reopened = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    assert!(reopened.pending().unwrap().is_none());
}
#[test]
fn adapter_exact_hash_consumption_and_explicit_durable_discard() {
    let (f, r, e) = prepared();
    let source = e.draft_source().unwrap();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    let before = calls(&f);
    let p = w.preview(e).unwrap();
    assert_eq!(calls(&f), before + 1);
    assert!(
        w.finalize(ea_types::Hash32::try_from(&[0xee; 32][..]).unwrap())
            .is_err()
    );
    assert!(w.issued_preview().is_none());
    assert!(w.finalize(p.preview_hash()).is_err());
    let binding = w.pending().unwrap().unwrap();
    drop(w);
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    assert!(w.pending().unwrap() == Some(binding));
    assert!(
        w.discard(
            source.destruction_id(),
            ea_types::ObjectHash::try_from(&[0xee; 32][..]).unwrap()
        )
        .is_err()
    );
    assert!(
        w.recover(
            ea_types::DestructionId::try_from(&[0xee; 16][..]).unwrap(),
            source.preflight_hash()
        )
        .is_err()
    );
    assert!(w.pending().unwrap() == Some(binding));
    assert!(matches!(
        w.discard(source.destruction_id(), source.preflight_hash())
            .unwrap(),
        ea_draft::RestartState::NewBlankDraft
    ));
    assert!(w.pending().unwrap().is_none());
    let mut admin = f.runtime();
    admin.unlock().unwrap();
    assert!(
        admin
            .status(source.destruction_id())
            .unwrap()
            .evidence_entry_hash
            .is_none()
    );
}
#[test]
fn adapter_recovers_same_job_after_native_key_delete_response_loss() {
    let (f, r, e) = prepared();
    let source = e.draft_source().unwrap();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    let p = w.preview(e).unwrap();
    fs::write(
        f.writer_directory.join("helper-mode"),
        "draft-delete-response-lost",
    )
    .unwrap();
    assert!(w.finalize(p.preview_hash()).is_err());
    assert!(!f.writer_directory.join("fixture-draft-key.sealed").exists());
    let binding = w.pending().unwrap().unwrap();
    drop(w);
    fs::remove_file(f.writer_directory.join("helper-mode")).unwrap();
    let r = f.runtime();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    assert!(w.pending().unwrap() == Some(binding));
    assert!(matches!(
        w.recover(source.destruction_id(), source.preflight_hash())
            .unwrap(),
        ea_writer::RecoveryOutcome::CommittedFromPreparedBytes { .. }
    ));
    assert!(w.pending().unwrap().is_none());
    let mut admin = f.runtime();
    admin.unlock().unwrap();
    assert!(
        admin
            .status(source.destruction_id())
            .unwrap()
            .evidence_entry_hash
            .is_some()
    );
}

#[test]
fn adapter_refuses_wrong_profile_and_preserves_occupied_incident() {
    use ea_draft::DraftRepository;
    let (f, r, e) = prepared();
    let mut profile = f.profile.clone();
    if let ArchiveBackendProfileV1::LocalPath(p) = &mut profile {
        p.capability_test_vector_id.push_str("-foreign");
    }
    assert!(r.evidence_writer("Europe/Berlin".into(), profile).is_err());
    let native = NativeOperatorProvider::open_test_fixture(
        f.writer_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let writer = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.writer_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    let repository = ea_draft::AutosaveDraftRepository::new(
        writer.database().clone(),
        writer.signing_provider().clone(),
    );
    let draft = repository.load_or_create().unwrap();
    let id = draft.draft_id();
    let saved = repository
        .save(draft.with_notes("occupied native incident"))
        .unwrap();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    assert!(w.preview(e).is_err());
    assert!(w.pending().unwrap().is_none());
    let after = repository.load_or_create().unwrap();
    assert!(after.draft_id() == id);
    assert_eq!(after.notes(), "occupied native incident");
    assert_eq!(after.revision(), saved.revision());
}

#[test]
fn adapter_native_watch_cannot_be_implicitly_replaced() {
    let (f, r, e) = prepared();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    let before = calls(&f);
    let event = f.writer_directory.join("watch-action");
    fs::write(&event, b"watch-event").unwrap();
    assert!(w.preview(e.clone()).is_err());
    fs::remove_file(event).unwrap();
    assert!(w.preview(e).is_err());
    assert_eq!(calls(&f), before);
}
#[test]
fn foreign_opaque_projection_preserves_the_existing_empty_draft_slot() {
    use ea_draft::DraftRepository;
    let (f, r, e) = prepared();
    let (_foreign, _foreign_runtime, foreign) = prepared();
    assert!(e.draft_source().unwrap() != foreign.draft_source().unwrap());
    let native = NativeOperatorProvider::open_test_fixture(
        f.writer_directory.join("ea-native-operator"),
        false,
    )
    .unwrap();
    let writer = OperatorRuntime::open_with_test_native(
        OperatorRuntimeConfig::load(&f.writer_config).unwrap(),
        &f.anchor,
        support::live_clock(),
        false,
        native,
    )
    .unwrap();
    let repository = ea_draft::AutosaveDraftRepository::new(
        writer.database().clone(),
        writer.signing_provider().clone(),
    );
    let d = repository.load_or_create().unwrap();
    let id = d.draft_id();
    let saved = repository.save(d).unwrap();
    let mut w = r
        .evidence_writer("Europe/Berlin".into(), f.profile.clone())
        .unwrap();
    assert!(w.preview(foreign).is_err());
    assert!(w.pending().unwrap().is_none());
    let after = repository.load_or_create().unwrap();
    assert!(after.draft_id() == id);
    assert!(after.notes().is_empty());
    assert_eq!(after.revision(), saved.revision());
}
